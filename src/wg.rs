use std::collections::HashMap;
use std::fmt::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use base64::Engine;
use boringtun::device::allowed_ips::AllowedIps;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use rand::{Rng, RngCore};
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::socket::{icmp, tcp, udp};
use smoltcp::wire::{
    Icmpv4Packet, Icmpv4Repr, Icmpv6Packet, Icmpv6Repr, IpAddress, IpEndpoint,
    IpListenEndpoint, Ipv4Address, Ipv6Address,
};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, Notify};
use tokio::time::Instant;

use crate::config::{DeviceConfig, PeerConfig};
use crate::netstack::Netstack;

const TIMER_INTERVAL: Duration = Duration::from_millis(100);
const DNS_TIMEOUT: Duration = Duration::from_secs(5);
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const TCP_RX_BUFFER: usize = 64 * 1024;
const TCP_TX_BUFFER: usize = 64 * 1024;
const UDP_RX_BUFFER: usize = 2048;
const UDP_TX_BUFFER: usize = 2048;
const ICMP_RX_BUFFER: usize = 256;
const ICMP_TX_BUFFER: usize = 256;

#[derive(Clone)]
pub struct WireguardRuntime {
    inner: Arc<Inner>,
}

struct Inner {
    state: Mutex<State>,
    notify: Notify,
    started: AtomicBool,
    dns_servers: Vec<IpAddr>,
    private_key: [u8; 32],
    listen_port: Option<u16>,
}

struct State {
    netstack: Netstack,
    peers: Vec<PeerState>,
    peer_by_endpoint: HashMap<SocketAddr, usize>,
    allowed_ips: AllowedIps<usize>,
    udp: Arc<UdpSocket>,
    mtu: usize,
}

struct PeerState {
    endpoint: SocketAddr,
    tunn: Tunn,
    config: PeerConfig,
}

impl PeerState {
    /// Format public key like wireguard-go: "(+zv+…vLBQ)"
    fn short_id(&self) -> String {
        let b64 = BASE64_STD.encode(self.config.public_key);
        if b64.len() >= 8 {
            format!("({}…{})", &b64[..4], &b64[b64.len()-4..])
        } else {
            format!("({})", b64)
        }
    }
}

#[derive(Clone)]
pub struct WgTcpConnection {
    handle: Arc<std::sync::Mutex<Option<smoltcp::iface::SocketHandle>>>,
    runtime: WireguardRuntime,
}

pub struct WgTcpListener {
    port: u16,
    runtime: WireguardRuntime,
}

impl WireguardRuntime {
    pub async fn new(config: &DeviceConfig) -> anyhow::Result<Self> {
        let mtu = config.mtu;
        let netstack = Netstack::new(&config.addresses, mtu);
        let udp = Arc::new(bind_udp_socket(config.listen_port).context("bind udp socket")?);

        let mut peers = Vec::new();
        let mut peer_by_endpoint = HashMap::new();
        let mut allowed_ips = AllowedIps::new();

        for (idx, peer) in config.peers.iter().enumerate() {
            let endpoint = peer
                .endpoint
                .ok_or_else(|| anyhow::anyhow!("peer endpoint is required"))?;
            let tunn = build_tunn(config, peer)?;
            for net in &peer.allowed_ips {
                allowed_ips.insert(net.addr(), net.prefix_len() as u32, idx);
            }
            peer_by_endpoint.insert(endpoint, idx);
            peers.push(PeerState {
                endpoint,
                tunn,
                config: peer.clone(),
            });
        }

        let state = State {
            netstack,
            peers,
            peer_by_endpoint,
            allowed_ips,
            udp,
            mtu,
        };

        Ok(WireguardRuntime {
            inner: Arc::new(Inner {
                state: Mutex::new(state),
                notify: Notify::new(),
                started: AtomicBool::new(false),
                dns_servers: config.dns.clone(),
                private_key: config.private_key,
                listen_port: config.listen_port,
            }),
        })
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        self.start_tasks().await;
        tokio::signal::ctrl_c().await?;
        Ok(())
    }

    pub fn dns_servers(&self) -> Vec<IpAddr> {
        self.inner.dns_servers.clone()
    }

    pub fn system_dns(&self) -> bool {
        self.inner.dns_servers.is_empty()
    }

    pub async fn start(&self) {
        self.start_tasks().await;
    }

    pub async fn metrics(&self) -> String {
        let state = self.inner.state.lock().await;
        let mut out = String::new();

        let _ = writeln!(&mut out, "protocol_version=1");
        let _ = writeln!(&mut out, "private_key={}", encode_key(&self.inner.private_key));
        if let Some(port) = self.inner.listen_port {
            let _ = writeln!(&mut out, "listen_port={}", port);
        }

        for peer in &state.peers {
            let _ = writeln!(&mut out, "public_key={}", encode_key(&peer.config.public_key));
            if peer.config.preshared_key != [0u8; 32] {
                let _ = writeln!(
                    &mut out,
                    "preshared_key={}",
                    encode_key(&peer.config.preshared_key)
                );
            }
            if peer.config.keepalive != 0 {
                let _ = writeln!(
                    &mut out,
                    "persistent_keepalive_interval={}",
                    peer.config.keepalive
                );
            }
            if let Some(endpoint) = peer.config.endpoint {
                let _ = writeln!(&mut out, "endpoint={endpoint}");
            }
            for net in &peer.config.allowed_ips {
                let _ = writeln!(&mut out, "allowed_ip={net}");
            }
            let (last_handshake, tx_bytes, rx_bytes, _, _) = peer.tunn.stats();
            if let Some(since) = last_handshake {
                if let Some(when) = SystemTime::now().checked_sub(since) {
                    if let Ok(delta) = when.duration_since(UNIX_EPOCH) {
                        let _ = writeln!(&mut out, "last_handshake_time_sec={}", delta.as_secs());
                        let _ = writeln!(
                            &mut out,
                            "last_handshake_time_nsec={}",
                            delta.subsec_nanos()
                        );
                    }
                }
            }
            let _ = writeln!(&mut out, "rx_bytes={rx_bytes}");
            let _ = writeln!(&mut out, "tx_bytes={tx_bytes}");
        }

        out
    }

    pub async fn ping(&self, target: IpAddr, timeout: Duration) -> anyhow::Result<()> {
        let ident: u16 = rand::random();
        let seq_no: u16 = rand::random();
        let mut payload = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut payload);

        let (handle, target_addr, v6_src) = {
            let mut state = self.inner.state.lock().await;
            let rx = icmp::PacketBuffer::new(
                vec![icmp::PacketMetadata::EMPTY; 4],
                vec![0u8; ICMP_RX_BUFFER],
            );
            let tx = icmp::PacketBuffer::new(
                vec![icmp::PacketMetadata::EMPTY; 4],
                vec![0u8; ICMP_TX_BUFFER],
            );
            let mut socket = icmp::Socket::new(rx, tx);
            socket
                .bind(icmp::Endpoint::Ident(ident))
                .map_err(|e| anyhow::anyhow!("icmp bind error: {e:?}"))?;
            let handle = state.netstack.add_socket(socket);

            let target_addr = to_ip_address(target);
            let v6_src = match target {
                IpAddr::V4(dst) => {
                    let dst_addr = Ipv4Address::from(dst);
                    let _src_addr = state
                        .netstack
                        .iface
                        .get_source_address_ipv4(&dst_addr)
                        .ok_or_else(|| anyhow::anyhow!("no IPv4 source address for {dst}"))?;
                    let repr = Icmpv4Repr::EchoRequest {
                        ident,
                        seq_no,
                        data: &payload,
                    };
                    let mut buf = vec![0u8; repr.buffer_len()];
                    repr.emit(
                        &mut Icmpv4Packet::new_unchecked(&mut buf),
                        &ChecksumCapabilities::default(),
                    );
                    let socket = state.netstack.sockets.get_mut::<icmp::Socket>(handle);
                    socket
                        .send_slice(&buf, target_addr)
                        .map_err(|e| anyhow::anyhow!("icmp send error: {e:?}"))?;
                    None
                }
                IpAddr::V6(dst) => {
                    let dst_addr = Ipv6Address::from(dst);
                    let src_addr = state
                        .netstack
                        .iface
                        .get_source_address_ipv6(&dst_addr)
                        .ok_or_else(|| anyhow::anyhow!("no IPv6 source address for {dst}"))?;
                    let repr = Icmpv6Repr::EchoRequest {
                        ident,
                        seq_no,
                        data: &payload,
                    };
                    let mut buf = vec![0u8; repr.buffer_len()];
                    repr.emit(
                        &IpAddress::Ipv6(src_addr),
                        &IpAddress::Ipv6(dst_addr),
                        &mut Icmpv6Packet::new_unchecked(&mut buf),
                        &ChecksumCapabilities::default(),
                    );
                    let socket = state.netstack.sockets.get_mut::<icmp::Socket>(handle);
                    socket
                        .send_slice(&buf, target_addr)
                        .map_err(|e| anyhow::anyhow!("icmp send error: {e:?}"))?;
                    Some(src_addr)
                }
            };

            (handle, target_addr, v6_src)
        };

        self.inner.notify.notify_waiters();

        let deadline = Instant::now() + timeout;
        let mut recv_buf = [0u8; 512];
        loop {
            let mut state = self.inner.state.lock().await;
            let maybe_reply = {
                let socket = state.netstack.sockets.get_mut::<icmp::Socket>(handle);
                if socket.can_recv() {
                    let (len, from) = socket
                        .recv_slice(&mut recv_buf)
                        .map_err(|e| anyhow::anyhow!("icmp recv error: {e:?}"))?;
                    Some((len, from))
                } else {
                    None
                }
            };

            if let Some((len, from)) = maybe_reply {
                if from == target_addr
                    && matches_echo_reply(
                        &recv_buf[..len],
                        target_addr,
                        v6_src,
                        ident,
                        seq_no,
                    )
                {
                    state.netstack.sockets.remove(handle);
                    self.inner.notify.notify_waiters();
                    return Ok(());
                }
            }

            if Instant::now() >= deadline {
                state.netstack.sockets.remove(handle);
                self.inner.notify.notify_waiters();
                anyhow::bail!("icmp ping timed out");
            }

            drop(state);
            self.inner.notify.notified().await;
        }
    }

    pub async fn connect(&self, addr: SocketAddr) -> anyhow::Result<WgTcpConnection> {
        let handle = {
            let mut state = self.inner.state.lock().await;
            if state.allowed_ips.find(addr.ip()).is_none() {
                anyhow::bail!("no peer for destination {addr}");
            }

            let rx = tcp::SocketBuffer::new(vec![0u8; TCP_RX_BUFFER]);
            let tx = tcp::SocketBuffer::new(vec![0u8; TCP_TX_BUFFER]);
            let mut socket = tcp::Socket::new(rx, tx);
            socket.set_nagle_enabled(false);

            let handle = state.netstack.add_socket(socket);
            let local_port = random_ephemeral_port();
            let netstack = &mut state.netstack;
            let (iface, sockets) = (&mut netstack.iface, &mut netstack.sockets);
            let socket = sockets.get_mut::<tcp::Socket>(handle);
            socket
                .connect(
                    iface.context(),
                    IpEndpoint::new(to_ip_address(addr.ip()), addr.port()),
                    IpListenEndpoint::from(local_port),
                )
                .map_err(|e| anyhow::anyhow!("tcp connect error: {e:?}"))?;
            handle
        };

        self.inner.notify.notify_waiters();

        let mut conn = WgTcpConnection {
            handle: Arc::new(std::sync::Mutex::new(Some(handle))),
            runtime: self.clone(),
        };
        conn.wait_established().await?;
        Ok(conn)
    }

    pub async fn listen(&self, port: u16) -> anyhow::Result<WgTcpListener> {
        Ok(WgTcpListener {
            port,
            runtime: self.clone(),
        })
    }

    pub async fn accept(&self, port: u16) -> anyhow::Result<WgTcpConnection> {
        let handle = {
            let mut state = self.inner.state.lock().await;
            let rx = tcp::SocketBuffer::new(vec![0u8; TCP_RX_BUFFER]);
            let tx = tcp::SocketBuffer::new(vec![0u8; TCP_TX_BUFFER]);
            let mut socket = tcp::Socket::new(rx, tx);
            socket
                .listen(IpListenEndpoint::from(port))
                .map_err(|e| anyhow::anyhow!("tcp listen error: {e:?}"))?;
            state.netstack.add_socket(socket)
        };

        self.inner.notify.notify_waiters();

        loop {
            let mut state = self.inner.state.lock().await;
            let socket = state
                .netstack
                .sockets
                .get_mut::<tcp::Socket>(handle);
            match socket.state() {
                tcp::State::Established => {
                    return Ok(WgTcpConnection {
                        handle: Arc::new(std::sync::Mutex::new(Some(handle))),
                        runtime: self.clone(),
                    })
                }
                tcp::State::Closed => {
                    state.netstack.sockets.remove(handle);
                    anyhow::bail!("listener closed before accept");
                }
                _ => {}
            }
            drop(state);
            self.inner.notify.notified().await;
        }
    }

    pub async fn udp_exchange(&self, target: SocketAddr, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
        let handle = {
            let mut state = self.inner.state.lock().await;
            let rx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0u8; UDP_RX_BUFFER]);
            let tx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0u8; UDP_TX_BUFFER]);
            let mut socket = udp::Socket::new(rx, tx);
            let local_port = random_ephemeral_port();
            socket
                .bind(IpListenEndpoint::from(local_port))
                .map_err(|e| anyhow::anyhow!("udp bind error: {e:?}"))?;
            let handle = state.netstack.add_socket(socket);
            let socket = state.netstack.sockets.get_mut::<udp::Socket>(handle);
            socket
                .send_slice(
                    payload,
                    IpEndpoint::new(to_ip_address(target.ip()), target.port()),
                )
                .map_err(|e| anyhow::anyhow!("udp send error: {e:?}"))?;
            handle
        };

        self.inner.notify.notify_waiters();

        let deadline = tokio::time::Instant::now() + DNS_TIMEOUT;
        loop {
            let mut state = self.inner.state.lock().await;
            let payload = {
                let socket = state.netstack.sockets.get_mut::<udp::Socket>(handle);
                if socket.can_recv() {
                    let (data, _) = socket
                        .recv()
                        .map_err(|e| anyhow::anyhow!("udp recv error: {e:?}"))?;
                    Some(data.to_vec())
                } else {
                    None
                }
            };
            if let Some(payload) = payload {
                state.netstack.sockets.remove(handle);
                return Ok(payload);
            }
            if tokio::time::Instant::now() >= deadline {
                state.netstack.sockets.remove(handle);
                anyhow::bail!("udp exchange timed out");
            }
            drop(state);
            self.inner.notify.notified().await;
        }
    }

    async fn start_tasks(&self) {
        if self.inner.started.swap(true, Ordering::SeqCst) {
            return;
        }

        let runtime = self.clone();
        tokio::spawn(async move { runtime.poll_loop().await });

        let runtime = self.clone();
        tokio::spawn(async move { runtime.udp_loop().await });

        let runtime = self.clone();
        tokio::spawn(async move { runtime.timer_loop().await });
    }

    async fn poll_loop(&self) {
        loop {
            let (frames, did_work, delay) = {
                let mut state = self.inner.state.lock().await;
                let did_work = state.netstack.poll();
                let frames = state.netstack.drain_outbound();
                let delay = state.netstack.poll_delay();
                (frames, did_work, delay)
            };

            if did_work {
                self.inner.notify.notify_waiters();
            }

            if let Err(err) = self.send_frames(frames).await {
                log::error!("failed sending frames: {err:#}");
            }

            // Use smoltcp's poll_delay for precise timing, with a small fallback
            // to avoid busy-looping while still being responsive
            let sleep_duration = delay
                .filter(|d| *d > Duration::ZERO)
                .unwrap_or(Duration::from_millis(1));

            tokio::select! {
                biased;
                _ = self.inner.notify.notified() => {}
                _ = tokio::time::sleep(sleep_duration) => {}
            }
        }
    }

    async fn udp_loop(&self) {
        let udp = {
            let state = self.inner.state.lock().await;
            state.udp.clone()
        };
        let mut buffer = vec![0u8; 65535];
        loop {
            let (len, src) = match udp.recv_from(&mut buffer).await {
                Ok(result) => result,
                Err(err) => {
                    log::error!("udp recv error: {err}");
                    continue;
                }
            };

            if let Err(err) = self.handle_incoming(src, &buffer[..len]).await {
                log::error!("failed handling udp packet: {err:#}");
            }
        }
    }

    async fn timer_loop(&self) {
        loop {
            let datagrams = {
                let mut state = self.inner.state.lock().await;
                let mut datagrams = Vec::new();
                for peer in &mut state.peers {
                    let mut buf = vec![0u8; 256];
                    match peer.tunn.update_timers(&mut buf) {
                        TunnResult::WriteToNetwork(packet) => {
                            // Handshake initiation is 148 bytes, keepalive is smaller
                            let msg_type = if packet.len() >= 148 {
                                "Sending handshake initiation"
                            } else {
                                "Sending keepalive packet"
                            };
                            log::debug!("peer{} - {}", peer.short_id(), msg_type);
                            datagrams.push((peer.endpoint, packet.to_vec()));
                        }
                        TunnResult::Err(err) => {
                            log::warn!("peer{} - timer error: {err:?}", peer.short_id());
                        }
                        _ => {}
                    }
                }
                datagrams
            };

            for (endpoint, packet) in datagrams {
                if let Err(err) = self.send_datagram(endpoint, packet).await {
                    log::error!("failed sending to {endpoint}: {err:#}");
                }
            }

            tokio::time::sleep(TIMER_INTERVAL).await;
        }
    }

    async fn send_frames(&self, frames: Vec<Vec<u8>>) -> anyhow::Result<()> {
        if frames.is_empty() {
            return Ok(());
        }

        let datagrams = {
            let mut state = self.inner.state.lock().await;
            let mut datagrams = Vec::new();

            for frame in frames {
                let dst = match dst_ip(&frame) {
                    Some(dst) => dst,
                    None => {
                        log::warn!("dropping packet without destination");
                        continue;
                    }
                };
                let Some(peer_idx) = state.allowed_ips.find(dst).cloned() else {
                    log::warn!("no peer for destination {dst}");
                    continue;
                };
                let peer = &mut state.peers[peer_idx];
                let mut buf = vec![0u8; wg_buffer_size(frame.len())];
                match peer.tunn.encapsulate(&frame, &mut buf) {
                    TunnResult::WriteToNetwork(packet) => {
                        datagrams.push((peer.endpoint, packet.to_vec()));
                    }
                    TunnResult::Err(err) => {
                        log::warn!("wireguard encapsulate error: {err:?}");
                    }
                    _ => {}
                }
            }
            datagrams
        };

        for (endpoint, packet) in datagrams {
            self.send_datagram(endpoint, packet).await?;
        }

        Ok(())
    }

    async fn handle_incoming(&self, src: SocketAddr, data: &[u8]) -> anyhow::Result<()> {
        let datagrams = {
            let mut state = self.inner.state.lock().await;
            let mut datagrams = Vec::new();
            let mut inbound = Vec::new();

            let mut out_buf = vec![0u8; wg_buffer_size(state.mtu)];
            if let Some(peer_idx) = state.peer_by_endpoint.get(&src).cloned() {
                let peer = &mut state.peers[peer_idx];
                process_datagram(peer, src.ip(), data, &mut out_buf, &mut datagrams, &mut inbound);
            } else {
                for peer in &mut state.peers {
                    let handled = process_datagram(peer, src.ip(), data, &mut out_buf, &mut datagrams, &mut inbound);
                    if handled {
                        break;
                    }
                }
            }

            for packet in inbound.drain(..) {
                state.netstack.push_inbound(packet);
            }

            datagrams
        };

        if !datagrams.is_empty() {
            for (endpoint, packet) in datagrams {
                self.send_datagram(endpoint, packet).await?;
            }
        }

        self.inner.notify.notify_waiters();
        Ok(())
    }

    async fn send_datagram(&self, endpoint: SocketAddr, payload: Vec<u8>) -> anyhow::Result<()> {
        let udp = {
            let state = self.inner.state.lock().await;
            state.udp.clone()
        };
        udp.send_to(&payload, endpoint)
            .await
            .context("udp send")?;
        Ok(())
    }
}

impl WgTcpConnection {
    pub async fn read(&mut self, buf: &mut [u8]) -> anyhow::Result<usize> {
        let handle = match *self.handle.lock().unwrap() {
            Some(h) => h,
            None => return Ok(0), // Connection already closed
        };
        loop {
            let mut state = self.runtime.inner.state.lock().await;
            let socket = state
                .netstack
                .sockets
                .get_mut::<tcp::Socket>(handle);
            if socket.can_recv() {
                let size = socket
                    .recv_slice(buf)
                    .map_err(|e| anyhow::anyhow!("tcp recv error: {e:?}"))?;
                if size == 0 {
                    socket.close();
                }
                return Ok(size);
            }
            if socket.state() == tcp::State::Closed {
                return Ok(0);
            }
            drop(state);
            self.runtime.inner.notify.notified().await;
        }
    }

    pub async fn write(&mut self, buf: &[u8]) -> anyhow::Result<usize> {
        let handle = match *self.handle.lock().unwrap() {
            Some(h) => h,
            None => anyhow::bail!("connection already closed"),
        };
        let mut offset = 0;
        while offset < buf.len() {
            let mut state = self.runtime.inner.state.lock().await;
            let socket = state
                .netstack
                .sockets
                .get_mut::<tcp::Socket>(handle);
            if socket.can_send() {
                let written = socket
                    .send_slice(&buf[offset..])
                    .map_err(|e| anyhow::anyhow!("tcp send error: {e:?}"))?;
                offset += written;
                self.runtime.inner.notify.notify_waiters();
            } else {
                drop(state);
                self.runtime.inner.notify.notified().await;
            }
        }
        Ok(offset)
    }

    pub async fn close(&mut self) {
        let handle = match self.handle.lock().unwrap().take() {
            Some(h) => h,
            None => return, // Already closed
        };
        let mut state = self.runtime.inner.state.lock().await;
        {
            let socket = state
                .netstack
                .sockets
                .get_mut::<tcp::Socket>(handle);
            socket.close();
        }
        state.netstack.sockets.remove(handle);
        self.runtime.inner.notify.notify_waiters();
    }

    async fn wait_established(&mut self) -> anyhow::Result<()> {
        let handle = match *self.handle.lock().unwrap() {
            Some(h) => h,
            None => anyhow::bail!("connection already closed"),
        };
        let deadline = tokio::time::Instant::now() + TCP_CONNECT_TIMEOUT;
        loop {
            let mut state = self.runtime.inner.state.lock().await;
            let socket = state
                .netstack
                .sockets
                .get_mut::<tcp::Socket>(handle);
            match socket.state() {
                tcp::State::Established => return Ok(()),
                tcp::State::Closed => {
                    *self.handle.lock().unwrap() = None; // Mark as closed
                    state.netstack.sockets.remove(handle);
                    anyhow::bail!("tcp connection failed to establish");
                }
                _ => {}
            }
            drop(state);

            if tokio::time::Instant::now() >= deadline {
                // Clean up the socket on timeout
                let mut state = self.runtime.inner.state.lock().await;
                let socket = state
                    .netstack
                    .sockets
                    .get_mut::<tcp::Socket>(handle);
                socket.abort();
                state.netstack.sockets.remove(handle);
                *self.handle.lock().unwrap() = None; // Mark as closed
                anyhow::bail!("tcp connection timed out");
            }

            self.runtime.inner.notify.notified().await;
        }
    }
}

impl WgTcpListener {
    pub async fn accept(&self) -> anyhow::Result<WgTcpConnection> {
        self.runtime.accept(self.port).await
    }
}

fn bind_udp_socket(listen_port: Option<u16>) -> anyhow::Result<UdpSocket> {
    let port = listen_port.unwrap_or(0);
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_only_v6(false)?;
    socket.bind(&SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port).into())?;
    socket.set_nonblocking(true)?;
    Ok(UdpSocket::from_std(socket.into())?)
}

fn build_tunn(device: &DeviceConfig, peer: &PeerConfig) -> anyhow::Result<Tunn> {
    let private_key = StaticSecret::from(device.private_key);
    let peer_public = PublicKey::from(peer.public_key);
    let preshared = if peer.preshared_key == [0u8; 32] {
        None
    } else {
        Some(peer.preshared_key)
    };
    let keepalive = if peer.keepalive == 0 {
        None
    } else {
        Some(peer.keepalive)
    };
    let index: u32 = rand::random();
    Tunn::new(
        private_key,
        peer_public,
        preshared,
        keepalive,
        index,
        None,
    )
    .map_err(|err| anyhow::anyhow!(err))
}

fn encode_key(key: &[u8; 32]) -> String {
    BASE64_STD.encode(key)
}

fn wg_buffer_size(payload_len: usize) -> usize {
    let mut size = payload_len + 32;
    if size < 148 {
        size = 148;
    }
    size
}

fn to_ip_address(addr: IpAddr) -> IpAddress {
    match addr {
        IpAddr::V4(v4) => IpAddress::Ipv4(Ipv4Address::from(v4)),
        IpAddr::V6(v6) => IpAddress::Ipv6(Ipv6Address::from(v6)),
    }
}

fn dst_ip(packet: &[u8]) -> Option<IpAddr> {
    let version = packet.first()? >> 4;
    match version {
        4 if packet.len() >= 20 => {
            let octets: [u8; 4] = packet[16..20].try_into().ok()?;
            Some(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        6 if packet.len() >= 40 => {
            let octets: [u8; 16] = packet[24..40].try_into().ok()?;
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

fn matches_echo_reply(
    buf: &[u8],
    target: IpAddress,
    v6_src: Option<Ipv6Address>,
    ident: u16,
    seq_no: u16,
) -> bool {
    match target {
        IpAddress::Ipv4(_) => {
            let packet = match Icmpv4Packet::new_checked(buf) {
                Ok(packet) => packet,
                Err(_) => return false,
            };
            matches!(
                Icmpv4Repr::parse(&packet, &ChecksumCapabilities::ignored()),
                Ok(Icmpv4Repr::EchoReply {
                    ident: reply_ident,
                    seq_no: reply_seq,
                    ..
                }) if reply_ident == ident && reply_seq == seq_no
            )
        }
        IpAddress::Ipv6(dst) => {
            let Some(src) = v6_src else {
                return false;
            };
            let packet = match Icmpv6Packet::new_checked(buf) {
                Ok(packet) => packet,
                Err(_) => return false,
            };
            matches!(
                Icmpv6Repr::parse(
                    &IpAddress::Ipv6(src),
                    &IpAddress::Ipv6(dst),
                    &packet,
                    &ChecksumCapabilities::ignored(),
                ),
                Ok(Icmpv6Repr::EchoReply {
                    ident: reply_ident,
                    seq_no: reply_seq,
                    ..
                }) if reply_ident == ident && reply_seq == seq_no
            )
        }
    }
}

fn process_datagram(
    peer: &mut PeerState,
    src_ip: IpAddr,
    data: &[u8],
    out_buf: &mut [u8],
    datagrams: &mut Vec<(SocketAddr, Vec<u8>)>,
    inbound: &mut Vec<Vec<u8>>,
) -> bool {
    let mut handled = false;
    let peer_id = peer.short_id();
    let mut result = peer.tunn.decapsulate(Some(src_ip), data, out_buf);
    loop {
        match result {
            TunnResult::WriteToNetwork(packet) => {
                log::debug!("peer{} - Received handshake response", peer_id);
                datagrams.push((peer.endpoint, packet.to_vec()));
                handled = true;
                result = peer.tunn.decapsulate(Some(src_ip), &[], out_buf);
            }
            TunnResult::WriteToTunnelV4(packet, _) => {
                log::trace!("peer{} - received {} bytes (IPv4)", peer_id, packet.len());
                inbound.push(packet.to_vec());
                handled = true;
                break;
            }
            TunnResult::WriteToTunnelV6(packet, _) => {
                log::trace!("peer{} - received {} bytes (IPv6)", peer_id, packet.len());
                inbound.push(packet.to_vec());
                handled = true;
                break;
            }
            TunnResult::Done => {
                // Could be a keepalive packet (empty data after decryption)
                if data.len() > 0 && data.len() < 100 {
                    log::debug!("peer{} - Receiving keepalive packet", peer_id);
                }
                handled = true;
                break;
            }
            TunnResult::Err(err) => {
                log::debug!("peer{} - decapsulate error: {err:?}", peer_id);
                break;
            }
        }
    }
    handled
}

fn random_ephemeral_port() -> u16 {
    let mut rng = rand::thread_rng();
    rng.gen_range(49152..65535)
}
