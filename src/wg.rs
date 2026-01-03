use std::collections::HashMap;
use std::fmt::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use base64::Engine;
use boringtun::device::allowed_ips::AllowedIps;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use bytes::Bytes;
use parking_lot::{Mutex, RwLock};
use rand::RngCore;
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::socket::{icmp, tcp, udp};
use smoltcp::wire::{
    Icmpv4Packet, Icmpv4Repr, Icmpv6Packet, Icmpv6Repr, IpAddress, IpEndpoint, IpListenEndpoint,
    Ipv4Address, Ipv6Address,
};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Notify};
use tokio::time::Instant;

use crate::buffer::BufferPool;
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

/// Outbound datagram for UDP sending (zero-copy with Bytes)
pub struct Datagram {
    pub endpoint: SocketAddr,
    pub data: Bytes,
}

#[derive(Clone)]
pub struct WireguardRuntime {
    inner: Arc<Inner>,
}

struct Inner {
    /// Network stack - protected by its own lock (high contention)
    netstack: Mutex<Netstack>,
    /// Peer states - protected by RwLock for read-heavy access
    peers: RwLock<PeerManager>,
    /// UDP socket - Arc for sharing without lock
    udp: Arc<UdpSocket>,
    /// Channel for outbound datagrams (event-driven)
    outbound_tx: mpsc::UnboundedSender<Datagram>,
    /// Notify for netstack events
    notify: Notify,
    /// Started flag
    started: AtomicBool,
    /// DNS servers
    dns_servers: Vec<IpAddr>,
    /// Private key for metrics
    private_key: [u8; 32],
    /// Listen port for metrics
    listen_port: Option<u16>,
    /// MTU
    #[allow(dead_code)]
    mtu: usize,
    /// Buffer pool for reducing allocations
    buffer_pool: Arc<BufferPool>,
}

struct PeerManager {
    peers: Vec<PeerState>,
    peer_by_endpoint: HashMap<SocketAddr, usize>,
    allowed_ips: AllowedIps<usize>,
}

struct PeerState {
    endpoint: SocketAddr,
    tunn: Tunn,
    config: PeerConfig,
}

impl PeerState {
    fn short_id(&self) -> String {
        let b64 = BASE64_STD.encode(self.config.public_key);
        if b64.len() >= 8 {
            format!("({}…{})", &b64[..4], &b64[b64.len() - 4..])
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

        let peer_manager = PeerManager {
            peers,
            peer_by_endpoint,
            allowed_ips,
        };

        let (outbound_tx, outbound_rx) = mpsc::unbounded_channel();
        let buffer_pool = Arc::new(BufferPool::new(128, 64));

        let inner = Arc::new(Inner {
            netstack: Mutex::new(netstack),
            peers: RwLock::new(peer_manager),
            udp: udp.clone(),
            outbound_tx,
            notify: Notify::new(),
            started: AtomicBool::new(false),
            dns_servers: config.dns.clone(),
            private_key: config.private_key,
            listen_port: config.listen_port,
            mtu,
            buffer_pool,
        });

        // Spawn the event-driven outbound sender task
        let udp_clone = udp.clone();
        tokio::spawn(outbound_sender_loop(udp_clone, outbound_rx));

        Ok(WireguardRuntime { inner })
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
        // Use read lock for peers - no mutation needed
        let peers = self.inner.peers.read();
        let mut out = String::new();

        let _ = writeln!(&mut out, "protocol_version=1");
        let _ = writeln!(&mut out, "private_key={}", encode_key(&self.inner.private_key));
        if let Some(port) = self.inner.listen_port {
            let _ = writeln!(&mut out, "listen_port={}", port);
        }

        for peer in &peers.peers {
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
        rand::rng().fill_bytes(&mut payload);

        let (handle, target_addr, v6_src) = {
            let mut netstack = self.inner.netstack.lock();
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
            let handle = netstack.add_socket(socket);

            let target_addr = to_ip_address(target);
            let v6_src = match target {
                IpAddr::V4(dst) => {
                    let dst_addr = Ipv4Address::from(dst);
                    let _src_addr = netstack
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
                    let socket = netstack.sockets.get_mut::<icmp::Socket>(handle);
                    socket
                        .send_slice(&buf, target_addr)
                        .map_err(|e| anyhow::anyhow!("icmp send error: {e:?}"))?;
                    None
                }
                IpAddr::V6(dst) => {
                    let dst_addr = Ipv6Address::from(dst);
                    let src_addr = netstack.iface.get_source_address_ipv6(&dst_addr);
                    let repr = Icmpv6Repr::EchoRequest {
                        ident,
                        seq_no,
                        data: &payload,
                    };
                    let mut buf = vec![0u8; repr.buffer_len()];
                    repr.emit(
                        &src_addr,
                        &dst_addr,
                        &mut Icmpv6Packet::new_unchecked(&mut buf),
                        &ChecksumCapabilities::default(),
                    );
                    let socket = netstack.sockets.get_mut::<icmp::Socket>(handle);
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
            {
                let mut netstack = self.inner.netstack.lock();
                let socket = netstack.sockets.get_mut::<icmp::Socket>(handle);
                if socket.can_recv() {
                    let (len, from) = socket
                        .recv_slice(&mut recv_buf)
                        .map_err(|e| anyhow::anyhow!("icmp recv error: {e:?}"))?;
                    if from == target_addr
                        && matches_echo_reply(&recv_buf[..len], target_addr, v6_src, ident, seq_no)
                    {
                        netstack.sockets.remove(handle);
                        self.inner.notify.notify_waiters();
                        return Ok(());
                    }
                }
            }

            if Instant::now() >= deadline {
                let mut netstack = self.inner.netstack.lock();
                netstack.sockets.remove(handle);
                self.inner.notify.notify_waiters();
                anyhow::bail!("icmp ping timed out");
            }

            self.inner.notify.notified().await;
        }
    }

    pub async fn connect(&self, addr: SocketAddr) -> anyhow::Result<WgTcpConnection> {
        let handle = {
            let peers = self.inner.peers.read();
            if peers.allowed_ips.find(addr.ip()).is_none() {
                anyhow::bail!("no peer for destination {addr}");
            }
            drop(peers);

            let mut netstack = self.inner.netstack.lock();
            let rx = tcp::SocketBuffer::new(vec![0u8; TCP_RX_BUFFER]);
            let tx = tcp::SocketBuffer::new(vec![0u8; TCP_TX_BUFFER]);
            let mut socket = tcp::Socket::new(rx, tx);
            socket.set_nagle_enabled(false);

            let handle = netstack.add_socket(socket);
            let local_port = random_ephemeral_port();
            netstack
                .tcp_connect(
                    handle,
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
            let mut netstack = self.inner.netstack.lock();
            let rx = tcp::SocketBuffer::new(vec![0u8; TCP_RX_BUFFER]);
            let tx = tcp::SocketBuffer::new(vec![0u8; TCP_TX_BUFFER]);
            let mut socket = tcp::Socket::new(rx, tx);
            socket
                .listen(IpListenEndpoint::from(port))
                .map_err(|e| anyhow::anyhow!("tcp listen error: {e:?}"))?;
            netstack.add_socket(socket)
        };

        self.inner.notify.notify_waiters();

        loop {
            {
                let mut netstack = self.inner.netstack.lock();
                let socket = netstack.sockets.get_mut::<tcp::Socket>(handle);
                match socket.state() {
                    tcp::State::Established => {
                        return Ok(WgTcpConnection {
                            handle: Arc::new(std::sync::Mutex::new(Some(handle))),
                            runtime: self.clone(),
                        })
                    }
                    tcp::State::Closed => {
                        netstack.sockets.remove(handle);
                        anyhow::bail!("listener closed before accept");
                    }
                    _ => {}
                }
            }
            self.inner.notify.notified().await;
        }
    }

    pub async fn udp_exchange(&self, target: SocketAddr, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
        let handle = {
            let mut netstack = self.inner.netstack.lock();
            let rx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0u8; UDP_RX_BUFFER]);
            let tx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0u8; UDP_TX_BUFFER]);
            let mut socket = udp::Socket::new(rx, tx);
            let local_port = random_ephemeral_port();
            socket
                .bind(IpListenEndpoint::from(local_port))
                .map_err(|e| anyhow::anyhow!("udp bind error: {e:?}"))?;
            let handle = netstack.add_socket(socket);
            let socket = netstack.sockets.get_mut::<udp::Socket>(handle);
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
            {
                let mut netstack = self.inner.netstack.lock();
                let socket = netstack.sockets.get_mut::<udp::Socket>(handle);
                if socket.can_recv() {
                    let (data, _) = socket
                        .recv()
                        .map_err(|e| anyhow::anyhow!("udp recv error: {e:?}"))?;
                    let result = data.to_vec();
                    netstack.sockets.remove(handle);
                    return Ok(result);
                }
            }
            if tokio::time::Instant::now() >= deadline {
                let mut netstack = self.inner.netstack.lock();
                netstack.sockets.remove(handle);
                anyhow::bail!("udp exchange timed out");
            }
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

    /// Event-driven poll loop - wakes on notify or timeout
    async fn poll_loop(&self) {
        loop {
            let (frames, did_work, delay) = {
                let mut netstack = self.inner.netstack.lock();
                let did_work = netstack.poll();
                let frames = netstack.drain_outbound();
                let delay = netstack.poll_delay();
                (frames, did_work, delay)
            };

            if did_work {
                self.inner.notify.notify_waiters();
            }

            if !frames.is_empty() {
                self.send_frames(frames);
            }

            // Event-driven: wait for notify or smoltcp's poll_delay
            let sleep_duration = delay
                .filter(|d| *d > Duration::ZERO)
                .unwrap_or(Duration::from_millis(5));

            tokio::select! {
                biased;
                _ = self.inner.notify.notified() => {}
                _ = tokio::time::sleep(sleep_duration) => {}
            }
        }
    }

    async fn udp_loop(&self) {
        let mut buffer = self.inner.buffer_pool.get_large();
        loop {
            let (len, src) = match self.inner.udp.recv_from(&mut buffer.buf[..]).await {
                Ok(result) => result,
                Err(err) => {
                    log::error!("udp recv error: {err}");
                    continue;
                }
            };

            if let Err(err) = self.handle_incoming(src, &buffer.buf[..len]) {
                log::error!("failed handling udp packet: {err:#}");
            }
        }
    }

    async fn timer_loop(&self) {
        let mut timer_buf = [0u8; 256];
        
        loop {
            {
                let mut peers = self.inner.peers.write();
                for peer in &mut peers.peers {
                    match peer.tunn.update_timers(&mut timer_buf) {
                        TunnResult::WriteToNetwork(packet) => {
                            let msg_type = if packet.len() >= 148 {
                                "Sending handshake initiation"
                            } else {
                                "Sending keepalive packet"
                            };
                            log::debug!("peer{} - {}", peer.short_id(), msg_type);
                            let _ = self.inner.outbound_tx.send(Datagram {
                                endpoint: peer.endpoint,
                                data: Bytes::copy_from_slice(packet),
                            });
                        }
                        TunnResult::Err(err) => {
                            log::warn!("peer{} - timer error: {err:?}", peer.short_id());
                        }
                        _ => {}
                    }
                }
            }

            tokio::time::sleep(TIMER_INTERVAL).await;
        }
    }

    fn send_frames(&self, frames: Vec<Vec<u8>>) {
        let mut peers = self.inner.peers.write();
        let mut buf = self.inner.buffer_pool.get_small();

        for frame in frames {
            let dst = match dst_ip(&frame) {
                Some(dst) => dst,
                None => {
                    log::warn!("dropping packet without destination");
                    continue;
                }
            };
            let Some(peer_idx) = peers.allowed_ips.find(dst).cloned() else {
                log::warn!("no peer for destination {dst}");
                continue;
            };
            let peer = &mut peers.peers[peer_idx];
            match peer.tunn.encapsulate(&frame, &mut buf.buf[..]) {
                TunnResult::WriteToNetwork(packet) => {
                    let _ = self.inner.outbound_tx.send(Datagram {
                        endpoint: peer.endpoint,
                        data: Bytes::copy_from_slice(packet),
                    });
                }
                TunnResult::Err(err) => {
                    log::warn!("wireguard encapsulate error: {err:?}");
                }
                _ => {}
            }
        }
    }

    /// Handle incoming UDP packet from WireGuard peer
    fn handle_incoming(&self, src: SocketAddr, data: &[u8]) -> anyhow::Result<()> {
        let mut buf = self.inner.buffer_pool.get_small();
        let mut inbound_packets = Vec::new();

        {
            let mut peers = self.inner.peers.write();
            if let Some(peer_idx) = peers.peer_by_endpoint.get(&src).cloned() {
                let peer = &mut peers.peers[peer_idx];
                process_datagram(peer, src.ip(), data, &mut buf.buf[..], &self.inner.outbound_tx, &mut inbound_packets);
            } else {
                for peer in &mut peers.peers {
                    let handled = process_datagram(peer, src.ip(), data, &mut buf.buf[..], &self.inner.outbound_tx, &mut inbound_packets);
                    if handled {
                        break;
                    }
                }
            }
        }

        // Push inbound packets to netstack (separate lock)
        if !inbound_packets.is_empty() {
            let mut netstack = self.inner.netstack.lock();
            for packet in inbound_packets {
                netstack.push_inbound(packet);
            }
        }

        self.inner.notify.notify_waiters();
        Ok(())
    }
}

impl WgTcpConnection {
    pub async fn read(&mut self, buf: &mut [u8]) -> anyhow::Result<usize> {
        let handle = match *self.handle.lock().unwrap() {
            Some(h) => h,
            None => return Ok(0),
        };
        loop {
            {
                let mut netstack = self.runtime.inner.netstack.lock();
                let socket = netstack.sockets.get_mut::<tcp::Socket>(handle);
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
            }
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
            {
                let mut netstack = self.runtime.inner.netstack.lock();
                let socket = netstack.sockets.get_mut::<tcp::Socket>(handle);
                if socket.can_send() {
                    let written = socket
                        .send_slice(&buf[offset..])
                        .map_err(|e| anyhow::anyhow!("tcp send error: {e:?}"))?;
                    offset += written;
                    self.runtime.inner.notify.notify_waiters();
                    continue;
                }
            }
            self.runtime.inner.notify.notified().await;
        }
        Ok(offset)
    }

    pub async fn close(&mut self) {
        let handle = match self.handle.lock().unwrap().take() {
            Some(h) => h,
            None => return,
        };
        let mut netstack = self.runtime.inner.netstack.lock();
        {
            let socket = netstack.sockets.get_mut::<tcp::Socket>(handle);
            socket.close();
        }
        netstack.sockets.remove(handle);
        self.runtime.inner.notify.notify_waiters();
    }

    async fn wait_established(&mut self) -> anyhow::Result<()> {
        let handle = match *self.handle.lock().unwrap() {
            Some(h) => h,
            None => anyhow::bail!("connection already closed"),
        };
        let deadline = tokio::time::Instant::now() + TCP_CONNECT_TIMEOUT;
        loop {
            {
                let mut netstack = self.runtime.inner.netstack.lock();
                let socket = netstack.sockets.get_mut::<tcp::Socket>(handle);
                match socket.state() {
                    tcp::State::Established => return Ok(()),
                    tcp::State::Closed => {
                        *self.handle.lock().unwrap() = None;
                        netstack.sockets.remove(handle);
                        anyhow::bail!("tcp connection failed to establish");
                    }
                    _ => {}
                }
            }

            if tokio::time::Instant::now() >= deadline {
                let mut netstack = self.runtime.inner.netstack.lock();
                let socket = netstack.sockets.get_mut::<tcp::Socket>(handle);
                socket.abort();
                netstack.sockets.remove(handle);
                *self.handle.lock().unwrap() = None;
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

// ============ Event-driven outbound sender ============

/// Event-driven outbound sender loop with Linux sendmmsg support
async fn outbound_sender_loop(udp: Arc<UdpSocket>, mut rx: mpsc::UnboundedReceiver<Datagram>) {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let fd = udp.as_raw_fd();
        let mut batch = Vec::with_capacity(64);

        loop {
            batch.clear();

            // Wait for at least one datagram
            match rx.recv().await {
                Some(dg) => batch.push(dg),
                None => break,
            }

            // Collect more without blocking (up to 64)
            while batch.len() < 64 {
                match rx.try_recv() {
                    Ok(dg) => batch.push(dg),
                    Err(_) => break,
                }
            }

            if batch.len() == 1 {
                let dg = &batch[0];
                if let Err(e) = udp.send_to(&dg.data, dg.endpoint).await {
                    log::error!("udp send error: {e}");
                }
            } else {
                // Batch send using sendmmsg
                if let Err(e) = send_batch_linux(fd, &batch) {
                    log::error!("sendmmsg error: {e}");
                }
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        while let Some(dg) = rx.recv().await {
            if let Err(e) = udp.send_to(&dg.data, dg.endpoint).await {
                log::error!("udp send error: {e}");
            }
        }
    }
}

/// Linux sendmmsg batch send implementation
#[cfg(target_os = "linux")]
fn send_batch_linux(fd: std::os::fd::RawFd, batch: &[Datagram]) -> anyhow::Result<()> {
    use nix::sys::socket::{sendmmsg, MsgFlags, MultiHeaders, SockaddrStorage};
    use std::io::IoSlice;

    let mut iovecs: Vec<[IoSlice<'_>; 1]> = Vec::with_capacity(batch.len());
    let mut addrs: Vec<Option<SockaddrStorage>> = Vec::with_capacity(batch.len());

    // Prepare addresses and iovecs
    for dg in batch {
        let addr: SockaddrStorage = dg.endpoint.into();
        addrs.push(Some(addr));
        iovecs.push([IoSlice::new(&dg.data)]);
    }

    // nix 0.30 sendmmsg requires MultiHeaders preallocated buffer
    let mut data: MultiHeaders<SockaddrStorage> =
        MultiHeaders::preallocate(batch.len(), None);
    let cmsgs: Vec<nix::sys::socket::ControlMessage<'_>> = vec![];

    sendmmsg(fd, &mut data, &iovecs, &addrs, &cmsgs, MsgFlags::empty())?;
    Ok(())
}

// ============ Helper functions ============

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
    Tunn::new(private_key, peer_public, preshared, keepalive, index, None)
        .map_err(|err| anyhow::anyhow!(err))
}

fn encode_key(key: &[u8; 32]) -> String {
    BASE64_STD.encode(key)
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
                Icmpv6Repr::parse(&src, &dst, &packet, &ChecksumCapabilities::ignored()),
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
    outbound_tx: &mpsc::UnboundedSender<Datagram>,
    inbound: &mut Vec<Vec<u8>>,
) -> bool {
    let mut handled = false;
    let peer_id = peer.short_id();
    let mut result = peer.tunn.decapsulate(Some(src_ip), data, out_buf);
    loop {
        match result {
            TunnResult::WriteToNetwork(packet) => {
                log::debug!("peer{} - Received handshake response", peer_id);
                let _ = outbound_tx.send(Datagram {
                    endpoint: peer.endpoint,
                    data: Bytes::copy_from_slice(packet),
                });
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
                if !data.is_empty() && data.len() < 100 {
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
    rand::random_range(49152..65535)
}