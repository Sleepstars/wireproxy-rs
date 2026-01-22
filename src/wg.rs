use std::collections::HashMap;
use std::fmt::Write;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use bytes::BytesMut;
use ipnetwork::IpNetwork;
use rand::RngCore;
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::socket::{icmp, tcp, udp};
use smoltcp::wire::{
    Icmpv4Packet, Icmpv4Repr, Icmpv6Packet, Icmpv6Repr, IpAddress, IpEndpoint, IpListenEndpoint,
    Ipv4Address, Ipv6Address,
};
use tokio::sync::{Notify, mpsc, oneshot};

use crate::buffer::BufferPool;
use crate::config::DeviceConfig;
use crate::netstack::{Netstack, PacketBuf};

use gotatun::device::{Device, DeviceBuilder, Peer as WgPeer};
use gotatun::packet::{Ip as WgIp, Packet as WgPacket, PacketBufPool};
use gotatun::tun::{IpRecv, IpSend, MtuWatcher};

const DNS_TIMEOUT: Duration = Duration::from_secs(5);
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

const TCP_RX_BUFFER: usize = 512 * 1024;
const TCP_TX_BUFFER: usize = 512 * 1024;
const UDP_RX_BUFFER: usize = 2048;
const UDP_TX_BUFFER: usize = 2048;
const ICMP_RX_BUFFER: usize = 256;
const ICMP_TX_BUFFER: usize = 256;

type PendingConnect = (tokio::time::Instant, oneshot::Sender<anyhow::Result<()>>);

type PendingUdp = (
    tokio::time::Instant,
    oneshot::Sender<anyhow::Result<Vec<u8>>>,
);

type PendingIcmp = (
    tokio::time::Instant,
    oneshot::Sender<anyhow::Result<()>>,
    IpAddress,
    Option<Ipv6Address>,
    u16,
    u16,
);

/// A minimal in-process "IP link" that connects gotatun <-> our smoltcp netstack.
///
/// - `IpSend` is used by gotatun to deliver decrypted IP packets to us.
/// - `IpRecv` is used by gotatun to read IP packets that our netstack wants to send.
#[derive(Clone)]
struct IpLinkTx {
    tx: mpsc::UnboundedSender<WgPacket<WgIp>>,
}

struct IpLinkRx {
    rx: mpsc::UnboundedReceiver<WgPacket<WgIp>>,
    mtu: MtuWatcher,
}

impl IpSend for IpLinkTx {
    fn send(
        &mut self,
        packet: WgPacket<WgIp>,
    ) -> impl std::future::Future<Output = io::Result<()>> + Send {
        let res = self.tx.send(packet);
        async move { res.map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "ip link closed")) }
    }
}

impl IpRecv for IpLinkRx {
    async fn recv<'a>(
        &'a mut self,
        _pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = WgPacket<WgIp>> + Send + 'a> {
        let Some(packet) = self.rx.recv().await else {
            // The sender being dropped means our runtime is shutting down.
            let () = std::future::pending().await;
            unreachable!();
        };
        Ok(std::iter::once(packet))
    }

    fn mtu(&self) -> MtuWatcher {
        self.mtu.clone()
    }
}

type GotatunDevice = Device<(gotatun::udp::socket::UdpSocketFactory, IpLinkTx, IpLinkRx)>;

#[derive(Clone)]
pub struct WireguardRuntime {
    inner: Arc<Inner>,
}

struct Inner {
    /// gotatun WireGuard engine.
    wg: GotatunDevice,

    /// Channel that forwards outbound IP packets (from smoltcp) into gotatun.
    tun_out_tx: mpsc::UnboundedSender<WgPacket<WgIp>>,

    /// Wakes the netstack poll loop when new work arrives.
    poll_notify: Notify,

    /// Wakes tasks waiting on socket readiness/state changes.
    io_notify: Notify,

    /// Started flag (kept for compatibility).
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

    /// Buffer pool for reducing allocations in the smoltcp path.
    buffer_pool: Arc<BufferPool>,

    /// A flattened view of all allowed IP networks, used for quick "has route" checks.
    allowed_ips: Vec<ipnet::IpNet>,

    /// Control plane for netstack operations (connect/read/write/etc).
    netstack_cmd_tx: mpsc::UnboundedSender<NetstackCmd>,
}

impl Inner {
    fn has_route_to(&self, ip: IpAddr) -> bool {
        // Fast path: scan allowed IP networks.
        // Peers are typically few, so this is fine.
        self.allowed_ips.iter().any(|net| net.contains(&ip))
    }
}

enum NetstackCmd {
    TcpConnect {
        remote: SocketAddr,
        reply: oneshot::Sender<anyhow::Result<smoltcp::iface::SocketHandle>>,
    },
    TcpListen {
        port: u16,
        reply: oneshot::Sender<anyhow::Result<smoltcp::iface::SocketHandle>>,
    },
    TcpWaitEstablished {
        handle: smoltcp::iface::SocketHandle,
        deadline: tokio::time::Instant,
        reply: oneshot::Sender<anyhow::Result<()>>,
    },
    TcpRead {
        handle: smoltcp::iface::SocketHandle,
        buf: Vec<u8>,
        reply: oneshot::Sender<anyhow::Result<(usize, Vec<u8>)>>,
    },
    TcpWrite {
        handle: smoltcp::iface::SocketHandle,
        data: Vec<u8>,
        reply: oneshot::Sender<anyhow::Result<usize>>,
    },
    TcpClose {
        handle: smoltcp::iface::SocketHandle,
    },

    UdpExchange {
        target: SocketAddr,
        payload: Vec<u8>,
        deadline: tokio::time::Instant,
        reply: oneshot::Sender<anyhow::Result<Vec<u8>>>,
    },

    IcmpPing {
        target: IpAddr,
        timeout: Duration,
        reply: oneshot::Sender<anyhow::Result<()>>,
    },
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
        let mtu_u16 = u16::try_from(mtu).unwrap_or(u16::MAX);

        // Channels bridging gotatun <-> smoltcp.
        // - gotatun -> netstack: decrypted IP packets
        // - netstack -> gotatun: plaintext IP packets to encrypt
        let (wg_to_tun_tx, wg_to_tun_rx) = mpsc::unbounded_channel::<WgPacket<WgIp>>();
        let (tun_to_wg_tx, tun_to_wg_rx) = mpsc::unbounded_channel::<WgPacket<WgIp>>();

        let ip_tx = IpLinkTx { tx: wg_to_tun_tx };
        let ip_rx = IpLinkRx {
            rx: tun_to_wg_rx,
            mtu: MtuWatcher::new(mtu_u16),
        };

        let listen_port = config.listen_port.unwrap_or(0);
        let wg = DeviceBuilder::new()
            .with_default_udp()
            .with_ip_pair(ip_tx, ip_rx)
            .with_listen_port(listen_port)
            .build()
            .await
            .context("build gotatun device")?;

        // Configure device keys and peers.
        // IMPORTANT: gotatun requires private key set before adding peers.
        let private_key = x25519_dalek::StaticSecret::from(config.private_key);

        let peers: Vec<WgPeer> = config
            .peers
            .iter()
            .map(|peer| {
                let endpoint = peer
                    .endpoint
                    .ok_or_else(|| anyhow::anyhow!("peer endpoint is required"))?;

                let mut p = WgPeer::new(x25519_dalek::PublicKey::from(peer.public_key));
                p.endpoint = Some(endpoint);

                if peer.preshared_key != [0u8; 32] {
                    p.preshared_key = Some(peer.preshared_key);
                }

                if peer.keepalive != 0 {
                    p.keepalive = Some(peer.keepalive);
                }

                p.allowed_ips = peer
                    .allowed_ips
                    .iter()
                    .map(|net| {
                        // gotatun uses `ipnetwork::IpNetwork`.
                        IpNetwork::new(net.addr(), net.prefix_len())
                            .expect("cidr length already validated")
                    })
                    .collect();

                Ok::<_, anyhow::Error>(p)
            })
            .collect::<Result<_, _>>()?;

        // Flatten allowed IPs for quick route checks.
        let mut allowed_ips = Vec::new();
        for peer in &config.peers {
            allowed_ips.extend(peer.allowed_ips.iter().cloned());
        }

        wg.write(async |device| {
            device.set_private_key(private_key).await;
            device.clear_peers();
            let _ = device.add_peers(peers);
        })
        .await
        .context("configure gotatun device")?;

        let (netstack_cmd_tx, netstack_cmd_rx) = mpsc::unbounded_channel();

        let buffer_pool = Arc::new(BufferPool::new(128));

        let inner = Arc::new(Inner {
            wg,
            tun_out_tx: tun_to_wg_tx,
            poll_notify: Notify::new(),
            io_notify: Notify::new(),
            started: AtomicBool::new(false),
            dns_servers: config.dns.clone(),
            private_key: config.private_key,
            listen_port: config.listen_port,
            mtu,
            buffer_pool: Arc::clone(&buffer_pool),
            allowed_ips,
            netstack_cmd_tx,
        });

        let netstack = Netstack::new(&config.addresses, mtu, Arc::clone(&inner.buffer_pool));
        tokio::spawn(netstack_loop(
            Arc::clone(&inner),
            netstack,
            netstack_cmd_rx,
            wg_to_tun_rx,
        ));

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
        let peers = self.inner.wg.read(async |dev| dev.peers().await).await;

        let mut out = String::new();
        let _ = writeln!(&mut out, "protocol_version=1");
        let _ = writeln!(
            &mut out,
            "private_key={}",
            encode_key(&self.inner.private_key)
        );
        if let Some(port) = self.inner.listen_port {
            let _ = writeln!(&mut out, "listen_port={}", port);
        }

        for peer in peers {
            if let Some(since) = peer.stats.last_handshake
                && let Some(when) = SystemTime::now().checked_sub(since)
                && let Ok(delta) = when.duration_since(UNIX_EPOCH)
            {
                let _ = writeln!(&mut out, "last_handshake_time_sec={}", delta.as_secs());
                let _ = writeln!(
                    &mut out,
                    "last_handshake_time_nsec={}",
                    delta.subsec_nanos()
                );
            }
            let _ = writeln!(&mut out, "rx_bytes={}", peer.stats.rx_bytes);
            let _ = writeln!(&mut out, "tx_bytes={}", peer.stats.tx_bytes);
        }

        out
    }

    pub async fn ping(&self, target: IpAddr, timeout: Duration) -> anyhow::Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let _ = self.inner.netstack_cmd_tx.send(NetstackCmd::IcmpPing {
            target,
            timeout,
            reply: reply_tx,
        });
        self.inner.poll_notify.notify_one();
        reply_rx
            .await
            .map_err(|_| anyhow::anyhow!("netstack task dropped ping"))??;
        Ok(())
    }

    pub async fn connect(&self, addr: SocketAddr) -> anyhow::Result<WgTcpConnection> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let _ = self.inner.netstack_cmd_tx.send(NetstackCmd::TcpConnect {
            remote: addr,
            reply: reply_tx,
        });
        self.inner.poll_notify.notify_one();
        let handle = reply_rx
            .await
            .map_err(|_| anyhow::anyhow!("netstack task dropped tcp connect"))??;

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
        let (listen_tx, listen_rx) = oneshot::channel();
        let _ = self.inner.netstack_cmd_tx.send(NetstackCmd::TcpListen {
            port,
            reply: listen_tx,
        });
        self.inner.poll_notify.notify_one();
        let handle = listen_rx
            .await
            .map_err(|_| anyhow::anyhow!("netstack task dropped tcp listen"))??;

        // For now, accept is treated as "wait for established" on the listening socket.
        // This mirrors the previous (simplified) behavior.
        let (wait_tx, wait_rx) = oneshot::channel();
        let deadline = tokio::time::Instant::now() + TCP_CONNECT_TIMEOUT;
        let _ = self
            .inner
            .netstack_cmd_tx
            .send(NetstackCmd::TcpWaitEstablished {
                handle,
                deadline,
                reply: wait_tx,
            });
        self.inner.poll_notify.notify_one();
        wait_rx
            .await
            .map_err(|_| anyhow::anyhow!("netstack task dropped tcp accept"))??;

        Ok(WgTcpConnection {
            handle: Arc::new(std::sync::Mutex::new(Some(handle))),
            runtime: self.clone(),
        })
    }

    pub async fn udp_exchange(
        &self,
        target: SocketAddr,
        payload: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let (reply_tx, reply_rx) = oneshot::channel();
        let deadline = tokio::time::Instant::now() + DNS_TIMEOUT;
        let _ = self.inner.netstack_cmd_tx.send(NetstackCmd::UdpExchange {
            target,
            payload: payload.to_vec(),
            deadline,
            reply: reply_tx,
        });
        self.inner.poll_notify.notify_one();
        reply_rx
            .await
            .map_err(|_| anyhow::anyhow!("netstack task dropped udp exchange"))?
    }

    async fn start_tasks(&self) {
        // gotatun starts/stops its own tasks based on configuration.
        // We keep this gate to preserve the old runtime contract.
        let _ = self.inner.started.swap(true, Ordering::SeqCst);
    }
}

impl WgTcpConnection {
    pub async fn read(&mut self, buf: &mut [u8]) -> anyhow::Result<usize> {
        let handle = match *self.handle.lock().unwrap() {
            Some(h) => h,
            None => return Ok(0),
        };

        loop {
            let (reply_tx, reply_rx) = oneshot::channel();
            let _ = self
                .runtime
                .inner
                .netstack_cmd_tx
                .send(NetstackCmd::TcpRead {
                    handle,
                    buf: vec![0u8; buf.len()],
                    reply: reply_tx,
                });
            self.runtime.inner.poll_notify.notify_one();

            let result = reply_rx
                .await
                .map_err(|_| anyhow::anyhow!("netstack task dropped tcp read"))?;

            match result {
                Ok((n, returned)) => {
                    buf[..n].copy_from_slice(&returned[..n]);
                    return Ok(n);
                }
                Err(err) if err.to_string().contains("would block") => {
                    self.runtime.inner.io_notify.notified().await;
                }
                Err(err) => return Err(err),
            }
        }
    }

    pub async fn write(&mut self, buf: &[u8]) -> anyhow::Result<usize> {
        let handle = match *self.handle.lock().unwrap() {
            Some(h) => h,
            None => anyhow::bail!("connection already closed"),
        };

        let mut offset = 0;
        while offset < buf.len() {
            let (reply_tx, reply_rx) = oneshot::channel();
            let _ = self
                .runtime
                .inner
                .netstack_cmd_tx
                .send(NetstackCmd::TcpWrite {
                    handle,
                    data: buf[offset..].to_vec(),
                    reply: reply_tx,
                });
            self.runtime.inner.poll_notify.notify_one();

            match reply_rx
                .await
                .map_err(|_| anyhow::anyhow!("netstack task dropped tcp write"))?
            {
                Ok(n) => {
                    offset += n;
                }
                Err(err) if err.to_string().contains("would block") => {
                    self.runtime.inner.io_notify.notified().await;
                }
                Err(err) => return Err(err),
            }
        }

        Ok(offset)
    }

    pub async fn close(&mut self) {
        let handle = match self.handle.lock().unwrap().take() {
            Some(h) => h,
            None => return,
        };
        let _ = self
            .runtime
            .inner
            .netstack_cmd_tx
            .send(NetstackCmd::TcpClose { handle });
        self.runtime.inner.poll_notify.notify_one();
    }

    async fn wait_established(&mut self) -> anyhow::Result<()> {
        let handle = match *self.handle.lock().unwrap() {
            Some(h) => h,
            None => anyhow::bail!("connection already closed"),
        };

        let (reply_tx, reply_rx) = oneshot::channel();
        let deadline = tokio::time::Instant::now() + TCP_CONNECT_TIMEOUT;
        let _ = self
            .runtime
            .inner
            .netstack_cmd_tx
            .send(NetstackCmd::TcpWaitEstablished {
                handle,
                deadline,
                reply: reply_tx,
            });
        self.runtime.inner.poll_notify.notify_one();

        reply_rx
            .await
            .map_err(|_| anyhow::anyhow!("netstack task dropped tcp wait"))??;
        Ok(())
    }
}

impl WgTcpListener {
    pub async fn accept(&self) -> anyhow::Result<WgTcpConnection> {
        self.runtime.accept(self.port).await
    }
}

fn encode_key(key: &[u8; 32]) -> String {
    BASE64_STD.encode(key)
}

fn to_ip_address(addr: IpAddr) -> IpAddress {
    match addr {
        IpAddr::V4(v4) => IpAddress::Ipv4(v4),
        IpAddr::V6(v6) => IpAddress::Ipv6(v6),
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

fn random_ephemeral_port() -> u16 {
    rand::random_range(49152..65535)
}

fn push_inbound_packet(inner: &Inner, netstack: &mut Netstack, packet: WgPacket<WgIp>) {
    let bytes: &[u8] = &packet.into_bytes();
    if bytes.is_empty() {
        return;
    }

    // Note: Netstack stores fixed-size pooled buffers; we copy into it.
    let mut buf = inner.buffer_pool.get_small();
    let len = bytes.len().min(buf.len());
    buf[..len].copy_from_slice(&bytes[..len]);
    netstack.push_inbound(PacketBuf::new(buf, len));
}

fn handle_netstack_cmd(
    inner: &Inner,
    netstack: &mut Netstack,
    pending_connects: &mut HashMap<smoltcp::iface::SocketHandle, PendingConnect>,
    pending_udp: &mut HashMap<smoltcp::iface::SocketHandle, PendingUdp>,
    pending_icmp: &mut HashMap<smoltcp::iface::SocketHandle, PendingIcmp>,
    cmd: NetstackCmd,
) {
    match cmd {
        NetstackCmd::TcpConnect { remote, reply } => {
            let result = (|| {
                if !inner.has_route_to(remote.ip()) {
                    anyhow::bail!("no peer for destination {remote}");
                }

                let rx = tcp::SocketBuffer::new(vec![0u8; TCP_RX_BUFFER]);
                let tx = tcp::SocketBuffer::new(vec![0u8; TCP_TX_BUFFER]);
                let mut socket = tcp::Socket::new(rx, tx);
                socket.set_nagle_enabled(false);

                let handle = netstack.add_socket(socket);
                let local_port = random_ephemeral_port();
                netstack
                    .tcp_connect(
                        handle,
                        IpEndpoint::new(to_ip_address(remote.ip()), remote.port()),
                        IpListenEndpoint::from(local_port),
                    )
                    .map_err(|e| anyhow::anyhow!("tcp connect error: {e:?}"))?;
                Ok(handle)
            })();
            let _ = reply.send(result);
            inner.poll_notify.notify_one();
        }
        NetstackCmd::TcpListen { port, reply } => {
            let result = (|| {
                let rx = tcp::SocketBuffer::new(vec![0u8; TCP_RX_BUFFER]);
                let tx = tcp::SocketBuffer::new(vec![0u8; TCP_TX_BUFFER]);
                let mut socket = tcp::Socket::new(rx, tx);
                socket
                    .listen(IpListenEndpoint::from(port))
                    .map_err(|e| anyhow::anyhow!("tcp listen error: {e:?}"))?;
                Ok(netstack.add_socket(socket))
            })();
            let _ = reply.send(result);
            inner.poll_notify.notify_one();
        }
        NetstackCmd::TcpWaitEstablished {
            handle,
            deadline,
            reply,
        } => {
            pending_connects.insert(handle, (deadline, reply));
            inner.poll_notify.notify_one();
        }
        NetstackCmd::TcpRead {
            handle,
            mut buf,
            reply,
        } => {
            let result = (|| {
                let socket = netstack.sockets.get_mut::<tcp::Socket>(handle);
                if socket.can_recv() {
                    let size = socket
                        .recv_slice(&mut buf)
                        .map_err(|e| anyhow::anyhow!("tcp recv error: {e:?}"))?;
                    if size == 0 {
                        socket.close();
                    }
                    return Ok((size, buf));
                }
                if socket.state() == tcp::State::Closed {
                    return Ok((0, buf));
                }
                anyhow::bail!("would block")
            })();
            let _ = reply.send(result);
        }
        NetstackCmd::TcpWrite {
            handle,
            data,
            reply,
        } => {
            let result = (|| {
                let socket = netstack.sockets.get_mut::<tcp::Socket>(handle);
                if socket.can_send() {
                    let written = socket
                        .send_slice(&data)
                        .map_err(|e| anyhow::anyhow!("tcp send error: {e:?}"))?;
                    inner.poll_notify.notify_one();
                    return Ok(written);
                }
                anyhow::bail!("would block")
            })();
            let _ = reply.send(result);
        }
        NetstackCmd::TcpClose { handle } => {
            {
                let socket = netstack.sockets.get_mut::<tcp::Socket>(handle);
                socket.close();
            }
            netstack.sockets.remove(handle);
            inner.poll_notify.notify_one();
        }

        NetstackCmd::UdpExchange {
            target,
            payload,
            deadline,
            reply,
        } => {
            let result = (|| {
                let rx = udp::PacketBuffer::new(
                    vec![udp::PacketMetadata::EMPTY; 4],
                    vec![0u8; UDP_RX_BUFFER],
                );
                let tx = udp::PacketBuffer::new(
                    vec![udp::PacketMetadata::EMPTY; 4],
                    vec![0u8; UDP_TX_BUFFER],
                );
                let mut socket = udp::Socket::new(rx, tx);
                let local_port = random_ephemeral_port();
                socket
                    .bind(IpListenEndpoint::from(local_port))
                    .map_err(|e| anyhow::anyhow!("udp bind error: {e:?}"))?;
                let handle = netstack.add_socket(socket);
                let socket = netstack.sockets.get_mut::<udp::Socket>(handle);
                socket
                    .send_slice(
                        &payload,
                        IpEndpoint::new(to_ip_address(target.ip()), target.port()),
                    )
                    .map_err(|e| anyhow::anyhow!("udp send error: {e:?}"))?;
                Ok(handle)
            })();

            match result {
                Ok(handle) => {
                    pending_udp.insert(handle, (deadline, reply));
                    inner.poll_notify.notify_one();
                }
                Err(err) => {
                    let _ = reply.send(Err(err));
                }
            }
        }

        NetstackCmd::IcmpPing {
            target,
            timeout,
            reply,
        } => {
            let result = (|| {
                let ident: u16 = rand::random();
                let seq_no: u16 = rand::random();
                let mut payload = [0u8; 16];
                rand::rng().fill_bytes(&mut payload);

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
                        let dst_addr: Ipv4Address = dst;
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
                        let dst_addr: Ipv6Address = dst;
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

                Ok((
                    handle,
                    tokio::time::Instant::now() + timeout,
                    target_addr,
                    v6_src,
                    ident,
                    seq_no,
                ))
            })();

            match result {
                Ok((handle, deadline, target_addr, v6_src, ident, seq_no)) => {
                    pending_icmp.insert(
                        handle,
                        (deadline, reply, target_addr, v6_src, ident, seq_no),
                    );
                    inner.poll_notify.notify_one();
                }
                Err(err) => {
                    let _ = reply.send(Err(err));
                }
            }
        }
    }
}

async fn netstack_loop(
    inner: Arc<Inner>,
    mut netstack: Netstack,
    mut cmd_rx: mpsc::UnboundedReceiver<NetstackCmd>,
    mut inbound_ip_rx: mpsc::UnboundedReceiver<WgPacket<WgIp>>,
) {
    let mut pending_connects: HashMap<smoltcp::iface::SocketHandle, PendingConnect> =
        HashMap::new();
    let mut pending_udp: HashMap<smoltcp::iface::SocketHandle, PendingUdp> = HashMap::new();
    let mut pending_icmp: HashMap<smoltcp::iface::SocketHandle, PendingIcmp> = HashMap::new();

    loop {
        // Drain inbound IP packets produced by gotatun (decrypted WG payloads).
        while let Ok(packet) = inbound_ip_rx.try_recv() {
            push_inbound_packet(inner.as_ref(), &mut netstack, packet);
        }

        // Drain commands without blocking.
        while let Ok(cmd) = cmd_rx.try_recv() {
            handle_netstack_cmd(
                inner.as_ref(),
                &mut netstack,
                &mut pending_connects,
                &mut pending_udp,
                &mut pending_icmp,
                cmd,
            );
        }

        // Run one poll step.
        let did_work = netstack.poll();
        if did_work {
            inner.io_notify.notify_waiters();
        }

        // Forward outbound frames (generated by smoltcp) into gotatun.
        let frames = netstack.drain_outbound();
        for frame in frames {
            let bytes = frame.as_slice();
            if bytes.is_empty() {
                continue;
            }

            let mut backing = BytesMut::with_capacity(bytes.len());
            backing.extend_from_slice(bytes);

            let packet = match WgPacket::from_bytes(backing).try_into_ip() {
                Ok(packet) => packet,
                Err(_) => continue,
            };

            let _ = inner.tun_out_tx.send(packet);
        }

        // Progress pending connect/readiness-style operations.
        if !pending_connects.is_empty() {
            let now = tokio::time::Instant::now();
            let mut done = Vec::new();
            for (&handle, (deadline, _)) in &pending_connects {
                if now >= *deadline {
                    done.push(handle);
                    continue;
                }
                let socket = netstack.sockets.get_mut::<tcp::Socket>(handle);
                let state = socket.state();
                if matches!(state, tcp::State::Established | tcp::State::Closed) {
                    done.push(handle);
                }
            }
            for handle in done {
                if let Some((deadline, reply)) = pending_connects.remove(&handle) {
                    let now = tokio::time::Instant::now();
                    let socket = netstack.sockets.get_mut::<tcp::Socket>(handle);
                    let state = socket.state();
                    let res = if now >= deadline {
                        netstack.sockets.remove(handle);
                        Err(anyhow::anyhow!("tcp connect timed out"))
                    } else if state == tcp::State::Established {
                        Ok(())
                    } else if state == tcp::State::Closed {
                        netstack.sockets.remove(handle);
                        Err(anyhow::anyhow!("connection closed"))
                    } else {
                        Ok(())
                    };
                    let _ = reply.send(res);
                }
            }
        }

        if !pending_udp.is_empty() {
            let now = tokio::time::Instant::now();
            let mut done = Vec::new();
            for (&handle, (deadline, _)) in &pending_udp {
                if now >= *deadline {
                    done.push(handle);
                    continue;
                }
                let socket = netstack.sockets.get_mut::<udp::Socket>(handle);
                if socket.can_recv() {
                    done.push(handle);
                }
            }
            for handle in done {
                if let Some((deadline, reply)) = pending_udp.remove(&handle) {
                    let now = tokio::time::Instant::now();
                    if now >= deadline {
                        netstack.sockets.remove(handle);
                        let _ = reply.send(Err(anyhow::anyhow!("udp exchange timed out")));
                        continue;
                    }
                    let socket = netstack.sockets.get_mut::<udp::Socket>(handle);
                    if socket.can_recv() {
                        match socket.recv() {
                            Ok((data, _)) => {
                                let out = data.to_vec();
                                netstack.sockets.remove(handle);
                                let _ = reply.send(Ok(out));
                            }
                            Err(e) => {
                                netstack.sockets.remove(handle);
                                let _ = reply.send(Err(anyhow::anyhow!("udp recv error: {e:?}")));
                            }
                        }
                    }
                }
            }
        }

        if !pending_icmp.is_empty() {
            let now = tokio::time::Instant::now();
            let mut done = Vec::new();
            let mut recv_buf = [0u8; 512];
            for (&handle, (deadline, _, target_addr, v6_src, ident, seq_no)) in &pending_icmp {
                if now >= *deadline {
                    done.push(handle);
                    continue;
                }
                let socket = netstack.sockets.get_mut::<icmp::Socket>(handle);
                if socket.can_recv()
                    && let Ok((len, from)) = socket.recv_slice(&mut recv_buf)
                    && from == *target_addr
                    && matches_echo_reply(&recv_buf[..len], *target_addr, *v6_src, *ident, *seq_no)
                {
                    done.push(handle);
                }
            }
            for handle in done {
                if let Some((_deadline, reply, _target_addr, _v6_src, _ident, _seq_no)) =
                    pending_icmp.remove(&handle)
                {
                    netstack.sockets.remove(handle);
                    let _ = reply.send(Ok(()));
                }
            }
        }

        // Sleep/yield until new work.
        //
        // Important: inbound decrypted packets arrive on `inbound_ip_rx`.
        // If we only wait on `poll_notify`, inbound packets can sit in the channel
        // and smoltcp never sees them.
        //
        // Also, smoltcp's `poll_delay()` does not know about our own user-level
        // deadlines (connect/udp/icmp timeouts), so we must wake for those too.
        let now = tokio::time::Instant::now();
        let next_deadline = pending_connects
            .values()
            .map(|(deadline, _)| *deadline)
            .chain(pending_udp.values().map(|(deadline, _)| *deadline))
            .chain(pending_icmp.values().map(|(deadline, ..)| *deadline))
            .min();

        let mut sleep_for = netstack.poll_delay();
        if let Some(deadline) = next_deadline {
            let until = deadline.saturating_duration_since(now);
            sleep_for = Some(match sleep_for {
                Some(d) => d.min(until),
                None => until,
            });
        }

        match sleep_for {
            Some(d) if d.is_zero() => tokio::task::yield_now().await,
            Some(d) => {
                tokio::select! {
                    biased;
                    _ = inner.poll_notify.notified() => {},
                    packet = inbound_ip_rx.recv() => {
                        let Some(packet) = packet else {
                            return;
                        };
                        push_inbound_packet(inner.as_ref(), &mut netstack, packet);
                    }
                    cmd = cmd_rx.recv() => {
                        let Some(cmd) = cmd else {
                            return;
                        };
                        handle_netstack_cmd(
                            inner.as_ref(),
                            &mut netstack,
                            &mut pending_connects,
                            &mut pending_udp,
                            &mut pending_icmp,
                            cmd,
                        );
                    }
                    _ = tokio::time::sleep(d) => {},
                }
            }
            None => {
                tokio::select! {
                    biased;
                    _ = inner.poll_notify.notified() => {},
                    packet = inbound_ip_rx.recv() => {
                        let Some(packet) = packet else {
                            return;
                        };
                        push_inbound_packet(inner.as_ref(), &mut netstack, packet);
                    }
                    cmd = cmd_rx.recv() => {
                        let Some(cmd) = cmd else {
                            return;
                        };
                        handle_netstack_cmd(
                            inner.as_ref(),
                            &mut netstack,
                            &mut pending_connects,
                            &mut pending_udp,
                            &mut pending_icmp,
                            cmd,
                        );
                    }
                }
            }
        }
    }
}
