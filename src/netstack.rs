use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant as StdInstant;

use rand::RngCore;
use smoltcp::iface::{Config, Interface, PollResult, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint, Ipv4Address, Ipv6Address,
};

use crate::buffer::{BufferPool, PooledSmallBuffer, WG_BUFFER_SIZE};

pub(crate) struct PacketBuf {
    buf: PooledSmallBuffer,
    len: usize,
}

impl PacketBuf {
    pub(crate) fn new(buf: PooledSmallBuffer, len: usize) -> Self {
        debug_assert!(len <= WG_BUFFER_SIZE);
        Self { buf, len }
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

pub(crate) struct Netstack {
    pub(crate) device: IpDevice,
    pub(crate) iface: Interface,
    pub(crate) sockets: SocketSet<'static>,
    start: StdInstant,
}

impl Netstack {
    pub(crate) fn new(addresses: &[std::net::IpAddr], mtu: usize, pool: Arc<BufferPool>) -> Self {
        let mut device = IpDevice::new(mtu, pool);
        let mut config = Config::new(HardwareAddress::Ip);
        let mut rng = rand::rng();
        config.random_seed = rng.next_u64();
        let now = Instant::from_millis(0i64);
        let mut iface = Interface::new(config, &mut device, now);

        iface.update_ip_addrs(|addrs| {
            let mut has_ipv4 = false;
            let mut has_ipv6 = false;

            for addr in addresses {
                let prefix = if addr.is_ipv4() {
                    has_ipv4 = true;
                    32
                } else {
                    has_ipv6 = true;
                    128
                };
                let cidr = IpCidr::new(to_ip_address(*addr), prefix);
                if addrs.push(cidr).is_err() {
                    log::warn!("interface address list full, skipping {addr}");
                }
            }

            // Add a link-local IPv6 address if only IPv4 is configured.
            // This prevents smoltcp from panicking when trying to send IPv6 packets.
            if has_ipv4 && !has_ipv6 {
                // Use fe80::1 as a dummy link-local address.
                let ipv6_ll = IpCidr::new(IpAddress::v6(0xfe80, 0, 0, 0, 0, 0, 0, 1), 128);
                if addrs.push(ipv6_ll).is_err() {
                    log::warn!("interface address list full, skipping IPv6 link-local");
                }
            }
        });

        // Add default routes for IPv4 and IPv6.
        // In a WireGuard tunnel, all traffic goes through the tunnel (no gateway needed).
        iface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::UNSPECIFIED)
            .ok();
        iface
            .routes_mut()
            .add_default_ipv6_route(Ipv6Address::UNSPECIFIED)
            .ok();

        Netstack {
            device,
            iface,
            sockets: SocketSet::new(Vec::new()),
            start: StdInstant::now(),
        }
    }

    pub(crate) fn poll(&mut self) -> bool {
        let now = self.now();
        self.iface.poll(now, &mut self.device, &mut self.sockets) != PollResult::None
    }

    pub(crate) fn poll_delay(&mut self) -> Option<std::time::Duration> {
        self.iface
            .poll_delay(self.now(), &self.sockets)
            .map(|delay| std::time::Duration::from_millis(delay.total_millis()))
    }

    pub(crate) fn push_inbound(&mut self, packet: PacketBuf) {
        self.device.push_rx(packet);
    }

    pub(crate) fn drain_outbound(&mut self) -> Vec<PacketBuf> {
        self.device.drain_tx()
    }

    pub(crate) fn now(&self) -> Instant {
        let elapsed = self.start.elapsed();
        Instant::from_millis(elapsed.as_millis() as i64)
    }

    pub(crate) fn add_socket<T>(&mut self, socket: T) -> SocketHandle
    where
        T: smoltcp::socket::AnySocket<'static>,
    {
        self.sockets.add(socket)
    }

    /// Connect a TCP socket - handles the borrow checker issue with iface.context().
    pub(crate) fn tcp_connect(
        &mut self,
        handle: SocketHandle,
        remote: IpEndpoint,
        local: IpListenEndpoint,
    ) -> Result<(), smoltcp::socket::tcp::ConnectError> {
        let socket = self.sockets.get_mut::<tcp::Socket>(handle);
        socket.connect(self.iface.context(), remote, local)
    }
}

fn to_ip_address(addr: std::net::IpAddr) -> IpAddress {
    match addr {
        std::net::IpAddr::V4(v4) => IpAddress::Ipv4(v4),
        std::net::IpAddr::V6(v6) => IpAddress::Ipv6(v6),
    }
}

pub(crate) struct IpDevice {
    rx: VecDeque<PacketBuf>,
    tx: VecDeque<PacketBuf>,
    mtu: usize,
    pool: Arc<BufferPool>,
}

impl IpDevice {
    pub(crate) fn new(mtu: usize, pool: Arc<BufferPool>) -> Self {
        Self {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
            mtu,
            pool,
        }
    }

    fn push_rx(&mut self, packet: PacketBuf) {
        self.rx.push_back(packet);
    }

    fn drain_tx(&mut self) -> Vec<PacketBuf> {
        self.tx.drain(..).collect()
    }
}

pub(crate) struct IpRxToken {
    packet: PacketBuf,
}

impl RxToken for IpRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(self.packet.as_slice())
    }
}

pub(crate) struct IpTxToken<'a> {
    queue: &'a mut VecDeque<PacketBuf>,
    pool: &'a Arc<BufferPool>,
}

impl<'a> TxToken for IpTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        debug_assert!(len <= WG_BUFFER_SIZE);

        // Allocate from the pool so we avoid per-packet `Vec` allocations.
        let mut buf = self.pool.get_small();
        let result = f(&mut buf[..len]);
        self.queue.push_back(PacketBuf::new(buf, len));
        result
    }
}

impl Device for IpDevice {
    type RxToken<'a>
        = IpRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = IpTxToken<'a>
    where
        Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.rx.pop_front()?;
        Some((
            IpRxToken { packet },
            IpTxToken {
                queue: &mut self.tx,
                pool: &self.pool,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(IpTxToken {
            queue: &mut self.tx,
            pool: &self.pool,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}
