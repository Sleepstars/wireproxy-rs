use std::collections::VecDeque;
use std::time::Instant as StdInstant;

use rand::RngCore;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address, Ipv6Address};

pub(crate) struct Netstack {
    pub(crate) device: IpDevice,
    pub(crate) iface: Interface,
    pub(crate) sockets: SocketSet<'static>,
    start: StdInstant,
}

impl Netstack {
    pub(crate) fn new(addresses: &[std::net::IpAddr], mtu: usize) -> Self {
        let mut device = IpDevice::new(mtu);
        let mut config = Config::new(HardwareAddress::Ip);
        let mut rng = rand::thread_rng();
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

            // Add a link-local IPv6 address if only IPv4 is configured
            // This prevents smoltcp from panicking when trying to send IPv6 packets
            if has_ipv4 && !has_ipv6 {
                // Use fe80::1 as a dummy link-local address
                let ipv6_ll = IpCidr::new(IpAddress::v6(0xfe80, 0, 0, 0, 0, 0, 0, 1), 128);
                if addrs.push(ipv6_ll).is_err() {
                    log::warn!("interface address list full, skipping IPv6 link-local");
                }
            }
        });

        // Add default routes for IPv4 and IPv6
        // In a WireGuard tunnel, all traffic goes through the tunnel (no gateway needed)
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
        self.iface.poll(now, &mut self.device, &mut self.sockets)
    }

    pub(crate) fn poll_delay(&mut self) -> Option<std::time::Duration> {
        self.iface
            .poll_delay(self.now(), &self.sockets)
            .map(|delay| std::time::Duration::from_millis(delay.total_millis() as u64))
    }

    pub(crate) fn push_inbound(&mut self, packet: Vec<u8>) {
        self.device.push_rx(packet);
    }

    pub(crate) fn drain_outbound(&mut self) -> Vec<Vec<u8>> {
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
}

fn to_ip_address(addr: std::net::IpAddr) -> IpAddress {
    match addr {
        std::net::IpAddr::V4(v4) => IpAddress::Ipv4(Ipv4Address::from(v4)),
        std::net::IpAddr::V6(v6) => IpAddress::Ipv6(Ipv6Address::from(v6)),
    }
}

pub(crate) struct IpDevice {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
    mtu: usize,
}

impl IpDevice {
    pub(crate) fn new(mtu: usize) -> Self {
        Self {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
            mtu,
        }
    }

    fn push_rx(&mut self, packet: Vec<u8>) {
        self.rx.push_back(packet);
    }

    fn drain_tx(&mut self) -> Vec<Vec<u8>> {
        self.tx.drain(..).collect()
    }
}

pub(crate) struct IpRxToken {
    buffer: Vec<u8>,
}

impl RxToken for IpRxToken {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        f(&mut self.buffer)
    }
}

pub(crate) struct IpTxToken<'a> {
    queue: &'a mut VecDeque<Vec<u8>>,
}

impl<'a> TxToken for IpTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        self.queue.push_back(buffer);
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
            IpRxToken { buffer: packet },
            IpTxToken {
                queue: &mut self.tx,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(IpTxToken {
            queue: &mut self.tx,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}
