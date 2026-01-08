use std::net::{IpAddr, SocketAddr};

use anyhow::Context;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RData, RecordType};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};

use crate::wg::WireguardRuntime;

/// Resolve hostname to IP address with parallel A/AAAA queries
pub async fn resolve(runtime: &WireguardRuntime, name: &str) -> anyhow::Result<IpAddr> {
    if runtime.system_dns() {
        let mut addrs = tokio::net::lookup_host((name, 0))
            .await
            .context("system dns lookup")?;
        return addrs
            .next()
            .map(|addr| addr.ip())
            .ok_or_else(|| anyhow::anyhow!("no dns records for {name}"));
    }

    let servers = runtime.dns_servers();

    for server in servers {
        // Query A and AAAA records in parallel
        match query_parallel(runtime, server, name).await {
            Ok(ip) => return Ok(ip),
            Err(e) => {
                log::debug!("dns query to {server} failed: {e}");
                continue;
            }
        }
    }

    anyhow::bail!("dns resolution failed for {name}")
}

/// Query A and AAAA records in parallel, return first successful result
async fn query_parallel(
    runtime: &WireguardRuntime,
    server: IpAddr,
    name: &str,
) -> anyhow::Result<IpAddr> {
    // Run both queries in parallel using join
    let (a_result, aaaa_result) = tokio::join!(
        query_dns(runtime, server, name, RecordType::A),
        query_dns(runtime, server, name, RecordType::AAAA)
    );

    // Prefer IPv4 if available, otherwise use IPv6
    if let Ok(ip) = a_result {
        return Ok(ip);
    }
    if let Ok(ip) = aaaa_result {
        return Ok(ip);
    }

    // Both failed, return the A query error
    a_result
}

async fn query_dns(
    runtime: &WireguardRuntime,
    server: IpAddr,
    name: &str,
    record_type: RecordType,
) -> anyhow::Result<IpAddr> {
    let mut msg = Message::new();
    let id: u16 = rand::random();
    msg.set_id(id);
    msg.set_message_type(MessageType::Query);
    msg.set_op_code(OpCode::Query);
    msg.set_recursion_desired(true);

    let dns_name = Name::from_ascii(name).context("invalid dns name")?;
    msg.add_query(Query::query(dns_name, record_type));

    let mut bytes = Vec::with_capacity(512);
    let mut encoder = BinEncoder::new(&mut bytes);
    msg.emit(&mut encoder).context("encode dns query")?;

    let response = runtime
        .udp_exchange(SocketAddr::new(server, 53), &bytes)
        .await
        .context("dns udp exchange")?;

    let message = Message::from_vec(&response).context("decode dns response")?;
    for answer in message.answers() {
        let rdata = answer.data();
        match rdata {
            RData::A(ip) => return Ok(IpAddr::V4(ip.0)),
            RData::AAAA(ip) => return Ok(IpAddr::V6(ip.0)),
            _ => {}
        }
    }

    anyhow::bail!("no dns records in response")
}
