use std::net::{IpAddr, SocketAddr};

use anyhow::Context;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RData, RecordType};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};

use crate::wg::WireguardRuntime;

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
    let mut last_err: Option<anyhow::Error> = None;
    for server in servers {
        match query_dns(runtime, server, name, RecordType::A).await {
            Ok(ip) => return Ok(ip),
            Err(err) => {
                if last_err.is_none() {
                    last_err = Some(err);
                }
            }
        }
        match query_dns(runtime, server, name, RecordType::AAAA).await {
            Ok(ip) => return Ok(ip),
            Err(err) => {
                if last_err.is_none() {
                    last_err = Some(err);
                }
            }
        }
    }

    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("dns resolution failed")))
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

    let name = Name::from_ascii(name).context("invalid dns name")?;
    msg.add_query(Query::query(name, record_type));

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
