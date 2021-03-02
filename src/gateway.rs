use std::{
    process::Command,
    sync::{Arc, Once},
    time::Instant,
};

use futures::future::join_all;
use futures::{SinkExt, StreamExt};
use icmp::destination_unreachable::IcmpCodes;
use ipnet::Ipv4Net;
use pnet::packet::{
    icmp::{self, IcmpTypes, MutableIcmpPacket},
    ip::IpNextHeaderProtocols,
    ipv4::{self, MutableIpv4Packet},
    udp::MutableUdpPacket,
    Packet,
};
use tokio_util::codec::Framed;
use tun::{AsyncDevice, Configuration, TunPacket, TunPacketCodec};

use crate::setting::{RuleType, Setting};

pub async fn serve(setting: Arc<Setting>) {
    let mut gateways = vec![];
    let mut id = 0;
    for network in setting.network.iter() {
        let gateway = Gateway::new(id, network, setting.clone());
        gateways.push(gateway);
        id += 1;
    }

    let mut handlers = vec![];
    for gateway in gateways.iter() {
        handlers.push(gateway.serve());
    }

    join_all(handlers).await;
}

struct Gateway {
    id: i32,
    net: Ipv4Net,
    setting: Arc<Setting>,
}

static ROUTE_RULE_ONCE: Once = Once::new();

const MTU: usize = 1400;

impl Gateway {
    fn new(id: i32, network: &str, setting: Arc<Setting>) -> Self {
        let net = network.parse().unwrap();
        Gateway { id, net, setting }
    }

    async fn serve(&self) {
        let mut config = Configuration::default();
        let name = format!("kungfu_{}", self.id);
        config
            .address(self.net.addr())
            .netmask(self.net.netmask())
            .mtu(MTU as i32)
            .name(name.clone())
            .layer(tun::Layer::L3)
            .up();

        let dev = tun::create_as_async(&config).expect("create tun failed");
        debug!("setup tun: {}", name);

        self.apply_rules();

        let mut stream = dev.into_framed();
        while let Some(packet) = stream.next().await {
            match packet {
                Ok(pkt) => {
                    let mut pkt = pkt.get_bytes().to_vec();
                    let mut packet = MutableIpv4Packet::new(&mut pkt).unwrap();
                    let payload = packet.to_immutable().payload().to_vec();
                    match packet.get_next_level_protocol() {
                        IpNextHeaderProtocols::Icmp => {
                            self.handle_icmp(&mut packet, payload, &mut stream).await;
                        }
                        IpNextHeaderProtocols::Tcp => {}
                        IpNextHeaderProtocols::Udp => {
                            self.handle_udp(&mut packet, payload, &mut stream).await;
                        }
                        _ => {}
                    }
                }
                Err(err) => {
                    error!("read dev ({}) packet error: {}", name, err);
                }
            }
        }
    }

    fn apply_rules(&self) {
        ROUTE_RULE_ONCE.call_once(|| {
            let rules = self
                .setting
                .rules
                .iter()
                .filter(|v| v.rule_type == RuleType::Route);
            let start = Instant::now();
            for rule in rules {
                for v in &rule.values {
                    #[cfg(target_os = "linux")]
                    {
                        let _ = Command::new("ip")
                            .args(&["route", "add", v, "via", &self.net.addr().to_string()])
                            .status();
                    }

                    #[cfg(target_os = "macos")]
                    {
                        let _ = Command::new("route")
                            .args(&["-n", "add", "-net", v, &self.net.addr().to_string()])
                            .status();
                    }
                }
            }
            debug!("add static route, route, elapsed: {:?}", start.elapsed());
        });
    }

    async fn handle_icmp(
        &self,
        packet: &mut MutableIpv4Packet<'_>,
        mut payload: Vec<u8>,
        stream: &mut Framed<AsyncDevice, TunPacketCodec>,
    ) {
        let mut icmp_pkt = MutableIcmpPacket::new(&mut payload).unwrap();
        let src = packet.get_source();
        let dst = packet.get_destination();
        if icmp_pkt.get_icmp_type() == IcmpTypes::EchoRequest {
            icmp_pkt.set_icmp_type(IcmpTypes::EchoReply);
            icmp_pkt.set_checksum(icmp::checksum(&icmp_pkt.to_immutable()));
            packet.set_payload(icmp_pkt.packet());
        }

        packet.set_source(dst);
        packet.set_destination(src);

        let _ = stream.send(TunPacket::new(packet.packet().to_vec())).await;
    }

    async fn handle_udp(
        &self,
        packet: &mut MutableIpv4Packet<'_>,
        mut payload: Vec<u8>,
        stream: &mut Framed<AsyncDevice, TunPacketCodec>,
    ) {
        let udp_pkt = MutableUdpPacket::new(&mut payload).unwrap();
        let s_port = udp_pkt.get_source();
        let d_port = udp_pkt.get_destination();

        let src = packet.get_source();
        let dst = packet.get_destination();
        let ttl = packet.get_ttl();

        debug!(
            "ucp tracing detected src:{}:{}, dst:{}:{}, ttl:{}",
            src, s_port, dst, d_port, ttl
        );

        if ttl < 10 && d_port >= 33000 && self.net.contains(&dst) {
            let payload = packet.to_immutable().packet().to_vec();
            let mut icmp_data = vec![0u8; 8 + payload.len()];
            // fix pnet icmp set payload issue
            // pnet 库的 icmp 包设置 payload 时不对，这里直接拷贝数据，跳过 payload 设置
            icmp_data[8..].copy_from_slice(&payload[..]);
            let mut icmp_pkt = MutableIcmpPacket::new(&mut icmp_data).unwrap();
            icmp_pkt.set_icmp_type(IcmpTypes::DestinationUnreachable);
            icmp_pkt.set_icmp_code(IcmpCodes::DestinationPortUnreachable);
            icmp_pkt.set_checksum(icmp::checksum(&icmp_pkt.to_immutable()));
            let icmp_data = icmp_pkt.packet();

            let head_len = (packet.get_header_length() * 4) as usize;
            let mut pkt_data = vec![0u8; head_len + icmp_data.len()];
            pkt_data[0..head_len].copy_from_slice(&payload[0..head_len]);
            let total_len = (&pkt_data).len() as u16;
            let mut pkt = MutableIpv4Packet::new(&mut pkt_data).unwrap();
            pkt.set_ttl(64);
            pkt.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
            pkt.set_total_length(total_len);
            pkt.set_source(dst);
            pkt.set_destination(src);
            pkt.set_payload(icmp_data);
            pkt.set_checksum(ipv4::checksum(&pkt.to_immutable()));

            let _ = stream.send(TunPacket::new(packet.packet().to_vec())).await;
        }
    }
}
