/*
   Copyright (c) Alex Forster <alex@alexforster.com>

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

   SPDX-License-Identifier: Apache-2.0
*/

use pdu::*;

use std::collections::VecDeque;
use std::error::Error;
use std::ffi;
use std::fs;
use std::path;
use std::process::{Command, Stdio};
use std::result::Result;

fn hex_decode<T: ?Sized + AsRef<[u8]>>(length: usize, input: &T) -> Vec<u8> {
    let input = input.as_ref();
    let mut padding = Vec::new();
    if input.len() % 2 != 0 {
        // left-pad input with an ASCII zero to make input length even
        padding.push(b'0');
    }
    while length > 0 && (input.len() + padding.len()) < (length * 2) {
        // left-pad input with two ASCII zeros for correct output length
        padding.push(b'0');
        padding.push(b'0');
    }
    let result = base16::decode([&padding, input].concat().as_slice()).unwrap();
    if length > 0 && result.len() > length {
        let mut result = VecDeque::from(result);
        while result.len() > length {
            result.pop_front();
        }
        Vec::from(result)
    } else {
        result
    }
}

fn descendant_value(
    node: &roxmltree::Node, proto: &str, field: &str, length: usize,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let descendant = node.descendants().find(|n| n.attribute("name") == Some(format!("{}.{}", proto, field).as_str()));
    eprintln!("{}.{} = {:?}", proto, field, descendant);
    let descendant = if let Some(descendant) = descendant {
        descendant
    } else {
        return Err(format!("{}.{} not found", proto, field).into());
    };
    let value = if let Some(value) = descendant.attribute("value") {
        value
    } else {
        return Err(format!("{}.{} has no 'value' attribute", proto, field).into());
    };
    Ok(hex_decode(length, value))
}

fn descendant_show(node: &roxmltree::Node, proto: &str, field: &str, length: usize) -> Result<Vec<u8>, Box<dyn Error>> {
    let descendant = node.descendants().find(|n| n.attribute("name") == Some(format!("{}.{}", proto, field).as_str()));
    eprintln!("{}.{} = {:?}", proto, field, descendant);
    let descendant = if let Some(descendant) = descendant {
        descendant
    } else {
        return Err(format!("{}.{} not found", proto, field).into());
    };
    let value = if let Some(value) = descendant.attribute("show") {
        value
    } else {
        return Err(format!("{}.{} has no 'show' attribute", proto, field).into());
    };
    Ok(hex_decode(length, value))
}

fn visit_ethernet_pdu(pdu: &EthernetPdu, mut nodes: VecDeque<roxmltree::Node>) -> Result<(), Box<dyn Error>> {
    let node = nodes.pop_front().unwrap();
    if node.attribute("name") == Some("_ws.malformed") {
        return Err("node: malformed".into());
    }
    assert_eq!(node.attribute("name"), Some("eth"));

    assert_eq!(pdu.destination_address().as_ref(), descendant_value(&node, "eth", "dst", 6)?.as_slice());
    assert_eq!(pdu.source_address().as_ref(), descendant_value(&node, "eth", "src", 6)?.as_slice());
    assert_eq!(&pdu.ethertype().to_be_bytes(), descendant_value(&node, "eth", "type", 2)?.as_slice());

    let mut vlan_count = 0;
    for _ in node.next_siblings().take_while(|n| n.attribute("name") == Some("vlan")) {
        vlan_count += 1;
    }

    let vlan_tags = pdu.vlan_tags();
    let mut last_etype = None;
    for _ in 0..vlan_count {
        let node = nodes.pop_front().unwrap();
        assert_eq!(node.attribute("name"), Some("vlan"));
        let vlan_tag = vlan_tags.unwrap().next().unwrap();
        assert_eq!(&vlan_tag.protocol_id.to_be_bytes(), descendant_value(&node, "vlan", "etype", 1)?.as_slice());
        last_etype = Some(vlan_tag.protocol_id.to_be_bytes());
        assert_eq!(
            &vlan_tag.priority_codepoint.to_be_bytes(),
            descendant_value(&node, "vlan", "priority", 1)?.as_slice()
        );
        assert_eq!((vlan_tag.drop_eligible as u8).to_be_bytes(), descendant_value(&node, "vlan", "dei", 1)?.as_slice());
    }

    if let Some(last_etype) = last_etype {
        assert_eq!(&last_etype, descendant_value(&node, "vlan", "id", 2)?.as_slice());
    }

    match pdu.inner() {
        Ok(ethernet) => match ethernet {
            Ethernet::Raw(raw) => {
                assert_eq!(&pdu.buffer()[pdu.computed_ihl()..], raw);
                Ok(())
            }
            Ethernet::Arp(arp_pdu) => visit_arp_pdu(&arp_pdu, nodes),
            Ethernet::Ipv4(ipv4_pdu) => visit_ipv4_pdu(&ipv4_pdu, nodes),
            Ethernet::Ipv6(ipv6_pdu) => visit_ipv6_pdu(&ipv6_pdu, nodes),
        },
        Err(e) => Err(e.into()),
    }
}

fn visit_arp_pdu(pdu: &ArpPdu, mut nodes: VecDeque<roxmltree::Node>) -> Result<(), Box<dyn Error>> {
    let node = nodes.pop_front().unwrap();
    if node.attribute("name") == Some("_ws.malformed") {
        return Err("node: malformed".into());
    }
    assert_eq!(node.attribute("name"), Some("arp"));

    assert_eq!(pdu.hardware_type().to_be_bytes(), descendant_value(&node, "arp", "hw.type", 2)?.as_slice());
    assert_eq!(pdu.protocol_type().to_be_bytes(), descendant_value(&node, "arp", "proto.type", 2)?.as_slice());
    assert_eq!(pdu.hardware_length().to_be_bytes(), descendant_value(&node, "arp", "hw.size", 1)?.as_slice());
    assert_eq!(pdu.protocol_length().to_be_bytes(), descendant_value(&node, "arp", "proto.size", 1)?.as_slice());
    assert_eq!(pdu.opcode().to_be_bytes(), descendant_value(&node, "arp", "opcode", 2)?.as_slice());
    assert_eq!(pdu.sender_hardware_address().as_ref(), descendant_value(&node, "arp", "src.hw_mac", 6)?.as_slice());
    assert_eq!(pdu.sender_protocol_address().as_ref(), descendant_value(&node, "arp", "src.proto_ipv4", 4)?.as_slice());
    assert_eq!(pdu.target_hardware_address().as_ref(), descendant_value(&node, "arp", "dst.hw_mac", 6)?.as_slice());
    assert_eq!(pdu.target_protocol_address().as_ref(), descendant_value(&node, "arp", "dst.proto_ipv4", 4)?.as_slice());

    Ok(())
}

fn visit_ipv4_pdu(pdu: &Ipv4Pdu, mut nodes: VecDeque<roxmltree::Node>) -> Result<(), Box<dyn Error>> {
    let node = nodes.pop_front().unwrap();
    if node.attribute("name") == Some("_ws.malformed") {
        return Err("node: malformed".into());
    }
    assert_eq!(node.attribute("name"), Some("ip"));

    assert_eq!(pdu.version().to_be_bytes(), descendant_value(&node, "ip", "version", 1)?.as_slice());
    // wireshark 3.2.3 ip.hdr_len[value] is not correctly right-shifted by 4
    //assert_eq!(pdu.ihl().to_be_bytes(), descendant_value(&node, "ip", "hdr_len", 1)?.as_slice());
    assert_eq!(pdu.dscp().to_be_bytes(), descendant_value(&node, "ip", "dsfield.dscp", 1)?.as_slice());
    assert_eq!(pdu.ecn().to_be_bytes(), descendant_value(&node, "ip", "dsfield.ecn", 1)?.as_slice());
    assert_eq!(pdu.total_length().to_be_bytes(), descendant_value(&node, "ip", "len", 2)?.as_slice());
    assert_eq!(pdu.identification().to_be_bytes(), descendant_value(&node, "ip", "id", 2)?.as_slice());
    assert_eq!((pdu.dont_fragment() as u8).to_be_bytes(), descendant_value(&node, "ip", "flags.df", 1)?.as_slice());
    assert_eq!((pdu.more_fragments() as u8).to_be_bytes(), descendant_value(&node, "ip", "flags.mf", 1)?.as_slice());
    // wireshark 3.2.3 ip.frag_offset[value] is not correctly masked with 0x1FFF
    //assert_eq!(pdu.fragment_offset().to_be_bytes(), descendant_value(&node, "ip", "frag_offset", 2)?.as_slice());
    assert_eq!(pdu.ttl().to_be_bytes(), descendant_value(&node, "ip", "ttl", 1)?.as_slice());
    assert_eq!(pdu.protocol().to_be_bytes(), descendant_value(&node, "ip", "proto", 1)?.as_slice());
    assert_eq!(pdu.checksum().to_be_bytes(), descendant_value(&node, "ip", "checksum", 2)?.as_slice());
    if descendant_show(&node, "ip", "checksum.status", 1)?.eq(&[0x01]) {
        assert_eq!(pdu.computed_checksum().to_be_bytes(), descendant_value(&node, "ip", "checksum", 2)?.as_slice());
    }
    assert_eq!(pdu.source_address().as_ref(), descendant_value(&node, "ip", "src", 4)?.as_slice());
    assert_eq!(pdu.destination_address().as_ref(), descendant_value(&node, "ip", "dst", 4)?.as_slice());

    if let Some(options) = node.children().find(|n| n.attribute("name") == Some("")) {
        let mut options = options.children().filter(|n| n.is_element()).collect::<VecDeque<roxmltree::Node>>();
        for option in pdu.options() {
            let node = options.pop_front().unwrap();
            match option {
                Ipv4Option::Raw { option, .. } => {
                    assert_eq!(option.to_be_bytes(), descendant_value(&node, "ip", "opt.type", 1)?.as_slice());
                }
            }
        }
        while options.front().is_some() && options.front().unwrap().attribute("name") == Some("") {
            options.pop_front().unwrap();
        }
        assert!(options.is_empty());
    }

    match pdu.inner() {
        Ok(ipv4) => match ipv4 {
            Ipv4::Raw(raw) => {
                assert_eq!(&pdu.buffer()[pdu.computed_ihl()..], raw);
                Ok(())
            }
            Ipv4::Tcp(tcp_pdu) => visit_tcp_pdu(&tcp_pdu, &Ip::Ipv4(*pdu), nodes),
            Ipv4::Udp(udp_pdu) => visit_udp_pdu(&udp_pdu, &Ip::Ipv4(*pdu), nodes),
            Ipv4::Icmp(icmp_pdu) => visit_icmp_pdu(&icmp_pdu, &Ip::Ipv4(*pdu), nodes),
            Ipv4::Gre(gre_pdu) => visit_gre_pdu(&gre_pdu, nodes),
            Ipv4::Esp(esp_pdu) => visit_esp_pdu(&esp_pdu, nodes),
            Ipv4::EtherIp(etherip_pdu) => visit_ethernet_pdu(&etherip_pdu, nodes),
            Ipv4::IpIp(ipip_pdu) => visit_ipv4_pdu(&ipip_pdu, nodes),
            Ipv4::Ip6In4(ip6in4_pdu) => visit_ipv6_pdu(&ip6in4_pdu, nodes),
        },
        Err(e) => Err(e.into()),
    }
}

fn visit_ipv6_pdu(pdu: &Ipv6Pdu, mut nodes: VecDeque<roxmltree::Node>) -> Result<(), Box<dyn Error>> {
    let node = nodes.pop_front().unwrap();
    if node.attribute("name") == Some("_ws.malformed") {
        return Err("node: malformed".into());
    }
    assert_eq!(node.attribute("name"), Some("ipv6"));

    assert_eq!(pdu.version().to_be_bytes(), descendant_value(&node, "ipv6", "version", 1)?.as_slice());
    assert_eq!(pdu.dscp().to_be_bytes(), descendant_value(&node, "ipv6", "tclass.dscp", 1)?.as_slice());
    assert_eq!(pdu.ecn().to_be_bytes(), descendant_value(&node, "ipv6", "tclass.ecn", 1)?.as_slice());
    assert_eq!(pdu.flow_label().to_be_bytes(), descendant_value(&node, "ipv6", "flow", 4)?.as_slice());
    assert_eq!(pdu.payload_length().to_be_bytes(), descendant_value(&node, "ipv6", "plen", 2)?.as_slice());
    assert_eq!(pdu.next_header().to_be_bytes(), descendant_value(&node, "ipv6", "nxt", 1)?.as_slice());
    assert_eq!(pdu.hop_limit().to_be_bytes(), descendant_value(&node, "ipv6", "hlim", 1)?.as_slice());
    assert_eq!(pdu.source_address().as_ref(), descendant_value(&node, "ipv6", "src", 16)?.as_slice());
    assert_eq!(pdu.destination_address().as_ref(), descendant_value(&node, "ipv6", "dst", 16)?.as_slice());

    if let Some(fraghdr) = node.children().find(|n| n.attribute("name") == Some("ipv6.fraghdr")) {
        assert_eq!(
            pdu.computed_identification().unwrap().to_be_bytes(),
            descendant_value(&fraghdr, "ipv6", "fraghdr.ident", 4)?.as_slice()
        );
        // wireshark 3.2.3 ipv6.fraghdr.offset[value] is not correctly multiplied by 8
        //assert_eq!(
        //    pdu.computed_fragment_offset().unwrap().to_be_bytes(),
        //    descendant_value(&fraghdr, "ipv6", "fraghdr.offset", 2)?.as_slice()
        //);
        assert_eq!(
            &[pdu.computed_more_fragments().unwrap() as u8],
            descendant_value(&fraghdr, "ipv6", "fraghdr.more", 1)?.as_slice()
        );
    }

    match pdu.inner() {
        Ok(ipv6) => match ipv6 {
            Ipv6::Raw(raw) => {
                assert_eq!(&pdu.buffer()[pdu.computed_ihl()..], raw);
                Ok(())
            }
            Ipv6::Tcp(tcp_pdu) => visit_tcp_pdu(&tcp_pdu, &Ip::Ipv6(*pdu), nodes),
            Ipv6::Udp(udp_pdu) => visit_udp_pdu(&udp_pdu, &Ip::Ipv6(*pdu), nodes),
            Ipv6::Icmp(icmp_pdu) => visit_icmp_pdu(&icmp_pdu, &Ip::Ipv6(*pdu), nodes),
            Ipv6::Gre(gre_pdu) => visit_gre_pdu(&gre_pdu, nodes),
            Ipv6::Esp(esp_pdu) => visit_esp_pdu(&esp_pdu, nodes),
            Ipv6::EtherIp(etherip_pdu) => visit_ethernet_pdu(&etherip_pdu, nodes),
            Ipv6::IpIp(ipip_pdu) => visit_ipv6_pdu(&ipip_pdu, nodes),
            Ipv6::Ip4In6(ip4in6_pdu) => visit_ipv4_pdu(&ip4in6_pdu, nodes),
        },
        Err(e) => Err(e.into()),
    }
}

fn visit_tcp_pdu(pdu: &TcpPdu, ip_pdu: &Ip, mut nodes: VecDeque<roxmltree::Node>) -> Result<(), Box<dyn Error>> {
    let node = nodes.pop_front().unwrap();
    if node.attribute("name") == Some("_ws.malformed") {
        return Err("node: malformed".into());
    }
    assert_eq!(node.attribute("name"), Some("tcp"));

    assert_eq!(pdu.source_port().to_be_bytes(), descendant_value(&node, "tcp", "srcport", 2)?.as_slice());
    assert_eq!(pdu.destination_port().to_be_bytes(), descendant_value(&node, "tcp", "dstport", 2)?.as_slice());
    assert_eq!(pdu.sequence_number().to_be_bytes(), descendant_value(&node, "tcp", "seq", 4)?.as_slice());
    assert_eq!(pdu.acknowledgement_number().to_be_bytes(), descendant_value(&node, "tcp", "ack", 4)?.as_slice());
    // wireshark 3.2.3 tcp.hdr_len[value] is not correctly right-shifted by 4
    //assert_eq!(pdu.data_offset().to_be_bytes(), descendant_value(&node, "tcp", "hdr_len", 1)?.as_slice());
    assert_eq!(pdu.flags().to_be_bytes(), descendant_value(&node, "tcp", "flags", 1)?.as_slice());
    assert_eq!((pdu.fin() as u8).to_be_bytes(), descendant_value(&node, "tcp", "flags.fin", 1)?.as_slice());
    assert_eq!((pdu.syn() as u8).to_be_bytes(), descendant_value(&node, "tcp", "flags.syn", 1)?.as_slice());
    assert_eq!((pdu.rst() as u8).to_be_bytes(), descendant_value(&node, "tcp", "flags.reset", 1)?.as_slice());
    assert_eq!((pdu.psh() as u8).to_be_bytes(), descendant_value(&node, "tcp", "flags.push", 1)?.as_slice());
    assert_eq!((pdu.ack() as u8).to_be_bytes(), descendant_value(&node, "tcp", "flags.ack", 1)?.as_slice());
    assert_eq!((pdu.urg() as u8).to_be_bytes(), descendant_value(&node, "tcp", "flags.urg", 1)?.as_slice());
    assert_eq!((pdu.ecn() as u8).to_be_bytes(), descendant_value(&node, "tcp", "flags.ecn", 1)?.as_slice());
    assert_eq!((pdu.cwr() as u8).to_be_bytes(), descendant_value(&node, "tcp", "flags.cwr", 1)?.as_slice());
    assert_eq!(pdu.window_size().to_be_bytes(), descendant_value(&node, "tcp", "window_size_value", 2)?.as_slice());
    assert_eq!(pdu.computed_window_size(0).to_be_bytes(), descendant_value(&node, "tcp", "window_size", 4)?.as_slice());
    assert_eq!(pdu.checksum().to_be_bytes(), descendant_value(&node, "tcp", "checksum", 2)?.as_slice());
    if descendant_show(&node, "tcp", "checksum.status", 1)?.eq(&[0x01]) {
        assert_eq!(
            pdu.computed_checksum(ip_pdu).to_be_bytes(),
            descendant_value(&node, "tcp", "checksum", 2)?.as_slice()
        );
    }
    assert_eq!(pdu.urgent_pointer().to_be_bytes(), descendant_value(&node, "tcp", "urgent_pointer", 2)?.as_slice());

    let mut options = pdu.options().collect::<VecDeque<TcpOption>>();

    for node in node
        .descendants()
        .filter(|n| n.attribute("name").is_some() && n.attribute("name").unwrap().starts_with("tcp.options."))
    {
        match node.attribute("name").unwrap() {
            "tcp.options.nop" => {
                if let Some(TcpOption::NoOp) = options.pop_front() {
                    continue;
                } else {
                    panic!("expected TcpOption::NoOp");
                }
            }
            "tcp.options.mss" => {
                if let Some(TcpOption::Mss { size }) = options.pop_front() {
                    assert_eq!(size.to_be_bytes(), descendant_value(&node, "tcp", "options.mss_val", 2)?.as_slice());
                } else {
                    panic!("expected TcpOption::Mss");
                }
            }
            "tcp.options.wscale" => {
                if let Some(TcpOption::WindowScale { shift }) = options.pop_front() {
                    assert_eq!(
                        shift.to_be_bytes(),
                        descendant_value(&node, "tcp", "options.wscale.shift", 1)?.as_slice()
                    );
                } else {
                    panic!("expected TcpOption::WindowScale");
                }
            }
            "tcp.options.sack_perm" => {
                if let Some(TcpOption::SackPermitted) = options.pop_front() {
                    continue;
                } else {
                    panic!("expected TcpOption::SackPermitted");
                }
            }
            "tcp.options.sack" => {
                if let Some(TcpOption::Sack { blocks }) = options.pop_front() {
                    match blocks {
                        [Some((l, r)), None, None, None]
                        | [Some((l, _)), Some((_, r)), None, None]
                        | [Some((l, _)), Some((_, _)), Some((_, r)), None]
                        | [Some((l, _)), Some((_, _)), Some((_, _)), Some((_, r))] => {
                            assert_eq!(
                                &l.to_be_bytes(),
                                descendant_value(&node, "tcp", "options.sack_le", 4)?.as_slice()
                            );
                            assert_eq!(
                                &r.to_be_bytes(),
                                descendant_value(&node, "tcp", "options.sack_re", 4)?.as_slice()
                            );
                        }
                        _ => panic!("TcpOption::Sack blocks are [None, None, None, None]"),
                    }
                } else {
                    panic!("expected TcpOption::Sack");
                }
            }
            "tcp.options.timestamp" => {
                if let Some(TcpOption::Timestamp { val, ecr }) = options.pop_front() {
                    assert_eq!(
                        val.to_be_bytes(),
                        descendant_value(&node, "tcp", "options.timestamp.tsval", 4)?.as_slice()
                    );
                    assert_eq!(
                        ecr.to_be_bytes(),
                        descendant_value(&node, "tcp", "options.timestamp.tsecr", 4)?.as_slice()
                    );
                } else {
                    panic!("expected TcpOption::Timestamp");
                }
            }
            _ => {}
        }
    }

    assert!(options.is_empty());

    match pdu.inner() {
        Ok(Tcp::Raw(raw)) => {
            assert_eq!(&pdu.buffer()[pdu.computed_data_offset()..], raw);
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

fn visit_udp_pdu(pdu: &UdpPdu, ip_pdu: &Ip, mut nodes: VecDeque<roxmltree::Node>) -> Result<(), Box<dyn Error>> {
    let node = nodes.pop_front().unwrap();
    if node.attribute("name") == Some("_ws.malformed") {
        return Err("node: malformed".into());
    }
    assert_eq!(node.attribute("name"), Some("udp"));

    assert_eq!(pdu.source_port().to_be_bytes(), descendant_value(&node, "udp", "srcport", 2)?.as_slice());
    assert_eq!(pdu.destination_port().to_be_bytes(), descendant_value(&node, "udp", "dstport", 2)?.as_slice());
    assert_eq!(pdu.length().to_be_bytes(), descendant_value(&node, "udp", "length", 2)?.as_slice());
    assert_eq!(pdu.checksum().to_be_bytes(), descendant_value(&node, "udp", "checksum", 2)?.as_slice());
    if descendant_show(&node, "udp", "checksum.status", 1)?.eq(&[0x01]) {
        assert_eq!(
            pdu.computed_checksum(ip_pdu).to_be_bytes(),
            descendant_value(&node, "udp", "checksum", 2)?.as_slice()
        );
    }

    match pdu.inner() {
        Ok(Udp::Raw(raw)) => {
            assert_eq!(&pdu.buffer()[pdu.computed_ihl()..], raw);
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

fn visit_icmp_pdu(pdu: &IcmpPdu, ip_pdu: &Ip, mut nodes: VecDeque<roxmltree::Node>) -> Result<(), Box<dyn Error>> {
    let node = nodes.pop_front().unwrap();
    if node.attribute("name") == Some("_ws.malformed") {
        return Err("node: malformed".into());
    }

    let proto = match node.attribute("name") {
        Some("icmp") => "icmp",
        Some("icmpv6") => "icmpv6",
        something_else => panic!("{:?}", something_else),
    };

    assert_eq!(pdu.message_type().to_be_bytes(), descendant_value(&node, proto, "type", 1)?.as_slice());
    assert_eq!(pdu.message_code().to_be_bytes(), descendant_value(&node, proto, "code", 1)?.as_slice());
    assert_eq!(pdu.checksum().to_be_bytes(), descendant_value(&node, proto, "checksum", 2)?.as_slice());
    if descendant_show(&node, proto, "checksum.status", 1)?.eq(&[0x01]) {
        assert_eq!(
            pdu.computed_checksum(ip_pdu).to_be_bytes(),
            descendant_value(&node, proto, "checksum", 2)?.as_slice()
        );
    }

    match pdu.inner() {
        Ok(Icmp::Raw(raw)) => {
            assert_eq!(&pdu.buffer()[pdu.computed_ihl()..], raw);
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

fn visit_gre_pdu(pdu: &GrePdu, mut nodes: VecDeque<roxmltree::Node>) -> Result<(), Box<dyn Error>> {
    let node = nodes.pop_front().unwrap();
    if node.attribute("name") == Some("_ws.malformed") {
        return Err("node: malformed".into());
    }
    assert_eq!(node.attribute("name"), Some("gre"));

    assert_eq!(pdu.version().to_be_bytes(), descendant_value(&node, "gre", "flags.version", 1)?.as_slice());
    assert_eq!(pdu.ethertype().to_be_bytes(), descendant_value(&node, "gre", "proto", 2)?.as_slice());

    if node.descendants().any(|n| n.attribute("name") == Some("gre.checksum")) {
        assert_eq!(pdu.checksum().unwrap().to_be_bytes(), descendant_value(&node, "gre", "checksum", 2)?.as_slice());
        if descendant_show(&node, "gre", "checksum.status", 1)?.eq(&[0x01]) {
            assert_eq!(
                pdu.computed_checksum().unwrap().to_be_bytes(),
                descendant_value(&node, "gre", "checksum", 2)?.as_slice()
            );
        }
    }

    if node.descendants().any(|n| n.attribute("name") == Some("gre.key")) {
        assert_eq!(pdu.key().unwrap().to_be_bytes(), descendant_value(&node, "gre", "key", 4)?.as_slice());
    }

    if node.descendants().any(|n| n.attribute("name") == Some("gre.sequence_number")) {
        assert_eq!(
            pdu.sequence_number().unwrap().to_be_bytes(),
            descendant_value(&node, "gre", "sequence_number", 4)?.as_slice()
        );
    }

    match pdu.inner() {
        Ok(gre) => match gre {
            Gre::Raw(raw) => {
                assert_eq!(&pdu.buffer()[pdu.computed_ihl()..], raw);
                Ok(())
            }
            Gre::Ethernet(ethernet_pdu) => visit_ethernet_pdu(&ethernet_pdu, nodes),
            Gre::Ipv4(ipv4_pdu) => visit_ipv4_pdu(&ipv4_pdu, nodes),
            Gre::Ipv6(ipv6_pdu) => visit_ipv6_pdu(&ipv6_pdu, nodes),
        },
        Err(e) => Err(e.into()),
    }
}

fn visit_esp_pdu(pdu: &EspPdu, mut nodes: VecDeque<roxmltree::Node>) -> Result<(), Box<dyn Error>> {
    let node = nodes.pop_front().unwrap();
    if node.attribute("name") == Some("_ws.malformed") {
        return Err("node: malformed".into());
    }
    assert_eq!(node.attribute("name"), Some("esp"));

    assert_eq!(pdu.spi().to_be_bytes(), descendant_value(&node, "esp", "spi", 4)?.as_slice());
    assert_eq!(pdu.sequence_number().to_be_bytes(), descendant_value(&node, "esp", "sequence", 4)?.as_slice());

    match pdu.inner() {
        Ok(Esp::Raw(raw)) => {
            assert_eq!(&pdu.buffer()[pdu.computed_ihl()..], raw);
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

#[test]
fn test_pcaps() -> Result<(), Box<dyn Error>> {
    let crate_root = path::Path::new(env!("CARGO_MANIFEST_DIR")).to_owned();

    let pcap_files = crate_root
        .join("tests/pcaps")
        .read_dir()?
        .filter_map(Result::ok)
        .filter(|f| f.path().is_file() && f.path().extension().unwrap_or_else(|| ffi::OsStr::new("")) == "pcap")
        .collect::<Vec<fs::DirEntry>>();

    for pcap_file in pcap_files.iter() {
        let pcap_file = pcap_file.path().to_str().unwrap().to_string();
        let mut tshark = Command::new("tshark");
        tshark.args(&[
            "-n",
            "-o",
            "ip.defragment:false",
            "-o",
            "ipv6.defragment:false",
            "-o",
            "tcp.desegment_tcp_streams:false",
            "-T",
            "pdml",
            "-r",
            &pcap_file,
        ]);
        tshark.stdout(Stdio::piped());

        let output = tshark.output()?;
        if !output.status.success() {
            eprintln!("[{}] tshark error: {:?}", pcap_file, output);
            continue;
        }

        let dissections = String::from_utf8(output.stdout)?;
        let dissections = roxmltree::Document::parse(dissections.as_str())?;
        let dissections: Vec<roxmltree::Node> =
            dissections.root().first_element_child().unwrap().children().filter(|n| n.is_element()).collect();

        let mut pcap = match pcap::Capture::from_file(&pcap_file) {
            Ok(pcap) => pcap,
            Err(e) => {
                eprintln!("[{}] pcap error: {:?}", &pcap_file, e);
                continue;
            }
        };

        let mut i = -1isize;
        for dissection in dissections.iter() {
            let data = pcap.next().unwrap().data;
            i += 1;
            let dissections: VecDeque<roxmltree::Node> = dissection
                .children()
                .filter(|n| n.is_element())
                .skip(2)
                .filter(|n| n.attribute("name") != Some("fake-field-wrapper"))
                .collect();

            if dissections.is_empty() {
                eprintln!("[{}] empty", &pcap_file);
                continue;
            }

            eprintln!("{} (#{})", &pcap_file, i + 1);
            let first_layer = dissections.front().unwrap().attribute("name");
            if first_layer == Some("eth") {
                match EthernetPdu::new(data) {
                    Ok(ethernet_pdu) => match visit_ethernet_pdu(&ethernet_pdu, dissections) {
                        Ok(()) => {}
                        Err(e) => {
                            eprintln!("[{}#{}] validate error: {:?}", &pcap_file, i + 1, e);
                            continue;
                        }
                    },
                    Err(e) => {
                        eprintln!("[{}#{}] decode error: {:?}", &pcap_file, i + 1, e);
                        continue;
                    }
                }
            } else if first_layer == Some("ip") || first_layer == Some("ipv6") {
                match Ip::new(data) {
                    Ok(Ip::Ipv4(ipv4_pdu)) => match visit_ipv4_pdu(&ipv4_pdu, dissections) {
                        Ok(()) => {}
                        Err(e) => {
                            eprintln!("[{}#{}] validate error: {:?}", &pcap_file, i + 1, e);
                            continue;
                        }
                    },
                    Ok(Ip::Ipv6(ipv6_pdu)) => match visit_ipv6_pdu(&ipv6_pdu, dissections) {
                        Ok(()) => {}
                        Err(e) => {
                            eprintln!("[{}#{}] validate error: {:?}", &pcap_file, i + 1, e);
                            continue;
                        }
                    },
                    Err(e) => {
                        eprintln!("[{}#{}] decode error: {:?}", &pcap_file, i + 1, e);
                        continue;
                    }
                }
            } else {
                eprintln!("[{}] unsupported first layer ({:?})", &pcap_file, first_layer);
                continue;
            }
        }
    }

    Ok(())
}
