# pdu

Small, fast, and correct L2/L3/L4 packet parser.

**Author:** Alex Forster \<alex@alexforster.com\><br/>
**License:** Apache-2.0

[![build status](https://travis-ci.org/alexforster/pdu.svg?branch=master)](https://travis-ci.org/alexforster/pdu)
[![crates.io version](https://img.shields.io/crates/v/pdu.svg)](https://crates.io/crates/pdu)
[![docs.rs](https://docs.rs/pdu/badge.svg)](https://docs.rs/pdu)

#### Small

 * Fully-featured `no_std` support
 * No Crate dependencies and no macros
 * Link/internet/transport protocols only: application-layer protocols are out of scope

#### Fast

 * Lazy parsing: only the fields that you access are parsed
 * Zero-copy construction: no heap allocations are performed

#### Correct

 * Tested against [Wireshark](https://www.wireshark.org/docs/man-pages/tshark.html) to ensure all packet fields are parsed correctly
 * Fuzzed using [Honggfuzz](https://github.com/google/honggfuzz) to ensure invalid input does not cause panics
 * Does not use any `unsafe` code

## Supported Protocols

The following protocol hierarchy can be parsed with this library:

 * Ethernet (including vlan/QinQ)
   * ARP
   * IPv4 (including options)
     * TCP (including options)
     * UDP
     * ICMP
     * GREv0
       * ...Ethernet, IPv4, IPv6...
     * ESP (no decryption)
     * EtherIP
       * ...Ethernet...
     * IPIP
       * ...IPv4...
     * 6in4
       * ...IPv6...
   * IPv6 (including extension headers)
     * TCP (including options)
     * UDP
     * ICMPv6
     * GREv0
       * ...Ethernet, IPv4, IPv6...
     * ESP (no decryption)
     * EtherIP
       * ...Ethernet...
     * IPIP
       * ...IPv6...
     * 4in6
       * ...IPv4...

In addition, unrecognized upper protocols are accessible as bytes via `Raw`
enum variants.

## Getting Started

#### `Cargo.toml`

```toml
[dependencies]
pdu = "1.1"
```

#### Examples

```rust
use pdu::*;

// parse a layer 2 (Ethernet) packet using EthernetPdu::new()

fn main() {
    let packet: &[u8] = &[
        0x68, 0x5b, 0x35, 0xc0, 0x61, 0xb6, 0x00, 0x1d, 0x09, 0x94, 0x65, 0x38, 0x08, 0x00, 0x45, 0x00, 0x00,
        0x3b, 0x2d, 0xfd, 0x00, 0x00, 0x40, 0x11, 0xbc, 0x43, 0x83, 0xb3, 0xc4, 0x2e, 0x83, 0xb3, 0xc4, 0xdc,
        0x18, 0xdb, 0x18, 0xdb, 0x00, 0x27, 0xe0, 0x3e, 0x05, 0x1d, 0x07, 0x15, 0x08, 0x07, 0x65, 0x78, 0x61,
        0x6d, 0x70, 0x6c, 0x65, 0x08, 0x07, 0x74, 0x65, 0x73, 0x74, 0x41, 0x70, 0x70, 0x08, 0x01, 0x31, 0x0a,
        0x04, 0x1e, 0xcc, 0xe2, 0x51,
    ];
    
    match EthernetPdu::new(&packet) {
        Ok(ethernet_pdu) => {
            println!("[ethernet] destination_address: {:x?}", ethernet_pdu.destination_address().as_ref());
            println!("[ethernet] source_address: {:x?}", ethernet_pdu.source_address().as_ref());
            println!("[ethernet] ethertype: 0x{:04x}", ethernet_pdu.ethertype());
            if let Some(vlan) = ethernet_pdu.vlan() {
                println!("[ethernet] vlan: 0x{:04x}", vlan);
            }
            // upper-layer protocols can be accessed via the inner() method
            match ethernet_pdu.inner() {
                Ok(Ethernet::Ipv4(ipv4_pdu)) => {
                    println!("[ipv4] source_address: {:x?}", ipv4_pdu.source_address().as_ref());
                    println!("[ipv4] destination_address: {:x?}", ipv4_pdu.destination_address().as_ref());
                    println!("[ipv4] protocol: 0x{:02x}", ipv4_pdu.protocol());
                    // upper-layer protocols can be accessed via the inner() method (not shown)
                }
                Ok(Ethernet::Ipv6(ipv6_pdu)) => {
                    println!("[ipv6] source_address: {:x?}", ipv6_pdu.source_address().as_ref());
                    println!("[ipv6] destination_address: {:x?}", ipv6_pdu.destination_address().as_ref());
                    println!("[ipv6] protocol: 0x{:02x}", ipv6_pdu.computed_protocol());
                    // upper-layer protocols can be accessed via the inner() method (not shown)
                }
                Ok(other) => {
                    panic!("Unexpected protocol {:?}", other);
                }
                Err(e) => {
                    panic!("EthernetPdu::inner() parser failure: {:?}", e);
                }
            }
        }
        Err(e) => {
            panic!("EthernetPdu::new() parser failure: {:?}", e);
        }
    }
}
```

```rust
use pdu::*;

// parse a layer 3 (IP) packet using Ip::new()

fn main() {
    let packet: &[u8] = &[
        0x45, 0x00, 0x00, 0x3b, 0x2d, 0xfd, 0x00, 0x00, 0x40, 0x11, 0xbc, 0x43, 0x83, 0xb3, 0xc4, 0x2e, 0x83, 0xb3,
        0xc4, 0xdc, 0x18, 0xdb, 0x18, 0xdb, 0x00, 0x27, 0xe0, 0x3e, 0x05, 0x1d, 0x07, 0x15, 0x08, 0x07, 0x65, 0x78,
        0x61, 0x6d, 0x70, 0x6c, 0x65, 0x08, 0x07, 0x74, 0x65, 0x73, 0x74, 0x41, 0x70, 0x70, 0x08, 0x01, 0x31, 0x0a,
        0x04, 0x1e, 0xcc, 0xe2, 0x51,
    ];

    match Ip::new(&packet) {
        Ok(Ip::Ipv4(ipv4_pdu)) => {
            println!("[ipv4] source_address: {:x?}", ipv4_pdu.source_address().as_ref());
            println!("[ipv4] destination_address: {:x?}", ipv4_pdu.destination_address().as_ref());
            println!("[ipv4] protocol: 0x{:02x}", ipv4_pdu.protocol());
            // upper-layer protocols can be accessed via the inner() method (not shown)
        }
        Ok(Ip::Ipv6(ipv6_pdu)) => {
            println!("[ipv6] source_address: {:x?}", ipv6_pdu.source_address().as_ref());
            println!("[ipv6] destination_address: {:x?}", ipv6_pdu.destination_address().as_ref());
            println!("[ipv6] protocol: 0x{:02x}", ipv6_pdu.computed_protocol());
            // upper-layer protocols can be accessed via the inner() method (not shown)
        }
        Err(e) => {
            panic!("Ip::new() parser failure: {:?}", e);
        }
    }
}
```
