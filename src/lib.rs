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

//! Small, fast, and correct L2/L3/L4 packet parser

#![cfg_attr(not(any(feature = "std", test)), no_std)]

mod ethernet;
pub use ethernet::{EtherType, Ethernet, EthernetPdu};

mod arp;
pub use arp::ArpPdu;

mod ip;
pub use ip::{Ip, IpProto, Ipv4, Ipv4Option, Ipv4Pdu, Ipv6, Ipv6ExtensionHeader, Ipv6Pdu};

mod tcp;
pub use tcp::{Tcp, TcpFlag, TcpOption, TcpPdu};

mod udp;
pub use udp::{Udp, UdpPdu};

mod icmp;
pub use icmp::{Icmp, IcmpPdu};

mod gre;
pub use gre::{Gre, GrePdu};

mod esp;
pub use esp::{Esp, EspPdu};

mod util;

/// Defines the set of possible errors returned by packet parsers in this crate
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Error {
    Truncated,
    Malformed,
}

/// Defines the return type used by packet parsers in this crate
pub type Result<T> = core::result::Result<T, Error>;

#[cfg(any(feature = "std", test))]
impl std::error::Error for Error {}

#[cfg(any(feature = "std", test))]
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::Truncated => f.write_str("frame is truncated"),
            Error::Malformed => f.write_str("frame is malformed"),
        }
    }
}
