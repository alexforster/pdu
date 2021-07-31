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

use core::convert::TryInto;

use crate::{util, Error, Result};

/// Provides constants representing various IP protocol numbers supported by this crate
#[allow(non_snake_case)]
pub mod IpProto {
    pub const TCP: u8 = 6;
    pub const UDP: u8 = 17;
    pub const ICMP: u8 = 1;
    pub const ICMP6: u8 = 58;
    pub const GRE: u8 = 47;
}

/// Contains either an [`Ipv4Pdu`] or [`Ipv6Pdu`] depending on address family
#[derive(Debug, Copy, Clone)]
pub enum Ip<'a> {
    Ipv4(Ipv4Pdu<'a>),
    Ipv6(Ipv6Pdu<'a>),
}

impl<'a> Ip<'a> {
    /// Constructs either an [`Ipv4Pdu`] or [`Ipv6Pdu`] backed by the provided `buffer`
    pub fn new(buffer: &'a [u8]) -> Result<Self> {
        if buffer.is_empty() {
            return Err(Error::Truncated);
        }
        match buffer[0] >> 4 {
            4 => Ok(Ip::Ipv4(Ipv4Pdu::new(buffer)?)),
            6 => Ok(Ip::Ipv6(Ipv6Pdu::new(buffer)?)),
            _ => Err(Error::Malformed),
        }
    }
}

/// Represents an IPv4 header and payload
#[derive(Debug, Copy, Clone)]
pub struct Ipv4Pdu<'a> {
    buffer: &'a [u8],
}

/// Contains the inner payload of an [`Ipv4Pdu`]
#[derive(Debug, Copy, Clone)]
pub enum Ipv4<'a> {
    Raw(&'a [u8]),
    Tcp(super::TcpPdu<'a>),
    Udp(super::UdpPdu<'a>),
    Icmp(super::IcmpPdu<'a>),
    Gre(super::GrePdu<'a>),
}

impl<'a> Ipv4Pdu<'a> {
    /// Constructs an [`Ipv4Pdu`] backed by the provided `buffer`
    pub fn new(buffer: &'a [u8]) -> Result<Self> {
        let pdu = Ipv4Pdu { buffer };
        if buffer.len() < 20 || pdu.computed_ihl() < 20 {
            return Err(Error::Truncated);
        }
        if buffer.len() < (pdu.computed_ihl() as usize) || (pdu.total_length() as usize) < pdu.computed_ihl() {
            return Err(Error::Malformed);
        }
        if pdu.version() != 4 {
            return Err(Error::Malformed);
        }
        Ok(pdu)
    }

    /// Returns a reference to the entire underlying buffer that was provided during construction
    pub fn buffer(&'a self) -> &'a [u8] {
        self.buffer
    }

    /// Consumes this object and returns a reference to the entire underlying buffer that was provided during
    /// construction
    pub fn into_buffer(self) -> &'a [u8] {
        self.buffer
    }

    /// Returns the slice of the underlying buffer that contains the header part of this PDU
    pub fn as_bytes(&'a self) -> &'a [u8] {
        self.clone().into_bytes()
    }

    /// Consumes this object and returns the slice of the underlying buffer that contains the header part of this PDU
    pub fn into_bytes(self) -> &'a [u8] {
        &self.buffer[0..self.computed_ihl()]
    }

    /// Returns an object representing the inner payload of this PDU
    pub fn inner(&'a self) -> Result<Ipv4<'a>> {
        self.clone().into_inner()
    }

    /// Consumes this object and returns an object representing the inner payload of this PDU
    pub fn into_inner(self) -> Result<Ipv4<'a>> {
        let rest = &self.buffer[self.computed_ihl()..];

        if self.fragment_offset() > 0 {
            Ok(Ipv4::Raw(rest))
        } else {
            Ok(match self.protocol() {
                IpProto::TCP => Ipv4::Tcp(super::TcpPdu::new(rest)?),
                IpProto::UDP => Ipv4::Udp(super::UdpPdu::new(rest)?),
                IpProto::ICMP => Ipv4::Icmp(super::IcmpPdu::new(rest)?),
                IpProto::GRE => {
                    if rest.len() > 1 && (rest[1] & 0x07) == 0 {
                        Ipv4::Gre(super::GrePdu::new(rest)?)
                    } else {
                        Ipv4::Raw(rest)
                    }
                }
                _ => Ipv4::Raw(rest),
            })
        }
    }

    pub fn version(&'a self) -> u8 {
        self.buffer[0] >> 4
    }

    pub fn ihl(&'a self) -> u8 {
        self.buffer[0] & 0xF
    }

    pub fn computed_ihl(&'a self) -> usize {
        self.ihl() as usize * 4
    }

    pub fn dscp(&'a self) -> u8 {
        self.buffer[1] >> 2
    }

    pub fn ecn(&'a self) -> u8 {
        self.buffer[1] & 0x3
    }

    pub fn total_length(&'a self) -> u16 {
        u16::from_be_bytes(self.buffer[2..4].try_into().unwrap())
    }

    pub fn identification(&'a self) -> u16 {
        u16::from_be_bytes(self.buffer[4..6].try_into().unwrap())
    }

    pub fn dont_fragment(&'a self) -> bool {
        self.buffer[6] & 0x40 != 0
    }

    pub fn more_fragments(&'a self) -> bool {
        self.buffer[6] & 0x20 != 0
    }

    pub fn fragment_offset(&'a self) -> u16 {
        u16::from_be_bytes([self.buffer[6] & 0x1f, self.buffer[7]])
    }

    pub fn computed_fragment_offset(&'a self) -> u16 {
        self.fragment_offset() * 8
    }

    pub fn ttl(&'a self) -> u8 {
        self.buffer[8]
    }

    pub fn protocol(&'a self) -> u8 {
        self.buffer[9]
    }

    pub fn checksum(&'a self) -> u16 {
        u16::from_be_bytes(self.buffer[10..12].try_into().unwrap())
    }

    pub fn computed_checksum(&'a self) -> u16 {
        util::checksum(&[&self.buffer[0..10], &self.buffer[12..self.computed_ihl()]])
    }

    pub fn source_address(&'a self) -> [u8; 4] {
        let mut source_address = [0u8; 4];
        source_address.copy_from_slice(&self.buffer[12..16]);
        source_address
    }

    pub fn destination_address(&'a self) -> [u8; 4] {
        let mut destination_address = [0u8; 4];
        destination_address.copy_from_slice(&self.buffer[16..20]);
        destination_address
    }

    pub fn options(&'a self) -> Ipv4OptionIterator<'a> {
        Ipv4OptionIterator { buffer: &self.buffer, pos: 20, ihl: self.computed_ihl() }
    }
}

/// Represents an IPv4 option
#[derive(Debug, Copy, Clone)]
pub enum Ipv4Option<'a> {
    Raw { option: u8, data: &'a [u8] },
}

#[derive(Debug, Copy, Clone)]
pub struct Ipv4OptionIterator<'a> {
    buffer: &'a [u8],
    pos: usize,
    ihl: usize,
}

impl<'a> Iterator for Ipv4OptionIterator<'a> {
    type Item = Ipv4Option<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos < self.ihl {
            let pos = self.pos;
            let option = self.buffer[pos];
            let len = match option {
                0 | 1 => 1usize,
                _ => {
                    if self.ihl <= (pos + 1) {
                        return None;
                    }
                    let len = self.buffer[pos + 1] as usize;
                    if len < 2 {
                        return None;
                    }
                    len
                }
            };
            if self.ihl < (pos + len) {
                return None;
            }
            self.pos += len;
            Some(Ipv4Option::Raw { option, data: &self.buffer[pos..(pos + len)] })
        } else {
            None
        }
    }
}

/// Represents an IPv6 header and payload
#[derive(Debug, Copy, Clone)]
pub struct Ipv6Pdu<'a> {
    buffer: &'a [u8],
}

/// Contains the inner payload of an [`Ipv6Pdu`]
#[derive(Debug, Copy, Clone)]
pub enum Ipv6<'a> {
    Raw(&'a [u8]),
    Tcp(super::TcpPdu<'a>),
    Udp(super::UdpPdu<'a>),
    Icmp(super::IcmpPdu<'a>),
    Gre(super::GrePdu<'a>),
}

impl<'a> Ipv6Pdu<'a> {
    /// Constructs an [`Ipv6Pdu`] backed by the provided `buffer`
    pub fn new(buffer: &'a [u8]) -> Result<Self> {
        let pdu = Ipv6Pdu { buffer };
        if buffer.len() < 40 {
            return Err(Error::Truncated);
        }
        if pdu.version() != 6 {
            return Err(Error::Malformed);
        }
        let mut position = 40;
        let mut next_header = buffer[6];
        while let 0 | 43 | 44 | 59 | 60 = next_header {
            if buffer.len() <= (position + 1) {
                return Err(Error::Truncated);
            }
            next_header = buffer[position];
            position += ((buffer[position + 1] as usize) + 1) * 8;
        }
        if buffer.len() < position {
            return Err(Error::Truncated);
        }
        if pdu.computed_ihl() != position {
            return Err(Error::Malformed);
        }
        Ok(pdu)
    }

    /// Returns a reference to the entire underlying buffer that was provided during construction
    pub fn buffer(&'a self) -> &'a [u8] {
        self.buffer
    }

    /// Consumes this object and returns a reference to the entire underlying buffer that was provided during
    /// construction
    pub fn into_buffer(self) -> &'a [u8] {
        self.buffer
    }

    /// Returns the slice of the underlying buffer that contains the header part of this PDU
    pub fn as_bytes(&'a self) -> &'a [u8] {
        self.clone().into_bytes()
    }

    /// Consumes this object and returns the slice of the underlying buffer that contains the header part of this PDU
    pub fn into_bytes(self) -> &'a [u8] {
        &self.buffer[0..self.computed_ihl()]
    }

    /// Returns an object representing the inner payload of this PDU
    pub fn inner(&'a self) -> Result<Ipv6<'a>> {
        self.clone().into_inner()
    }

    /// Consumes this object and returns an object representing the inner payload of this PDU
    pub fn into_inner(self) -> Result<Ipv6<'a>> {
        let rest = &self.buffer[self.computed_ihl()..];

        if self.computed_fragment_offset().unwrap_or_default() > 0 {
            Ok(Ipv6::Raw(rest))
        } else {
            Ok(match self.computed_protocol() {
                IpProto::TCP => Ipv6::Tcp(super::TcpPdu::new(rest)?),
                IpProto::UDP => Ipv6::Udp(super::UdpPdu::new(rest)?),
                IpProto::ICMP6 => Ipv6::Icmp(super::IcmpPdu::new(rest)?),
                IpProto::GRE => {
                    if rest.len() > 1 && (rest[1] & 0x07) == 0 {
                        Ipv6::Gre(super::GrePdu::new(rest)?)
                    } else {
                        Ipv6::Raw(rest)
                    }
                }
                _ => Ipv6::Raw(rest),
            })
        }
    }

    pub fn version(&'a self) -> u8 {
        self.buffer[0] >> 4
    }

    pub fn dscp(&'a self) -> u8 {
        ((self.buffer[0] << 4) | (self.buffer[1] >> 4)) >> 2
    }

    pub fn ecn(&'a self) -> u8 {
        (self.buffer[1] >> 4) & 0x3
    }

    pub fn flow_label(&'a self) -> u32 {
        u32::from_be_bytes([0, self.buffer[1] & 0xf, self.buffer[2], self.buffer[3]])
    }

    pub fn payload_length(&'a self) -> u16 {
        u16::from_be_bytes(self.buffer[4..6].try_into().unwrap())
    }

    pub fn next_header(&'a self) -> u8 {
        self.buffer[6]
    }

    pub fn computed_ihl(&'a self) -> usize {
        let mut position = 40;
        let mut next_header = self.next_header();
        while let 0 | 43 | 44 | 59 | 60 = next_header {
            next_header = self.buffer[position];
            position += ((self.buffer[position + 1] as usize) + 1) * 8;
        }
        position
    }

    pub fn computed_protocol(&'a self) -> u8 {
        let mut position = 40;
        let mut next_header = self.next_header();
        while let 0 | 43 | 44 | 59 | 60 = next_header {
            next_header = self.buffer[position];
            position += ((self.buffer[position + 1] as usize) + 1) * 8;
        }
        next_header
    }

    pub fn computed_identification(&'a self) -> Option<u32> {
        for header in self.extension_headers() {
            if let Ipv6ExtensionHeader::Fragment { identification, .. } = header {
                return Some(identification);
            }
        }
        None
    }

    pub fn computed_more_fragments(&'a self) -> Option<bool> {
        for header in self.extension_headers() {
            if let Ipv6ExtensionHeader::Fragment { more_fragments, .. } = header {
                return Some(more_fragments);
            }
        }
        None
    }

    pub fn computed_fragment_offset(&'a self) -> Option<u16> {
        for header in self.extension_headers() {
            if let Ipv6ExtensionHeader::Fragment { offset, .. } = header {
                return Some(offset * 8);
            }
        }
        None
    }

    pub fn hop_limit(&'a self) -> u8 {
        self.buffer[7]
    }

    pub fn source_address(&'a self) -> [u8; 16] {
        let mut source_address = [0u8; 16];
        source_address.copy_from_slice(&self.buffer[8..24]);
        source_address
    }

    pub fn destination_address(&'a self) -> [u8; 16] {
        let mut destination_address = [0u8; 16];
        destination_address.copy_from_slice(&self.buffer[24..40]);
        destination_address
    }

    pub fn extension_headers(&'a self) -> Ipv6ExtensionHeaderIterator<'a> {
        Ipv6ExtensionHeaderIterator { buffer: self.buffer, pos: 40, next_header: self.next_header() }
    }
}

/// Represents an IPv6 extension header
#[derive(Debug, Copy, Clone)]
pub enum Ipv6ExtensionHeader<'a> {
    Raw { header: u8, data: &'a [u8] },
    Fragment { identification: u32, offset: u16, more_fragments: bool },
}

#[derive(Debug, Copy, Clone)]
pub struct Ipv6ExtensionHeaderIterator<'a> {
    buffer: &'a [u8],
    pos: usize,
    next_header: u8,
}

impl<'a> Iterator for Ipv6ExtensionHeaderIterator<'a> {
    type Item = Ipv6ExtensionHeader<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if let 0 | 43 | 44 | 59 | 60 = self.next_header {
            let header = self.next_header;
            self.next_header = self.buffer[self.pos];
            let header_length = ((self.buffer[self.pos + 1] as usize) + 1) * 8;
            let pos = self.pos;
            self.pos += header_length;
            if header == 44 && header_length == 8 {
                let identification = u32::from_be_bytes([
                    self.buffer[pos + 4],
                    self.buffer[pos + 5],
                    self.buffer[pos + 6],
                    self.buffer[pos + 7],
                ]);
                let offset = u16::from_be_bytes([self.buffer[pos + 2], self.buffer[pos + 3]]) >> 3;
                let more_fragments = self.buffer[pos + 3] & 0x1 > 0;
                Some(Ipv6ExtensionHeader::Fragment { identification, offset, more_fragments })
            } else {
                Some(Ipv6ExtensionHeader::Raw { header, data: &self.buffer[pos..(pos + header_length)] })
            }
        } else {
            None
        }
    }
}
