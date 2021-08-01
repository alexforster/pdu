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

use crate::{Error, Result};

/// Provides constants representing various EtherTypes supported by this crate
#[allow(non_snake_case)]
pub mod EtherType {
    pub const ARP: u16 = 0x0806;
    pub const IPV4: u16 = 0x0800;
    pub const IPV6: u16 = 0x86DD;
    pub const DOT1Q: u16 = 0x8100;
    pub const QINQ: u16 = 0x88A8;
    pub const TEB: u16 = 0x6558;
}

/// Represents an Ethernet header and payload
#[derive(Debug, Copy, Clone)]
pub struct EthernetPdu<'a> {
    buffer: &'a [u8],
}

/// Contains the inner payload of an [`EthernetPdu`]
#[derive(Debug, Copy, Clone)]
pub enum Ethernet<'a> {
    Raw(&'a [u8]),
    Arp(super::ArpPdu<'a>),
    Ipv4(super::Ipv4Pdu<'a>),
    Ipv6(super::Ipv6Pdu<'a>),
}

impl<'a> EthernetPdu<'a> {
    /// Constructs an [`EthernetPdu`] backed by the provided `buffer`
    pub fn new(buffer: &'a [u8]) -> Result<Self> {
        if buffer.len() < 12 {
            return Err(Error::Truncated);
        }
        let mut pos = 12;
        loop {
            if buffer.len() < pos + 2 {
                return Err(Error::Truncated);
            }
            let ethertype = u16::from_be_bytes(buffer[pos..pos + 2].try_into().unwrap());
            if ethertype != EtherType::DOT1Q && ethertype != EtherType::QINQ {
                break;
            }
            if buffer.len() < pos + 4 {
                return Err(Error::Truncated);
            }
            pos += 4;
        }
        let pdu = EthernetPdu { buffer };
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
        (*self).into_bytes()
    }

    /// Consumes this object and returns the slice of the underlying buffer that contains the header part of this PDU
    pub fn into_bytes(self) -> &'a [u8] {
        &self.buffer[0..self.computed_ihl()]
    }

    /// Returns an object representing the inner payload of this PDU
    pub fn inner(&'a self) -> Result<Ethernet<'a>> {
        (*self).into_inner()
    }

    /// Consumes this object and returns an object representing the inner payload of this PDU
    pub fn into_inner(self) -> Result<Ethernet<'a>> {
        let rest = &self.buffer[self.computed_ihl()..];
        Ok(match self.computed_ethertype() {
            EtherType::ARP => Ethernet::Arp(super::ArpPdu::new(rest)?),
            EtherType::IPV4 => Ethernet::Ipv4(super::Ipv4Pdu::new(rest)?),
            EtherType::IPV6 => Ethernet::Ipv6(super::Ipv6Pdu::new(rest)?),
            _ => Ethernet::Raw(rest),
        })
    }

    pub fn computed_ihl(&'a self) -> usize {
        let mut pos = 12;
        loop {
            let ethertype = u16::from_be_bytes(self.buffer[pos..pos + 2].try_into().unwrap());
            if ethertype != EtherType::DOT1Q && ethertype != EtherType::QINQ {
                break;
            }
            pos += 4;
        }
        pos
    }

    pub fn source_address(&'a self) -> [u8; 6] {
        let mut source_address = [0u8; 6];
        source_address.copy_from_slice(&self.buffer[6..12]);
        source_address
    }

    pub fn destination_address(&'a self) -> [u8; 6] {
        let mut destination_address = [0u8; 6];
        destination_address.copy_from_slice(&self.buffer[0..6]);
        destination_address
    }

    pub fn ethertype(&'a self) -> u16 {
        u16::from_be_bytes(self.buffer[12..14].try_into().unwrap())
    }

    pub fn computed_ethertype(&'a self) -> u16 {
        let mut pos = 12;
        loop {
            let ethertype = u16::from_be_bytes(self.buffer[pos..pos + 2].try_into().unwrap());
            if ethertype != EtherType::DOT1Q && ethertype != EtherType::QINQ {
                return ethertype;
            }
            pos += 4;
        }
    }

    pub fn vlan_tags(&'a self) -> Option<VlanTagIterator<'a>> {
        match self.ethertype() {
            EtherType::DOT1Q | EtherType::QINQ => Some(VlanTagIterator { buffer: self.buffer, pos: 12, eol: false }),
            _ => None,
        }
    }
}

/// Represents a VLAN tag
#[derive(Debug, Copy, Clone)]
pub struct VlanTag {
    pub protocol_id: u16,
    pub priority_codepoint: u8,
    pub drop_eligible: bool,
    pub id: u16,
}

#[derive(Debug, Copy, Clone)]
pub struct VlanTagIterator<'a> {
    buffer: &'a [u8],
    pos: usize,
    eol: bool,
}

impl<'a> Iterator for VlanTagIterator<'a> {
    type Item = VlanTag;

    fn next(&mut self) -> Option<Self::Item> {
        if self.eol {
            return None;
        }
        let tpid = u16::from_be_bytes(self.buffer[self.pos..self.pos + 2].try_into().unwrap());
        if tpid != EtherType::DOT1Q && tpid != EtherType::QINQ {
            return None;
        }
        if tpid == EtherType::DOT1Q {
            self.eol = true;
        }
        let vlan_tag = VlanTag {
            protocol_id: tpid,
            priority_codepoint: (self.buffer[self.pos + 2] & 0xE0) >> 5,
            drop_eligible: ((self.buffer[self.pos + 2] & 0x10) >> 4) > 0,
            id: u16::from_be_bytes([self.buffer[self.pos + 2] & 0x0F, self.buffer[self.pos + 3]]),
        };
        self.pos += 4;
        Some(vlan_tag)
    }
}
