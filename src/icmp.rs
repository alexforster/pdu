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

/// Represents an ICMP payload
#[derive(Debug, Copy, Clone)]
pub struct IcmpPdu<'a> {
    buffer: &'a [u8],
}

/// Contains the inner payload of an [`IcmpPdu`]
#[derive(Debug, Copy, Clone)]
pub enum Icmp<'a> {
    Raw(&'a [u8]),
}

impl<'a> IcmpPdu<'a> {
    /// Constructs a [`IcmpPdu`] backed by the provided `buffer`
    pub fn new(buffer: &'a [u8]) -> Result<Self> {
        if buffer.len() < 8 {
            return Err(Error::Truncated);
        }
        Ok(IcmpPdu { buffer })
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
    pub fn inner(&'a self) -> Result<Icmp<'a>> {
        (*self).into_inner()
    }

    /// Consumes this object and returns an object representing the inner payload of this PDU
    pub fn into_inner(self) -> Result<Icmp<'a>> {
        let rest = &self.buffer[self.computed_ihl()..];
        Ok(Icmp::Raw(rest))
    }

    pub fn computed_ihl(&'a self) -> usize {
        8
    }

    pub fn message_type(&'a self) -> u8 {
        self.buffer[0]
    }

    pub fn message_code(&'a self) -> u8 {
        self.buffer[1]
    }

    pub fn checksum(&'a self) -> u16 {
        u16::from_be_bytes(self.buffer[2..4].try_into().unwrap())
    }

    pub fn computed_checksum(&'a self, ip: &crate::Ip) -> u16 {
        match ip {
            crate::Ip::Ipv4(_) => util::checksum(&[&self.buffer[0..2], &self.buffer[4..]]),
            crate::Ip::Ipv6(ipv6) => util::checksum(&[
                ipv6.source_address().as_ref(),
                ipv6.destination_address().as_ref(),
                (ipv6.payload_length() as u32).to_be_bytes().as_ref(),
                [0x0, 0x0, 0x0, ipv6.computed_protocol()].as_ref(),
                &self.buffer[0..2],
                &self.buffer[4..],
            ]),
        }
    }
}
