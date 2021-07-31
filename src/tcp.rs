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

/// Provides constants representing the set of TCP bitflags
#[allow(non_snake_case)]
pub mod TcpFlag {
    pub const FIN: u8 = 1;
    pub const SYN: u8 = 2;
    pub const RST: u8 = 4;
    pub const PSH: u8 = 8;
    pub const ACK: u8 = 16;
    pub const URG: u8 = 32;
    pub const ECN: u8 = 64;
    pub const CWR: u8 = 128;
}

/// Represents a TCP header and payload
#[derive(Debug, Copy, Clone)]
pub struct TcpPdu<'a> {
    buffer: &'a [u8],
}

/// Contains the inner payload of a [`TcpPdu`]
#[derive(Debug, Copy, Clone)]
pub enum Tcp<'a> {
    Raw(&'a [u8]),
}

impl<'a> TcpPdu<'a> {
    /// Constructs a [`TcpPdu`] backed by the provided `buffer`
    pub fn new(buffer: &'a [u8]) -> Result<Self> {
        let pdu = TcpPdu { buffer };
        if buffer.len() < 20 || buffer.len() < pdu.computed_data_offset() {
            return Err(Error::Truncated);
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
        (*self).into_bytes()
    }

    /// Consumes this object and returns the slice of the underlying buffer that contains the header part of this PDU
    pub fn into_bytes(self) -> &'a [u8] {
        &self.buffer[0..self.computed_data_offset()]
    }

    /// Returns an object representing the inner payload of this PDU
    pub fn inner(&'a self) -> Result<Tcp<'a>> {
        (*self).into_inner()
    }

    /// Consumes this object and returns an object representing the inner payload of this PDU
    pub fn into_inner(self) -> Result<Tcp<'a>> {
        let rest = &self.buffer[self.computed_data_offset()..];
        Ok(Tcp::Raw(rest))
    }

    pub fn source_port(&'a self) -> u16 {
        u16::from_be_bytes(self.buffer[0..2].try_into().unwrap())
    }

    pub fn destination_port(&'a self) -> u16 {
        u16::from_be_bytes(self.buffer[2..4].try_into().unwrap())
    }

    pub fn sequence_number(&'a self) -> u32 {
        u32::from_be_bytes(self.buffer[4..8].try_into().unwrap())
    }

    pub fn acknowledgement_number(&'a self) -> u32 {
        u32::from_be_bytes(self.buffer[8..12].try_into().unwrap())
    }

    pub fn data_offset(&'a self) -> u8 {
        self.buffer[12] >> 4
    }

    pub fn computed_data_offset(&'a self) -> usize {
        self.data_offset() as usize * 4
    }

    pub fn flags(&'a self) -> u8 {
        self.buffer[13]
    }

    pub fn fin(&'a self) -> bool {
        self.flags() & 0x1 != 0
    }

    pub fn syn(&'a self) -> bool {
        self.flags() & 0x2 != 0
    }

    pub fn rst(&'a self) -> bool {
        self.flags() & 0x4 != 0
    }

    pub fn psh(&'a self) -> bool {
        self.flags() & 0x8 != 0
    }

    pub fn ack(&'a self) -> bool {
        self.flags() & 0x10 != 0
    }

    pub fn urg(&'a self) -> bool {
        self.flags() & 0x20 != 0
    }

    pub fn ecn(&'a self) -> bool {
        self.flags() & 0x40 != 0
    }

    pub fn cwr(&'a self) -> bool {
        self.flags() & 0x80 != 0
    }

    pub fn window_size(&'a self) -> u16 {
        u16::from_be_bytes(self.buffer[14..16].try_into().unwrap())
    }

    pub fn computed_window_size(&'a self, shift: u8) -> u32 {
        (self.window_size() as u32) << (shift as u32)
    }

    pub fn checksum(&'a self) -> u16 {
        u16::from_be_bytes(self.buffer[16..18].try_into().unwrap())
    }

    pub fn computed_checksum(&'a self, ip: &crate::Ip) -> u16 {
        match ip {
            crate::Ip::Ipv4(ipv4) => util::checksum(&[
                ipv4.source_address().as_ref(),
                ipv4.destination_address().as_ref(),
                [0x00, ipv4.protocol()].as_ref(),
                (ipv4.total_length() as usize - ipv4.computed_ihl()).to_be_bytes().as_ref(),
                &self.buffer[0..16],
                &self.buffer[18..],
            ]),
            crate::Ip::Ipv6(ipv6) => util::checksum(&[
                ipv6.source_address().as_ref(),
                ipv6.destination_address().as_ref(),
                (ipv6.payload_length() as u32).to_be_bytes().as_ref(),
                [0x0, 0x0, 0x0, ipv6.computed_protocol()].as_ref(),
                &self.buffer[0..16],
                &self.buffer[18..],
            ]),
        }
    }

    pub fn urgent_pointer(&'a self) -> u16 {
        u16::from_be_bytes(self.buffer[18..20].try_into().unwrap())
    }

    pub fn options(&'a self) -> TcpOptionIterator<'a> {
        TcpOptionIterator { buffer: self.buffer, pos: 20, data_offset: self.computed_data_offset() }
    }
}

/// Represents a TCP option
#[derive(Debug, Copy, Clone)]
pub enum TcpOption<'a> {
    Raw { option: u8, data: &'a [u8] },
    NoOp,
    Mss { size: u16 },
    WindowScale { shift: u8 },
    SackPermitted,
    Sack { blocks: [Option<(u32, u32)>; 4] },
    Timestamp { val: u32, ecr: u32 },
}

#[derive(Debug, Copy, Clone)]
pub struct TcpOptionIterator<'a> {
    buffer: &'a [u8],
    pos: usize,
    data_offset: usize,
}

impl<'a> Iterator for TcpOptionIterator<'a> {
    type Item = TcpOption<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos < self.data_offset {
            let pos = self.pos;
            let option = self.buffer[pos];
            let len = match option {
                0 | 1 => 1usize,
                _ => {
                    if self.data_offset <= (pos + 1) {
                        return None;
                    }
                    let len = self.buffer[pos + 1] as usize;
                    if len < 2 {
                        return None;
                    }
                    len
                }
            };
            if self.data_offset < (pos + len) {
                return None;
            }
            self.pos += len;
            match option {
                0 => None,
                1 => Some(TcpOption::NoOp),
                2 if len == 4 => {
                    Some(TcpOption::Mss { size: u16::from_be_bytes(self.buffer[pos + 2..pos + 4].try_into().unwrap()) })
                }
                3 if len == 3 => Some(TcpOption::WindowScale { shift: self.buffer[pos + 2] }),
                4 => Some(TcpOption::SackPermitted),
                5 if len == 10 => Some(TcpOption::Sack {
                    blocks: [
                        Some((
                            u32::from_be_bytes(self.buffer[pos + 2..pos + 6].try_into().unwrap()),
                            u32::from_be_bytes(self.buffer[pos + 6..pos + 10].try_into().unwrap()),
                        )),
                        None,
                        None,
                        None,
                    ],
                }),
                5 if len == 18 => Some(TcpOption::Sack {
                    blocks: [
                        Some((
                            u32::from_be_bytes(self.buffer[pos + 2..pos + 6].try_into().unwrap()),
                            u32::from_be_bytes(self.buffer[pos + 6..pos + 10].try_into().unwrap()),
                        )),
                        Some((
                            u32::from_be_bytes(self.buffer[pos + 10..pos + 14].try_into().unwrap()),
                            u32::from_be_bytes(self.buffer[pos + 14..pos + 18].try_into().unwrap()),
                        )),
                        None,
                        None,
                    ],
                }),
                5 if len == 26 => Some(TcpOption::Sack {
                    blocks: [
                        Some((
                            u32::from_be_bytes(self.buffer[pos + 2..pos + 6].try_into().unwrap()),
                            u32::from_be_bytes(self.buffer[pos + 6..pos + 10].try_into().unwrap()),
                        )),
                        Some((
                            u32::from_be_bytes(self.buffer[pos + 10..pos + 14].try_into().unwrap()),
                            u32::from_be_bytes(self.buffer[pos + 14..pos + 18].try_into().unwrap()),
                        )),
                        Some((
                            u32::from_be_bytes(self.buffer[pos + 18..pos + 22].try_into().unwrap()),
                            u32::from_be_bytes(self.buffer[pos + 22..pos + 26].try_into().unwrap()),
                        )),
                        None,
                    ],
                }),
                5 if len == 34 => Some(TcpOption::Sack {
                    blocks: [
                        Some((
                            u32::from_be_bytes(self.buffer[pos + 2..pos + 6].try_into().unwrap()),
                            u32::from_be_bytes(self.buffer[pos + 6..pos + 10].try_into().unwrap()),
                        )),
                        Some((
                            u32::from_be_bytes(self.buffer[pos + 10..pos + 14].try_into().unwrap()),
                            u32::from_be_bytes(self.buffer[pos + 14..pos + 18].try_into().unwrap()),
                        )),
                        Some((
                            u32::from_be_bytes(self.buffer[pos + 18..pos + 22].try_into().unwrap()),
                            u32::from_be_bytes(self.buffer[pos + 22..pos + 26].try_into().unwrap()),
                        )),
                        Some((
                            u32::from_be_bytes(self.buffer[pos + 26..pos + 30].try_into().unwrap()),
                            u32::from_be_bytes(self.buffer[pos + 30..pos + 34].try_into().unwrap()),
                        )),
                    ],
                }),
                8 if len == 10 => Some(TcpOption::Timestamp {
                    val: u32::from_be_bytes(self.buffer[pos + 2..pos + 6].try_into().unwrap()),
                    ecr: u32::from_be_bytes(self.buffer[pos + 6..pos + 10].try_into().unwrap()),
                }),
                _ => Some(TcpOption::Raw { option, data: &self.buffer[pos..(pos + len)] }),
            }
        } else {
            None
        }
    }
}
