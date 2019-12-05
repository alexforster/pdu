/*
   Copyright (c) 2019 Alex Forster <alex@alexforster.com>

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

use crate::{Error, Result};

/// Provides constants representing TCP bitflags
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

/// Represents the payload of a [`TcpPdu`]
#[derive(Debug, Copy, Clone)]
pub enum Tcp<'a> {
    Raw(&'a [u8]),
}

impl<'a> TcpPdu<'a> {
    pub fn new(buffer: &'a [u8]) -> Result<Self> {
        let pdu = TcpPdu { buffer };
        if buffer.len() < 20 || buffer.len() < pdu.computed_data_offset() {
            return Err(Error::Truncated);
        }
        if pdu.computed_data_offset() > 20 {
            let mut position = 20;
            while position < pdu.computed_data_offset() {
                if buffer.len() <= position {
                    return Err(Error::Truncated);
                }
                position += match buffer[position] {
                    0 | 1 => 1usize,
                    _ => {
                        if buffer.len() <= (position + 1) {
                            return Err(Error::Truncated);
                        }
                        if buffer[position + 1] < 2 {
                            return Err(Error::Malformed);
                        }
                        buffer[position + 1] as usize
                    }
                };
            }
            if buffer.len() < position {
                return Err(Error::Truncated);
            }
            if pdu.computed_data_offset() != position {
                return Err(Error::Malformed);
            }
        }
        Ok(pdu)
    }

    pub fn buffer(&'a self) -> &'a [u8] {
        self.buffer
    }

    pub fn as_bytes(&'a self) -> &'a [u8] {
        &self.buffer[0..self.computed_data_offset()]
    }

    pub fn inner(&'a self) -> Result<Tcp<'a>> {
        Ok(Tcp::Raw(&self.buffer[self.computed_data_offset()..]))
    }

    pub fn source_port(&'a self) -> u16 {
        u16::from_be_bytes([self.buffer[0], self.buffer[1]])
    }

    pub fn destination_port(&'a self) -> u16 {
        u16::from_be_bytes([self.buffer[2], self.buffer[3]])
    }

    pub fn sequence_number(&'a self) -> u32 {
        u32::from_be_bytes([self.buffer[4], self.buffer[5], self.buffer[6], self.buffer[7]])
    }

    pub fn acknowledgement_number(&'a self) -> u32 {
        u32::from_be_bytes([self.buffer[8], self.buffer[9], self.buffer[10], self.buffer[11]])
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
        u16::from_be_bytes([self.buffer[14], self.buffer[15]])
    }

    pub fn computed_window_size(&'a self) -> u32 {
        for option in self.options() {
            if let TcpOption::WindowScale { shift } = option {
                return (self.window_size() as u32) << (shift as usize % std::mem::size_of::<u32>()) as u32;
            }
        }
        self.window_size() as u32
    }

    pub fn checksum(&'a self) -> u16 {
        u16::from_be_bytes([self.buffer[16], self.buffer[17]])
    }

    pub fn urgent_pointer(&'a self) -> u16 {
        u16::from_be_bytes([self.buffer[18], self.buffer[19]])
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
    Sack { blocks: &'a [u8] },
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
                _ => self.buffer[pos + 1] as usize,
            };
            self.pos += len;
            match option {
                0 => None,
                1 => Some(TcpOption::NoOp),
                2 => {
                    if len < 4 {
                        None
                    } else {
                        Some(TcpOption::Mss { size: u16::from_be_bytes([self.buffer[pos + 2], self.buffer[pos + 3]]) })
                    }
                }
                3 => {
                    if len < 3 {
                        None
                    } else {
                        Some(TcpOption::WindowScale { shift: self.buffer[pos + 2] })
                    }
                }
                4 => Some(TcpOption::SackPermitted),
                5 => Some(TcpOption::Sack { blocks: &self.buffer[(pos + 2)..(pos + len)] }),
                8 => {
                    if len < 10 {
                        None
                    } else {
                        Some(TcpOption::Timestamp {
                            val: u32::from_be_bytes([
                                self.buffer[pos + 2],
                                self.buffer[pos + 3],
                                self.buffer[pos + 4],
                                self.buffer[pos + 5],
                            ]),
                            ecr: u32::from_be_bytes([
                                self.buffer[pos + 6],
                                self.buffer[pos + 7],
                                self.buffer[pos + 8],
                                self.buffer[pos + 9],
                            ]),
                        })
                    }
                }
                _ => Some(TcpOption::Raw { option, data: &self.buffer[pos..(pos + len)] }),
            }
        } else {
            None
        }
    }
}
