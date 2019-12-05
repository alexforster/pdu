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

/// Represents an ICMP payload
#[derive(Debug, Copy, Clone)]
pub struct IcmpPdu<'a> {
    buffer: &'a [u8],
}

impl<'a> IcmpPdu<'a> {
    pub fn new(buffer: &'a [u8]) -> Result<Self> {
        if buffer.len() < 8 {
            return Err(Error::Truncated);
        }
        Ok(IcmpPdu { buffer })
    }

    pub fn buffer(&'a self) -> &'a [u8] {
        self.buffer
    }

    pub fn as_bytes(&'a self) -> &'a [u8] {
        &self.buffer[0..8]
    }

    pub fn message_type(&'a self) -> u8 {
        self.buffer[0]
    }

    pub fn message_code(&'a self) -> u8 {
        self.buffer[1]
    }

    pub fn checksum(&'a self) -> u16 {
        u16::from_be_bytes([self.buffer[2], self.buffer[3]])
    }

    pub fn message(&'a self) -> &'a [u8] {
        &self.buffer[8..]
    }
}
