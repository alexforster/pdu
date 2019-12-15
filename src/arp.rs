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

/// Represents an ARP payload
#[derive(Debug, Copy, Clone)]
pub struct ArpPdu<'a> {
    buffer: &'a [u8],
}

impl<'a> ArpPdu<'a> {
    /// Constructs an [`ArpPdu`] backed by the provided `buffer`
    pub fn new(buffer: &'a [u8]) -> Result<Self> {
        if buffer.len() < 12 {
            return Err(Error::Truncated);
        }
        if buffer[4] != 6 {
            // we only support 6-octet hardware addresses
            return Err(Error::Malformed);
        }
        if buffer[5] != 4 {
            // we only support 4-octet protocol addresses
            return Err(Error::Malformed);
        }
        if buffer.len() < 28 {
            return Err(Error::Truncated);
        }
        Ok(ArpPdu { buffer })
    }

    /// Returns a reference to the entire underlying buffer that was provided during construction
    pub fn buffer(&'a self) -> &'a [u8] {
        self.buffer
    }

    /// Returns the slice of the underlying buffer that contains this PDU
    pub fn as_bytes(&'a self) -> &'a [u8] {
        &self.buffer[0..28]
    }

    pub fn hardware_type(&'a self) -> u16 {
        u16::from_be_bytes([self.buffer[0], self.buffer[1]])
    }

    pub fn protocol_type(&'a self) -> u16 {
        u16::from_be_bytes([self.buffer[2], self.buffer[3]])
    }

    pub fn hardware_length(&'a self) -> u8 {
        self.buffer[4]
    }

    pub fn protocol_length(&'a self) -> u8 {
        self.buffer[5]
    }

    pub fn opcode(&'a self) -> u16 {
        u16::from_be_bytes([self.buffer[6], self.buffer[7]])
    }

    pub fn sender_hardware_address(&'a self) -> [u8; 6] {
        let mut sender_hardware_address = [0u8; 6];
        sender_hardware_address.copy_from_slice(&self.buffer[8..14]);
        sender_hardware_address
    }

    pub fn sender_protocol_address(&'a self) -> [u8; 4] {
        let mut sender_protocol_address = [0u8; 4];
        sender_protocol_address.copy_from_slice(&self.buffer[14..18]);
        sender_protocol_address
    }

    pub fn target_hardware_address(&'a self) -> [u8; 6] {
        let mut target_hardware_address = [0u8; 6];
        target_hardware_address.copy_from_slice(&self.buffer[18..24]);
        target_hardware_address
    }

    pub fn target_protocol_address(&'a self) -> [u8; 4] {
        let mut target_protocol_address = [0u8; 4];
        target_protocol_address.copy_from_slice(&self.buffer[24..28]);
        target_protocol_address
    }
}
