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

/// Represents an ARP payload
#[derive(Debug, Copy, Clone)]
pub struct ArpPdu<'a> {
    buffer: &'a [u8],
}

impl<'a> ArpPdu<'a> {
    /// Constructs an [`ArpPdu`] backed by the provided `buffer`
    pub fn new(buffer: &'a [u8]) -> Result<Self> {
        if buffer.len() < 8 {
            return Err(Error::Truncated);
        }
        let pdu = ArpPdu { buffer };
        if buffer.len() < 8 + (pdu.hardware_length() as usize * 2) + (pdu.protocol_length() as usize * 2) {
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

    /// Returns the slice of the underlying buffer that contains this PDU
    pub fn as_bytes(&'a self) -> &'a [u8] {
        (*self).into_bytes()
    }

    /// Consumes this object and returns the slice of the underlying buffer that contains this PDU
    pub fn into_bytes(self) -> &'a [u8] {
        &self.buffer[0..8 + (self.hardware_length() as usize * 2) + (self.protocol_length() as usize * 2)]
    }

    pub fn hardware_type(&'a self) -> u16 {
        u16::from_be_bytes(self.buffer[0..2].try_into().unwrap())
    }

    pub fn protocol_type(&'a self) -> u16 {
        u16::from_be_bytes(self.buffer[2..4].try_into().unwrap())
    }

    pub fn hardware_length(&'a self) -> u8 {
        self.buffer[4]
    }

    pub fn protocol_length(&'a self) -> u8 {
        self.buffer[5]
    }

    pub fn opcode(&'a self) -> u16 {
        u16::from_be_bytes(self.buffer[6..8].try_into().unwrap())
    }

    pub fn sender_hardware_address(&'a self) -> &'a [u8] {
        let start = 8 as usize;
        let end = start + self.hardware_length() as usize;
        &self.buffer[start..end]
    }

    pub fn sender_protocol_address(&'a self) -> &'a [u8] {
        let start = 8 + self.hardware_length() as usize;
        let end = start + self.protocol_length() as usize;
        &self.buffer[start..end]
    }

    pub fn target_hardware_address(&'a self) -> &'a [u8] {
        let start = 8 + self.hardware_length() as usize + self.protocol_length() as usize;
        let end = start + self.hardware_length() as usize;
        &self.buffer[start..end]
    }

    pub fn target_protocol_address(&'a self) -> &'a [u8] {
        let start = 8 + (self.hardware_length() as usize * 2) + self.protocol_length() as usize;
        let end = start + self.protocol_length() as usize;
        &self.buffer[start..end]
    }
}

/// Represents an [`ArpPdu`] builder
#[derive(Debug)]
pub struct ArpPduBuilder<'a> {
    buffer: &'a mut [u8],
}

impl<'a> ArpPduBuilder<'a> {
    /// Constructs an [`ArpPduBuilder`] backed by the provided `buffer`
    pub fn new(buffer: &'a mut [u8]) -> Result<Self> {
        if buffer.len() < 8 {
            return Err(Error::Truncated);
        }
        buffer.fill(0);
        let pdu = ArpPduBuilder { buffer };
        Ok(pdu)
    }

    pub fn build(mut self) -> Result<ArpPdu<'a>> {
        ArpPdu::new(self.buffer)
    }
}
