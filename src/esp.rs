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

/// Represents an ESP payload
#[derive(Debug, Copy, Clone)]
pub struct EspPdu<'a> {
    buffer: &'a [u8],
}

/// Contains the inner payload of an [`EspPdu`]
#[derive(Debug, Copy, Clone)]
pub enum Esp<'a> {
    Raw(&'a [u8]),
}

impl<'a> EspPdu<'a> {
    /// Constructs a [`EspPdu`] backed by the provided `buffer`
    pub fn new(buffer: &'a [u8]) -> Result<Self> {
        if buffer.len() < 8 {
            return Err(Error::Truncated);
        }
        Ok(EspPdu { buffer })
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
        &self.buffer[0..8]
    }

    /// Returns an object representing the inner payload of this PDU
    pub fn inner(&'a self) -> Result<Esp<'a>> {
        (*self).into_inner()
    }

    /// Consumes this object and returns an object representing the inner payload of this PDU
    pub fn into_inner(self) -> Result<Esp<'a>> {
        let rest = &self.buffer[self.computed_ihl()..];
        Ok(Esp::Raw(rest))
    }

    pub fn computed_ihl(&'a self) -> usize {
        8
    }

    pub fn spi(&'a self) -> u32 {
        u32::from_be_bytes(self.buffer[0..4].try_into().unwrap())
    }

    pub fn sequence_number(&'a self) -> u32 {
        u32::from_be_bytes(self.buffer[4..8].try_into().unwrap())
    }
}

/// Represents an [`EspPdu`] builder
#[derive(Debug)]
pub struct EspPduBuilder<'a> {
    buffer: &'a mut [u8],
}

impl<'a> EspPduBuilder<'a> {
    /// Constructs an [`EspPduBuilder`] backed by the provided `buffer`
    pub fn new(buffer: &'a mut [u8]) -> Result<Self> {
        if buffer.len() < 8 {
            return Err(Error::Truncated);
        }
        buffer.fill(0);
        let pdu = EspPduBuilder { buffer };
        Ok(pdu)
    }

    pub fn inner(mut self, inner: Esp) -> Result<Self> {
        todo!()
    }

    pub fn build(mut self) -> Result<EspPdu<'a>> {
        EspPdu::new(self.buffer)
    }
}
