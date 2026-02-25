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
#[derive(Debug, Copy, Clone, PartialEq)]
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
        let rest = &self.buffer[self.computed_data_offset()..];
        Ok(Esp::Raw(rest))
    }

    pub fn computed_data_offset(&'a self) -> usize {
        8
    }

    pub fn spi(&'a self) -> u32 {
        u32::from_be_bytes(self.buffer[0..4].try_into().unwrap())
    }

    pub fn sequence_number(&'a self) -> u32 {
        u32::from_be_bytes(self.buffer[4..8].try_into().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_esp_parse_basic() {
        // ESP header: SPI=0x12345678, SeqNum=0x00000001, followed by payload
        let buffer: [u8; 16] = [
            0x12, 0x34, 0x56, 0x78, // SPI
            0x00, 0x00, 0x00, 0x01, // Sequence Number
            0xde, 0xad, 0xbe, 0xef, // Payload (encrypted)
            0xca, 0xfe, 0xba, 0xbe,
        ];

        let esp = EspPdu::new(&buffer).unwrap();
        assert_eq!(esp.spi(), 0x12345678);
        assert_eq!(esp.sequence_number(), 1);
        assert_eq!(esp.computed_data_offset(), 8);
        assert_eq!(esp.as_bytes(), &buffer[0..8]);

        let Esp::Raw(payload) = esp.inner().unwrap();
        assert_eq!(payload, &[0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe]);
    }

    #[test]
    fn test_esp_truncated() {
        // Only 7 bytes - too short for ESP header
        let buffer: [u8; 7] = [0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00];
        assert_eq!(EspPdu::new(&buffer), Err(Error::Truncated));
    }

    #[test]
    fn test_esp_minimum_valid() {
        // Exactly 8 bytes - minimum valid ESP header (no payload)
        let buffer: [u8; 8] = [
            0x00, 0x00, 0x00, 0x01, // SPI = 1
            0x00, 0x00, 0x00, 0x02, // Sequence Number = 2
        ];

        let esp = EspPdu::new(&buffer).unwrap();
        assert_eq!(esp.spi(), 1);
        assert_eq!(esp.sequence_number(), 2);

        let Esp::Raw(payload) = esp.inner().unwrap();
        assert!(payload.is_empty());
    }

    #[test]
    fn test_esp_max_values() {
        // Test with maximum u32 values
        let buffer: [u8; 8] = [
            0xff, 0xff, 0xff, 0xff, // SPI = u32::MAX
            0xff, 0xff, 0xff, 0xff, // Sequence Number = u32::MAX
        ];

        let esp = EspPdu::new(&buffer).unwrap();
        assert_eq!(esp.spi(), u32::MAX);
        assert_eq!(esp.sequence_number(), u32::MAX);
    }
}
