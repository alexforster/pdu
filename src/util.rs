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

pub fn checksum<I, J>(spans: I) -> u16
where
    I: IntoIterator<Item = J>,
    J: AsRef<[u8]>,
{
    let mut accum = 0u32;

    for span in spans.into_iter() {
        accum += sum(span.as_ref()) as u32;
    }

    accum = (accum >> 16) + (accum & 0xffff);
    !(((accum >> 16) as u16) + (accum as u16))
}

fn sum(mut buffer: &[u8]) -> u16 {
    let mut accum = 0;

    while buffer.len() >= 32 {
        let mut b = &buffer[..32];
        while b.len() >= 2 {
            accum += u16::from_be_bytes(b[0..2].try_into().unwrap()) as u32;
            b = &b[2..];
        }
        buffer = &buffer[32..];
    }

    while buffer.len() >= 2 {
        accum += u16::from_be_bytes(buffer[0..2].try_into().unwrap()) as u32;
        buffer = &buffer[2..];
    }

    if let Some(&value) = buffer.first() {
        accum += (value as u32) << 8;
    }

    accum = (accum >> 16) + (accum & 0xffff);
    ((accum >> 16) as u16) + (accum as u16)
}
