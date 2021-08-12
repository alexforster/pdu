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

use std::error::Error;
use std::result::Result;

use pdu::*;

#[test]
fn test_builder() -> Result<(), Box<dyn Error>> {
    let mut buffer = [0u8; 1500];

    let ipv4 = Ipv4PduBuilder::new(&mut buffer)?
        .identification(9401)
        .fragment_offset(0)?
        .more_fragments()
        .inner(Ipv4::Tcp(
            TcpPduBuilder::new(&mut [0u8; 1500])?
                .sequence_number(123)
                .acknowledgement_number(321)
                .window_size(46, 0)?
                .build()?,
        ))?
        .build()?;

    Ok(())
}
