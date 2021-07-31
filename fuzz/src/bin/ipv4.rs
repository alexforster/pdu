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

use pdu::*;

pub fn fuzz(data: &[u8]) {
    match Ipv4Pdu::new(&data) {
        Ok(ipv4_pdu) => {
            ipv4_pdu.version();
            ipv4_pdu.ihl();
            ipv4_pdu.computed_ihl();
            ipv4_pdu.dscp();
            ipv4_pdu.ecn();
            ipv4_pdu.total_length();
            ipv4_pdu.identification();
            ipv4_pdu.dont_fragment();
            ipv4_pdu.more_fragments();
            ipv4_pdu.fragment_offset();
            ipv4_pdu.ttl();
            ipv4_pdu.protocol();
            ipv4_pdu.checksum();
            ipv4_pdu.computed_checksum();
            ipv4_pdu.source_address();
            ipv4_pdu.destination_address();
            for option in ipv4_pdu.options() {
                match option {
                    Ipv4Option::Raw { .. } => {
                        continue;
                    }
                }
            }
        }
        Err(_) => {}
    }
}

fn main() {
    loop {
        honggfuzz::fuzz!(|data: &[u8]| {
            fuzz(&data);
        });
    }
}
