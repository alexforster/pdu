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
    if let Ok(ipv6_pdu) = Ipv6Pdu::new(data) {
        ipv6_pdu.version();
        ipv6_pdu.dscp();
        ipv6_pdu.ecn();
        ipv6_pdu.flow_label();
        ipv6_pdu.payload_length();
        ipv6_pdu.next_header();
        ipv6_pdu.computed_ihl();
        ipv6_pdu.computed_protocol();
        ipv6_pdu.computed_identification();
        ipv6_pdu.computed_more_fragments();
        ipv6_pdu.computed_fragment_offset();
        ipv6_pdu.hop_limit();
        ipv6_pdu.source_address();
        ipv6_pdu.destination_address();
        for extension_header in ipv6_pdu.extension_headers() {
            match extension_header {
                Ipv6ExtensionHeader::Raw { .. } => {
                    continue;
                }
                Ipv6ExtensionHeader::Fragment { .. } => {
                    continue;
                }
            }
        }
    }
}

fn main() {
    loop {
        honggfuzz::fuzz!(|data: &[u8]| {
            fuzz(data);
        });
    }
}
