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
    if let Ok(ethernet_pdu) = EthernetPdu::new(data) {
        ethernet_pdu.computed_ihl();
        ethernet_pdu.destination_address();
        ethernet_pdu.source_address();
        ethernet_pdu.ethertype();
        ethernet_pdu.computed_ethertype();
        if let Some(vlan_tags) = ethernet_pdu.vlan_tags() {
            for vlan_tag in vlan_tags {
                vlan_tag.protocol_id;
                vlan_tag.priority_codepoint;
                vlan_tag.drop_eligible;
                vlan_tag.id;
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
