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
    match UdpPdu::new(&data) {
        Ok(udp_pdu) => {
            udp_pdu.source_port();
            udp_pdu.destination_port();
            udp_pdu.length();
            udp_pdu.checksum();
            let ip = Ip::Ipv4(
                Ipv4Pdu::new(&[
                    0x45u8, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                ])
                .unwrap(),
            );
            udp_pdu.computed_checksum(&ip);
            let ip = Ip::Ipv6(
                Ipv6Pdu::new(&[
                    0x60u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ])
                .unwrap(),
            );
            udp_pdu.computed_checksum(&ip);
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
