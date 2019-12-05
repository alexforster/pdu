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

use pdu::*;

pub fn fuzz(data: &[u8]) {
    match TcpPdu::new(&data) {
        Ok(tcp_pdu) => {
            tcp_pdu.source_port();
            tcp_pdu.destination_port();
            tcp_pdu.sequence_number();
            tcp_pdu.acknowledgement_number();
            tcp_pdu.data_offset();
            tcp_pdu.computed_data_offset();
            tcp_pdu.flags();
            tcp_pdu.fin();
            tcp_pdu.syn();
            tcp_pdu.rst();
            tcp_pdu.psh();
            tcp_pdu.ack();
            tcp_pdu.urg();
            tcp_pdu.ecn();
            tcp_pdu.cwr();
            tcp_pdu.window_size();
            tcp_pdu.computed_window_size();
            tcp_pdu.checksum();
            tcp_pdu.urgent_pointer();
            for option in tcp_pdu.options() {
                match option {
                    TcpOption::Raw { option, data } => {
                        continue;
                    }
                    TcpOption::NoOp => {
                        continue;
                    }
                    TcpOption::Mss(mss) => {
                        continue;
                    }
                    TcpOption::WindowScale(wscale) => {
                        continue;
                    }
                    TcpOption::SackPermitted => {
                        continue;
                    }
                    TcpOption::Sack(blocks) => {
                        continue;
                    }
                    TcpOption::Timestamp { val, ecr } => {
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
