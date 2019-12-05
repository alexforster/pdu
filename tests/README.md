### Test Harness

This library implements a single integration test which parses realistic traffic
samples and then compares the result against Wireshark's parser. New tests can
be created by adding `.pcap` files to the `pcaps/` subdirectory.

**Note:** Wireshark must be installed to run these tests, so that the `tshark`
executable is available in the system path.

*macOS* – `brew install wireshark`<br/>
*Debian* – `apt-get install tshark`<br/>
*RedHat* – `yum install wireshark`<br/>
