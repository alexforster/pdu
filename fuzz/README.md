### Fuzzing Harness

This library uses Google's [Honggfuzz](https://google.github.io/honggfuzz/) to
verify correct behavior in the face of invalid input.

**Note:** you must first `cargo install honggfuzz` so that the `cargo hfuzz`
subcommand is available.

To fuzz this library, change into this working directory and then run...

`RUSTFLAGS="-C link-dead-code" cargo hfuzz run <name>`

...where *name* is one of `arp`, `ethernet`, `gre`, `icmp`, `ipv4`, `ipv6`,
`tcp`, or `udp`.
