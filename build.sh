#!/bin/bash

RUSTFLAGS='-C target-feature=+crt-static' \
cargo build --release --target x86_64-pc-windows-gnu

RUSTFLAGS='-C target-feature=+crt-static' \
cargo build --release --target aarch64-pc-windows-gnu
