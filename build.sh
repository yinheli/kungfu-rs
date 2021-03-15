#!/bin/bash
set -e

cd $(dirname $0)

# rustup target add x86_64-unknown-linux-musl

#  refer https://github.com/johnthagen/min-sized-rust

RUSTFLAGS='-C link-arg=-s' cargo build --target x86_64-unknown-linux-musl --release
strip target/x86_64-unknown-linux-musl/release/kungfu
upx --best --lzma target/x86_64-unknown-linux-musl/release/kungfu
ls -lah target/x86_64-unknown-linux-musl/release/kungfu
