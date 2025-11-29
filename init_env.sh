#!/bin/bash
set -e

echo "=== Step 0: Ensure rustup and set Rust toolchain to 1.84.0 ==="
rustup install 1.84.0
rustup default 1.84.0
rustup target add wasm32-unknown-unknown
echo "Rust version: $(rustc --version)"
echo "Cargo version: $(cargo --version)"

echo "=== Step 1: Install solc (Solidity Compiler) ==="
wget https://github.com/ethereum/solidity/releases/download/v0.8.30/solc-static-linux
chmod +x solc-static-linux
sudo mv solc-static-linux /usr/bin/solc

echo "=== Step 2: Download dependencies ==="
./download_deps.sh

echo "=== Step 3: Set environment variables ==="
export CLANG_RT_LIB=$(pwd)/lib/wasi
export RUSTFLAGS="-L $CLANG_RT_LIB"

echo "=== Step 4: Build stdlib ==="
cd stdlib
make release
cd ..

echo "=== Step 5: Build project with cargo ==="
SKIP_DEV_MAKE=1 cargo build --release

echo "=== Initialization complete! ==="