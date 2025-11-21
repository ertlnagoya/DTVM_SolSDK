#!/bin/bash
set -e

echo "=== Step 1: Install solc (Solidity Compiler) ==="
apt-get update
apt-get install -y software-properties-common
add-apt-repository -y ppa:ethereum/ethereum
apt-get update
apt-get install -y solc

echo "=== Step 2: Download dependencies ==="
./download_deps.sh

echo "=== Step 3: Set environment variables ==="
export CLANG_RT_LIB=$(pwd)/lib/wasi
export RUSTFLAGS="-L $CLANG_RT_LIB"

echo "=== Step 4: Generate .cargo/config.toml ==="
mkdir -p .cargo
cat <<EOF > .cargo/config.toml
[build]
target = "wasm32-unknown-unknown"

[target.wasm32-unknown-unknown]
rustflags = [
  "-L", "/workspaces/DTVM_SolSDK/lib/wasi",
  "-Clinker=wasm-ld"
]
EOF

echo "=== Step 5: Build stdlib ==="
cd stdlib
make release
cd ..

echo "=== Step 6: Build project with cargo ==="
SKIP_DEV_MAKE=1 cargo build --release

echo "=== Initialization complete! ==="