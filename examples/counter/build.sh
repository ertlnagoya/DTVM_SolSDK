#!/bin/bash
set -e

# install solidity
# https://docs.soliditylang.org/en/latest/installing-solidity.html

# Determine the build mode
BUILD_MODE=${2:-release}

# Allow building an alternate Solidity file by passing it as the first argument.
SOURCE_FILE=${1:-counter.sol}
BASE_NAME=$(basename "$SOURCE_FILE" .sol)

echo "Building in $BUILD_MODE mode"

YUL2WASM_EXTRA_ARGS="--verbose"

# Respect externally chosen yul2wasm path
if [ -n "$YUL2WASM_PATH" ]; then
    echo "Using YUL2WASM_PATH=$YUL2WASM_PATH"
elif [ "$BUILD_MODE" == "release" ]; then
    YUL2WASM_PATH="../../target/release/yul2wasm"
else
    YUL2WASM_PATH="../../target/debug/yul2wasm"
    YUL2WASM_EXTRA_ARGS="--verbose --debug"
fi

echo "Compiling $SOURCE_FILE"
rm -f *.yul
solc --ir --optimize-yul -o . --overwrite "$SOURCE_FILE"

YUL_FILE=$(ls *.yul 2>/dev/null | head -n 1 || true)
if [[ -z "$YUL_FILE" ]]; then
    echo "ERROR: no .yul file was generated" >&2
    exit 1
fi
echo "Using $YUL_FILE -> ${BASE_NAME}.wasm"
$YUL2WASM_PATH --input "$YUL_FILE" --output "${BASE_NAME}.wasm" $YUL2WASM_EXTRA_ARGS
wasm2wat -o "${BASE_NAME}.wat" "${BASE_NAME}.wasm"
