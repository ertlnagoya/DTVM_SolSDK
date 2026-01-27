#!/bin/bash
set -e

# install solidity
# https://docs.soliditylang.org/en/latest/installing-solidity.html

# Determine the build mode
BUILD_MODE=${1:-release}

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

solc --ir --optimize-yul -o . --overwrite counter.sol

# solc outputs "<ContractName>.yul"; normalize the filename so we can target it explicitly
YUL_FILE="counter.yul"
if [[ ! -f "$YUL_FILE" ]]; then
    if [[ -f Counter.yul ]]; then
        mv Counter.yul counter.yul
    else
        YUL_FILE=$(ls *.yul 2>/dev/null | head -n 1 || true)
        if [[ -n "$YUL_FILE" && "$YUL_FILE" != "counter.yul" ]]; then
            mv "$YUL_FILE" counter.yul
            YUL_FILE="counter.yul"
        fi
    fi
fi
if [[ ! -f "$YUL_FILE" ]]; then
    echo "ERROR: no .yul file was generated" >&2
    exit 1
fi

$YUL2WASM_PATH --input counter.yul --output counter.wasm $YUL2WASM_EXTRA_ARGS
wasm2wat -o counter.wat counter.wasm
