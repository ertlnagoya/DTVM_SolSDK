#!/bin/bash
set -e

# Determine the build mode
BUILD_MODE=${2:-release}

echo "Building in $BUILD_MODE mode"

YUL2WASM_EXTRA_ARGS="--verbose"

# Set the yul2wasm path based on the build mode, unless already provided
if [[ -z "$YUL2WASM_PATH" ]]; then
    if [ "$BUILD_MODE" == "release" ]; then
        YUL2WASM_PATH="../../target/release/yul2wasm"
    else
        YUL2WASM_PATH="../../target/debug/yul2wasm"
        YUL2WASM_EXTRA_ARGS="--verbose --debug"
    fi
else
    echo "Using YUL2WASM_PATH=$YUL2WASM_PATH"
fi

if [[ -n "$1" ]]; then
    SOURCE_FILE="$1"
    BASE_NAME=$(basename "$SOURCE_FILE" .sol)
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
    exit 0
fi

solc --ir --optimize-yul -o . --overwrite fib.sol
solc --ir --optimize-yul -o . --overwrite fib_recur.sol

$YUL2WASM_PATH --input FibonacciTest.yul --output fib.wasm $YUL2WASM_EXTRA_ARGS
wasm2wat -o fib.wat fib.wasm

$YUL2WASM_PATH --input FibonacciRecurTest.yul --output fib_recur.wasm $YUL2WASM_EXTRA_ARGS
wasm2wat -o fib_recur.wat fib_recur.wasm
