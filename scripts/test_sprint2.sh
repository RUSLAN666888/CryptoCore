#!/usr/bin/env bash
#
# Acceptance tests for Sprint 2.
# Covers round-trip and OpenSSL compatibility for all four modes.

set -euo pipefail

# ---- Configuration ----
BINARY="${BINARY:-./../build/custom_kit_Debug/CryptoCore}"
KEY="000102030405060708090a0b0c0d0e0f"
IV="aabbccddeeff00112233445566778899"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

MODES=(cbc cfb ofb ctr)

# ---- Sanity ----
if [[ ! -x "$BINARY" ]]; then
    echo "error: binary not found or not executable: $BINARY" >&2
    echo "build it first: cmake --build build" >&2
    exit 1
fi

if ! command -v openssl > /dev/null; then
    echo "error: openssl not found in PATH" >&2
    exit 1
fi

# ---- Test file ----
printf 'Hello, CryptoCore!\nThis is a test file for Sprint 2.\n' \
    > "$WORK/plain.txt"

# ============================================================
# TEST-1: round-trip for each mode
# ============================================================
echo "TEST-1: round-trip"

for mode in "${MODES[@]}"; do
    "$BINARY" --algorithm aes --mode "$mode" --encrypt \
        --key "$KEY" \
        --input "$WORK/plain.txt" \
        --output "$WORK/$mode.enc"

    "$BINARY" --algorithm aes --mode "$mode" --decrypt \
        --key "$KEY" \
        --input "$WORK/$mode.enc" \
        --output "$WORK/$mode.dec"

    if diff -q "$WORK/plain.txt" "$WORK/$mode.dec" > /dev/null; then
        echo "  [$mode] PASS"
    else
        echo "  [$mode] FAIL: decrypted differs from original" >&2
        exit 1
    fi
done

# ============================================================
# TEST-2: CryptoCore -> OpenSSL
# ============================================================
echo "TEST-2: CryptoCore -> OpenSSL"

for mode in "${MODES[@]}"; do
    # Encrypt with our tool (IV is written at the start).
    "$BINARY" --algorithm aes --mode "$mode" --encrypt \
        --key "$KEY" \
        --input "$WORK/plain.txt" \
        --output "$WORK/$mode.enc"

    # Extract IV and ciphertext.
    dd if="$WORK/$mode.enc" of="$WORK/$mode.iv" bs=16 count=1 2>/dev/null
    dd if="$WORK/$mode.enc" of="$WORK/$mode.ct" bs=16 skip=1 2>/dev/null
    IV_HEX=$(xxd -p "$WORK/$mode.iv" | tr -d '\n')

    # Decrypt with OpenSSL.
    openssl enc "-aes-128-$mode" -d \
        -K "$KEY" -iv "$IV_HEX" \
        -in "$WORK/$mode.ct" \
        -out "$WORK/$mode.openssl.dec"

    if diff -q "$WORK/plain.txt" "$WORK/$mode.openssl.dec" > /dev/null; then
        echo "  [$mode] PASS"
    else
        echo "  [$mode] FAIL: OpenSSL decryption differs" >&2
        exit 1
    fi
done

# ============================================================
# TEST-3: OpenSSL -> CryptoCore
# ============================================================
echo "TEST-3: OpenSSL -> CryptoCore"

for mode in "${MODES[@]}"; do
    # Encrypt with OpenSSL (no IV in the file).
    openssl enc "-aes-128-$mode" \
        -K "$KEY" -iv "$IV" \
        -in "$WORK/plain.txt" \
        -out "$WORK/$mode.openssl.enc"

    # Decrypt with our tool, passing IV explicitly.
    "$BINARY" --algorithm aes --mode "$mode" --decrypt \
        --key "$KEY" --iv "$IV" \
        --input "$WORK/$mode.openssl.enc" \
        --output "$WORK/$mode.ours.dec"

    if diff -q "$WORK/plain.txt" "$WORK/$mode.ours.dec" > /dev/null; then
        echo "  [$mode] PASS"
    else
        echo "  [$mode] FAIL: our decryption differs" >&2
        exit 1
    fi
done

echo
echo "All Sprint 2 acceptance tests passed."