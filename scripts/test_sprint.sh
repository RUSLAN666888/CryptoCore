#!/usr/bin/env bash
#
# Acceptance tests for Sprint 1 (AES-128 ECB).
# Covers round-trip and OpenSSL compatibility.

set -euo pipefail

# ---- Configuration ----
BINARY="${BINARY:-./../build/custom_kit_Debug/CryptoCore}"
KEY="000102030405060708090a0b0c0d0e0f"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

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

# ---- round-trip ----
echo "TEST-1: round-trip (encrypt then decrypt)"

printf 'Hello, CryptoCore!\nThis is a test file for ECB mode.\n' \
    > "$WORK/plain.txt"

"$BINARY" --algorithm aes --mode ecb --encrypt \
    --key "$KEY" \
    --input "$WORK/plain.txt" \
    --output "$WORK/cipher.bin"

"$BINARY" --algorithm aes --mode ecb --decrypt \
    --key "$KEY" \
    --input "$WORK/cipher.bin" \
    --output "$WORK/decrypted.txt"

if diff -q "$WORK/plain.txt" "$WORK/decrypted.txt" > /dev/null; then
    echo "  PASS"
else
    echo "  FAIL: decrypted file differs from original" >&2
    exit 1
fi

# ---- OpenSSL compatibility ----
echo "TEST-2: OpenSSL compatibility"

openssl enc -aes-128-ecb -K "$KEY" \
    -in "$WORK/plain.txt" \
    -out "$WORK/cipher.openssl.bin"

if cmp -s "$WORK/cipher.bin" "$WORK/cipher.openssl.bin"; then
    echo "  PASS"
else
    echo "  FAIL: our ciphertext differs from OpenSSL" >&2
    exit 1
fi

echo
echo "All Sprint 1 acceptance tests passed."