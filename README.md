# CryptoCore

CryptoCore — a minimalistic cryptographic provider written in C++.

Educational project implementing block cipher modes, hash functions,
MACs, and key derivation on top of OpenSSL. Includes both a static
library and a command-line utility.

**Sprint 1: AES-128 in ECB mode with PKCS#7 padding.**

## Dependencies

- C++20 compatible compiler (GCC 10+, Clang 10+, MSVC 2019+)
- CMake 3.16+ (build system)
- OpenSSL 1.1.1+ (development package)
- Git

### Installing dependencies

**Ubuntu / Debian:**

```bash
sudo apt install build-essential cmake libssl-dev git
```

**Fedora:**

```bash
sudo dnf install gcc-c++ cmake openssl-devel git
```

**macOS:**

```bash
brew install cmake openssl git
```

**Windows:**

Install OpenSSL from https://slproweb.com/products/Win32OpenSSL.html
or via vcpkg.

## Building

Two equivalent ways to build.

### With Make (recommended)

```bash
git clone https://github.com/RUSLAN666888/CryptoCore.git
cd CryptoCore
make
```

The binary is produced at `build/CryptoCore`.

### With CMake directly

```bash
git clone https://github.com/RUSLAN666888/CryptoCore.git
cd CryptoCore

cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

The binary is produced at `build/CryptoCore` (or
`build/<config>/CryptoCore` with a multi-config generator).

## Usage

Encrypt a file:

```bash
./build/CryptoCore --algorithm aes --mode ecb --encrypt \
    --key 000102030405060708090a0b0c0d0e0f \
    --input plaintext.txt \
    --output ciphertext.bin
```

Decrypt a file:

```bash
./build/CryptoCore --algorithm aes --mode ecb --decrypt \
    --key 000102030405060708090a0b0c0d0e0f \
    --input ciphertext.bin \
    --output plaintext.txt
```

### Arguments

| Flag          | Description                                              |
|---------------|----------------------------------------------------------|
| `--algorithm` | Cipher algorithm. Currently only `aes`.                  |
| `--mode`      | Cipher mode. Currently only `ecb`.                       |
| `--encrypt`   | Encrypt the input file.                                  |
| `--decrypt`   | Decrypt the input file.                                  |
| `--key`       | 16-byte AES-128 key as a 32-character hex string.        |
| `--input`     | Path to the input file.                                  |
| `--output`    | Path to the output file. Optional; defaults to           |
|               | `<input>.enc` for encryption and `<input>.dec` for       |
|               | decryption.                                              |

Exactly one of `--encrypt` or `--decrypt` must be given.
`--algorithm`, `--mode`, `--key`, and `--input` are required.

## Testing

### Round-trip test (encrypt then decrypt)

```bash
echo "Hello, CryptoCore!" > plain.txt

./build/CryptoCore --algorithm aes --mode ecb --encrypt \
    --key 000102030405060708090a0b0c0d0e0f \
    --input plain.txt --output plain.enc

./build/CryptoCore --algorithm aes --mode ecb --decrypt \
    --key 000102030405060708090a0b0c0d0e0f \
    --input plain.enc --output plain.dec

diff plain.txt plain.dec
# No output — the files are identical.
```

### OpenSSL compatibility

The ciphertext produced by CryptoCore must match the output of
`openssl enc -aes-128-ecb` for the same key and plaintext.

```bash
openssl enc -aes-128-ecb \
    -K 000102030405060708090a0b0c0d0e0f \
    -in plain.txt \
    -out plain.openssl.enc

cmp plain.enc plain.openssl.enc
# No output — the ciphertexts are identical.
```

### Automated acceptance tests

```bash
./scripts/test_sprint.sh
```

The script covers both the round-trip test and OpenSSL compatibility.
It requires a built binary and `openssl` in `PATH`.

### Unit tests

```bash
ctest --test-dir build --output-on-failure
```

Unit tests use GoogleTest, fetched automatically by CMake on the first
configure.

## Project layout

```
CryptoCore/
├── CMakeLists.txt              Top-level build configuration
├── Makefile                    Convenience wrapper around CMake
├── main.cpp                    CLI entry point
├── src/
│   ├── cli/                    Argument parsing
│   ├── crypto/
│   │   ├── aes128/             AES-128 block primitive (OpenSSL wrapper)
│   │   ├── modes/
│   │   │   ├── ecb/            ECB mode
│   │   │   └── padding/        PKCS#7 padding
│   │   └── utils/
│   │       ├── file_io/        Binary file I/O
│   │       └── hex/            Hex conversion
│   └── ...
├── tests/                      Unit tests (GoogleTest)
├── scripts/                    Acceptance test scripts
└── README.md
```

## Status

Sprint 1 complete:

- AES-128 block encryption and decryption via OpenSSL EVP
- ECB mode with PKCS#7 padding
- Command-line interface with argument validation
- Binary file I/O
- Unit tests and OpenSSL compatibility test

Upcoming sprints will add CBC, CFB, OFB, and CTR modes, a CSPRNG,
SHA-256, HMAC, GCM, and PBKDF2.

## License

MIT License. See [LICENSE](LICENSE).
