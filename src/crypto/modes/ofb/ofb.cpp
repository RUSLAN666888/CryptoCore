// src/crypto/modes/ofb/ofb.cpp
#include "ofb.h"

#include <cstdint>

namespace cryptocore::modes::ofb {

namespace {

using aes128::BLOCK_SIZE;
using aes128::Block;

void xor_bytes(std::uint8_t* dst, const std::uint8_t* a, const std::uint8_t* b, std::size_t n) {
    for (std::size_t i = 0; i < n; ++i) {
        dst[i] = static_cast<std::uint8_t>(a[i] ^ b[i]);
    }
}

/**
 * @brief Advance the OFB keystream block: O = AES(O).
 */
Block next_keystream(const Block& current, const aes128::Key& key) {
    return aes128::encrypt_block(current, key);
}

} // namespace

void encrypt_stream(utils::FileReader& in, utils::FileWriter& out, const aes128::Key& key, const aes128::Block& iv) {
    Block keystream = iv;

    std::uint8_t plain[BLOCK_SIZE];
    std::uint8_t cipher[BLOCK_SIZE];

    while (true) {
        const std::size_t got = in.read(plain, BLOCK_SIZE);
        if (got == 0) {
            break;
        }

        keystream = next_keystream(keystream, key);
        xor_bytes(cipher, plain, keystream.data(), got);
        out.write(cipher, got);

        if (got < BLOCK_SIZE) {
            break;
        }
    }
}

void decrypt_stream(utils::FileReader& in, utils::FileWriter& out, const aes128::Key& key, const aes128::Block& iv) {
    Block keystream = iv;

    std::uint8_t cipher[BLOCK_SIZE];
    std::uint8_t plain[BLOCK_SIZE];

    while (true) {
        const std::size_t got = in.read(cipher, BLOCK_SIZE);
        if (got == 0) {
            break;
        }

        keystream = next_keystream(keystream, key);
        xor_bytes(plain, cipher, keystream.data(), got);
        out.write(plain, got);

        if (got < BLOCK_SIZE) {
            break;
        }
    }
}

} // namespace cryptocore::modes::ofb