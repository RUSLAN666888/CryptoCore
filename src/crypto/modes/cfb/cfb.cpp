// src/crypto/modes/cfb/cfb.cpp
#include "cfb.h"

#include <algorithm>
#include <cstdint>

namespace cryptocore::modes::cfb {

namespace {

using aes128::BLOCK_SIZE;
using aes128::Block;

/**
 * @brief XOR `n` bytes from two buffers into `dst`.
 */
void xor_bytes(std::uint8_t* dst, const std::uint8_t* a, const std::uint8_t* b, std::size_t n) {
    for (std::size_t i = 0; i < n; ++i) {
        dst[i] = static_cast<std::uint8_t>(a[i] ^ b[i]);
    }
}

} // namespace

void encrypt_stream(utils::FileReader& in, utils::FileWriter& out, const aes128::Key& key, const aes128::Block& iv) {
    std::uint8_t prev[BLOCK_SIZE];
    std::copy(iv.begin(), iv.end(), prev);

    std::uint8_t plain[BLOCK_SIZE];
    std::uint8_t cipher[BLOCK_SIZE];

    while (true) {
        const std::size_t got = in.read(plain, BLOCK_SIZE);
        if (got == 0) {
            break;
        }

        // gamma = AES(prev)
        Block gamma_input{};
        std::copy(prev, prev + BLOCK_SIZE, gamma_input.begin());
        const Block gamma = aes128::encrypt_block(gamma_input, key);

        // cipher = plain XOR gamma
        xor_bytes(cipher, plain, gamma.data(), got);
        out.write(cipher, got);

        if (got == BLOCK_SIZE) {
            std::copy(cipher, cipher + BLOCK_SIZE, prev);
        } else {
            break;
        }
    }
}

void decrypt_stream(utils::FileReader& in, utils::FileWriter& out, const aes128::Key& key, const aes128::Block& iv) {
    std::uint8_t prev[BLOCK_SIZE];
    std::copy(iv.begin(), iv.end(), prev);

    std::uint8_t cipher[BLOCK_SIZE];
    std::uint8_t plain[BLOCK_SIZE];

    while (true) {
        const std::size_t got = in.read(cipher, BLOCK_SIZE);
        if (got == 0) {
            break;
        }

        // gamma = AES(prev)
        Block gamma_input{};
        std::copy(prev, prev + BLOCK_SIZE, gamma_input.begin());
        const Block gamma = aes128::encrypt_block(gamma_input, key);

        // plain = cipher XOR gamma
        xor_bytes(plain, cipher, gamma.data(), got);
        out.write(plain, got);

        if (got == BLOCK_SIZE) {
            std::copy(cipher, cipher + BLOCK_SIZE, prev);
        } else {
            break;
        }
    }
}

} // namespace cryptocore::modes::cfb