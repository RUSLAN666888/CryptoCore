// src/crypto/modes/ctr/ctr.cpp
#include "ctr.h"

#include <cstdint>

namespace cryptocore::modes::ctr {

namespace {

using aes128::BLOCK_SIZE;
using aes128::Block;

/**
 * @brief Increment a 128-bit big-endian counter by one.
 *
 * On overflow (all bytes become zero) the counter wraps; the caller
 * must ensure it never happens in practice.
 */
void increment_counter(Block& counter) {
    for (std::size_t i = BLOCK_SIZE; i-- > 0; ) {
        counter[i] = static_cast<std::uint8_t>(counter[i] + 1);
        if (counter[i] != 0) {
            return;  // no carry
        }
    }
}

void xor_bytes(std::uint8_t* dst, const std::uint8_t* a, const std::uint8_t* b, std::size_t n) {
    for (std::size_t i = 0; i < n; ++i) {
        dst[i] = static_cast<std::uint8_t>(a[i] ^ b[i]);
    }
}

} // namespace

void encrypt_stream(utils::FileReader& in, utils::FileWriter& out, const aes128::Key& key, const aes128::Block& iv) {
    Block counter = iv;

    std::uint8_t plain[BLOCK_SIZE];
    std::uint8_t cipher[BLOCK_SIZE];

    while (true) {
        const std::size_t got = in.read(plain, BLOCK_SIZE);
        if (got == 0) {
            break;
        }

        const Block gamma = aes128::encrypt_block(counter, key);
        increment_counter(counter);

        xor_bytes(cipher, plain, gamma.data(), got);
        out.write(cipher, got);

        if (got < BLOCK_SIZE) {
            break;
        }
    }
}

void decrypt_stream(utils::FileReader& in, utils::FileWriter& out,
                    const aes128::Key& key, const aes128::Block& iv) {
    Block counter = iv;

    std::uint8_t cipher[BLOCK_SIZE];
    std::uint8_t plain[BLOCK_SIZE];

    while (true) {
        const std::size_t got = in.read(cipher, BLOCK_SIZE);
        if (got == 0) {
            break;
        }

        const Block gamma = aes128::encrypt_block(counter, key);
        increment_counter(counter);

        xor_bytes(plain, cipher, gamma.data(), got);
        out.write(plain, got);

        if (got < BLOCK_SIZE) {
            break;
        }
    }
}

} // namespace cryptocore::modes::ctr