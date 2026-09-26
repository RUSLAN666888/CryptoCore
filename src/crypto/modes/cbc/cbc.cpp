// src/crypto/modes/cbc/cbc.cpp
#include "cbc.h"
#include "padding.h"

#include <algorithm>
#include <stdexcept>
#include <vector>

namespace cryptocore::modes::cbc {

namespace {

using aes128::BLOCK_SIZE;
using aes128::Block;

/**
 * @brief XOR two blocks byte by byte.
 */
Block xor_blocks(const Block& a, const Block& b) {
    Block result{};
    for (std::size_t i = 0; i < BLOCK_SIZE; ++i) {
        result[i] = static_cast<std::uint8_t>(a[i] ^ b[i]);
    }
    return result;
}

/**
 * @brief Encrypt one block in CBC: C = AES(P XOR prev).
 */
Block encrypt_one(const Block& plain, const Block& prev, const aes128::Key& key) {
    return aes128::encrypt_block(xor_blocks(plain, prev), key);
}

/**
 * @brief Decrypt one block in CBC: P = AES^-1(C) XOR prev.
 */
Block decrypt_one(const Block& cipher, const Block& prev, const aes128::Key& key) {
    return xor_blocks(aes128::decrypt_block(cipher, key), prev);
}

/**
 * @brief Copy `n` bytes from `src` into a Block, zero-padding the rest.
 */
Block to_block(const std::uint8_t* src, std::size_t n) {
    Block block{};
    std::copy(src, src + n, block.begin());
    return block;
}

} // namespace

void encrypt_stream(utils::FileReader& in, utils::FileWriter& out, const aes128::Key& key, const aes128::Block& iv) {
    std::uint8_t buffer[BLOCK_SIZE * 2] = {};
    const std::size_t got = in.read(buffer, sizeof(buffer));

    // Empty input: one block of PKCS#7 padding (0x10 * 16).
    if (got == 0) {
        Block padded{};
        padded.fill(static_cast<std::uint8_t>(BLOCK_SIZE));
        const Block cipher = encrypt_one(padded, iv, key);
        out.write(cipher.data(), BLOCK_SIZE);
        return;
    }

    // Input fits in fewer than 2 blocks: pad and encrypt once.
    if (got < BLOCK_SIZE * 2) {
        const std::vector<std::uint8_t> data(buffer, buffer + got);
        const auto padded = padding::pad(data);

        Block prev = iv;
        for (std::size_t i = 0; i < padded.size(); i += BLOCK_SIZE) {
            const Block block = to_block(padded.data() + i, BLOCK_SIZE);
            const Block cipher = encrypt_one(block, prev, key);
            out.write(cipher.data(), BLOCK_SIZE);
            prev = cipher;
        }
        return;
    }

    // Two full blocks in hand. First one is not the last.
    Block prev = iv;

    while (true) {
        // Encrypt buffer[0..15].
        const Block current = to_block(buffer, BLOCK_SIZE);
        const Block cipher = encrypt_one(current, prev, key);
        out.write(cipher.data(), BLOCK_SIZE);
        prev = cipher;

        // Shift the second block to the front.
        std::copy(buffer + BLOCK_SIZE, buffer + BLOCK_SIZE * 2, buffer);

        // Read another block into the second half.
        const std::size_t next_got = in.read(buffer + BLOCK_SIZE, BLOCK_SIZE);

        if (next_got == BLOCK_SIZE) {
            continue;  // have two full blocks again
        }

        // Last block(s): combine remainder, pad, encrypt.
        const std::vector<std::uint8_t> tail(buffer, buffer + BLOCK_SIZE + next_got);
        const auto padded = padding::pad(tail);

        for (std::size_t i = 0; i < padded.size(); i += BLOCK_SIZE) {
            const Block block = to_block(padded.data() + i, BLOCK_SIZE);
            const Block c = encrypt_one(block, prev, key);
            out.write(c.data(), BLOCK_SIZE);
            prev = c;
        }
        return;
    }
}

void decrypt_stream(utils::FileReader& in, utils::FileWriter& out, const aes128::Key& key, const aes128::Block& iv) {
    const std::size_t total = in.size();

    if (total == 0) {
        throw std::runtime_error("cbc: empty ciphertext");
    }
    if (total % BLOCK_SIZE != 0) {
        throw std::runtime_error("cbc: ciphertext size is not a multiple of the block size");
    }

    // If there is only one block, it is the last one.
    if (total == BLOCK_SIZE) {
        std::uint8_t buf[BLOCK_SIZE];
        in.read(buf, BLOCK_SIZE);
        const Block cipher = to_block(buf, BLOCK_SIZE);
        const Block plain = decrypt_one(cipher, iv, key);

        const std::vector<std::uint8_t> plain_vec(plain.begin(), plain.end());
        const auto unpadded = padding::unpad(plain_vec);
        if (!unpadded.empty()) {
            out.write(unpadded.data(), unpadded.size());
        }
        return;
    }

    // Read all but the last block as full blocks.
    std::size_t remaining = total - BLOCK_SIZE;
    Block prev = iv;

    while (remaining >= BLOCK_SIZE) {
        std::uint8_t buf[BLOCK_SIZE];
        in.read(buf, BLOCK_SIZE);
        const Block cipher = to_block(buf, BLOCK_SIZE);

        const Block plain = decrypt_one(cipher, prev, key);
        out.write(plain.data(), BLOCK_SIZE);

        prev = cipher;
        remaining -= BLOCK_SIZE;
    }

    // Last block: decrypt, unpad, write remainder.
    std::uint8_t buf[BLOCK_SIZE];
    in.read(buf, BLOCK_SIZE);
    const Block cipher = to_block(buf, BLOCK_SIZE);
    const Block plain = decrypt_one(cipher, prev, key);

    const std::vector<std::uint8_t> plain_vec(plain.begin(), plain.end());
    const auto unpadded = padding::unpad(plain_vec);
    if (!unpadded.empty()) {
        out.write(unpadded.data(), unpadded.size());
    }
}

} // namespace cryptocore::modes::cbc