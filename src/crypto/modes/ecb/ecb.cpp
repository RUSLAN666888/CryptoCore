// src/crypto/modes/ecb/ecb.cpp
#include "ecb.h"
#include "padding.h"

#include <algorithm>
#include <stdexcept>
#include <vector>

namespace cryptocore::modes::ecb {

namespace {

using aes128::BLOCK_SIZE;
using aes128::Block;

Block to_block(const std::uint8_t* src, std::size_t n) {
    Block block{};
    std::copy(src, src + n, block.begin());
    return block;
}

} // namespace

void encrypt_stream(utils::FileReader& in, utils::FileWriter& out, const aes128::Key& key) {
    std::uint8_t buffer[BLOCK_SIZE * 2] = {};
    const std::size_t got = in.read(buffer, sizeof(buffer));

    if (got == 0) {
        Block padded{};
        padded.fill(static_cast<std::uint8_t>(BLOCK_SIZE));
        const Block cipher = aes128::encrypt_block(padded, key);
        out.write(cipher.data(), BLOCK_SIZE);
        return;
    }

    if (got < BLOCK_SIZE * 2) {
        const std::vector<std::uint8_t> data(buffer, buffer + got);
        const auto padded = padding::pad(data);
        for (std::size_t i = 0; i < padded.size(); i += BLOCK_SIZE) {
            const Block block = to_block(padded.data() + i, BLOCK_SIZE);
            const Block cipher = aes128::encrypt_block(block, key);
            out.write(cipher.data(), BLOCK_SIZE);
        }
        return;
    }

    while (true) {
        const Block current = to_block(buffer, BLOCK_SIZE);
        const Block cipher = aes128::encrypt_block(current, key);
        out.write(cipher.data(), BLOCK_SIZE);

        std::copy(buffer + BLOCK_SIZE, buffer + BLOCK_SIZE * 2, buffer);

        const std::size_t next_got = in.read(buffer + BLOCK_SIZE, BLOCK_SIZE);
        if (next_got == BLOCK_SIZE) {
            continue;
        }

        const std::vector<std::uint8_t> tail(buffer,
                                             buffer + BLOCK_SIZE + next_got);
        const auto padded = padding::pad(tail);
        for (std::size_t i = 0; i < padded.size(); i += BLOCK_SIZE) {
            const Block block = to_block(padded.data() + i, BLOCK_SIZE);
            const Block c = aes128::encrypt_block(block, key);
            out.write(c.data(), BLOCK_SIZE);
        }
        return;
    }
}

void decrypt_stream(utils::FileReader& in, utils::FileWriter& out, const aes128::Key& key) {
    const std::size_t total = in.size();

    if (total == 0) {
        throw std::runtime_error("ecb: empty ciphertext");
    }
    if (total % BLOCK_SIZE != 0) {
        throw std::runtime_error(
            "ecb: ciphertext size is not a multiple of the block size");
    }

    if (total == BLOCK_SIZE) {
        std::uint8_t buf[BLOCK_SIZE];
        in.read(buf, BLOCK_SIZE);
        const Block cipher = to_block(buf, BLOCK_SIZE);
        const Block plain = aes128::decrypt_block(cipher, key);

        const std::vector<std::uint8_t> plain_vec(plain.begin(), plain.end());
        const auto unpadded = padding::unpad(plain_vec);
        if (!unpadded.empty()) {
            out.write(unpadded.data(), unpadded.size());
        }
        return;
    }

    std::size_t remaining = total - BLOCK_SIZE;

    while (remaining >= BLOCK_SIZE) {
        std::uint8_t buf[BLOCK_SIZE];
        in.read(buf, BLOCK_SIZE);
        const Block cipher = to_block(buf, BLOCK_SIZE);
        const Block plain = aes128::decrypt_block(cipher, key);
        out.write(plain.data(), BLOCK_SIZE);
        remaining -= BLOCK_SIZE;
    }

    std::uint8_t buf[BLOCK_SIZE];
    in.read(buf, BLOCK_SIZE);
    const Block cipher = to_block(buf, BLOCK_SIZE);
    const Block plain = aes128::decrypt_block(cipher, key);

    const std::vector<std::uint8_t> plain_vec(plain.begin(), plain.end());
    const auto unpadded = padding::unpad(plain_vec);
    if (!unpadded.empty()) {
        out.write(unpadded.data(), unpadded.size());
    }
}

} // namespace cryptocore::modes::ecb