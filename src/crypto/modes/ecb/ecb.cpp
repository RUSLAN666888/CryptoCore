// src/modes/ecb.cpp
#include "ecb.h"
#include "padding.h"

#include <stdexcept>

namespace cryptocore::modes::ecb {

namespace {

using aes128::BLOCK_SIZE;
using aes128::Block;

/**
 * @brief Copy 16 bytes from src[start..start+16) into a Block.
 */
Block read_block(const std::vector<std::uint8_t>& src, std::size_t start) {
    Block block{};
    for (std::size_t i = 0; i < BLOCK_SIZE; ++i) {
        block[i] = src[start + i];
    }
    return block;
}

/**
 * @brief Append a Block to the end of a byte vector.
 */
void append_block(std::vector<std::uint8_t>& dst, const Block& block) {
    dst.insert(dst.end(), block.begin(), block.end());
}

} // namespace

std::vector<std::uint8_t> encrypt(const std::vector<std::uint8_t>& data, const aes128::Key& key) {
    const std::vector<std::uint8_t> padded = padding::pad(data);

    std::vector<std::uint8_t> ciphertext;
    ciphertext.reserve(padded.size());

    for (std::size_t i = 0; i < padded.size(); i += BLOCK_SIZE) {
        const Block plain_block = read_block(padded, i);
        const Block cipher_block = aes128::encrypt_block(plain_block, key);
        append_block(ciphertext, cipher_block);
    }

    return ciphertext;
}

std::vector<std::uint8_t> decrypt(const std::vector<std::uint8_t>& data, const aes128::Key& key) {
    if (data.empty()) {
        throw std::runtime_error("ecb: empty ciphertext");
    }
    if (data.size() % BLOCK_SIZE != 0) {
        throw std::runtime_error("ecb: ciphertext size is not a multiple of the block size");
    }

    std::vector<std::uint8_t> plaintext;
    plaintext.reserve(data.size());

    for (std::size_t i = 0; i < data.size(); i += BLOCK_SIZE) {
        const Block cipher_block = read_block(data, i);
        const Block plain_block = aes128::decrypt_block(cipher_block, key);
        append_block(plaintext, plain_block);
    }

    return padding::unpad(plaintext);
}

} // namespace cryptocore::modes::ecb