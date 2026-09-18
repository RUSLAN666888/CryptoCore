// src/aes128/aes128.h
#ifndef CRYPTOCORE_AES128_AES128_H
#define CRYPTOCORE_AES128_AES128_H

#include <array>
#include <cstdint>

namespace cryptocore::aes128 {

/**
 * @brief Size of an AES block in bytes.
 */
inline constexpr std::size_t BLOCK_SIZE = 16;

/**
 * @brief Size of an AES-128 key in bytes.
 */
inline constexpr std::size_t KEY_SIZE = 16;

/**
 * @brief A single AES block (16 bytes).
 */
using Block = std::array<std::uint8_t, BLOCK_SIZE>;

/**
 * @brief An AES-128 key (16 bytes).
 */
using Key = std::array<std::uint8_t, KEY_SIZE>;

/**
 * @brief Encrypt a single 16-byte block using AES-128.
 *
 * @param block Plaintext block to encrypt.
 * @param key   16-byte AES-128 key.
 * @return     Encrypted 16-byte block.
 *
 * @throws std::runtime_error If OpenSSL fails to initialize or process the block.
 *
 * @note This function operates on a single block only. It does not perform
 *       padding and does not implement any block cipher mode of operation.
 *       Use a mode from cryptocore::modes for encrypting data of arbitrary length.
 */
Block encrypt_block(const Block& block, const Key& key);

/**
 * @brief Decrypt a single 16-byte block using AES-128.
 *
 * @param block Ciphertext block to decrypt.
 * @param key   16-byte AES-128 key.
 * @return     Decrypted 16-byte block.
 *
 * @throws std::runtime_error If OpenSSL fails to initialize or process the block.
 *
 * @note This function operates on a single block only. It does not perform
 *       padding removal and does not implement any block cipher mode of
 *       operation. Use a mode from cryptocore::modes for decrypting data of
 *       arbitrary length.
 */
Block decrypt_block(const Block& block, const Key& key);

}

#endif // CRYPTOCORE_AES128_AES128_HPP