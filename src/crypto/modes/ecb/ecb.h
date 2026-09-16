// src/modes/ecb.h
#ifndef CRYPTOCORE_MODES_ECB_HPP
#define CRYPTOCORE_MODES_ECB_HPP

#include "aes128.h"

#include <cstdint>
#include <vector>

namespace cryptocore::modes::ecb {

/**
 * @brief Encrypt data using AES-128 in ECB mode with PKCS#7 padding.
 *
 * The input may have any length. PKCS#7 padding is applied before
 * encryption, so the ciphertext length is always a positive multiple
 * of 16 bytes.
 *
 * @param data Plaintext of arbitrary length.
 * @param key  16-byte AES-128 key.
 * @return Ciphertext whose size is a multiple of 16 bytes.
 *
 * @throws std::runtime_error If the underlying AES primitive fails.
 *
 * @warning ECB mode is not semantically secure. Equal plaintext blocks
 *          produce equal ciphertext blocks, revealing structure in the
 *          data.
 */
std::vector<std::uint8_t> encrypt(const std::vector<std::uint8_t>& data, const aes128::Key& key);

/**
 * @brief Decrypt data using AES-128 in ECB mode with PKCS#7 padding.
 *
 * The input length must be a non-zero multiple of 16 bytes. After
 * decryption, PKCS#7 padding is validated and removed.
 *
 * @param data Ciphertext whose size is a non-zero multiple of 16 bytes.
 * @param key  16-byte AES-128 key.
 * @return Decrypted plaintext with padding removed.
 *
 * @throws padding::PaddingError If the decrypted padding is invalid,
 *         which typically means a wrong key or corrupted ciphertext.
 * @throws std::runtime_error If the underlying AES primitive fails.
 */
std::vector<std::uint8_t> decrypt(const std::vector<std::uint8_t>& data, const aes128::Key& key);

}

#endif // CRYPTOCORE_MODES_ECB_HPP