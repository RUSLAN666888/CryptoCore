// src/crypto/modes/ecb/ecb.h
#ifndef CRYPTOCORE_MODES_ECB_H
#define CRYPTOCORE_MODES_ECB_H

#include "aes128.h"
#include "file_io.h"

namespace cryptocore::modes::ecb {

/**
 * @brief Encrypt a stream using AES-128 in ECB mode with PKCS#7 padding.
 *
 * @warning ECB is not semantically secure. Equal plaintext blocks
 *          produce equal ciphertext blocks.
 *
 * @throws std::runtime_error If the underlying AES primitive fails.
 * @throws utils::FileError  If reading or writing fails.
 */
void encrypt_stream(utils::FileReader& in, utils::FileWriter& out, const aes128::Key& key);

/**
 * @brief Decrypt a stream using AES-128 in ECB mode with PKCS#7 padding.
 *
 * @throws padding::PaddingError If the decrypted padding is invalid.
 * @throws std::runtime_error    If the ciphertext size is invalid.
 * @throws utils::FileError      If reading or writing fails.
 */
void decrypt_stream(utils::FileReader& in, utils::FileWriter& out, const aes128::Key& key);

}

#endif // CRYPTOCORE_MODES_ECB_HPP