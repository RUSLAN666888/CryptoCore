// src/crypto/modes/cfb/cfb.h
#ifndef CRYPTOCORE_MODES_CFB_H
#define CRYPTOCORE_MODES_CFB_H

#include "aes128.h"
#include "file_io.h"

namespace cryptocore::modes::cfb {

/**
 * @brief Encrypt a stream using AES-128 in CFB mode (128-bit segments).
 *
 * No padding is applied; the last block may be partial.
 *
 * @param in  Input stream (plaintext).
 * @param out Output stream (ciphertext).
 * @param key 16-byte AES-128 key.
 * @param iv  16-byte initialization vector.
 *
 * @throws std::runtime_error If the underlying AES primitive fails.
 * @throws utils::FileError  If reading or writing fails.
 */
void encrypt_stream(utils::FileReader& in, utils::FileWriter& out, const aes128::Key& key, const aes128::Block& iv);

/**
 * @brief Decrypt a stream using AES-128 in CFB mode (128-bit segments).
 *
 * @throws std::runtime_error If the underlying AES primitive fails.
 * @throws utils::FileError  If reading or writing fails.
 */
void decrypt_stream(utils::FileReader& in, utils::FileWriter& out, const aes128::Key& key, const aes128::Block& iv);

}

#endif // CRYPTOCORE_MODES_CFB_HPP