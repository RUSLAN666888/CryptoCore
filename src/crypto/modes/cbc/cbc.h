// src/crypto/modes/cbc/cbc.h
#ifndef CRYPTOCORE_MODES_CBC_H
#define CRYPTOCORE_MODES_CBC_H

#include "aes128.h"
#include "file_io.h"

namespace cryptocore::modes::cbc {

/**
 * @brief Encrypt a stream using AES-128 in CBC mode with PKCS#7 padding.
 *
 * Reads from @p in until EOF, writes ciphertext to @p out.
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
 * @brief Decrypt a stream using AES-128 in CBC mode with PKCS#7 padding.
 *
 * Reads from @p in until EOF, writes plaintext to @p out.
 *
 * @throws padding::PaddingError If the decrypted padding is invalid,
 *         which typically means a wrong key or corrupted ciphertext.
 * @throws std::runtime_error    If the ciphertext size is invalid or
 *         the underlying AES primitive fails.
 * @throws utils::FileError      If reading or writing fails.
 */
void decrypt_stream(utils::FileReader& in, utils::FileWriter& out, const aes128::Key& key, const aes128::Block& iv);

}

#endif // CRYPTOCORE_MODES_CBC_HPP