// src/modes/padding.hpp
#ifndef CRYPTOCORE_MODES_PADDING_HPP
#define CRYPTOCORE_MODES_PADDING_HPP

#include <cstdint>
#include <vector>
#include <stdexcept>

namespace cryptocore::modes::padding {

/**
 * @brief Raised when PKCS#7 padding is invalid.
 *
 * This exception indicates that the padding of a decrypted message could
 * not be validated. The most common causes are:
 *  - a wrong key was used for decryption,
 *  - the ciphertext was corrupted in transit,
 *  - the ciphertext was tampered with.
 *
 * @warning The caller must treat this as a hard failure and must not use
 *       any partially decrypted output. In particular, this exception
 *       intentionally does not carry the offending data, to avoid
 *       encouraging callers to ignore the failure.
 */
class PaddingError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

/**
 * @brief Apply PKCS#7 padding to data.
 *
 * Appends N bytes, each equal to N, where N is chosen so that the
 * resulting length is a multiple of the AES block size (16 bytes).
 * N is always in the range [1, 16]: if the input is already a multiple
 * of the block size, a full block of padding is added.
 *
 * @param data Input data of arbitrary length.
 * @return Padded data whose size is a multiple of 16 bytes.
 *
 * @note This function does not throw. Every input has a well-defined
 *       padded form.
 */
std::vector<std::uint8_t> pad(const std::vector<std::uint8_t>& data);

/**
 * @brief Remove PKCS#7 padding from data.
 *
 * Reads the last byte as the padding length N, verifies that N is in
 * the range [1, 16] and that the last N bytes all equal N, then returns
 * the data without those N bytes.
 *
 * @param data Padded data. Its size must be a non-zero multiple of 16.
 * @return Data with padding removed.
 *
 * @throws std::runtime_error If data is empty, its size is not a multiple
 *         of 16, or the padding bytes are invalid.
 *
 * @note Invalid padding usually indicates a wrong key, a corrupted
 *       ciphertext, or tampering. The caller should treat it as a hard
 *       failure and must not use any partially decrypted output.
 */
std::vector<std::uint8_t> unpad(const std::vector<std::uint8_t>& data);

}

#endif // CRYPTOCORE_MODES_PADDING_HPP