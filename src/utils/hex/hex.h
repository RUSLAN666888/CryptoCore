// src/utils/hex.h
#ifndef CRYPTOCORE_UTILS_HEX_H
#define CRYPTOCORE_UTILS_HEX_H

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace cryptocore::utils {

/**
 * @brief Raised when a hex string cannot be decoded.
 */
class HexError : public std::invalid_argument {
public:
    using std::invalid_argument::invalid_argument;
};

/**
 * @brief Decode a hexadecimal string into raw bytes.
 *
 * Accepts both lowercase and uppercase hex digits. The input must have
 * even length, since each byte is encoded by exactly two hex characters.
 *
 * @param hex Hex string, e.g. "00112233aabbccdd".
 * @return Decoded bytes.
 *
 * @throws HexError If the string has odd length or contains a character
 *         outside [0-9a-fA-F].
 *
 * @note An empty input string produces an empty output vector. This is
 *       well-defined and not an error.
 */
std::vector<std::uint8_t> hex_to_bytes(const std::string& hex);

/**
 * @brief Encode raw bytes as a lowercase hexadecimal string.
 *
 * Each byte is represented by exactly two hex characters, high nibble
 * first.
 *
 * @param bytes Raw bytes to encode.
 * @return Lowercase hex string of length `2 * bytes.size()`.
 *
 * @note This function does not throw.
 */
std::string bytes_to_hex(const std::vector<std::uint8_t>& bytes);

}

#endif // CRYPTOCORE_UTILS_HEX_HPP