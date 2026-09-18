// src/utils/hex.cpp
#include "hex.h"

#include <array>

namespace cryptocore::utils {

namespace {

/**
 * @brief Convert a single hex character to its numeric value.
 *
 * @throws HexError If the character is not a valid hex digit.
 */
std::uint8_t hex_value(char c) {
    if (c >= '0' && c <= '9') {
        return static_cast<std::uint8_t>(c - '0');
    }
    if (c >= 'a' && c <= 'f') {
        return static_cast<std::uint8_t>(c - 'a' + 10);
    }
    if (c >= 'A' && c <= 'F') {
        return static_cast<std::uint8_t>(c - 'A' + 10);
    }
    throw HexError(std::string("hex: invalid character '") + c + "'");
}

/**
 * @brief Convert a nibble (0..15) to its lowercase hex character.
 */
char hex_digit(std::uint8_t value) {
    static constexpr std::array<char, 16> digits = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };
    return digits[value & 0x0F];
}

} // namespace

std::vector<std::uint8_t> hex_to_bytes(const std::string& hex) {
    if (hex.size() % 2 != 0) {
        throw HexError("hex: odd-length input");
    }

    std::vector<std::uint8_t> bytes;
    bytes.reserve(hex.size() / 2);

    for (std::size_t i = 0; i < hex.size(); i += 2) {
        const std::uint8_t high = hex_value(hex[i]);
        const std::uint8_t low  = hex_value(hex[i + 1]);
        bytes.push_back(static_cast<std::uint8_t>((high << 4) | low));
    }

    return bytes;
}

std::string bytes_to_hex(const std::vector<std::uint8_t>& bytes) {
    std::string result;
    result.reserve(bytes.size() * 2);

    for (std::uint8_t b : bytes) {
        result.push_back(hex_digit(static_cast<std::uint8_t>(b >> 4)));
        result.push_back(hex_digit(b));
    }

    return result;
}

} // namespace cryptocore::utils