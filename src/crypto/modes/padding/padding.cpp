// src/modes/padding.cpp
#include "padding.h"

#include "aes128.h"

#include <stdexcept>

namespace cryptocore::modes::padding {

namespace {

using cryptocore::aes128::BLOCK_SIZE;

std::size_t read_padding_length(const std::vector<std::uint8_t>& data) {
    if (data.empty()) {
        throw PaddingError("padding: empty input");
    }

    if (data.size() % BLOCK_SIZE != 0) {
        throw PaddingError("padding: size is not a multiple of the block size");
    }

    const std::uint8_t n = data.back();

    if (n < 1 || n > BLOCK_SIZE) {
        throw PaddingError("padding: invalid padding length");
    }

    if (static_cast<std::size_t>(n) > data.size()) {
        throw PaddingError("padding: padding length exceeds data size");
    }

    return n;
}

void verify_padding_bytes(const std::vector<std::uint8_t>& data, std::size_t n) {
    const std::uint8_t expected = static_cast<std::uint8_t>(n);
    const std::size_t start = data.size() - n;

    for (std::size_t i = start; i < data.size(); ++i) {
        if (data[i] != expected) {
            throw PaddingError("padding: padding bytes are inconsistent");
        }
    }
}

} // namespace

std::vector<std::uint8_t> pad(const std::vector<std::uint8_t>& data) {
    const std::size_t n = BLOCK_SIZE - (data.size() % BLOCK_SIZE);

    std::vector<std::uint8_t> result;
    result.reserve(data.size() + n);
    result.insert(result.end(), data.begin(), data.end());
    result.insert(result.end(), n, static_cast<std::uint8_t>(n));

    return result;
}

std::vector<std::uint8_t> unpad(const std::vector<std::uint8_t>& data) {
    const std::size_t n = read_padding_length(data);
    verify_padding_bytes(data, n);

    return std::vector<std::uint8_t>(data.begin(), data.end() - n);
}

} // namespace cryptocore::modes::padding