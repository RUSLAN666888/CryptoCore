#include "hex.h"

#include <gtest/gtest.h>

namespace {

using cryptocore::utils::bytes_to_hex;
using cryptocore::utils::hex_to_bytes;
using cryptocore::utils::HexError;

} // namespace

TEST(Hex, DecodeLowercase) {
    EXPECT_EQ(hex_to_bytes("00"), (std::vector<std::uint8_t>{0x00}));
    EXPECT_EQ(hex_to_bytes("ff"), (std::vector<std::uint8_t>{0xFF}));
    EXPECT_EQ(hex_to_bytes("deadbeef"), (std::vector<std::uint8_t>{0xDE, 0xAD, 0xBE, 0xEF}));
}

TEST(Hex, DecodeUppercase) {
    EXPECT_EQ(hex_to_bytes("FF"), (std::vector<std::uint8_t>{0xFF}));
    EXPECT_EQ(hex_to_bytes("DEADBEEF"), (std::vector<std::uint8_t>{0xDE, 0xAD, 0xBE, 0xEF}));
}

TEST(Hex, DecodeMixedCase) {
    EXPECT_EQ(hex_to_bytes("DeAdBeEf"), (std::vector<std::uint8_t>{0xDE, 0xAD, 0xBE, 0xEF}));
}

TEST(Hex, DecodeEmpty) {
    EXPECT_TRUE(hex_to_bytes("").empty());
}

TEST(Hex, DecodeOddLengthThrows) {
    EXPECT_THROW(hex_to_bytes("0"), HexError);
    EXPECT_THROW(hex_to_bytes("abc"), HexError);
}

TEST(Hex, DecodeInvalidCharacterThrows) {
    EXPECT_THROW(hex_to_bytes("gg"), HexError);
    EXPECT_THROW(hex_to_bytes("0g"), HexError);
    EXPECT_THROW(hex_to_bytes("0x00"), HexError);
    EXPECT_THROW(hex_to_bytes("00 11"), HexError);
}

TEST(Hex, EncodeLowercase) {
    EXPECT_EQ(bytes_to_hex({0x00}), "00");
    EXPECT_EQ(bytes_to_hex({0xFF}), "ff");
    EXPECT_EQ(bytes_to_hex({0xDE, 0xAD, 0xBE, 0xEF}), "deadbeef");
}

TEST(Hex, EncodeEmpty) {
    EXPECT_EQ(bytes_to_hex({}), "");
}

TEST(Hex, RoundTrip) {
    const std::vector<std::uint8_t> original = {0x00, 0x11, 0x22, 0xFF, 0xAB};
    EXPECT_EQ(hex_to_bytes(bytes_to_hex(original)), original);
}

TEST(Hex, FullByteRange) {
    std::vector<std::uint8_t> all_bytes;
    for (int i = 0; i < 256; ++i) {
        all_bytes.push_back(static_cast<std::uint8_t>(i));
    }
    EXPECT_EQ(hex_to_bytes(bytes_to_hex(all_bytes)), all_bytes);
}