#include "padding.h"

#include <gtest/gtest.h>

namespace {

using cryptocore::modes::padding::PaddingError;
using cryptocore::modes::padding::pad;
using cryptocore::modes::padding::unpad;

} // namespace

TEST(Padding, PadEmptyInput) {
    const auto result = pad({});
    ASSERT_EQ(result.size(), 16u);
    for (auto b : result) {
        EXPECT_EQ(b, 0x10);
    }
}

TEST(Padding, PadFiveBytes) {
    const std::vector<std::uint8_t> data = {0x01, 0x02, 0x03, 0x04, 0x05};
    const auto result = pad(data);

    ASSERT_EQ(result.size(), 16u);
    EXPECT_EQ(result[0], 0x01);
    EXPECT_EQ(result[4], 0x05);
    for (std::size_t i = 5; i < 16; ++i) {
        EXPECT_EQ(result[i], 0x0B);
    }
}

TEST(Padding, PadFullBlockAddsWholeBlock) {
    const std::vector<std::uint8_t> data(16, 0xAA);
    const auto result = pad(data);

    ASSERT_EQ(result.size(), 32u);
    for (std::size_t i = 16; i < 32; ++i) {
        EXPECT_EQ(result[i], 0x10);
    }
}

TEST(Padding, PadThirtyTwoBytes) {
    const std::vector<std::uint8_t> data(32, 0xBB);
    const auto result = pad(data);

    ASSERT_EQ(result.size(), 48u);
    for (std::size_t i = 32; i < 48; ++i) {
        EXPECT_EQ(result[i], 0x10);
    }
}

TEST(Padding, UnpadRoundTrip) {
    const std::vector<std::uint8_t> original = {0x01, 0x02, 0x03, 0x04, 0x05};
    const auto padded = pad(original);
    const auto unpadded = unpad(padded);

    EXPECT_EQ(unpadded, original);
}

TEST(Padding, UnpadEmptyThrows) {
    EXPECT_THROW(unpad({}), PaddingError);
}

TEST(Padding, UnpadWrongSizeThrows) {
    EXPECT_THROW(unpad({0x01, 0x02, 0x03}), PaddingError);
}

TEST(Padding, UnpadInvalidLengthThrows) {
    std::vector<std::uint8_t> data(16, 0xAA);
    data[15] = 0x00;  // N = 0
    EXPECT_THROW(unpad(data), PaddingError);

    data[15] = 0x11;  // N = 17 > 16
    EXPECT_THROW(unpad(data), PaddingError);
}

TEST(Padding, UnpadInconsistentBytesThrows) {
    std::vector<std::uint8_t> data(16, 0xAA);
    data[14] = 0x02;
    data[15] = 0x03;  // N = 3, но data[13] != 3
    EXPECT_THROW(unpad(data), PaddingError);
}