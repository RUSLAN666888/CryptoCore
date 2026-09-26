// tests/unit/test_ecb.cpp
#include "ecb.h"
#include "file_io.h"
#include "padding.h"

#include <gtest/gtest.h>

#include <filesystem>
#include <vector>

namespace {

namespace fs = std::filesystem;

using cryptocore::aes128::Key;
using cryptocore::modes::ecb::decrypt_stream;
using cryptocore::modes::ecb::encrypt_stream;
using cryptocore::utils::FileReader;
using cryptocore::utils::FileWriter;
using cryptocore::utils::read_file;
using cryptocore::utils::write_file;

const Key kKey = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
};

const Key kOtherKey = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
};

const fs::path kDir = fs::temp_directory_path() / "cryptocore_ecb_test";
const fs::path kPlain = kDir / "plain.bin";
const fs::path kCipher = kDir / "cipher.bin";
const fs::path kDecrypted = kDir / "decrypted.bin";

class ECBTest : public ::testing::Test {
protected:
    void SetUp() override { fs::create_directories(kDir); }
    void TearDown() override {
        std::error_code ec;
        fs::remove_all(kDir, ec);
    }
};

std::vector<std::uint8_t> round_trip(const std::vector<std::uint8_t>& data,
                                     const Key& key) {
    write_file(kPlain.string(), data);
    {
        FileReader in(kPlain.string());
        FileWriter out(kCipher.string());
        encrypt_stream(in, out, key);
    }
    {
        FileReader in(kCipher.string());
        FileWriter out(kDecrypted.string());
        decrypt_stream(in, out, key);
    }
    return read_file(kDecrypted.string());
}

} // namespace

TEST_F(ECBTest, RoundTripEmpty) {
    EXPECT_TRUE(round_trip({}, kKey).empty());
}

TEST_F(ECBTest, RoundTripShort) {
    const std::vector<std::uint8_t> data = {'H', 'e', 'l', 'l', 'o'};
    EXPECT_EQ(round_trip(data, kKey), data);
}

TEST_F(ECBTest, RoundTripFullBlock) {
    const std::vector<std::uint8_t> data = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    };
    EXPECT_EQ(round_trip(data, kKey), data);
}

TEST_F(ECBTest, RoundTripManyBlocks) {
    std::vector<std::uint8_t> data;
    for (int i = 0; i < 1000; ++i) data.push_back(static_cast<std::uint8_t>(i));
    EXPECT_EQ(round_trip(data, kKey), data);
}

TEST_F(ECBTest, CiphertextIsMultipleOfBlockSize) {
    for (std::size_t len : {0u, 1u, 15u, 16u, 17u, 31u, 32u, 100u}) {
        const std::vector<std::uint8_t> data(len, 0xAA);
        write_file(kPlain.string(), data);

        {
            FileReader in(kPlain.string());
            FileWriter out(kCipher.string());
            encrypt_stream(in, out, kKey);
        }

        const auto ct = read_file(kCipher.string());
        EXPECT_EQ(ct.size() % 16, 0u) << "len=" << len;
        EXPECT_GT(ct.size(), 0u) << "len=" << len;
    }
}

TEST_F(ECBTest, Deterministic) {
    const std::vector<std::uint8_t> data = {'H', 'e', 'l', 'l', 'o'};
    write_file(kPlain.string(), data);

    {
        FileReader in(kPlain.string());
        FileWriter out(kCipher.string());
        encrypt_stream(in, out, kKey);
    }
    const auto ct1 = read_file(kCipher.string());

    {
        FileReader in(kPlain.string());
        FileWriter out(kCipher.string());
        encrypt_stream(in, out, kKey);
    }
    const auto ct2 = read_file(kCipher.string());

    EXPECT_EQ(ct1, ct2);
}

TEST_F(ECBTest, DecryptEmptyThrows) {
    write_file(kCipher.string(), {});

    FileReader in(kCipher.string());
    FileWriter out(kDecrypted.string());

    EXPECT_THROW(decrypt_stream(in, out, kKey), std::runtime_error);
}

TEST_F(ECBTest, DecryptWrongSizeThrows) {
    write_file(kCipher.string(), {0x01, 0x02, 0x03});

    FileReader in(kCipher.string());
    FileWriter out(kDecrypted.string());

    EXPECT_THROW(decrypt_stream(in, out, kKey), std::runtime_error);
}