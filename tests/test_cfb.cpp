// tests/test_cfb.cpp
#include "cfb.h"
#include "file_io.h"

#include <gtest/gtest.h>

#include <cstdio>
#include <filesystem>
#include <vector>

namespace {

namespace fs = std::filesystem;

using cryptocore::aes128::Block;
using cryptocore::aes128::Key;
using cryptocore::modes::cfb::decrypt_stream;
using cryptocore::modes::cfb::encrypt_stream;
using cryptocore::utils::FileReader;
using cryptocore::utils::FileWriter;
using cryptocore::utils::read_file;
using cryptocore::utils::write_file;

const fs::path kDir = fs::temp_directory_path() / "cryptocore_cfb_test";
const fs::path kPlain = kDir / "plain.bin";
const fs::path kCipher = kDir / "cipher.bin";
const fs::path kDecrypted = kDir / "decrypted.bin";

const Key kKey = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
};

const Block kIv = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

class CFBTest : public ::testing::Test {
protected:
    void SetUp() override {
        fs::create_directories(kDir);
    }
    void TearDown() override {
        std::error_code ec;
        fs::remove_all(kDir, ec);
    }
};

std::vector<std::uint8_t> round_trip(const std::vector<std::uint8_t>& data, const Key& key, const Block& iv) {
    write_file(kPlain.string(), data);

    {
        FileReader in(kPlain.string());
        FileWriter out(kCipher.string());
        encrypt_stream(in, out, key, iv);
    }
    {
        FileReader in(kCipher.string());
        FileWriter out(kDecrypted.string());
        decrypt_stream(in, out, key, iv);
    }

    return read_file(kDecrypted.string());
}

} // namespace

TEST_F(CFBTest, RoundTripEmpty) {
    EXPECT_TRUE(round_trip({}, kKey, kIv).empty());
}

TEST_F(CFBTest, RoundTripOneByte) {
    const std::vector<std::uint8_t> data = {0x42};
    EXPECT_EQ(round_trip(data, kKey, kIv), data);
}

TEST_F(CFBTest, RoundTripShortText) {
    const std::vector<std::uint8_t> data = {'H', 'e', 'l', 'l', 'o'};
    EXPECT_EQ(round_trip(data, kKey, kIv), data);
}

TEST_F(CFBTest, RoundTripFullBlock) {
    const std::vector<std::uint8_t> data(16, 0xAA);
    EXPECT_EQ(round_trip(data, kKey, kIv), data);
}

TEST_F(CFBTest, RoundTripSeventeenBytes) {
    std::vector<std::uint8_t> data;
    for (int i = 0; i < 17; ++i) data.push_back(static_cast<std::uint8_t>(i));
    EXPECT_EQ(round_trip(data, kKey, kIv), data);
}

TEST_F(CFBTest, RoundTripManyBlocks) {
    std::vector<std::uint8_t> data;
    for (int i = 0; i < 1000; ++i) data.push_back(static_cast<std::uint8_t>(i));
    EXPECT_EQ(round_trip(data, kKey, kIv), data);
}

TEST_F(CFBTest, CiphertextLengthEqualsPlaintextLength) {
    for (std::size_t len : {0u, 1u, 5u, 15u, 16u, 17u, 31u, 32u, 100u}) {
        const std::vector<std::uint8_t> data(len, 0xAA);
        write_file(kPlain.string(), data);

        {
            FileReader in(kPlain.string());
            FileWriter out(kCipher.string());
            encrypt_stream(in, out, kKey, kIv);
        }

        EXPECT_EQ(read_file(kCipher.string()).size(), len) << "len=" << len;
    }
}

TEST_F(CFBTest, DifferentIvProducesDifferentCiphertext) {
    const std::vector<std::uint8_t> data = {'H', 'e', 'l', 'l', 'o'};
    write_file(kPlain.string(), data);

    {
        FileReader in(kPlain.string());
        FileWriter out(kCipher.string());
        encrypt_stream(in, out, kKey, kIv);
    }
    const auto ct1 = read_file(kCipher.string());

    Block iv2 = kIv;
    iv2[0] ^= 0xFF;

    {
        FileReader in(kPlain.string());
        FileWriter out(kCipher.string());
        encrypt_stream(in, out, kKey, iv2);
    }
    const auto ct2 = read_file(kCipher.string());

    EXPECT_NE(ct1, ct2);
}

TEST_F(CFBTest, WrongIvProducesWrongData) {
    const std::vector<std::uint8_t> data = {'H', 'e', 'l', 'l', 'o'};
    write_file(kPlain.string(), data);

    {
        FileReader in(kPlain.string());
        FileWriter out(kCipher.string());
        encrypt_stream(in, out, kKey, kIv);
    }

    Block wrong_iv = kIv;
    wrong_iv[0] ^= 0xFF;

    {
        FileReader in(kCipher.string());
        FileWriter out(kDecrypted.string());
        decrypt_stream(in, out, kKey, wrong_iv);
    }

    EXPECT_NE(read_file(kDecrypted.string()), data);
}

TEST_F(CFBTest, WrongKeyProducesWrongData) {
    const std::vector<std::uint8_t> data = {'H', 'e', 'l', 'l', 'o'};
    write_file(kPlain.string(), data);

    {
        FileReader in(kPlain.string());
        FileWriter out(kCipher.string());
        encrypt_stream(in, out, kKey, kIv);
    }

    Key wrong_key = kKey;
    wrong_key[0] ^= 0xFF;

    {
        FileReader in(kCipher.string());
        FileWriter out(kDecrypted.string());
        decrypt_stream(in, out, wrong_key, kIv);
    }

    EXPECT_NE(read_file(kDecrypted.string()), data);
}

TEST_F(CFBTest, Deterministic) {
    const std::vector<std::uint8_t> data = {'H', 'e', 'l', 'l', 'o'};
    write_file(kPlain.string(), data);

    {
        FileReader in(kPlain.string());
        FileWriter out(kCipher.string());
        encrypt_stream(in, out, kKey, kIv);
    }
    const auto ct1 = read_file(kCipher.string());

    {
        FileReader in(kPlain.string());
        FileWriter out(kCipher.string());
        encrypt_stream(in, out, kKey, kIv);
    }
    const auto ct2 = read_file(kCipher.string());

    EXPECT_EQ(ct1, ct2);
}

// // NIST SP 800-38A, F.3.13, CFB128-AES128.Encrypt
TEST_F(CFBTest, NistVectorFirstBlock) {
    const std::vector<std::uint8_t> plaintext = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
        0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
        0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
    };
    const std::vector<std::uint8_t> expected = {
        0x3b, 0x3f, 0xd9, 0x2e, 0xb7, 0x2d, 0xad, 0x20,
        0x33, 0x34, 0x49, 0xf8, 0xe8, 0x3c, 0xfb, 0x4a,
        0xc8, 0xa6, 0x45, 0x37, 0xa0, 0xb3, 0xa9, 0x3f,
        0xcd, 0xe3, 0xcd, 0xad, 0x9f, 0x1c, 0xe5, 0x8b,
        0x26, 0x75, 0x1f, 0x67, 0xa3, 0xcb, 0xb1, 0x40,
        0xb1, 0x80, 0x8c, 0xf1, 0x87, 0xa4, 0xf4, 0xdf,
        0xc0, 0x4b, 0x05, 0x35, 0x7c, 0x5d, 0x1c, 0x0e,
        0xea, 0xc4, 0xc6, 0x6f, 0x9f, 0xf7, 0xf2, 0xe6,
    };

    write_file(kPlain.string(), plaintext);

    {
        FileReader in(kPlain.string());
        FileWriter out(kCipher.string());
        encrypt_stream(in, out, kKey, kIv);
    }

    EXPECT_EQ(read_file(kCipher.string()), expected);
}