// tests/test_ofb.cpp
#include "ofb.h"
#include "file_io.h"

#include <gtest/gtest.h>

#include <filesystem>
#include <vector>

namespace {

namespace fs = std::filesystem;

using cryptocore::aes128::Block;
using cryptocore::aes128::Key;
using cryptocore::modes::ofb::decrypt_stream;
using cryptocore::modes::ofb::encrypt_stream;
using cryptocore::utils::FileReader;
using cryptocore::utils::FileWriter;
using cryptocore::utils::read_file;
using cryptocore::utils::write_file;

const fs::path kDir = fs::temp_directory_path() / "cryptocore_ofb_test";
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

class OFBTest : public ::testing::Test {
protected:
    void SetUp() override { fs::create_directories(kDir); }
    void TearDown() override {
        std::error_code ec;
        fs::remove_all(kDir, ec);
    }
};

std::vector<std::uint8_t> round_trip(const std::vector<std::uint8_t>& data) {
    write_file(kPlain.string(), data);
    {
        FileReader in(kPlain.string());
        FileWriter out(kCipher.string());
        encrypt_stream(in, out, kKey, kIv);
    }
    {
        FileReader in(kCipher.string());
        FileWriter out(kDecrypted.string());
        decrypt_stream(in, out, kKey, kIv);
    }
    return read_file(kDecrypted.string());
}

} // namespace

TEST_F(OFBTest, RoundTripEmpty) {
    EXPECT_TRUE(round_trip({}).empty());
}

TEST_F(OFBTest, RoundTripOneByte) {
    const std::vector<std::uint8_t> data = {0x42};
    EXPECT_EQ(round_trip(data), data);
}

TEST_F(OFBTest, RoundTripShort) {
    const std::vector<std::uint8_t> data = {'H', 'e', 'l', 'l', 'o'};
    EXPECT_EQ(round_trip(data), data);
}

TEST_F(OFBTest, RoundTripFullBlock) {
    const std::vector<std::uint8_t> data(16, 0xAA);
    EXPECT_EQ(round_trip(data), data);
}

TEST_F(OFBTest, RoundTripManyBlocks) {
    std::vector<std::uint8_t> data;
    for (int i = 0; i < 1000; ++i) data.push_back(static_cast<std::uint8_t>(i));
    EXPECT_EQ(round_trip(data), data);
}

TEST_F(OFBTest, CiphertextLengthEqualsPlaintext) {
    for (std::size_t len : {0u, 1u, 15u, 16u, 17u, 32u, 100u}) {
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

TEST_F(OFBTest, KeystreamIsIndependentOfData) {
    // Encrypting two different plaintexts with the same key/IV must
    // produce ciphertexts whose XOR equals the XOR of the plaintexts.
    const std::vector<std::uint8_t> p1 = {0x00, 0x00, 0x00, 0x00};
    const std::vector<std::uint8_t> p2 = {0x11, 0x22, 0x33, 0x44};

    write_file(kPlain.string(), p1);
    {
        FileReader in(kPlain.string());
        FileWriter out(kCipher.string());
        encrypt_stream(in, out, kKey, kIv);
    }
    const auto c1 = read_file(kCipher.string());

    write_file(kPlain.string(), p2);
    {
        FileReader in(kPlain.string());
        FileWriter out(kCipher.string());
        encrypt_stream(in, out, kKey, kIv);
    }
    const auto c2 = read_file(kCipher.string());

    for (std::size_t i = 0; i < p1.size(); ++i) {
        EXPECT_EQ(static_cast<std::uint8_t>(c1[i] ^ c2[i]), static_cast<std::uint8_t>(p1[i] ^ p2[i]));
    }
}

TEST_F(OFBTest, WrongKeyProducesWrongData) {
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

// NIST SP 800-38A, F.4.1, OFB-AES128.Encrypt
TEST_F(OFBTest, NistVectorFirstBlock) {
    const std::vector<std::uint8_t> plaintext = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    };
    const std::vector<std::uint8_t> expected = {
        0x3b, 0x3f, 0xd9, 0x2e, 0xb7, 0x2d, 0xad, 0x20,
        0x33, 0x34, 0x49, 0xf8, 0xe8, 0x3c, 0xfb, 0x4a,
    };

    write_file(kPlain.string(), plaintext);
    {
        FileReader in(kPlain.string());
        FileWriter out(kCipher.string());
        encrypt_stream(in, out, kKey, kIv);
    }

    EXPECT_EQ(read_file(kCipher.string()), expected);
}