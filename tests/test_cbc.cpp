// tests/test_cbc.cpp
#include "cbc.h"
#include "file_io.h"
#include "padding.h"

#include <gtest/gtest.h>

#include <cstdio>
#include <filesystem>
#include <vector>

namespace {

namespace fs = std::filesystem;

using cryptocore::aes128::Block;
using cryptocore::aes128::Key;
using cryptocore::modes::cbc::decrypt_stream;
using cryptocore::modes::cbc::encrypt_stream;
using cryptocore::modes::padding::PaddingError;
using cryptocore::utils::FileError;
using cryptocore::utils::FileReader;
using cryptocore::utils::FileWriter;
using cryptocore::utils::read_file;

const fs::path kDir = fs::temp_directory_path() / "cryptocore_cbc_test";
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

class CBCTest : public ::testing::Test {
protected:
    void SetUp() override {
        fs::create_directories(kDir);
        std::remove(kPlain.c_str());
        std::remove(kCipher.c_str());
        std::remove(kDecrypted.c_str());
    }
    void TearDown() override {
        std::error_code ec;
        fs::remove_all(kDir, ec);
    }
};

// Encrypt `data` with the given key/iv, then decrypt and return the result.
std::vector<std::uint8_t> round_trip(const std::vector<std::uint8_t>& data, const Key& key, const Block& iv) {
    cryptocore::utils::write_file(kPlain.string(), data);

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

TEST_F(CBCTest, RoundTripEmpty) {
    EXPECT_TRUE(round_trip({}, kKey, kIv).empty());
}

TEST_F(CBCTest, RoundTripOneByte) {
    const std::vector<std::uint8_t> data = {0x42};
    EXPECT_EQ(round_trip(data, kKey, kIv), data);
}

TEST_F(CBCTest, RoundTripShortText) {
    const std::vector<std::uint8_t> data = {'H', 'e', 'l', 'l', 'o'};
    EXPECT_EQ(round_trip(data, kKey, kIv), data);
}

TEST_F(CBCTest, RoundTripFullBlock) {
    const std::vector<std::uint8_t> data(16, 0xAA);
    EXPECT_EQ(round_trip(data, kKey, kIv), data);
}

TEST_F(CBCTest, RoundTripTwoBlocks) {
    const std::vector<std::uint8_t> data(32, 0xBB);
    EXPECT_EQ(round_trip(data, kKey, kIv), data);
}

TEST_F(CBCTest, RoundTripManyBlocks) {
    std::vector<std::uint8_t> data;
    for (int i = 0; i < 1000; ++i) {
        data.push_back(static_cast<std::uint8_t>(i));
    }
    EXPECT_EQ(round_trip(data, kKey, kIv), data);
}

TEST_F(CBCTest, CiphertextLengthIsMultipleOfBlock) {
    for (std::size_t len : {0u, 1u, 15u, 16u, 17u, 31u, 32u, 100u}) {
        const std::vector<std::uint8_t> data(len, 0xAA);
        cryptocore::utils::write_file(kPlain.string(), data);

        FileReader in(kPlain.string());
        FileWriter out(kCipher.string());
        encrypt_stream(in, out, kKey, kIv);
        out = FileWriter(kCipher.string());  // flush

        const auto ct = read_file(kCipher.string());
        EXPECT_EQ(ct.size() % 16, 0u) << "len=" << len;
        EXPECT_GT(ct.size(), 0u) << "len=" << len;
    }
}

TEST_F(CBCTest, DifferentIvProducesDifferentCiphertext) {
    const std::vector<std::uint8_t> data = {'H', 'e', 'l', 'l', 'o'};

    cryptocore::utils::write_file(kPlain.string(), data);

    FileReader in1(kPlain.string());
    FileWriter out1(kCipher.string());
    encrypt_stream(in1, out1, kKey, kIv);
    out1 = FileWriter(kCipher.string());

    const auto ct1 = read_file(kCipher.string());

    Block iv2 = kIv;
    iv2[0] ^= 0xFF;

    FileReader in2(kPlain.string());
    FileWriter out2(kCipher.string());
    encrypt_stream(in2, out2, kKey, iv2);
    out2 = FileWriter(kCipher.string());

    const auto ct2 = read_file(kCipher.string());

    EXPECT_NE(ct1, ct2);
}

TEST_F(CBCTest, DecryptWrongKeyThrowsOrProducesWrongData) {
    const std::vector<std::uint8_t> data = {'H', 'e', 'l', 'l', 'o'};
    cryptocore::utils::write_file(kPlain.string(), data);

    {
        FileReader in(kPlain.string());
        FileWriter out(kCipher.string());
        encrypt_stream(in, out, kKey, kIv);
    }

    Key wrong_key = kKey;
    wrong_key[0] ^= 0xFF;

    FileReader in(kCipher.string());
    FileWriter out(kDecrypted.string());

    try {
        decrypt_stream(in, out, wrong_key, kIv);
        // If it didn't throw, decrypted data must differ.
        EXPECT_NE(read_file(kDecrypted.string()), data);
    } catch (const PaddingError&) {
        // Expected in most cases.
    }
}

TEST_F(CBCTest, DecryptEmptyThrows) {
    cryptocore::utils::write_file(kCipher.string(), {});

    FileReader in(kCipher.string());
    FileWriter out(kDecrypted.string());

    EXPECT_THROW(decrypt_stream(in, out, kKey, kIv), std::runtime_error);
}

TEST_F(CBCTest, DecryptNonMultipleOfBlockThrows) {
    cryptocore::utils::write_file(kCipher.string(), {0x01, 0x02, 0x03});

    FileReader in(kCipher.string());
    FileWriter out(kDecrypted.string());

    EXPECT_THROW(decrypt_stream(in, out, kKey, kIv), std::runtime_error);
}

TEST_F(CBCTest, DecryptSingleBlockRoundTrip) {
    // A single block: plaintext of exactly 16 bytes.
    const std::vector<std::uint8_t> data = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    };
    EXPECT_EQ(round_trip(data, kKey, kIv), data);
}

// NIST SP 800-38A, F.2.1, CBC-AES128.Encrypt
// Plaintext block 1 with key/iv below must produce the known ciphertext.
TEST_F(CBCTest, NistVectorFirstBlock) {
    const Key nist_key = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    };
    const Block nist_iv = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };
    const std::vector<std::uint8_t> plaintext = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    };
    const std::vector<std::uint8_t> expected_first_block = {
        0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46,
        0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
    };

    cryptocore::utils::write_file(kPlain.string(), plaintext);

    FileReader in(kPlain.string());
    FileWriter out(kCipher.string());
    encrypt_stream(in, out, nist_key, nist_iv);
    out = FileWriter(kCipher.string());

    const auto ct = read_file(kCipher.string());

    ASSERT_GE(ct.size(), 16u);
    EXPECT_EQ(std::vector<std::uint8_t>(ct.begin(), ct.begin() + 16), expected_first_block);
}