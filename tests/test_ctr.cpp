// tests/test_ctr.cpp
#include "ctr.h"
#include "file_io.h"

#include <gtest/gtest.h>

#include <filesystem>
#include <vector>

namespace {

namespace fs = std::filesystem;

using cryptocore::aes128::Block;
using cryptocore::aes128::Key;
using cryptocore::modes::ctr::decrypt_stream;
using cryptocore::modes::ctr::encrypt_stream;
using cryptocore::utils::FileReader;
using cryptocore::utils::FileWriter;
using cryptocore::utils::read_file;
using cryptocore::utils::write_file;

const fs::path kDir = fs::temp_directory_path() / "cryptocore_ctr_test";
const fs::path kPlain = kDir / "plain.bin";
const fs::path kCipher = kDir / "cipher.bin";
const fs::path kDecrypted = kDir / "decrypted.bin";

const Key kKey = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
};

const Block kIv = {
    0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
    0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
};

class CTRTest : public ::testing::Test {
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

TEST_F(CTRTest, RoundTripEmpty) {
    EXPECT_TRUE(round_trip({}).empty());
}

TEST_F(CTRTest, RoundTripOneByte) {
    const std::vector<std::uint8_t> data = {0x42};
    EXPECT_EQ(round_trip(data), data);
}

TEST_F(CTRTest, RoundTripShort) {
    const std::vector<std::uint8_t> data = {'H', 'e', 'l', 'l', 'o'};
    EXPECT_EQ(round_trip(data), data);
}

TEST_F(CTRTest, RoundTripFullBlock) {
    const std::vector<std::uint8_t> data(16, 0xAA);
    EXPECT_EQ(round_trip(data), data);
}

TEST_F(CTRTest, RoundTripManyBlocks) {
    std::vector<std::uint8_t> data;
    for (int i = 0; i < 1000; ++i) data.push_back(static_cast<std::uint8_t>(i));
    EXPECT_EQ(round_trip(data), data);
}

TEST_F(CTRTest, CiphertextLengthEqualsPlaintext) {
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

TEST_F(CTRTest, KeystreamIsIndependentOfData) {
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
        EXPECT_EQ(static_cast<std::uint8_t>(c1[i] ^ c2[i]),
                  static_cast<std::uint8_t>(p1[i] ^ p2[i]));
    }
}

TEST_F(CTRTest, WrongKeyProducesWrongData) {
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

// NIST SP 800-38A, F.5.1, CTR-AES128.Encrypt
TEST_F(CTRTest, NistVectorFirstBlock) {
    const Block nist_iv = {
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
        0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
    };
    const std::vector<std::uint8_t> plaintext = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    };
    const std::vector<std::uint8_t> expected = {
        0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26,
        0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce,
    };

    write_file(kPlain.string(), plaintext);
    {
        FileReader in(kPlain.string());
        FileWriter out(kCipher.string());
        encrypt_stream(in, out, kKey, nist_iv);
    }

    EXPECT_EQ(read_file(kCipher.string()), expected);
}