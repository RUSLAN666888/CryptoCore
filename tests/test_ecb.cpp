#include "aes128.h"
#include "ecb.h"
#include "padding.h"

#include <gtest/gtest.h>

namespace {

using cryptocore::aes128::Key;
using cryptocore::modes::ecb::decrypt;
using cryptocore::modes::ecb::encrypt;

// NIST SP 800-38A, Appendix F.1.1 — AES-128 ECB key.
const Key kKey = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
};

// A second key for negative tests.
const Key kOtherKey = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
};

TEST(ECB, RoundTripShortData) {
    const std::vector<std::uint8_t> plaintext = {'H', 'e', 'l', 'l', 'o'};

    const auto ciphertext = encrypt(plaintext, kKey);
    const auto decrypted = decrypt(ciphertext, kKey);

    EXPECT_EQ(decrypted, plaintext);
}

TEST(ECB, RoundTripFullBlock) {
    const std::vector<std::uint8_t> plaintext = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
    };

    const auto ciphertext = encrypt(plaintext, kKey);
    const auto decrypted = decrypt(ciphertext, kKey);

    EXPECT_EQ(decrypted, plaintext);
}

TEST(ECB, RoundTripEmptyData) {
    const std::vector<std::uint8_t> plaintext = {};

    const auto ciphertext = encrypt(plaintext, kKey);
    const auto decrypted = decrypt(ciphertext, kKey);

    EXPECT_EQ(decrypted, plaintext);
}

TEST(ECB, CiphertextIsMultipleOfBlockSize) {
    for (std::size_t len : {0u, 1u, 15u, 16u, 17u, 31u, 32u, 100u}) {
        const std::vector<std::uint8_t> plaintext(len, 0xAA);
        const auto ciphertext = encrypt(plaintext, kKey);

        EXPECT_EQ(ciphertext.size() % 16, 0u)
            << "for input length " << len;
        EXPECT_GT(ciphertext.size(), 0u)
            << "for input length " << len;
    }
}

TEST(ECB, Deterministic) {
    const std::vector<std::uint8_t> plaintext = {'H', 'e', 'l', 'l', 'o'};

    const auto ct1 = encrypt(plaintext, kKey);
    const auto ct2 = encrypt(plaintext, kKey);

    EXPECT_EQ(ct1, ct2);
}

TEST(ECB, DecryptEmptyThrows) {
    EXPECT_THROW(decrypt({}, kKey), std::runtime_error);
}

TEST(ECB, DecryptWrongSizeThrows) {
    const std::vector<std::uint8_t> bad(15, 0xAA);
    EXPECT_THROW(decrypt(bad, kKey), std::runtime_error);
}

TEST(ECB, DecryptWrongKeyThrowsOrProducesWrongData) {
    // Wrong key usually causes invalid padding, but may occasionally
    // produce a valid-looking padding by chance (~1/256 for N=1).
    // This test only checks it does not crash.
    const std::vector<std::uint8_t> plaintext{'H', 'e', 'l', 'l', 'o'};

    const auto ciphertext = encrypt(plaintext, kKey);

    try {
        const auto decrypted = decrypt(ciphertext, kOtherKey);
        EXPECT_NE(decrypted, plaintext);
    } catch (const cryptocore::modes::padding::PaddingError&) {
        // Expected in the vast majority of cases.
    }
}
}