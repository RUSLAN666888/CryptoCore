#include <gtest/gtest.h>
#include "csprng.h"
#include "hex.h"

TEST(Csprng, GeneratesRequestedSize) {
    EXPECT_EQ(cryptocore::csprng::generate_random_bytes(0).size(), 0u);
    EXPECT_EQ(cryptocore::csprng::generate_random_bytes(16).size(), 16u);
    EXPECT_EQ(cryptocore::csprng::generate_random_bytes(100).size(), 100u);
}

TEST(Csprng, FillsBuffer) {
    std::uint8_t buf[32] = {};
    cryptocore::csprng::generate_random_bytes(buf, 32);

    bool all_zero = true;
    for (auto b : buf) {
        if (b != 0) { all_zero = false; break; }
    }
    EXPECT_FALSE(all_zero);
}

TEST(Csprng, ProducesUniqueValues) {
    std::set<std::string> seen;
    for (int i = 0; i < 100; ++i) {
        seen.insert(cryptocore::utils::bytes_to_hex(cryptocore::csprng::generate_random_bytes(16)));
    }
    EXPECT_EQ(seen.size(), 100u);
}