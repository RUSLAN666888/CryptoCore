#include "csprng.h"

#include <openssl/rand.h>

namespace cryptocore::csprng {

void generate_random_bytes(std::uint8_t* buffer, std::size_t size) {
    if (size == 0) {
        return;
    }

    if (RAND_bytes(buffer, static_cast<int>(size)) != 1) {
        throw RandomError("csprng: RAND_bytes failed");
    }
}

std::vector<std::uint8_t> generate_random_bytes(std::size_t size) {
    std::vector<std::uint8_t> result(size);
    generate_random_bytes(result.data(), size);
    return result;
}

} // namespace cryptocore::csprng