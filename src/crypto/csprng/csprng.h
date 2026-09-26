#ifndef CRYPTOCORE_CSPRNG_CSPRNG_H
#define CRYPTOCORE_CSPRNG_CSPRNG_H

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace cryptocore::csprng {

/**
 * @brief Raised when the random number generator fails.
 */
class RandomError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

/**
 * @brief Fill `buffer` with `size` cryptographically secure random bytes.
 *
 * Backed by OpenSSL's RAND_bytes(), which draws entropy from the
 * operating system. Suitable for keys and IVs.
 *
 * @param buffer Destination buffer. Must be at least `size` bytes long.
 * @param size   Number of bytes to generate. Zero is allowed.
 *
 * @throws RandomError If the generator fails.
 */
void generate_random_bytes(std::uint8_t* buffer, std::size_t size);

/**
 * @brief Generate `size` cryptographically secure random bytes.
 *
 * @throws RandomError If the generator fails.
 */
std::vector<std::uint8_t> generate_random_bytes(std::size_t size);

}

#endif // CRYPTOCORE_CSPRNG_CSPRNG_H