// src/cli/args.h
#ifndef CRYPTOCORE_CLI_ARGS_H
#define CRYPTOCORE_CLI_ARGS_H

#include "aes128.h"

#include <optional>
#include <stdexcept>
#include <string>

namespace cryptocore::cli {

/**
 * @brief Raised when command-line arguments are invalid.
 */
class ParseError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

/**
 * @brief Cipher algorithm selected by the user.
 */
enum class Algorithm {
    AES,
};

/**
 * @brief Block cipher mode selected by the user.
 */
enum class Mode {
    ECB,
};

/**
 * @brief Operation to perform.
 */
enum class Operation {
    Encrypt,
    Decrypt,
};

/**
 * @brief Parsed command-line arguments for encryption/decryption.
 *
 * All fields are validated by the parser. Missing optional fields are
 * represented by std::nullopt.
 */
struct Args {
    Algorithm algorithm = Algorithm::AES;
    Mode mode = Mode::ECB;
    Operation operation = Operation::Encrypt;  // overwritten by parser
    aes128::Key key{};
    std::string input;
    std::optional<std::string> output;
};

}

#endif // CRYPTOCORE_CLI_ARGS_H