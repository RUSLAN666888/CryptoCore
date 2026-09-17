// src/cli/parser.cpp
#include "parser.h"

#include "hex.h"

#include <algorithm>
#include <string>
#include <vector>

namespace cryptocore::cli {

namespace {

using cryptocore::utils::hex_to_bytes;

/**
 * @brief Read the value that follows a flag and advance the index.
 *
 * @param argv Argument vector.
 * @param argc Argument count.
 * @param i    Index of the flag. Advanced past the value on success.
 * @param flag Flag name, used in the error message.
 * @return The value string.
 * @throws ParseError If the value is missing.
 */
std::string take_value(char* argv[], int argc, int& i, const char* flag) {
    if (i + 1 >= argc) {
        throw ParseError(std::string(flag) + " requires a value");
    }
    ++i;
    return argv[i];
}

/**
 * @brief Parse an AES-128 key from a 32-character hex string.
 *
 * @throws ParseError If the string is not valid hex or not 16 bytes long.
 */
aes128::Key parse_key(const std::string& hex) {
    std::vector<std::uint8_t> bytes;
    try {
        bytes = hex_to_bytes(hex);
    } catch (const std::exception& e) {
        throw ParseError(std::string("--key is not valid hex: ") + e.what());
    }

    if (bytes.size() != aes128::KEY_SIZE) {
        throw ParseError(
            "--key must be exactly 32 hex characters ("
            + std::to_string(bytes.size() * 2) + " given)");
    }

    aes128::Key key{};
    std::copy(bytes.begin(), bytes.end(), key.begin());
    return key;
}

/**
 * @brief Throw if a flag has already been seen.
 *
 * @throws ParseError If @p already_set is true.
 */
void reject_duplicate(bool already_set, const char* flag) {
    if (already_set) {
        throw ParseError(std::string(flag) + " specified more than once");
    }
}

} // namespace

Args parse(int argc, char* argv[]) {
    if (argc < 2) {
        throw ParseError("no arguments given");
    }

    Args args;
    bool algorithm_set = false;
    bool mode_set = false;
    bool key_set = false;
    bool input_set = false;
    bool output_set = false;
    bool encrypt_set = false;
    bool decrypt_set = false;

    for (int i = 1; i < argc; ++i) {
        const std::string flag = argv[i];

        if (flag == "--algorithm") {
            reject_duplicate(algorithm_set, "--algorithm");
            const std::string value = take_value(argv, argc, i, "--algorithm");
            if (value != "aes") {
                throw ParseError("--algorithm must be 'aes' (got '" + value + "')");
            }
            args.algorithm = Algorithm::AES;
            algorithm_set = true;

        } else if (flag == "--mode") {
            reject_duplicate(mode_set, "--mode");
            const std::string value = take_value(argv, argc, i, "--mode");
            if (value != "ecb") {
                throw ParseError("--mode must be 'ecb' (got '" + value + "')");
            }
            args.mode = Mode::ECB;
            mode_set = true;

        } else if (flag == "--encrypt") {
            reject_duplicate(encrypt_set, "--encrypt");
            args.operation = Operation::Encrypt;
            encrypt_set = true;

        } else if (flag == "--decrypt") {
            reject_duplicate(decrypt_set, "--decrypt");
            args.operation = Operation::Decrypt;
            decrypt_set = true;

        } else if (flag == "--key") {
            reject_duplicate(key_set, "--key");
            const std::string value = take_value(argv, argc, i, "--key");
            args.key = parse_key(value);
            key_set = true;

        } else if (flag == "--input") {
            reject_duplicate(input_set, "--input");
            const std::string value = take_value(argv, argc, i, "--input");
            if (value.empty()) {
                throw ParseError("--input must not be empty");
            }
            args.input = value;
            input_set = true;

        } else if (flag == "--output") {
            reject_duplicate(output_set, "--output");
            const std::string value = take_value(argv, argc, i, "--output");
            if (value.empty()) {
                throw ParseError("--output must not be empty");
            }
            args.output = value;
            output_set = true;

        } else {
            throw ParseError("unknown argument: " + flag);
        }
    }

    // ---- Required arguments ----
    if (!algorithm_set) {
        throw ParseError("missing required argument: --algorithm");
    }
    if (!mode_set) {
        throw ParseError("missing required argument: --mode");
    }
    if (!key_set) {
        throw ParseError("missing required argument: --key");
    }
    if (!input_set) {
        throw ParseError("missing required argument: --input");
    }

    // ---- Operation ----
    if (encrypt_set && decrypt_set) {
        throw ParseError("--encrypt and --decrypt are mutually exclusive");
    }
    if (!encrypt_set && !decrypt_set) {
        throw ParseError("one of --encrypt or --decrypt is required");
    }

    return args;
}

} // namespace cryptocore::cli