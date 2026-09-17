// main.cpp
#include "args.h"
#include "parser.h"

#include "ecb.h"
#include "file_io.h"

#include <exception>
#include <iostream>
#include <string>

namespace {

using cryptocore::cli::Args;
using cryptocore::cli::Operation;

/**
 * @brief Build the default output path when --output was not given.
 *
 * encrypt: <input>.enc
 * decrypt: <input>.dec
 */
std::string default_output_path(const Args& args) {
    const std::string suffix = (args.operation == Operation::Encrypt) ? ".enc" : ".dec";
    return args.input + suffix;
}

/**
 * @brief Run the requested operation using the parsed arguments.
 *
 * @return Process exit code (0 on success).
 */
int run(const Args& args) {
    const auto input_data = cryptocore::utils::read_file(args.input);

    const std::vector<std::uint8_t> output_data = (args.operation == Operation::Encrypt)
            ? cryptocore::modes::ecb::encrypt(input_data, args.key)
            : cryptocore::modes::ecb::decrypt(input_data, args.key);

    const std::string output_path = args.output.has_value() ? args.output.value() : default_output_path(args);

    cryptocore::utils::write_file(output_path, output_data);
    return 0;
}

} // namespace

int main(int argc, char* argv[]) {
    try {
        const Args args = cryptocore::cli::parse(argc, argv);
        return run(args);
    } catch (const std::exception& e) {
        std::cerr << "cryptocore: " << e.what() << "\n";
        return 1;
    }
}