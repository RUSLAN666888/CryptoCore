// src/cli/parser.hp
#ifndef CRYPTOCORE_CLI_PARSER_H
#define CRYPTOCORE_CLI_PARSER_H

#include "args.h"

namespace cryptocore::cli {

/**
 * @brief Parse command-line arguments for encryption/decryption.
 *
 * Expected form:
 *   cryptocore --algorithm aes --mode ecb --encrypt|--decrypt
 *              --key <hex> --input <file> [--output <file>]
 *
 * @param argc Argument count from main().
 * @param argv Argument vector from main().
 * @return Validated Args structure.
 *
 * @throws ParseError If any argument is missing, malformed, duplicated,
 *         or conflicting (e.g. both --encrypt and --decrypt).
 */
Args parse(int argc, char* argv[]);

}

#endif // CRYPTOCORE_CLI_PARSER_H