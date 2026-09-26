// src/cli/parser.h
#ifndef CRYPTOCORE_CLI_PARSER_H
#define CRYPTOCORE_CLI_PARSER_H

#include "args.h"

namespace cryptocore::cli {

/**
 * @brief Parse command-line arguments for encryption/decryption.
 *
 * Expected form:
 *   cryptocore --algorithm aes --mode <mode> --encrypt|--decrypt
 *              --key <hex> --input <file> [--output <file>] [--iv <hex>]
 *
 * --mode is one of: ecb, cbc, cfb, ofb, ctr.
 * --iv is a 32-character hex string; allowed only when decrypting with
 * a mode that uses an IV (cbc, cfb, ofb, ctr). Rejected when encrypting
 * or with ECB.
 *
 * @param argc Argument count from main().
 * @param argv Argument vector from main().
 * @return Validated Args structure.
 *
 * @throws ParseError If any argument is missing, malformed, duplicated,
 *         or conflicting (e.g. both --encrypt and --decrypt, or --iv
 *         given while encrypting).
 */
Args parse(int argc, char* argv[]);

}

#endif // CRYPTOCORE_CLI_PARSER_H