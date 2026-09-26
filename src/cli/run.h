#ifndef CRYPTOCORE_CLI_RUN_HPP
#define CRYPTOCORE_CLI_RUN_HPP

#include "args.h"

namespace cryptocore::cli {

/**
 * @brief Execute the requested operation.
 *
 * Reads the input file, encrypts or decrypts it using the selected
 * mode, and writes the result to the output file.
 *
 * For modes that use an IV:
 *  - On encrypt, a random IV is generated and written to the start
 *    of the output file.
 *  - On decrypt, the IV is taken from --iv if given; otherwise it is
 *    read from the first 16 bytes of the input file.
 *
 * @return Process exit code (0 on success).
 *
 * @throws std::exception On any failure (parsing already happened).
 */
int run(const Args& args);

}

#endif // CRYPTOCORE_CLI_RUN_HPP