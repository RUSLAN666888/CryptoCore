// src/utils/file_io.h
#ifndef CRYPTOCORE_UTILS_FILE_IO_H
#define CRYPTOCORE_UTILS_FILE_IO_H

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace cryptocore::utils {

/**
 * @brief Raised when a file cannot be read or written.
 */
class FileError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

/**
 * @brief Read the entire contents of a file into a byte vector.
 *
 * The file is opened in binary mode.
 *
 * @param path Path to the file.
 * @return File contents as raw bytes.
 *
 * @throws FileError If the file cannot be opened or read.
 *
 * @note This function loads the whole file into memory.
 */
std::vector<std::uint8_t> read_file(const std::string& path);

/**
 * @brief Write raw bytes to a file, overwriting it if it exists.
 *
 * The file is opened in binary mode.
 *
 * @param path Path to the file.
 * @param data Bytes to write.
 *
 * @throws FileError If the file cannot be opened or written.
 */
void write_file(const std::string& path, const std::vector<std::uint8_t>& data);

}

#endif // CRYPTOCORE_UTILS_FILE_IO_H