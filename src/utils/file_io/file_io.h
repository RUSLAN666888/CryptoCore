#ifndef CRYPTOCORE_UTILS_FILE_IO_H
#define CRYPTOCORE_UTILS_FILE_IO_H

#include <cstdint>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace cryptocore::utils {

/**
 * @brief Raised when a file cannot be opened, read, or written.
 */
class FileError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

/**
 * @brief Streaming reader for binary files.
 *
 * Wraps std::ifstream. Reading is buffered by the underlying stream,
 * so small reads (e.g. 16 bytes) are cheap.
 */
class FileReader {
public:
    /**
     * @brief Open a file for reading in binary mode.
     * @throws FileError If the file cannot be opened.
     */
    explicit FileReader(const std::string& path);

    /**
     * @brief Read up to `max_bytes` bytes into `buffer`.
     *
     * @param buffer Destination buffer. Must be at least `max_bytes` long.
     * @param max_bytes Maximum number of bytes to read.
     * @return Number of bytes actually read. 0 means end of file.
     *
     * @throws FileError On read error.
     */
    std::size_t read(std::uint8_t* buffer, std::size_t max_bytes);

    /**
     * @brief Move the read position to an absolute offset from the start.
     *
     * Clears any end-of-file or fail state left by previous reads.
     *
     * @param offset Byte offset from the beginning of the file.
     * @throws FileError If the seek fails.
     */
    void seek(std::size_t offset);

    /**
     * @brief Return the current read position in bytes from the start.
     *
     * @throws FileError If the position cannot be determined.
     */
    std::size_t tell();

    /**
     * @brief Return the number of bytes remaining from the current position.
     *
     * After read() advances the position, size() reflects only the
     * unread tail. At the start of a freshly opened file, this equals
     * the total file size.
     *
     * @throws FileError If the size cannot be determined.
     */
    std::size_t size();

    /**
     * @brief Return true if the last read reached end of file.
     */
    bool eof();

private:
    std::ifstream file_;
};

/**
 * @brief Streaming writer for binary files.
 *
 * Wraps std::ofstream. Writing is buffered by the underlying stream.
 * The file is created or truncated on construction.
 */
class FileWriter {
public:
    /**
     * @brief Open a file for writing in binary mode, truncating it.
     * @throws FileError If the file cannot be opened.
     */
    explicit FileWriter(const std::string& path);

    /**
     * @brief Write exactly `size` bytes from `data`.
     *
     * @throws FileError On write error.
     */
    void write(const std::uint8_t* data, std::size_t size);

private:
    std::ofstream file_;
};

/**
 * @brief Read the entire contents of a file into a byte vector.
 *
 * @throws FileError If the file cannot be opened or read.
 *
 * @note Loads the whole file into memory. For large files use FileReader.
 */
std::vector<std::uint8_t> read_file(const std::string& path);

/**
 * @brief Write raw bytes to a file, overwriting it if it exists.
 *
 * @throws FileError If the file cannot be opened or written.
 */
void write_file(const std::string& path, const std::vector<std::uint8_t>& data);

}

#endif // CRYPTOCORE_UTILS_FILE_IO_H