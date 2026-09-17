// src/utils/file_io.cpp
#include "file_io.h"

#include <fstream>
#include <iterator>

namespace cryptocore::utils {

std::vector<std::uint8_t> read_file(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        throw FileError("cannot open file for reading: " + path);
    }

    std::vector<std::uint8_t> data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    if (file.bad()) {
        throw FileError("error while reading file: " + path);
    }

    return data;
}

void write_file(const std::string& path, const std::vector<std::uint8_t>& data) {
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    if (!file) {
        throw FileError("cannot open file for writing: " + path);
    }

    file.write(reinterpret_cast<const char*>(data.data()),
               static_cast<std::streamsize>(data.size()));

    if (!file) {
        throw FileError("error while writing file: " + path);
    }
}

} // namespace cryptocore::utils