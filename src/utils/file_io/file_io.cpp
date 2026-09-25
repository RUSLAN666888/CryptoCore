#include "file_io.h"

#include <iterator>

namespace cryptocore::utils {

FileReader::FileReader(const std::string& path) : file_(path, std::ios::binary){
    if (!file_) {
        throw FileError("cannot open file for reading: " + path);
    }
}

std::size_t FileReader::read(std::uint8_t* buffer, std::size_t max_bytes) {
    file_.read(reinterpret_cast<char*>(buffer), static_cast<std::streamsize>(max_bytes));

    const std::streamsize got = file_.gcount();

    if (file_.bad()) {
        throw FileError("error while reading file");
    }

    return static_cast<std::size_t>(got);
}

FileWriter::FileWriter(const std::string& path) : file_(path, std::ios::binary | std::ios::trunc){
    if (!file_) {
        throw FileError("cannot open file for writing: " + path);
    }
}

void FileWriter::write(const std::uint8_t* data, std::size_t size) {
    file_.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(size));

    if (!file_) {
        throw FileError("error while writing file");
    }
}

std::vector<std::uint8_t> read_file(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        throw FileError("cannot open file for reading: " + path);
    }

    std::vector<std::uint8_t> data((std::istreambuf_iterator<char>(file)),std::istreambuf_iterator<char>());

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

    file.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));

    if (!file) {
        throw FileError("error while writing file: " + path);
    }
}

} // namespace cryptocore::utils