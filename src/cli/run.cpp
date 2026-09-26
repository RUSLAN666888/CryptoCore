#include "run.h"

#include "cbc.h"
#include "cfb.h"
#include "csprng.h"
#include "ctr.h"
#include "ecb.h"
#include "file_io.h"
#include "ofb.h"

#include <algorithm>
#include <stdexcept>
#include <string>

namespace cryptocore::cli {

namespace {

using cryptocore::aes128::Block;

std::string default_output_path(const Args& args) {
    const std::string suffix =
        (args.operation == Operation::Encrypt) ? ".enc" : ".dec";
    return args.input + suffix;
}

Block generate_iv() {
    const auto bytes = cryptocore::csprng::generate_random_bytes(
        cryptocore::aes128::BLOCK_SIZE);
    Block iv{};
    std::copy(bytes.begin(), bytes.end(), iv.begin());
    return iv;
}

Block read_iv_from_stream(cryptocore::utils::FileReader& in) {
    Block iv{};
    if (in.read(iv.data(), iv.size()) != iv.size()) {
        throw std::runtime_error("input file is too short to contain an IV");
    }
    return iv;
}

void do_encrypt(const Args& args, const std::string& output_path) {
    cryptocore::utils::FileReader in(args.input);
    cryptocore::utils::FileWriter out(output_path);

    switch (args.mode) {
    case Mode::ECB:
        cryptocore::modes::ecb::encrypt_stream(in, out, args.key);
        break;

    case Mode::CBC: {
        const Block iv = generate_iv();
        out.write(iv.data(), iv.size());
        cryptocore::modes::cbc::encrypt_stream(in, out, args.key, iv);
        break;
    }
    case Mode::CFB: {
        const Block iv = generate_iv();
        out.write(iv.data(), iv.size());
        cryptocore::modes::cfb::encrypt_stream(in, out, args.key, iv);
        break;
    }
    case Mode::OFB: {
        const Block iv = generate_iv();
        out.write(iv.data(), iv.size());
        cryptocore::modes::ofb::encrypt_stream(in, out, args.key, iv);
        break;
    }
    case Mode::CTR: {
        const Block iv = generate_iv();
        out.write(iv.data(), iv.size());
        cryptocore::modes::ctr::encrypt_stream(in, out, args.key, iv);
        break;
    }
    }
}

void do_decrypt(const Args& args, const std::string& output_path) {
    cryptocore::utils::FileReader in(args.input);
    cryptocore::utils::FileWriter out(output_path);

    switch (args.mode) {
    case Mode::ECB:
        cryptocore::modes::ecb::decrypt_stream(in, out, args.key);
        break;

    case Mode::CBC: {
        const Block iv = args.iv.has_value()
        ? *args.iv
        : read_iv_from_stream(in);
        cryptocore::modes::cbc::decrypt_stream(in, out, args.key, iv);
        break;
    }
    case Mode::CFB: {
        const Block iv = args.iv.has_value()
        ? *args.iv
        : read_iv_from_stream(in);
        cryptocore::modes::cfb::decrypt_stream(in, out, args.key, iv);
        break;
    }
    case Mode::OFB: {
        const Block iv = args.iv.has_value()
        ? *args.iv
        : read_iv_from_stream(in);
        cryptocore::modes::ofb::decrypt_stream(in, out, args.key, iv);
        break;
    }
    case Mode::CTR: {
        const Block iv = args.iv.has_value()
        ? *args.iv
        : read_iv_from_stream(in);
        cryptocore::modes::ctr::decrypt_stream(in, out, args.key, iv);
        break;
    }
    }
}

} // namespace

int run(const Args& args) {
    const std::string output_path =
        args.output.has_value() ? args.output.value() : default_output_path(args);

    if (args.operation == Operation::Encrypt) {
        do_encrypt(args, output_path);
    } else {
        do_decrypt(args, output_path);
    }
    return 0;
}

} // namespace cryptocore::cli