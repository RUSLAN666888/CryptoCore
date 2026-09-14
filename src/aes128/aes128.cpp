// src/aes128/aes128.cpp
#include "aes128.h"

#include <openssl/evp.h>

#include <memory>
#include <stdexcept>

namespace cryptocore::aes128 {

namespace {

// unique_ptr with custom deleter
// EVP_CIPHER_CTX_free when out of scope
using CipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

Block process_block(bool encrypt, const Block& block, const Key& key) {
    CipherCtxPtr ctx(EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free);
    if (!ctx) {
        throw std::runtime_error("AES-128: failed to allocate context");
    }

    const int init_ok = encrypt
                            ? EVP_EncryptInit_ex(ctx.get(), EVP_aes_128_ecb(), nullptr, key.data(), nullptr)
                            : EVP_DecryptInit_ex(ctx.get(), EVP_aes_128_ecb(), nullptr, key.data(), nullptr);
    if (init_ok != 1) {
        throw std::runtime_error("AES-128: failed to initialize context");
    }

    if (EVP_CIPHER_CTX_set_padding(ctx.get(), 0) != 1) {
        throw std::runtime_error("AES-128: failed to disable padding");
    }

    Block output{};
    int out_len = 0;

    const int update_ok = encrypt
                              ? EVP_EncryptUpdate(ctx.get(), output.data(), &out_len, block.data(), BLOCK_SIZE)
                              : EVP_DecryptUpdate(ctx.get(), output.data(), &out_len, block.data(), BLOCK_SIZE);
    if (update_ok != 1) {
        throw std::runtime_error("AES-128: failed to process block");
    }

    int final_len = 0;
    const int final_ok = encrypt
                             ? EVP_EncryptFinal_ex(ctx.get(), output.data() + out_len, &final_len)
                             : EVP_DecryptFinal_ex(ctx.get(), output.data() + out_len, &final_len);
    if (final_ok != 1) {
        throw std::runtime_error("AES-128: failed to finalize block");
    }

    return output;
}

} // namespace

Block encrypt_block(const Block& block, const Key& key) {
    return process_block(true, block, key);
}

Block decrypt_block(const Block& block, const Key& key) {
    return process_block(false, block, key);
}

} // namespace cryptocore::aes128