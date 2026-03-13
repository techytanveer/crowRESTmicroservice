#ifndef CRYPTO_UTILS_HPP
#define CRYPTO_UTILS_HPP

#include <string>
#include <vector>

struct EncryptionResult {
    std::string ciphertext_base64;
    std::string iv_base64;
};

std::string sha256(const std::string& str);
std::string base64_encode(const unsigned char* buffer, size_t length);
std::vector<unsigned char> base64_decode(const std::string& input);

EncryptionResult encrypt_aes_256_cbc(const std::string& plaintext, const unsigned char* key);
std::string decrypt_aes_256_cbc(const std::string& ciphertext_base64, const std::string& iv_base64, const unsigned char* key);

#endif
