#include "crypto_utils.hpp"
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <iomanip>
#include <sstream>

std::string sha256(const std::string& str) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)str.c_str(), str.size(), hash);
    std::stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    return ss.str();
}

std::string base64_encode(const unsigned char* buffer, size_t length) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, buffer, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    std::string result(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    return result;
}

std::vector<unsigned char> base64_decode(const std::string& input) {
    BIO *bio, *b64;
    std::vector<unsigned char> buffer(input.length());
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(input.data(), input.length());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    int length = BIO_read(bio, buffer.data(), input.length());
    buffer.resize(length);
    BIO_free_all(bio);
    return buffer;
}

EncryptionResult encrypt_aes_256_cbc(const std::string& plaintext, const unsigned char* key) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[16];
    RAND_bytes(iv, sizeof(iv));
    std::vector<unsigned char> ciphertext(plaintext.length() + 16);
    int len, ciphertext_len;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, (unsigned char*)plaintext.c_str(), plaintext.length());
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return {base64_encode(ciphertext.data(), ciphertext_len), base64_encode(iv, 16)};
}

std::string decrypt_aes_256_cbc(const std::string& cipher64, const std::string& iv64, const unsigned char* key) {
    auto cipher_bytes = base64_decode(cipher64);
    auto iv_bytes = base64_decode(iv64);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    std::vector<unsigned char> plaintext(cipher_bytes.size());
    int len, p_len;
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv_bytes.data());
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, cipher_bytes.data(), cipher_bytes.size());
    p_len = len;
    EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    p_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return std::string((char*)plaintext.data(), p_len);
}
