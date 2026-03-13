#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"
#include "crypto_utils.hpp"

TEST_CASE("Cryptographic Logic Tests") {
    std::string original = "Hello World!";
    std::string key = "12345678901234567890123456789012"; // 32 bytes

    SUBCASE("SHA-256 Hashing") {
        std::string hash = sha256(original);
        CHECK(hash.length() == 64); // SHA-256 hex string length
        CHECK(hash != original);
    }

    SUBCASE("AES-256 CBC Roundtrip") {
        // 1. Encrypt
        auto encrypted = encrypt_aes_256_cbc(original, (unsigned char*)key.c_str());
        
        // 2. Decrypt
        std::string decrypted = decrypt_aes_256_cbc(
            encrypted.ciphertext_base64, 
            encrypted.iv_base64, 
            (unsigned char*)key.c_str()
        );

        // 3. Verify
        CHECK(decrypted == original);
    }
}
