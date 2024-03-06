// AESCrypt.cpp

#include "AESCrypt.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>

AESCrypt::AESCrypt(const std::string& password) {
    deriveKeyFromPassword(password, key);
    RAND_bytes(iv, 16);
}

void AESCrypt::encrypt(const std::string& plaintext, unsigned char* ciphertext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv);
    int len;
    int ciphertext_len;
    EVP_EncryptUpdate(ctx, ciphertext, &len, reinterpret_cast<const unsigned char*>(plaintext.c_str()), plaintext.length());
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
}

void AESCrypt::decrypt(unsigned char* ciphertext, unsigned char* decryptedtext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv);
    int len;
    int plaintext_len;
    EVP_DecryptUpdate(ctx, decryptedtext, &len, ciphertext, 1024);
    plaintext_len = len;
    EVP_DecryptFinal_ex(ctx, decryptedtext + len, &len);
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
}

void AESCrypt::deriveKeyFromPassword(const std::string& password, unsigned char* key) {
    EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), nullptr,
                   reinterpret_cast<const unsigned char*>(password.c_str()), password.length(), 1, key, nullptr);
}
