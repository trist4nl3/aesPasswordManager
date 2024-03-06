#include "AESCrypt.hpp"
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

const int KEY_SIZE = 32; // AES 256-bit key size
const int IV_SIZE = 16;  // AES block size
const int MAX_CIPHERTEXT_SIZE = 1024; // Maximum size for ciphertext array

void AESCrypt::deriveKeyFromPassword(const std::string &password, unsigned char *key)
{   
    // Taken from documentation
    // EVP_aes_256_cbc() the AES encryption algorithm with a 256-bit key in CBC mode 
    // EVP_sha256() is the hash alogirthm used for key derivation
    // nullptr is the salt, we are not using any salt, salt is used to protect against dictionary attacks
    // reinterpret_cast<const unsigned char *> This is the password string the reinterpret is used to convert const char*
    // pointer returned by c_str() to const unsigned char* as required by EVP_BytesToKey
    // key is the buffer where the derived key will be stored

    EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), nullptr,
                   reinterpret_cast<const unsigned char *>(password.c_str()), password.length(), 1, key, nullptr);
}

AESCrypt::AESCrypt(const std::string &password)
{
    unsigned char key[KEY_SIZE];
    unsigned char iv[IV_SIZE];
    // Derive key from password
    deriveKeyFromPassword(password, key);

    // Initialize IV with some random data
    // RAND_bytes is used to generate random bytes, iv and IV_SIZE mean the buffer and the number of bytes to generate
    RAND_bytes(iv, IV_SIZE);
}


// Asks for a plaintext and encrypts it to a ciphertext
void AESCrypt::encrypt(const std::string &plaintext, unsigned char *ciphertext)
{
    AES_KEY aesKey;
    AES_set_encrypt_key(key, KEY_SIZE * 8, &aesKey);
    AES_cbc_encrypt(reinterpret_cast<const unsigned char *>(plaintext.c_str()), ciphertext, plaintext.size(), &aesKey, iv, AES_ENCRYPT);

}

// Decrypts a ciphertext to a plaintext
void AESCrypt::decrypt(unsigned char *ciphertext, unsigned char *decryptedtext)
{
    AES_KEY aesKey;
    AES_set_decrypt_key(key, KEY_SIZE * 8, &aesKey);
    AES_cbc_encrypt(ciphertext, decryptedtext, AES_BLOCK_SIZE, &aesKey, iv, AES_DECRYPT);
}

