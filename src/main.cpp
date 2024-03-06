#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <vector>

const int KEY_SIZE = 32; // AES 256-bit key size
const int IV_SIZE = 16;  // AES block size
const int MAX_CIPHERTEXT_SIZE = 1024; // Maximum size for ciphertext array

// Function to encrypt data using AES
void encrypt(const std::string& password, const std::string& plaintext, unsigned char* ciphertext, unsigned char* key, unsigned char* iv) {
    AES_KEY aesKey;
    AES_set_encrypt_key(key, KEY_SIZE * 8, &aesKey);
    AES_cbc_encrypt(reinterpret_cast<const unsigned char*>(plaintext.c_str()), ciphertext, plaintext.size(), &aesKey, iv, AES_ENCRYPT);
}

// Function to decrypt data using AES
void decrypt(const std::string& password, unsigned char* ciphertext, unsigned char* decryptedtext, unsigned char* key, unsigned char* iv) {
    AES_KEY aesKey;
    AES_set_decrypt_key(key, KEY_SIZE * 8, &aesKey);
    AES_cbc_encrypt(ciphertext, decryptedtext, AES_BLOCK_SIZE, &aesKey, iv, AES_DECRYPT);
}

// Function to read key from password
void deriveKeyFromPassword(const std::string& password, unsigned char* key) {
    EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), nullptr,
                   reinterpret_cast<const unsigned char*>(password.c_str()), password.length(), 1, key, nullptr);
}

int main() {
    unsigned char key[KEY_SIZE];
    unsigned char iv[IV_SIZE];
    std::string password;

    std::cout << "Enter master password: ";
    std::getline(std::cin, password);

    // Derive key from password
    deriveKeyFromPassword(password, key);

    // Initialize IV with some random data
    RAND_bytes(iv, IV_SIZE);

    // Example plaintext password
    const std::string plaintextPassword = "examplepassword";

    // Encrypt the plaintext password
    unsigned char ciphertext[MAX_CIPHERTEXT_SIZE]; // Allocate with a fixed size
    encrypt(password, plaintextPassword, ciphertext, key, iv);

    // Save ciphertext to a file
    std::ofstream file("passwords.dat", std::ios::binary);
    file.write(reinterpret_cast<char*>(ciphertext), MAX_CIPHERTEXT_SIZE); // Write fixed size
    file.close();

    // Read ciphertext from file
    std::ifstream infile("passwords.dat", std::ios::binary | std::ios::ate);
    std::streamsize size = infile.tellg();
    infile.seekg(0, std::ios::beg);

    std::vector<unsigned char> buffer(size);
    if (infile.read(reinterpret_cast<char*>(buffer.data()), size)) {
        // Decrypt ciphertext
        unsigned char decryptedtext[MAX_CIPHERTEXT_SIZE]; // Allocate with a fixed size
        decrypt(password, buffer.data(), decryptedtext, key, iv);

        // Output decrypted password
        std::string decryptedPassword(reinterpret_cast<char*>(decryptedtext));
        std::cout << "Decrypted password: " << decryptedPassword << std::endl;
    } else {
        std::cerr << "Failed to read ciphertext from file!" << std::endl;
    }

    return 0;
}
