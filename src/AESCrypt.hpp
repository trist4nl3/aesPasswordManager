// AESCrypt.h

#ifndef AESCRYPT_HPP
#define AESCRYPT_HPP

#include <string>

class AESCrypt {
private:
    unsigned char key[32];
    unsigned char iv[16];

public:
    AESCrypt(const std::string& password);
    void encrypt(const std::string& plaintext, unsigned char* ciphertext);
    void decrypt(unsigned char* ciphertext, unsigned char* decryptedtext);

private:
    void deriveKeyFromPassword(const std::string& password, unsigned char* key);
};

#endif 
