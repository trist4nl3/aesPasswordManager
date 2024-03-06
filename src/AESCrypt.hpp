#ifndef AESCRYPT_HPP
#define AESCRYPT_HPP

#include <string>

class AESCrypt 
{
    private:
        unsigned char key[KEY_SIZE];
        unsigned char iv[IV_SIZE];
        void deriveKeyFromPassword(const std::string& password, unsigned char* key);

    public:
        AESCrypt(const std::string& password);
        void encrypt(const std::string& plaintext, unsigned char* ciphertext);
        void decrypt(unsigned char* ciphertext, unsigned char* decryptedtext);

};

#endif