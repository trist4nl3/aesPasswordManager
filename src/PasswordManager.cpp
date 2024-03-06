// PasswordManager.cpp

#include "PasswordManager.hpp"
#include <fstream>
#include <iostream>
const int MAX_CIPHERTEXT_SIZE = 1024;
PasswordManager::PasswordManager(const std::string& masterPassword) : aesCrypt(masterPassword) {}


void PasswordManager::storePassword(const std::string& filename, const std::string& serviceName, const std::string& username, const std::string& password) {
    unsigned char ciphertext[MAX_CIPHERTEXT_SIZE];
    aesCrypt.encrypt(password, ciphertext);

    std::ofstream file(filename, std::ios::app | std::ios::binary);
    file << serviceName << " " << username << " ";
    file.write(reinterpret_cast<char*>(ciphertext), MAX_CIPHERTEXT_SIZE);
    file << std::endl;
    file.close();
}

std::string PasswordManager::retrievePassword(const std::string& filename, const std::string& serviceName, const std::string& username) {
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Error: Unable to open file: " << filename << std::endl;
        return "";
    }

    std::string serviceNameInFile, usernameInFile;
    std::string password;
    unsigned char decryptedtext[MAX_CIPHERTEXT_SIZE];
    while (file >> serviceNameInFile >> usernameInFile) {
        if (serviceNameInFile == serviceName && usernameInFile == username) {
            file.read(reinterpret_cast<char*>(decryptedtext), MAX_CIPHERTEXT_SIZE);
            aesCrypt.decrypt(decryptedtext, decryptedtext);
            password = std::string(reinterpret_cast<char*>(decryptedtext));
            break;
        }
    }
    file.close();
    return password;
}
