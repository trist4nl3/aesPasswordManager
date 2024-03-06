#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <cstring>
#include <sstream>
#include <limits>

// AES encryption key size in bytes (256-bit key)
#define AES_KEY_SIZE 32
// AES IV size in bytes (128-bit IV)
#define AES_IV_SIZE 16

// Struct to hold password entry
struct PasswordEntry {
    std::string serviceName;
    std::string username;
    std::string password;
};

// Function to generate a random master key
std::string generateMasterKey() {
    unsigned char buffer[AES_KEY_SIZE];
    RAND_bytes(buffer, AES_KEY_SIZE);
    return std::string(reinterpret_cast<char*>(buffer), AES_KEY_SIZE);
}

// Function to encrypt data using AES
bool encryptData(const std::string& input, const std::string& key, const std::string& iv, std::string& output) {
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (const unsigned char*)key.c_str(), (const unsigned char*)iv.c_str())) {
        return false;
    }

    int len;
    int ciphertext_len;
    unsigned char ciphertext[input.size() + AES_KEY_SIZE];

    if (!EVP_EncryptUpdate(ctx, ciphertext, &len, (const unsigned char*)input.c_str(), input.size())) {
        return false;
    }
    ciphertext_len = len;

    if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        return false;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    output.assign((char*)ciphertext, ciphertext_len);

    return true;
}

// Function to decrypt data using AES
bool decryptData(const std::string& input, const std::string& key, const std::string& iv, std::string& output) {
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, (const unsigned char*)key.c_str(), (const unsigned char*)iv.c_str())) {
        return false;
    }

    int len;
    int plaintext_len;
    unsigned char plaintext[input.size()];

    if (!EVP_DecryptUpdate(ctx, plaintext, &len, (const unsigned char*)input.c_str(), input.size())) {
        return false;
    }
    plaintext_len = len;

    if (!EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        return false;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    output.assign((char*)plaintext, plaintext_len);

    return true;
}

// Function to load master key from file or generate a new one
std::string loadOrCreateMasterKey() {
    std::ifstream keyFile("master.key", std::ios::binary);
    if (keyFile) {
        std::string key;
        keyFile.seekg(0, std::ios::end);
        size_t size = keyFile.tellg();
        key.resize(size);
        keyFile.seekg(0);
        keyFile.read(&key[0], size);
        std::cout << "Master key loaded from file.\n";
        return key;
    } else {
        std::string key = generateMasterKey();
        std::ofstream newKeyFile("master.key", std::ios::binary);
        newKeyFile.write(key.c_str(), key.size());
        return key;
    }
}
// Function to save encrypted password to file
void saveEncryptedPasswords(const std::vector<PasswordEntry>& entries, const std::string& masterKey) {
    std::ofstream passwordFile("passwords.enc", std::ios::binary | std::ios::app); // Open in append mode
    if (!passwordFile) {
        std::cerr << "Failed to open passwords.enc for writing." << std::endl;
        return;
    }
    for (const auto& entry : entries) {
        std::string encryptedEntry;
        std::string plainEntry = entry.serviceName + "\n" + entry.username + "\n" + entry.password + "\n";
        if (encryptData(plainEntry, masterKey, masterKey.substr(0, AES_IV_SIZE), encryptedEntry)) {
            passwordFile.write(encryptedEntry.c_str(), encryptedEntry.size());
        } else {
            std::cerr << "Encryption failed for entry: " << entry.serviceName << std::endl;
        }
    }
    passwordFile.close(); // Close the file after writing
}

std::vector<PasswordEntry> readEncryptedPasswords(const std::string& masterKey) {
    std::vector<PasswordEntry> entries;
    std::ifstream passwordFile("passwords.enc", std::ios::binary);
    if (!passwordFile) {
        std::cerr << "Failed to open passwords.enc for reading." << std::endl;
        return entries;
    }

    std::string encryptedData((std::istreambuf_iterator<char>(passwordFile)), std::istreambuf_iterator<char>());
    passwordFile.close();

    std::string decryptedData;
    if (!decryptData(encryptedData, masterKey, masterKey.substr(0, AES_IV_SIZE), decryptedData)) {
        std::cerr << "Decryption failed for passwords.enc." << std::endl;
        return entries;
    }

    std::istringstream iss(decryptedData);
    std::string line;
    while (std::getline(iss, line)) {
        PasswordEntry entry;
        entry.serviceName = line;
        if (!std::getline(iss, entry.username)) {
            std::cerr << "Error: Unexpected end of file while reading username." << std::endl;
            return entries;
        }
        if (!std::getline(iss, entry.password)) {
            std::cerr << "Error: Unexpected end of file while reading password." << std::endl;
            return entries;
        }
        entries.push_back(entry);
    }

    return entries;
}



// Function to add or update a password entry
void addOrUpdatePassword(std::vector<PasswordEntry>& entries) {
    PasswordEntry entry;
    std::cout << "Enter service name: ";
    std::getline(std::cin, entry.serviceName);
    std::cout << "Enter username: ";
    std::getline(std::cin, entry.username);
    std::cout << "Enter password: ";
    std::getline(std::cin, entry.password);

    // Check if the service already exists
    for (auto& existingEntry : entries) {
        if (existingEntry.serviceName == entry.serviceName && existingEntry.username == entry.username) {
            existingEntry.password = entry.password;
            std::cout << "Password updated for " << entry.serviceName << std::endl;
            return;
        }
    }

    // If the service doesn't exist, add a new entry
    entries.push_back(entry);
    std::cout << "New password added for " << entry.serviceName << std::endl;
}

// Function to remove a password entry
void removePassword(std::vector<PasswordEntry>& entries) {
    std::string serviceName, username;
    std::cout << "Enter service name: ";
    std::getline(std::cin, serviceName);
    std::cout << "Enter username: ";
    std::getline(std::cin, username);

    for (auto it = entries.begin(); it != entries.end(); ++it) {
        if (it->serviceName == serviceName && it->username == username) {
            entries.erase(it);
            std::cout << "Password removed for " << serviceName << std::endl;
            return;
        }
    }

    std::cout << "Password not found for " << serviceName << std::endl;
}

// Function to view all password entries
void viewPasswords(const std::vector<PasswordEntry>& entries) {
    if (entries.empty()) {
        std::cout << "No passwords stored.\n";
    } else {
        std::cout << "Stored Passwords:\n";
        for (const auto& entry : entries) {
            std::cout << "Service: " << entry.serviceName << "\nUsername: " << entry.username << "\nPassword: " << entry.password << "\n\n";
        }
    }
}

int main() {
    // Load or generate master key
    std::string masterKey = loadOrCreateMasterKey();

    // Load password entries from file
    std::vector<PasswordEntry> passwordEntries = readEncryptedPasswords(masterKey);
    // Main loop
    while (true) {
        std::cout << "1. Add/Update Password\n2. Remove Password\n3. View Passwords\n4. Exit\n";
        int choice;
        std::cin >> choice;
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        switch (choice) {
            case 1:
                addOrUpdatePassword(passwordEntries);
                break;
            case 2:
                removePassword(passwordEntries);
                break;
            case 3:
                viewPasswords(passwordEntries);
                break;
            case 4:
                // Save encrypted passwords to file and exit
                saveEncryptedPasswords(passwordEntries, masterKey);
                return 0;
            default:
                std::cerr << "Invalid choice. Please try again.\n";
                break;
        }
    }

    return 0;
}
