// PasswordManager.h

#ifndef PASSWORDMANAGER_HPP
#define PASSWORDMANAGER_HPP

#include <string>
#include "AESCrypt.hpp"

class PasswordManager {
public:
    PasswordManager(const std::string& masterPassword);
    void storePassword(const std::string& filename, const std::string& serviceName, const std::string& username, const std::string& password);
    std::string retrievePassword(const std::string& filename, const std::string& serviceName, const std::string& username);

private:
    AESCrypt aesCrypt;
};

#endif // PASSWORDMANAGER_HPP
