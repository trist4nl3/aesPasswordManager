
#include "PasswordManager.hpp"
#include <iostream>
#include <cstdlib> // For exit()

int main() {
    std::string masterPassword;
    std::cout << "Enter master password: ";
    std::getline(std::cin, masterPassword);

    PasswordManager passwordManager(masterPassword);

    // Main menu loop
    while (true) {
        std::cout << "\nOptions:\n1. Store password\n2. Retrieve password\n3. Exit\n";
        int choice;
        std::cout << "Enter your choice: ";
        std::cin >> choice;
        std::cin.ignore(); // Clear the input buffer

        switch (choice) {
            case 1: {
                std::string serviceName, username, password;
                std::cout << "Enter service name: ";
                std::getline(std::cin, serviceName);
                std::cout << "Enter username: ";
                std::getline(std::cin, username);
                std::cout << "Enter password: ";
                std::getline(std::cin, password);
                passwordManager.storePassword("passwords.dat", serviceName, username, password);
                std::cout << "Password stored successfully!\n";
                break;
            }
            case 2: {
                std::string serviceName, username;
                std::cout << "Enter service name: ";
                std::getline(std::cin, serviceName);
                std::cout << "Enter username: ";
                std::getline(std::cin, username);
                std::string password = passwordManager.retrievePassword("passwords.dat", serviceName, username);
                if (!password.empty()) {
                    std::cout << "Retrieved password: " << password << std::endl;
                } else {
                    std::cout << "Password not found!\n";
                }
                break;
            }
            case 3: {
                std::cout << "Exiting program.\n";
                exit(0); // Exit the program
            }
            default:
                std::cout << "Invalid choice. Please enter a valid option.\n";
        }
    }

    return 0;
}