#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <algorithm>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <cstring>

using namespace std;

struct UserInfo {
    string username;
    string password;
    string serviceName;
};

class User {
private:
    string masterPassword;
    vector<UserInfo> storedInfo;
public:

    const vector<UserInfo>& getStoredInfo() const {
        return storedInfo;
    }
    User(const string& password) : masterPassword(password) {}

    bool authenticate(const string& password) const {
        return masterPassword == password;
    }

    void addInfo(const string& username, const string& password, const string& serviceName) {
        // Encrypt password using AES before storing
        string encryptedPassword = aesEncrypt(password, masterPassword);
        storedInfo.push_back({username, encryptedPassword, serviceName});
    }

    void removeInfo(const string& serviceName) {
        auto it = remove_if(storedInfo.begin(), storedInfo.end(),
                            [&](const UserInfo& info) { return info.serviceName == serviceName; });
        storedInfo.erase(it, storedInfo.end());
    }

    void updateInfo(const string& serviceName, const string& newUsername, const string& newPassword) {
        for (auto& info : storedInfo) {
            if (info.serviceName == serviceName) {
                info.username = newUsername;
                // Encrypt new password using AES before updating
                info.password = aesEncrypt(newPassword, masterPassword);
                break;
            }
        }
    }

    void logout() {
        storedInfo.clear();
    }

    string aesEncrypt(const string& plaintext, const string& key) const {
        unsigned char iv[AES_BLOCK_SIZE];
        memset(iv, 0, AES_BLOCK_SIZE);

        AES_KEY aesKey;
        if (AES_set_encrypt_key((const unsigned char*)key.c_str(), 128, &aesKey) < 0) {
            cerr << "Error setting AES encryption key\n";
            exit(1);
        }

        int ciphertextLen = ((plaintext.length() - 1) / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;
        unsigned char ciphertext[ciphertextLen];

        AES_cbc_encrypt((const unsigned char*)plaintext.c_str(), ciphertext, plaintext.length(),
                        &aesKey, iv, AES_ENCRYPT);

        return string((char*)ciphertext, ciphertextLen);
    }

    static string aesDecrypt(const string& ciphertext, const string& key) {
        unsigned char iv[AES_BLOCK_SIZE];
        memset(iv, 0, AES_BLOCK_SIZE);

        AES_KEY aesKey;
        if (AES_set_decrypt_key((const unsigned char*)key.c_str(), 128, &aesKey) < 0) {
            cerr << "Error setting AES decryption key\n";
            exit(1);
        }

        int plaintextLen = ciphertext.length();
        unsigned char plaintext[plaintextLen];

        AES_cbc_encrypt((const unsigned char*)ciphertext.c_str(), plaintext, plaintextLen,
                        &aesKey, iv, AES_DECRYPT);

        return string((char*)plaintext);
    }

    void saveData(const string& filename) {
        ofstream file(filename);
        if (!file) {
            cerr << "Error opening file for writing\n";
            exit(1);
        }

        for (const auto& info : storedInfo) {
            file << info.username << ',' << info.password << ',' << info.serviceName << '\n';
        }

        file.close();
    }

    void loadData(const string& filename) {
        ifstream file(filename);
        if (!file) {
            cerr << "Error opening file for reading\n";
            exit(1);
        }

        storedInfo.clear();

        string line;
        while (getline(file, line)) {
            size_t pos1 = line.find(',');
            size_t pos2 = line.find(',', pos1 + 1);
            if (pos1 != string::npos && pos2 != string::npos) {
                string username = line.substr(0, pos1);
                string password = line.substr(pos1 + 1, pos2 - pos1 - 1);
                string serviceName = line.substr(pos2 + 1);
                storedInfo.push_back({username, password, serviceName});
            }
        }

        file.close();
    }

    const string& getMasterPassword() const {
        return masterPassword;
    }
};

vector<User> users;

void createNewUser() {
    string masterPassword;
    cout << "Enter master password for new user: ";
    cin >> masterPassword;
    User newUser(masterPassword);
    users.push_back(newUser);

    // Save user information to users.txt
    ofstream usersFile("users.txt", ios::app); // Append mode
    if (!usersFile) {
        cerr << "Error opening users file for writing\n";
        exit(1);
    }
    usersFile << newUser.getMasterPassword() << '\n';
    usersFile.close();

    // Save userdata file for the new user
    string encryptedFilename = encryptFilename(masterPassword);
    newUser.saveData(encryptedFilename);
}

User* loginUser() {
    string masterPassword;
    cout << "Enter master password: ";
    cin >> masterPassword;

    for (auto& user : users) {
        if (user.authenticate(masterPassword))
            return &user;
    }

    cout << "Invalid master password\n";
    return nullptr;
}

string encryptFilename(const string& username) {
    string encryptedFilename = username;
    // Encrypt the filename using a simple XOR cipher
    const char key = 'K'; // You can choose any character as a key
    for (char& c : encryptedFilename) {
        c = c ^ key;
    }
    return encryptedFilename + ".txt";
}

int main() {
    int choice;
    User* currentUser = nullptr;

    // Load existing users from users.txt
    ifstream usersFile("users.txt");
    if (usersFile) {
        string masterPassword;
        while (getline(usersFile, masterPassword)) {
            users.emplace_back(masterPassword);
        }
        usersFile.close();
    }

    while (true) {
        cout << "\n1. Login\n2. Create New User\n3. Exit\nEnter your choice: ";
        cin >> choice;

        switch (choice) {
            case 1:
                currentUser = loginUser();
                if (currentUser != nullptr) {
                    cout << "Login successful\n";
                    string encryptedFilename = encryptFilename(currentUser->getMasterPassword());
                    ifstream file(encryptedFilename);
                    if (!file.is_open()) {
                        // If user is logging in for the first time, create a new file
                        currentUser->saveData(encryptedFilename);
                    } else {
                        currentUser->loadData(encryptedFilename);
                    }
                    file.close();
                    while (true) {
                        cout << "\nLogged in Menu:\n"
                             << "1. Add Information\n"
                             << "2. Remove Information\n"
                             << "3. Update Information\n"
                             << "4. Logout\n"
                             << "5. View Password\n"
                             << "Enter your choice: ";
                        cin >> choice;
                        cin.ignore(); // Consume newline character left in buffer

                        switch (choice) {
                            case 1: {
                                string username, password, serviceName;
                                cout << "Enter username: ";
                                cin >> username;
                                cout << "Enter password: ";
                                cin >> password;
                                cout << "Enter service name: ";
                                cin >> serviceName;
                                currentUser->addInfo(username, password, serviceName);
                                cout << "Information added successfully\n";
                                break;
                            }
                            case 2: {
                                string serviceName;
                                cout << "Enter service name to remove: ";
                                cin >> serviceName;
                                currentUser->removeInfo(serviceName);
                                cout << "Information removed successfully\n";
                                break;
                            }
                            case 3: {
                                string serviceName, newUsername, newPassword;
                                cout << "Enter service name to update: ";
                                cin >> serviceName;
                                cout << "Enter new username: ";
                                cin >> newUsername;
                                cout << "Enter new password: ";
                                cin >> newPassword;
                                currentUser->updateInfo(serviceName, newUsername, newPassword);
                                cout << "Information updated successfully\n";
                                break;
                            }
                            case 4:
                                currentUser->saveData(encryptedFilename);
                                currentUser->logout();
                                currentUser = nullptr;
                                cout << "Logged out\n";
                                break;
                            case 5: {
                                cout << "Enter service name to view password: ";
                                string serviceName;
                                cin >> serviceName;
                                for (const auto& info : currentUser->getStoredInfo()) {
                                    if (info.serviceName == serviceName) {
                                        cout << "Password for " << serviceName << ": " << User::aesDecrypt(info.password, currentUser->getMasterPassword()) << endl;
                                        break;
                                    }
                                }
                                break;
                            }
                            default:
                                cout << "Invalid choice\n";
                        }

                        if (currentUser == nullptr)
                            break; // Break out of inner loop if logged out
                    }
                }
                break;
            case 2:
                createNewUser();
                break;
            case 3:
                cout << "Exiting...\n";
                return 0;
            default:
                cout << "Invalid choice\n";
        }
    }

    return 0;
}