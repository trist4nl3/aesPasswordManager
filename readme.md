# Password Manager
###Description
A simple CLI based made in C++. Utilises AES Encryption to protect passwords as well as a master key for access.

## Features
- AES Encryption
- Master key authentication
- Local encryption storage
- Master Key generation
- Ability Add/Remove/Update serviceName, Usernames and passwords
- Local storage

## Planned Features
- [ ] Known bug where the data would sometime be deleted after exisiting due to decryption errors
- [ ] Converting storage from local to SQLite to implement multiple users towards the application
- [ ] A Desktop GUI
- [ ] Potential Web GUI



## Installation
To run this project locally


1. Clone the repository and build the project
Make sure you have a valid complier to run this
```
g++ -o passwordManager main.cpp -lssl -lcrypto -mconsole
```

2. Requires OpenSSL library
```
Depending on your device
```
3. Run compile the exe file
```
./passwordManager
```

## Contribution
Feel free to contribute!

## License
This project is licensed under the MIT Licence

## Acknowledgements
- OpenSSL
