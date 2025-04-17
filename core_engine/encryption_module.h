#ifndef ENCRYPTION_MODULE_H
#define ENCRYPTION_MODULE_H

#include <string>
#include <utility> // For std::pair

namespace AES256 {
    std::string generateKey();
    std::string encrypt(const std::string& plaintext, const std::string& key, std::string& iv);
    std::string decrypt(const std::string& ciphertext, const std::string& key, const std::string& iv);
}

namespace QuantumResistant {
    std::pair<std::string, std::string> encrypt(const std::string& plaintext, const std::string& publicKey);
    std::string decrypt(const std::pair<std::string, std::string>& encryptedData, const std::string& privateKey);
    std::pair<std::string, std::string> generateKeyPair(); // Add this declaration
}

#endif // ENCRYPTION_MODULE_H