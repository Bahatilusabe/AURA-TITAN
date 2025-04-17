#include "encryption_module.h"
#include <iostream>
#include <stdexcept>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <oqs/oqs.h>
#include <vector> // Include the vector header
#include <cassert> // Include the cassert header for assert

// AES-256 Encryption and Decryption
namespace AES256 {
    const int KEY_SIZE = 32; // 256 bits
    const int BLOCK_SIZE = 16; // 128 bits

    // Generate a random AES key
    std::string generateKey() {
        unsigned char key[KEY_SIZE];
        if (!RAND_bytes(key, KEY_SIZE)) {
            throw std::runtime_error("Failed to generate random AES key.");
        }
        return std::string(reinterpret_cast<char*>(key), KEY_SIZE);
    }

    // Encrypt data using AES-256-CBC
    std::string encrypt(const std::string& plaintext, const std::string& key, std::string& iv) {
        if (key.size() != KEY_SIZE) {
            throw std::invalid_argument("Invalid key size for AES-256 encryption.");
        }

        unsigned char ivBuffer[BLOCK_SIZE];
        if (!RAND_bytes(ivBuffer, BLOCK_SIZE)) {
            throw std::runtime_error("Failed to generate random IV.");
        }
        iv = std::string(reinterpret_cast<char*>(ivBuffer), BLOCK_SIZE);

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            throw std::runtime_error("Failed to create EVP_CIPHER_CTX.");
        }

        std::string ciphertext(plaintext.size() + BLOCK_SIZE, '\0');
        int len = 0, ciphertextLen = 0;

        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
                               reinterpret_cast<const unsigned char*>(key.data()),
                               reinterpret_cast<const unsigned char*>(iv.data())) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize AES-256 encryption.");
        }

        if (EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char*>(&ciphertext[0]), &len,
                              reinterpret_cast<const unsigned char*>(plaintext.data()),
                              plaintext.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to encrypt data.");
        }
        ciphertextLen = len;

        if (EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&ciphertext[0]) + len, &len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to finalize AES-256 encryption.");
        }
        ciphertextLen += len;

        EVP_CIPHER_CTX_free(ctx);
        ciphertext.resize(ciphertextLen);
        return ciphertext;
    }

    // Decrypt data using AES-256-CBC
    std::string decrypt(const std::string& ciphertext, const std::string& key, const std::string& iv) {
        if (key.size() != KEY_SIZE) {
            throw std::invalid_argument("Invalid key size for AES-256 decryption.");
        }
        if (iv.size() != BLOCK_SIZE) {
            throw std::invalid_argument("Invalid IV size for AES-256 decryption.");
        }

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            throw std::runtime_error("Failed to create EVP_CIPHER_CTX.");
        }

        std::string plaintext(ciphertext.size(), '\0');
        int len = 0, plaintextLen = 0;

        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr,
                               reinterpret_cast<const unsigned char*>(key.data()),
                               reinterpret_cast<const unsigned char*>(iv.data())) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to initialize AES-256 decryption.");
        }

        if (EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(&plaintext[0]), &len,
                              reinterpret_cast<const unsigned char*>(ciphertext.data()),
                              ciphertext.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to decrypt data.");
        }
        plaintextLen = len;

        if (EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&plaintext[0]) + len, &len) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("Failed to finalize AES-256 decryption.");
        }
        plaintextLen += len;

        EVP_CIPHER_CTX_free(ctx);
        plaintext.resize(plaintextLen);
        return plaintext;
    }
}

// Quantum-Resistant Encryption
namespace QuantumResistant {
    std::pair<std::string, std::string> encrypt(const std::string& plaintext, const std::string& publicKey) {
        OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
        if (!kem) {
            throw std::runtime_error("Failed to initialize Kyber KEM.");
        }

        std::vector<uint8_t> ciphertext(kem->length_ciphertext);
        std::vector<uint8_t> sharedSecret(kem->length_shared_secret);

        if (OQS_KEM_encaps(kem, ciphertext.data(), sharedSecret.data(),
                           reinterpret_cast<const uint8_t*>(publicKey.data())) != OQS_SUCCESS) {
            OQS_KEM_free(kem);
            throw std::runtime_error("Kyber encryption failed.");
        }

        OQS_KEM_free(kem);

        // Combine the shared secret with the plaintext (e.g., XOR for simplicity)
        std::string encryptedPlaintext = plaintext;
        for (size_t i = 0; i < plaintext.size(); ++i) {
            encryptedPlaintext[i] ^= sharedSecret[i % sharedSecret.size()];
        }

        return {std::string(ciphertext.begin(), ciphertext.end()), encryptedPlaintext};
    }

    std::string decrypt(const std::pair<std::string, std::string>& encryptedData, const std::string& privateKey) {
        OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
        if (!kem) {
            throw std::runtime_error("Failed to initialize Kyber KEM.");
        }

        std::vector<uint8_t> sharedSecret(kem->length_shared_secret);

        if (OQS_KEM_decaps(kem, sharedSecret.data(),
                           reinterpret_cast<const uint8_t*>(encryptedData.first.data()),
                           reinterpret_cast<const uint8_t*>(privateKey.data())) != OQS_SUCCESS) {
            OQS_KEM_free(kem);
            throw std::runtime_error("Kyber decryption failed.");
        }

        OQS_KEM_free(kem);

        // Decrypt the plaintext using the shared secret
        std::string decryptedPlaintext = encryptedData.second;
        for (size_t i = 0; i < decryptedPlaintext.size(); ++i) {
            decryptedPlaintext[i] ^= sharedSecret[i % sharedSecret.size()];
        }

        return decryptedPlaintext;
    }

    std::pair<std::string, std::string> generateKeyPair() {
        OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
        if (!kem) {
            throw std::runtime_error("Failed to initialize Kyber KEM.");
        }

        std::vector<uint8_t> publicKey(kem->length_public_key);
        std::vector<uint8_t> privateKey(kem->length_secret_key);

        if (OQS_KEM_keypair(kem, publicKey.data(), privateKey.data()) != OQS_SUCCESS) {
            OQS_KEM_free(kem);
            throw std::runtime_error("Failed to generate Kyber key pair.");
        }

        OQS_KEM_free(kem);

        return {std::string(publicKey.begin(), publicKey.end()), std::string(privateKey.begin(), privateKey.end())};
    }
}