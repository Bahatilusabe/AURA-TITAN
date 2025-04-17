#include "encryption_module.h"
#include <iostream>
#include <cassert> // For assertions in unit tests

void testEncryptionDecryption() {
    std::cout << "Running Encryption and Decryption Test...\n";
    std::string plaintext = "Aura Titan Firewall - Secure Data";
    std::string key = AES256::generateKey();
    std::string iv;

    // Encrypt the plaintext
    std::string ciphertext = AES256::encrypt(plaintext, key, iv);
    std::cout << "Encrypted Ciphertext: " << ciphertext << "\n";

    // Decrypt the ciphertext
    std::string decryptedText = AES256::decrypt(ciphertext, key, iv);
    std::cout << "Decrypted Plaintext: " << decryptedText << "\n";

    // Assert that the decrypted text matches the original plaintext
    assert(decryptedText == plaintext && "Decryption failed: Decrypted text does not match plaintext.");
    std::cout << "Encryption and Decryption Test Passed.\n";
}

void testEdgeCases() {
    std::cout << "Running Edge Case Tests...\n";

    // Test with empty plaintext
    std::string emptyPlaintext = "";
    std::string key = AES256::generateKey();
    std::string iv;

    std::string emptyCiphertext = AES256::encrypt(emptyPlaintext, key, iv);
    std::string emptyDecryptedText = AES256::decrypt(emptyCiphertext, key, iv);
    assert(emptyDecryptedText == emptyPlaintext && "Decryption failed for empty plaintext.");
    std::cout << "Empty plaintext test passed.\n";

    // Test with very large plaintext
    std::string largePlaintext(10000, 'A'); // 10,000 'A's
    std::string largeCiphertext = AES256::encrypt(largePlaintext, key, iv);
    std::string largeDecryptedText = AES256::decrypt(largeCiphertext, key, iv);
    assert(largeDecryptedText == largePlaintext && "Decryption failed for large plaintext.");
    std::cout << "Large plaintext test passed.\n";

    // Test with non-ASCII characters
    std::string nonAsciiPlaintext = "🔥 Secure Data 🔒";
    std::string nonAsciiCiphertext = AES256::encrypt(nonAsciiPlaintext, key, iv);
    std::string nonAsciiDecryptedText = AES256::decrypt(nonAsciiCiphertext, key, iv);
    assert(nonAsciiDecryptedText == nonAsciiPlaintext && "Decryption failed for non-ASCII plaintext.");
    std::cout << "Non-ASCII plaintext test passed.\n";

    // Test with corrupted ciphertext
    try {
        std::string corruptedCiphertext = emptyCiphertext;
        corruptedCiphertext[0] ^= 0xFF; // Corrupt the first byte
        AES256::decrypt(corruptedCiphertext, key, iv);
        assert(false && "Decryption should fail for corrupted ciphertext.");
    } catch (const std::exception& e) {
        std::cout << "Corrupted ciphertext test passed: " << e.what() << "\n";
    }

    // Test with reused IV
    try {
        std::string reusedIvCiphertext = AES256::encrypt(largePlaintext, key, iv);
        std::string reusedIvDecryptedText = AES256::decrypt(reusedIvCiphertext, key, iv);
        assert(reusedIvDecryptedText == largePlaintext && "Decryption failed for reused IV.");
        std::cout << "Reused IV test passed (Note: Reusing IV is insecure).\n";
    } catch (const std::exception& e) {
        std::cout << "Reused IV test failed: " << e.what() << "\n";
    }
}

void testQuantumResistantPlaceholder() {
    std::cout << "Running Quantum-Resistant Placeholder Test...\n";

    // Generate public and private keys
    auto keyPair = QuantumResistant::generateKeyPair();
    std::string publicKey = keyPair.first;
    std::string privateKey = keyPair.second;

    // Simulate plaintext
    std::string plaintext = "Quantum-resistant test data";

    // Encrypt the plaintext
    try {
        auto encryptedData = QuantumResistant::encrypt(plaintext, publicKey);
        std::cout << "Encrypted Ciphertext: " << encryptedData.first << "\n";
        std::cout << "Encrypted Plaintext: " << encryptedData.second << "\n";

        // Decrypt the ciphertext
        std::string decryptedText = QuantumResistant::decrypt(encryptedData, privateKey);
        std::cout << "Decrypted Plaintext: " << decryptedText << "\n";

        assert(decryptedText == plaintext && "Decryption failed: Decrypted text does not match plaintext.");
        std::cout << "Quantum-resistant encryption and decryption test passed.\n";
    } catch (const std::exception& e) {
        std::cerr << "Quantum-resistant encryption test failed: " << e.what() << "\n";
    }
}

int main() {
    try {
        testEncryptionDecryption();
        testEdgeCases();
        testQuantumResistantPlaceholder();
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
    }

    return 0;
}