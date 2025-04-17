#include "dpi_module.h"
#include <iostream>
#include <regex>

// Function to inspect packet payload
bool inspectPacketPayload(const std::string& payload, const std::vector<std::string>& patterns) {
    for (const auto& pattern : patterns) {
        std::regex regexPattern(pattern);
        if (std::regex_search(payload, regexPattern)) {
            std::cout << "Match found for pattern: " << pattern << "\n";
            return true; // Block packet if a match is found
        }
    }
    return false; // Allow packet if no match is found
}

// Function to get default patterns for DPI
std::vector<std::string> getDefaultPatterns() {
    return {
        "malicious",             // Generic malicious keyword
        "unauthorized",          // Unauthorized access
        ".*DROP TABLE.*",        // SQL injection
        ".*<script>.*",          // Cross-site scripting (XSS)
        ".*password.*",          // Sensitive data leakage
        ".*SELECT .* FROM .*",   // SQL query detection
        ".*eval\\(.*\\).*",      // Code injection
        ".*admin.*",             // Admin access attempts
        ".*DELETE FROM .*",      // SQL deletion
        ".*INSERT INTO .*",      // SQL insertion
        ".*OR 1=1.*",            // SQL injection bypass
        ".*alert\\(.*\\).*",     // JavaScript alert (XSS)
        ".*base64_decode.*",     // PHP code injection
    };
}