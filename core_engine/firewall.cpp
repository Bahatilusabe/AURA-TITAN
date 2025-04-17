#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <bitset>
#include <ctime>
#include <regex>
#include <iomanip> // For timestamp formatting
#include "dpi_module.h" // Include the DPI module header
#include "encryption_module.h" // Include the encryption module header

// Function prototypes
bool isIPInRange(const std::string& ip, const std::string& range);
bool isTimeInRange(const std::string& timeRange);
bool isValidPort(const std::string& port);
void saveRulesToFile(const std::string& filename);
void loadRulesFromFile(const std::string& filename);
void managePatterns(); // Add this prototype
void readLogs(); // Add this prototype
void saveConfig(const std::string& configData, const std::string& filename); // Add this prototype
std::string loadConfig(const std::string& filename); // Add this prototype
void processPacket(Packet& packet); // Add this prototype

// Rule structure to define firewall rules
struct Rule {
    std::string sourceIP;
    std::string destinationIP;
    int sourcePort;
    int destinationPort;
    std::string protocol; // "TCP", "UDP", or "*"
    std::string action;   // "ALLOW" or "DENY"
    std::string timeRange; // Format: "HH:MM-HH:MM"
};

// Packet structure to represent incoming packets
struct Packet {
    std::string sourceIP;
    std::string destinationIP;
    int sourcePort;
    int destinationPort;
    std::string protocol; // "TCP" or "UDP"
    std::string payload;  // Packet payload for DPI
};

class Firewall {
private:
    std::vector<Rule> rules;
    std::ofstream logFile;

public:
    Firewall() {
        // Open a log file for recording packet activity
        logFile.open("firewall.log", std::ios::app);
        if (!logFile.is_open()) {
            std::cerr << "Error: Unable to open log file.\n";
        }
    }

    ~Firewall() {
        if (logFile.is_open()) {
            logFile.close();
        }
    }

    // Add a new rule to the firewall
    void addRule(const Rule& rule) {
        rules.push_back(rule);
    }

    // Remove a rule by index
    void removeRule(int index) {
        if (index >= 0 && index < rules.size()) {
            rules.erase(rules.begin() + index);
        } else {
            std::cerr << "Error: Invalid rule index.\n";
        }
    }

    // Check if a packet matches a rule
    bool isPacketAllowed(const Packet& packet) {
        for (const auto& rule : rules) {
            if ((rule.sourceIP == "*" || isIPInRange(packet.sourceIP, rule.sourceIP)) &&
                (rule.destinationIP == "*" || isIPInRange(packet.destinationIP, rule.destinationIP)) &&
                (rule.sourcePort == -1 || rule.sourcePort == packet.sourcePort) &&
                (rule.destinationPort == -1 || rule.destinationPort == packet.destinationPort) &&
                (rule.protocol == "*" || rule.protocol == packet.protocol) &&
                (rule.timeRange == "*" || isTimeInRange(rule.timeRange))) {
                
                // Inspect packet payload
                std::vector<std::string> patterns = getDefaultPatterns();
                for (const auto& pattern : patterns) {
                    if (inspectPacketPayload(packet.payload, {pattern})) {
                        logPacket(packet, "DENY", "Matched pattern: " + pattern);
                        return false; // Deny the packet
                    }
                }

                logPacket(packet, rule.action); // Log the packet
                return rule.action == "ALLOW";
            }
        }
        // Default action: deny if no rule matches
        logPacket(packet, "DENY", "No matching rule");
        return false;
    }

    // Display all rules
    void displayRules() const {
        std::cout << "Firewall Rules:\n";
        for (size_t i = 0; i < rules.size(); ++i) {
            const auto& rule = rules[i];
            std::cout << i << ": Source IP: " << rule.sourceIP
                      << ", Destination IP: " << rule.destinationIP
                      << ", Source Port: " << (rule.sourcePort == -1 ? "*" : std::to_string(rule.sourcePort))
                      << ", Destination Port: " << (rule.destinationPort == -1 ? "*" : std::to_string(rule.destinationPort))
                      << ", Protocol: " << rule.protocol
                      << ", Action: " << rule.action << "\n";
        }
    }

    // Log packet activity
    void logPacket(const Packet& packet, const std::string& action, const std::string& reason = "") {
        std::ofstream logFile("firewall.log", std::ios::app);
        if (logFile.is_open()) {
            // Add a timestamp to the log
            std::time_t now = std::time(nullptr);
            std::string logEntry = "[" + std::string(std::put_time(std::localtime(&now), "%Y-%m-%d %H:%M:%S")) + "] ";

            // Log packet details
            logEntry += "Packet: " + packet.sourceIP + " -> " + packet.destinationIP +
                        ", Source Port: " + std::to_string(packet.sourcePort) +
                        ", Destination Port: " + std::to_string(packet.destinationPort) +
                        ", Protocol: " + packet.protocol +
                        ", Action: " + action;

            // Log the reason if provided
            if (!reason.empty()) {
                logEntry += ", Reason: " + reason;
            }

            // Encrypt the log entry
            std::string iv;
            std::string encryptedLogEntry = AES256::encrypt(logEntry, logEncryptionKey, iv);

            // Write the encrypted log entry and IV to the file
            logFile << encryptedLogEntry << " " << iv << "\n";
            logFile.close();
        }
    }

    void saveRulesToFile(const std::string& filename) {
        std::ofstream file(filename);
        if (!file.is_open()) {
            std::cerr << "Error: Unable to open file " << filename << " for saving.\n";
            return;
        }
        for (const auto& rule : rules) {
            file << rule.sourceIP << " " << rule.destinationIP << " "
                 << (rule.sourcePort == -1 ? "*" : std::to_string(rule.sourcePort)) << " "
                 << (rule.destinationPort == -1 ? "*" : std::to_string(rule.destinationPort)) << " "
                 << rule.protocol << " " << rule.action << " " << rule.timeRange << "\n";
        }
        file.close();
        std::cout << "Rules saved to " << filename << ".\n";
    }
};

bool isIPInRange(const std::string& ip, const std::string& range);
bool isTimeInRange(const std::string& timeRange);
bool isValidPort(const std::string& port);

bool isIPInRange(const std::string& ip, const std::string& range) {
    size_t slashPos = range.find('/');
    if (slashPos == std::string::npos) {
        return ip == range; // Exact match
    }

    std::string baseIP = range.substr(0, slashPos);
    std::string prefixLengthStr = range.substr(slashPos + 1);

    // Validate prefix length
    if (!std::all_of(prefixLengthStr.begin(), prefixLengthStr.end(), ::isdigit)) {
        std::cerr << "Error: Invalid prefix length in range: " << range << "\n";
        return false;
    }

    int prefixLength = std::stoi(prefixLengthStr);
    if (prefixLength < 0 || prefixLength > 32) {
        std::cerr << "Error: Prefix length out of range (0-32): " << prefixLength << "\n";
        return false;
    }

    auto ipToBinary = [](const std::string& ip) -> std::bitset<32> {
        std::stringstream ss(ip);
        std::string segment;
        std::bitset<32> binaryIP;
        int shift = 24;

        while (std::getline(ss, segment, '.')) {
            if (!std::all_of(segment.begin(), segment.end(), ::isdigit)) {
                throw std::invalid_argument("Invalid IP segment: " + segment);
            }

            int num = std::stoi(segment);
            if (num < 0 || num > 255) {
                throw std::out_of_range("IP segment out of range (0-255): " + std::to_string(num));
            }

            binaryIP |= (num << shift);
            shift -= 8;
        }

        return binaryIP;
    };

    try {
        std::bitset<32> binaryIP = ipToBinary(ip);
        std::bitset<32> binaryBaseIP = ipToBinary(baseIP);

        return (binaryIP >> (32 - prefixLength)) == (binaryBaseIP >> (32 - prefixLength));
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << " in IP range: " << range << "\n";
        return false;
    }
}

bool isTimeInRange(const std::string& timeRange) {
    std::cout << "Checking time range: " << timeRange << "\n"; // Debugging output

    if (timeRange.empty()) {
        std::cerr << "Error: Empty time range.\n";
        return false;
    }

    if (timeRange == "*") return true; // Wildcard matches any time

    std::time_t now = std::time(nullptr);
    std::tm* localTime = std::localtime(&now);

    int currentMinutes = localTime->tm_hour * 60 + localTime->tm_min;

    size_t dashPos = timeRange.find('-');
    if (dashPos == std::string::npos) {
        std::cerr << "Error: Invalid time range format: " << timeRange << "\n";
        return false;
    }

    std::string startTime = timeRange.substr(0, dashPos);
    std::string endTime = timeRange.substr(dashPos + 1);

    if (startTime.size() != 5 || endTime.size() != 5 || startTime[2] != ':' || endTime[2] != ':') {
        std::cerr << "Error: Invalid time format in range: " << timeRange << "\n";
        return false;
    }

    try {
        int startMinutes = std::stoi(startTime.substr(0, 2)) * 60 + std::stoi(startTime.substr(3, 2));
        int endMinutes = std::stoi(endTime.substr(0, 2)) * 60 + std::stoi(endTime.substr(3, 2));

        return currentMinutes >= startMinutes && currentMinutes <= endMinutes;
    } catch (const std::invalid_argument& e) {
        std::cerr << "Error: Invalid time value in range: " << timeRange << "\n";
        return false;
    }
}

bool isValidPort(const std::string& port) {
    if (port == "*" || port == "-1") return true; // Wildcard or any port
    if (!std::all_of(port.begin(), port.end(), ::isdigit)) return false; // Check if all characters are digits

    try {
        int portNum = std::stoi(port);
        return portNum >= 0 && portNum <= 65535; // Check if port is within valid range
    } catch (const std::exception&) {
        return false; // Handle any conversion errors
    }
}

void loadRulesFromFile(Firewall& firewall, const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Error: Unable to open file " << filename << "\n";
        return;
    }

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty()) {
            std::cout << "Skipping blank line.\n";
            continue;
        }

        std::istringstream iss(line);
        Rule rule;
        std::string sourcePort, destinationPort;

        if (!(iss >> rule.sourceIP >> rule.destinationIP >> sourcePort >> destinationPort >> rule.protocol >> rule.action)) {
            std::cerr << "Error: Malformed rule. Skipping line: " << line << "\n";
            continue;
        }

        if (!(iss >> rule.timeRange) || rule.timeRange.empty()) {
            rule.timeRange = "*"; // Default to wildcard if timeRange is missing
        }

        try {
            // Debugging: Print the raw data being processed
            std::cout << "Raw data: " << rule.sourceIP << " " << rule.destinationIP << " "
                      << sourcePort << " " << destinationPort << " " << rule.protocol << " " << rule.action
                      << " " << rule.timeRange << "\n";

            // Validate and parse ports
            if (!isValidPort(sourcePort) || !isValidPort(destinationPort)) {
                throw std::invalid_argument("Invalid port value");
            }
            rule.sourcePort = (sourcePort == "*" || sourcePort == "-1") ? -1 : std::stoi(sourcePort);
            rule.destinationPort = (destinationPort == "*" || destinationPort == "-1") ? -1 : std::stoi(destinationPort);

            // Debugging: Print after port parsing
            std::cout << "Parsed ports: " << rule.sourcePort << ", " << rule.destinationPort << "\n";

            // Validate protocol
            if (rule.protocol != "TCP" && rule.protocol != "UDP" && rule.protocol != "*") {
                throw std::invalid_argument("Invalid protocol");
            }

            // Validate action
            if (rule.action != "ALLOW" && rule.action != "DENY") {
                throw std::invalid_argument("Invalid action");
            }

            // Add the rule to the firewall
            firewall.addRule(rule);
            std::cout << "Rule added successfully.\n";
        } catch (const std::invalid_argument& e) {
            std::cerr << "Error: " << e.what() << ". Skipping rule: " << line << "\n";
        }
    }

    file.close();
}

void interactiveMenu(Firewall& firewall) {
    int choice;
    do {
        std::cout << "\nFirewall Menu:\n";
        std::cout << "1. Add Rule\n";
        std::cout << "2. Remove Rule\n";
        std::cout << "3. Display Rules\n";
        std::cout << "4. Manage Patterns\n"; // New option
        std::cout << "5. Read Logs\n"; // New option
        std::cout << "6. Exit\n";
        std::cout << "Enter your choice: ";
        std::cin >> choice;

        switch (choice) {
            case 1: {
                Rule newRule;
                std::cout << "Enter source IP (or *): ";
                std::cin >> newRule.sourceIP;
                std::cout << "Enter destination IP (or *): ";
                std::cin >> newRule.destinationIP;
                std::cout << "Enter source port (-1 for any): ";
                std::cin >> newRule.sourcePort;
                std::cout << "Enter destination port (-1 for any): ";
                std::cin >> newRule.destinationPort;
                std::cout << "Enter protocol (TCP/UDP/*): ";
                std::cin >> newRule.protocol;
                std::cout << "Enter action (ALLOW/DENY): ";
                std::cin >> newRule.action;
                firewall.addRule(newRule);
                break;
            }
            case 2: {
                int index;
                std::cout << "Enter rule index to remove: ";
                std::cin >> index;
                firewall.removeRule(index);
                break;
            }
            case 3: {
                firewall.displayRules();
                break;
            }
            case 4: {
                managePatterns();
                break;
            }
            case 5: {
                readLogs();
                break;
            }
        }
    } while (choice != 6);
}

int main() {
    Firewall firewall;

    // Add some rules
    firewall.addRule({"192.168.1.1", "10.0.0.1", 80, 443, "TCP", "ALLOW", "*"});
    firewall.addRule({"*", "*", -1, -1, "*", "DENY", "*"}); // Default deny rule

    // Add more rules
    firewall.addRule({"192.168.2.1", "10.0.0.2", 1234, 80, "UDP", "ALLOW", "08:00-18:00"}); // Allow UDP packets from 192.168.2.1 to 10.0.0.2
    firewall.addRule({"10.0.0.3", "192.168.1.2", -1, 22, "TCP", "ALLOW", "09:00-17:00"});  // Allow TCP packets to port 22 (SSH) from 10.0.0.3
    firewall.addRule({"*", "10.0.0.4", -1, 443, "TCP", "DENY", "*"});            // Deny all TCP packets to 10.0.0.4 on port 443

    // Load rules from file
    loadRulesFromFile(firewall, "firewall_rules.txt");

    // Display rules
    firewall.displayRules();

    // Test packets
    Packet packet1 = {"192.168.1.1", "10.0.0.1", 80, 443, "TCP", "This is a harmless payload."};
    Packet packet2 = {"192.168.2.1", "10.0.0.2", 1234, 80, "UDP", "This payload contains malicious content."};

    if (firewall.isPacketAllowed(packet1)) {
        std::cout << "Packet 1 allowed.\n";
    } else {
        std::cout << "Packet 1 denied.\n";
    }

    if (firewall.isPacketAllowed(packet2)) {
        std::cout << "Packet 2 allowed.\n";
    } else {
        std::cout << "Packet 2 denied.\n";
    }

    // Test new packets
    Packet packet3 = {"192.168.2.1", "10.0.0.2", 1234, 80, "UDP"}; // Matches rule 2
    Packet packet4 = {"10.0.0.3", "192.168.1.2", 5678, 22, "TCP"}; // Matches rule 3
    Packet packet5 = {"192.168.1.5", "10.0.0.4", 8080, 443, "TCP"}; // Matches rule 4

    if (firewall.isPacketAllowed(packet3)) {
        std::cout << "Packet 3 allowed.\n";
    } else {
        std::cout << "Packet 3 denied.\n";
    }

    if (firewall.isPacketAllowed(packet4)) {
        std::cout << "Packet 4 allowed.\n";
    } else {
        std::cout << "Packet 4 denied.\n";
    }

    if (firewall.isPacketAllowed(packet5)) {
        std::cout << "Packet 5 allowed.\n";
    } else {
        std::cout << "Packet 5 denied.\n";
    }

    interactiveMenu(firewall);

    return 0;
}

// Encryption key for logs (should be securely stored in production)
std::string logEncryptionKey = AES256::generateKey();

void logPacket(const Packet& packet, const std::string& action, const std::string& reason = "") {
    std::ofstream logFile("firewall.log", std::ios::app);
    if (logFile.is_open()) {
        // Add a timestamp to the log
        std::time_t now = std::time(nullptr);
        std::string logEntry = "[" + std::string(std::put_time(std::localtime(&now), "%Y-%m-%d %H:%M:%S")) + "] ";

        // Log packet details
        logEntry += "Packet: " + packet.sourceIP + " -> " + packet.destinationIP +
                    ", Source Port: " + std::to_string(packet.sourcePort) +
                    ", Destination Port: " + std::to_string(packet.destinationPort) +
                    ", Protocol: " + packet.protocol +
                    ", Action: " + action;

        // Log the reason if provided
        if (!reason.empty()) {
            logEntry += ", Reason: " + reason;
        }

        // Encrypt the log entry
        std::string iv;
        std::string encryptedLogEntry = AES256::encrypt(logEntry, logEncryptionKey, iv);

        // Write the encrypted log entry and IV to the file
        logFile << encryptedLogEntry << " " << iv << "\n";
        logFile.close();
    }
}

void readLogs() {
    std::ifstream logFile("firewall.log");
    if (logFile.is_open()) {
        std::string encryptedLogEntry, iv;
        while (logFile >> encryptedLogEntry >> iv) {
            try {
                // Decrypt the log entry
                std::string decryptedLogEntry = AES256::decrypt(encryptedLogEntry, logEncryptionKey, iv);
                std::cout << decryptedLogEntry << "\n";
            } catch (const std::exception& e) {
                std::cerr << "Failed to decrypt log entry: " << e.what() << "\n";
            }
        }
        logFile.close();
    }
}

#include "dpi_module.h"
#include <iostream>
#include <vector>

// Global patterns vector
std::vector<std::string> patterns = getDefaultPatterns();

// Function to manage patterns
void managePatterns() {
    int choice;
    do {
        std::cout << "\nPattern Management Menu:\n";
        std::cout << "1. View Patterns\n";
        std::cout << "2. Add Pattern\n";
        std::cout << "3. Remove Pattern\n";
        std::cout << "4. Back to Main Menu\n";
        std::cout << "Enter your choice: ";
        std::cin >> choice;

        switch (choice) {
            case 1: {
                std::cout << "Current Patterns:\n";
                for (size_t i = 0; i < patterns.size(); ++i) {
                    std::cout << i + 1 << ". " << patterns[i] << "\n";
                }
                break;
            }
            case 2: {
                std::string newPattern;
                std::cout << "Enter new pattern: ";
                std::cin.ignore();
                std::getline(std::cin, newPattern);
                patterns.push_back(newPattern);
                std::cout << "Pattern added successfully.\n";
                break;
            }
            case 3: {
                size_t index;
                std::cout << "Enter pattern number to remove: ";
                std::cin >> index;
                if (index > 0 && index <= patterns.size()) {
                    patterns.erase(patterns.begin() + index - 1);
                    std::cout << "Pattern removed successfully.\n";
                } else {
                    std::cout << "Invalid pattern number.\n";
                }
                break;
            }
            case 4:
                std::cout << "Returning to main menu...\n";
                break;
            default:
                std::cout << "Invalid choice. Try again.\n";
        }
    } while (choice != 4);
}

void saveConfig(const std::string& configData, const std::string& filename) {
    std::ofstream configFile(filename, std::ios::binary);
    if (configFile.is_open()) {
        std::string iv;
        std::string encryptedConfig = AES256::encrypt(configData, logEncryptionKey, iv);
        configFile << encryptedConfig << " " << iv;
        configFile.close();
    }
}

std::string loadConfig(const std::string& filename) {
    std::ifstream configFile(filename, std::ios::binary);
    if (configFile.is_open()) {
        std::string encryptedConfig, iv;
        configFile >> encryptedConfig >> iv;
        configFile.close();
        return AES256::decrypt(encryptedConfig, logEncryptionKey, iv);
    }
    throw std::runtime_error("Failed to load configuration file.");
}

void processPacket(Packet& packet) {
    // Encrypt the packet payload
    std::string iv;
    packet.payload = AES256::encrypt(packet.payload, logEncryptionKey, iv);

    // Process the packet (e.g., apply firewall rules)
    // ...

    // Decrypt the packet payload if needed
    packet.payload = AES256::decrypt(packet.payload, logEncryptionKey, iv);
}