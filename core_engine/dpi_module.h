#ifndef DPI_MODULE_H
#define DPI_MODULE_H

#include <string>
#include <vector>

// Function prototype for inspecting packet payload
bool inspectPacketPayload(const std::string& payload, const std::vector<std::string>& patterns);

// Function prototype for getting default patterns
std::vector<std::string> getDefaultPatterns();

#endif // DPI_MODULE_H