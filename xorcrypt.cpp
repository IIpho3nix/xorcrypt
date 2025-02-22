#include <iostream>
#include <fstream>
#include <vector>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <string>

void xorEncryptDecrypt(std::vector<unsigned char>& data, const std::vector<unsigned char>& key) {
    size_t keyLen = key.size();
    for (size_t i = 0; i < data.size(); ++i) {
        data[i] ^= key[i % keyLen];
    }
}

std::vector<unsigned char> parseHexKey(const std::string& hexString) {
    std::vector<unsigned char> key;
    std::istringstream iss(hexString);
    std::string byteStr;
    while (std::getline(iss, byteStr, ',')) {
        if (byteStr.find("0x") == 0 || byteStr.find("0X") == 0) {
            byteStr = byteStr.substr(2);
        }
        key.push_back(static_cast<unsigned char>(std::stoi(byteStr, nullptr, 16)));
    }
    return key;
}

std::vector<unsigned char> readFile(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Error reading file: " + filePath);
    }
    return std::vector<unsigned char>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

void writeFile(const std::string& filePath, const std::vector<unsigned char>& data) {
    std::ofstream file(filePath, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Error writing file: " + filePath);
    }
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
}

void printHelp() {
    std::cout << "Usage: xorcrypt -f <file_path> [-x <xor_key> | -xf <xor_file>] [-o <output_file>]\n"
              << "\n"
              << "Arguments:\n"
              << "  -f <file_path>       Input file path to encrypt or decrypt (required).\n"
              << "  -x <xor_key>         XOR key as a comma-separated list of hex values (e.g., 0x1f,0x2a).\n"
              << "  -xf <xor_file>       XOR key file containing raw bytes to use for XOR encryption.\n"
              << "  -o <output_file>     Output file path (optional).\n"
              << "  --help               Display this help message.\n"
              << "\n"
              << "Note: The XOR key file or hex key must be provided, not both.\n"
              << "      If using -x, specify a comma-separated list of hex values.\n"
              << "      If using -xf, provide a path to a file containing the XOR key in raw byte form.\n";
}

std::string getOutputFileName(const std::string& inputFile, const std::string& outputFile) {
    if (!outputFile.empty()) {
        return outputFile;
    }

    std::string outputPath = inputFile;
    if (outputPath.rfind(".xor") == outputPath.length() - 4) {
        outputPath = outputPath.substr(0, outputPath.length() - 4);
    } else {
        outputPath += ".xor";
    }
    return outputPath;
}

int main(int argc, char* argv[]) {
    std::string filePath, xorKey, xorFile, outputFile;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-f" && i + 1 < argc) {
            filePath = argv[++i];
        } else if (arg == "-x" && i + 1 < argc) {
            xorKey = argv[++i];
        } else if (arg == "-xf" && i + 1 < argc) {
            xorFile = argv[++i];
        } else if (arg == "-o" && i + 1 < argc) {
            outputFile = argv[++i];
        } else if (arg == "--help") {
            printHelp();
            return 0;
        }
    }
    
    if (filePath.empty()) {
        std::cerr << "Error: file path (-f) is required" << std::endl;
        return 1;
    }
    if (!xorKey.empty() && !xorFile.empty()) {
        std::cerr << "Error: -x and -xf are mutually exclusive" << std::endl;
        return 1;
    }
    if (xorKey.empty() && xorFile.empty()) {
        std::cerr << "Error: either -x or -xf must be provided" << std::endl;
        return 1;
    }
    
    try {
        std::vector<unsigned char> data = readFile(filePath);
        std::vector<unsigned char> key;
        
        if (!xorKey.empty()) {
            key = parseHexKey(xorKey);
        } else {
            key = readFile(xorFile);
        }
        
        xorEncryptDecrypt(data, key);
        
        std::string outputPath = getOutputFileName(filePath, outputFile);
        writeFile(outputPath, data);
        std::cout << "File successfully encrypted/decrypted: " << outputPath << std::endl;
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
