#include <iostream>
#include <fstream>
#include <vector>
#include <sstream>
#include <iomanip>
#include <string>
#include <random>

bool xorEncryptDecrypt(std::vector<unsigned char>& data, const std::vector<unsigned char>& key) {
    if (key.empty()) {
        std::cerr << "Error: XOR key is empty.\n";
        return false;
    }
    size_t keyLen = key.size();
    for (size_t i = 0; i < data.size(); ++i) {
        data[i] ^= key[i % keyLen];
    }
    return true;
}

bool parseHexKey(const std::string& hexString, std::vector<unsigned char>& key) {
    std::istringstream iss(hexString);
    std::string byteStr;
    while (std::getline(iss, byteStr, ',')) {
        if (byteStr.find("0x") == 0 || byteStr.find("0X") == 0) {
            byteStr = byteStr.substr(2);
        }
        int byteVal;
        if (!(std::istringstream(byteStr) >> std::hex >> byteVal)) {
            std::cerr << "Error: Invalid hex value '" << byteStr << "' in key.\n";
            return false;
        }
        key.push_back(static_cast<unsigned char>(byteVal));
    }
    return true;
}

bool readFile(const std::string& filePath, std::vector<unsigned char>& data) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        std::cerr << "Error: Could not open file '" << filePath << "' for reading.\n";
        return false;
    }
    data.assign((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    return true;
}

bool writeFile(const std::string& filePath, const std::vector<unsigned char>& data) {
    std::ofstream file(filePath, std::ios::binary);
    if (!file) {
        std::cerr << "Error: Could not open file '" << filePath << "' for writing.\n";
        return false;
    }
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    return true;
}

void printHelp() {
    std::cout << "Usage: xorcrypt -f <file_path> [-x <xor_key> | -xf <xor_file>] [-o <output_file>] [-g <bytes>]\n"
              << "\n"
              << "Arguments:\n"
              << "  -f <file_path>       Input file path to encrypt or decrypt (required, unless using -g).\n"
              << "  -x <xor_key>         XOR key as a comma-separated list of hex values (e.g., 0x1f,0x2a).\n"
              << "  -xf <xor_file>       XOR key file containing raw bytes to use for XOR encryption.\n"
              << "  -o <output_file>     Output file path (optional).\n"
              << "  -g <bytes>           Generate a specified amount of random bytes. Ignores all other options except -o.\n"
              << "  --help               Display this help message.\n";
}

std::string getOutputFileName(const std::string& inputFile, const std::string& outputFile) {
    if (!outputFile.empty()) {
        return outputFile;
    }
    return (inputFile.rfind(".xor") == inputFile.length() - 4) ? inputFile.substr(0, inputFile.length() - 4) : inputFile + ".xor";
}

void generateRandomBytes(size_t numBytes, std::vector<unsigned char>& data) {
    data.resize(numBytes);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<unsigned char> dist(0, 255);
    for (size_t i = 0; i < numBytes; ++i) {
        data[i] = dist(gen);
    }
}

int main(int argc, char* argv[]) {
    std::string filePath, xorKey, xorFile, outputFile;
    size_t generateBytes = 0;

    if (argc == 1) {
        printHelp();
        return 0;
    }

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
        } else if (arg == "-g" && i + 1 < argc) {
            generateBytes = std::stoul(argv[++i]);
        } else if (arg == "--help") {
            printHelp();
            return 0;
        }
    }

    if (generateBytes > 0) {
        std::vector<unsigned char> data;
        generateRandomBytes(generateBytes, data);
        if (!outputFile.empty()) {
            if (!writeFile(outputFile, data)) return 1;
            std::cout << "Generated " << generateBytes << " random bytes and saved to: " << outputFile << "\n";
        } else {
            for (size_t i = 0; i < data.size(); ++i) {
                if (i > 0) std::cout << ",";
                std::cout << "0x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
            }
            std::cout << "\n";
        }
        return 0;
    }

    if (filePath.empty()) {
        std::cerr << "Error: file path (-f) is required\n";
        return 1;
    }
    if (!xorKey.empty() && !xorFile.empty()) {
        std::cerr << "Error: -x and -xf are mutually exclusive\n";
        return 1;
    }
    if (xorKey.empty() && xorFile.empty()) {
        std::cerr << "Error: either -x or -xf must be provided\n";
        return 1;
    }

    std::vector<unsigned char> data, key;
    if (!readFile(filePath, data)) return 1;

    if (!xorKey.empty()) {
        if (!parseHexKey(xorKey, key)) return 1;
    } else {
        if (!readFile(xorFile, key)) return 1;
    }

    if (!xorEncryptDecrypt(data, key)) return 1;

    std::string outputPath = getOutputFileName(filePath, outputFile);
    if (!writeFile(outputPath, data)) return 1;

    std::cout << "File successfully encrypted/decrypted: " << outputPath << "\n";
    return 0;
}
