// main.cpp
// C++14-compatible Local File Encryption Vault (XOR-based, educational)
// Compile with: -std=c++14
// Portable directory traversal:
//   - Windows: uses FindFirstFileA / FindNextFileA
//   - Unix: uses opendir / readdir

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <sstream>
#include <functional>
#include <chrono>
#include <algorithm>
#include <cstdint>
#include <sys/types.h>
#include <sys/stat.h>

#if defined(_WIN32)
  #include <windows.h>
#else
  #include <dirent.h>
  #include <unistd.h>
#endif

using byte = unsigned char;

// --- Helpers for path and file checks (portable) ---
bool file_exists(const std::string &path) {
    std::ifstream f(path.c_str(), std::ios::binary);
    return (bool)f;
}

bool is_regular_file(const std::string &path) {
    struct stat st;
    if (stat(path.c_str(), &st) != 0) return false;
#if defined(_WIN32)
    return (st.st_mode & _S_IFREG) != 0;
#else
    return S_ISREG(st.st_mode);
#endif
}

std::string join_path(const std::string &a, const std::string &b) {
#if defined(_WIN32)
    char sep = '\\';
#else
    char sep = '/';
#endif
    if (a.empty()) return b;
    if (a.back() == sep) return a + b;
    return a + sep + b;
}

std::string get_extension(const std::string &p) {
    auto pos = p.find_last_of('.');
    if (pos == std::string::npos) return "";
    return p.substr(pos); // includes dot
}

std::string filename_from_path(const std::string &p) {
    auto pos1 = p.find_last_of("/\\");
    if (pos1 == std::string::npos) return p;
    return p.substr(pos1 + 1);
}

std::string parent_path(const std::string &p) {
    auto pos1 = p.find_last_of("/\\");
    if (pos1 == std::string::npos) return ".";
    return p.substr(0, pos1);
}

// --- Key derivation and XOR ---
std::vector<byte> derive_key(const std::string &password, size_t key_len = 4096, unsigned iterations = 1000) {
    std::vector<byte> key;
    key.reserve(key_len);
    std::string state = password;
    std::hash<std::string> hasher;
    for (size_t i = 0; key.size() < key_len; ++i) {
        std::ostringstream oss;
        oss << state << '|' << i << '|' << (i * 1103515245u + 12345u);
        std::string mixed = oss.str();
        size_t h = hasher(mixed);
        for (unsigned it = 0; it < iterations; ++it) {
            std::ostringstream oss2;
            oss2 << h << '|' << it;
            h = hasher(oss2.str());
        }
        for (size_t b = 0; b < sizeof(size_t) && key.size() < key_len; ++b) {
            key.push_back(static_cast<byte>((h >> (8 * b)) & 0xFF));
        }
    }
    return key;
}

void xor_crypt_buffer(std::vector<byte> &buf, const std::vector<byte> &key, size_t offset = 0) {
    size_t keylen = key.size();
    if (keylen == 0) return;
    for (size_t i = 0; i < buf.size(); ++i) {
        buf[i] = buf[i] ^ key[(offset + i) % keylen];
    }
}

// --- Encrypt / Decrypt single files (paths as strings) ---
bool encrypt_file(const std::string &input_path, const std::string &password, bool remove_original = false) {
    try {
        if (!file_exists(input_path) || !is_regular_file(input_path)) {
            std::cerr << "Input is not a regular file: " << input_path << "\n";
            return false;
        }
        std::ifstream in(input_path.c_str(), std::ios::binary);
        if (!in) { std::cerr << "Failed to open input: " << input_path << "\n"; return false; }

        std::vector<byte> buffer((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        in.close();

        auto key = derive_key(password, 8192, 500);

        std::string header_magic = "VLT1";
        std::string orig_name = filename_from_path(input_path);
        std::vector<byte> outbuf;
        for (char c : header_magic) outbuf.push_back(static_cast<byte>(c));
        uint32_t name_len = static_cast<uint32_t>(orig_name.size());
        for (int i = 0; i < 4; ++i) outbuf.push_back(static_cast<byte>((name_len >> (8 * i)) & 0xFF));
        for (char c : orig_name) outbuf.push_back(static_cast<byte>(c));
        outbuf.insert(outbuf.end(), buffer.begin(), buffer.end());

        xor_crypt_buffer(outbuf, key, 0);

        std::string outpath = input_path + ".vault";
        std::ofstream out(outpath.c_str(), std::ios::binary);
        if (!out) { std::cerr << "Failed to open output: " << outpath << "\n"; return false; }
        out.write(reinterpret_cast<const char*>(outbuf.data()), static_cast<std::streamsize>(outbuf.size()));
        out.close();

        if (remove_original) {
            if (std::remove(input_path.c_str()) != 0) {
                std::cerr << "Warning: failed to remove original file: " << input_path << "\n";
            }
        }

        std::cout << "Encrypted: " << input_path << " -> " << outpath << "\n";
        return true;
    } catch (const std::exception &e) {
        std::cerr << "Exception encrypt_file: " << e.what() << "\n";
        return false;
    }
}

bool decrypt_file(const std::string &input_path, const std::string &password, bool remove_original = false) {
    try {
        if (!file_exists(input_path) || !is_regular_file(input_path)) {
            std::cerr << "Input is not a regular file: " << input_path << "\n";
            return false;
        }
        std::ifstream in(input_path.c_str(), std::ios::binary);
        if (!in) { std::cerr << "Failed to open input: " << input_path << "\n"; return false; }

        std::vector<byte> buffer((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        in.close();

        auto key = derive_key(password, 8192, 500);
        xor_crypt_buffer(buffer, key, 0);

        if (buffer.size() < 8) { std::cerr << "File too small or wrong format.\n"; return false; }
        std::string magic;
        for (int i = 0; i < 4; ++i) magic.push_back(static_cast<char>(buffer[i]));
        if (magic != "VLT1") {
            std::cerr << "Header magic mismatch - wrong password or not a vault file.\n";
            return false;
        }
        uint32_t name_len = 0;
        for (int i = 0; i < 4; ++i) {
            name_len |= (static_cast<uint32_t>(buffer[4 + i]) << (8 * i));
        }
        if (buffer.size() < 8 + name_len) { std::cerr << "Corrupt file or wrong header length.\n"; return false; }

        std::string orig_name;
        orig_name.reserve(name_len);
        for (uint32_t i = 0; i < name_len; ++i) {
            orig_name.push_back(static_cast<char>(buffer[8 + i]));
        }

        size_t payload_offset = 8 + name_len;
        std::vector<byte> payload;
        payload.insert(payload.end(), buffer.begin() + payload_offset, buffer.end());

        std::string outpath = join_path(parent_path(input_path), orig_name);
        if (file_exists(outpath)) {
            auto t = std::chrono::system_clock::now();
            auto secs = std::chrono::duration_cast<std::chrono::seconds>(t.time_since_epoch()).count();
            outpath += ".dec" + std::to_string(secs);
        }

        std::ofstream out(outpath.c_str(), std::ios::binary);
        if (!out) { std::cerr << "Failed to create output file: " << outpath << "\n"; return false; }
        if (!payload.empty()) out.write(reinterpret_cast<const char*>(payload.data()), static_cast<std::streamsize>(payload.size()));
        out.close();

        if (remove_original) {
            if (std::remove(input_path.c_str()) != 0) {
                std::cerr << "Warning: failed to remove original file: " << input_path << "\n";
            }
        }

        std::cout << "Decrypted: " << input_path << " -> " << outpath << "\n";
        return true;
    } catch (const std::exception &e) {
        std::cerr << "Exception decrypt_file: " << e.what() << "\n";
        return false;
    }
}

// --- Directory traversal (platform-specific implementations) ---
void process_directory_recursive(const std::string &dirpath, const std::string &password, bool encrypt_mode, bool remove_original = false);

#if defined(_WIN32)

void process_directory_recursive(const std::string &dirpath, const std::string &password, bool encrypt_mode, bool remove_original) {
    std::string pattern = dirpath;
    if (!pattern.empty() && (pattern.back() != '\\' && pattern.back() != '/')) pattern += "\\";
    pattern += "*";

    WIN32_FIND_DATAA wfd;
    HANDLE h = FindFirstFileA(pattern.c_str(), &wfd);
    if (h == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open directory: " << dirpath << "\n";
        return;
    }
    do {
        std::string name = wfd.cFileName;
        if (name == "." || name == "..") continue;
        std::string full = join_path(dirpath, name);
        if (wfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            process_directory_recursive(full, password, encrypt_mode, remove_original);
        } else {
            if (encrypt_mode) {
                if (get_extension(full) == ".vault") continue;
                encrypt_file(full, password, remove_original);
            } else {
                if (get_extension(full) == ".vault") decrypt_file(full, password, remove_original);
            }
        }
    } while (FindNextFileA(h, &wfd) != 0);
    FindClose(h);
}

#else // POSIX

void process_directory_recursive(const std::string &dirpath, const std::string &password, bool encrypt_mode, bool remove_original) {
    DIR *dp = opendir(dirpath.c_str());
    if (!dp) {
        std::cerr << "Failed to open directory: " << dirpath << "\n";
        return;
    }
    struct dirent *entry;
    while ((entry = readdir(dp)) != nullptr) {
        std::string name = entry->d_name;
        if (name == "." || name == "..") continue;
        std::string full = join_path(dirpath, name);
        struct stat st;
        if (stat(full.c_str(), &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) {
            process_directory_recursive(full, password, encrypt_mode, remove_original);
        } else {
            if (encrypt_mode) {
                if (get_extension(full) == ".vault") continue;
                encrypt_file(full, password, remove_original);
            } else {
                if (get_extension(full) == ".vault") decrypt_file(full, password, remove_original);
            }
        }
    }
    closedir(dp);
}

#endif

// --- CLI ---
std::string read_password(const std::string &prompt = "Password: ") {
    std::string pwd;
    std::cout << prompt;
    std::getline(std::cin, pwd);
    return pwd;
}

void print_menu() {
    std::cout << "=== Local File Encryption Vault (C++14, educational) ===\n";
    std::cout << "1) Encrypt a file\n";
    std::cout << "2) Decrypt a .vault file\n";
    std::cout << "3) Encrypt a directory (recursive)\n";
    std::cout << "4) Decrypt a directory (recursive .vault files)\n";
    std::cout << "5) Exit\n";
    std::cout << "Select option: ";
}

int main() {
    std::ios::sync_with_stdio(false);
    std::cin.tie(nullptr);

    while (true) {
        print_menu();
        std::string opt;
        std::getline(std::cin, opt);
        if (opt.empty()) continue;

        if (opt == "1") {
            std::cout << "Enter file path to encrypt: ";
            std::string path; std::getline(std::cin, path);
            std::string pwd = read_password("Enter password: ");
            std::string confirm = read_password("Confirm password: ");
            if (pwd != confirm) { std::cerr << "Passwords do not match. Aborting.\n"; continue; }
            std::cout << "Remove original file after encryption? (y/N): ";
            std::string ans; std::getline(std::cin, ans);
            bool remove_original = (ans == "y" || ans == "Y");
            encrypt_file(path, pwd, remove_original);
        }
        else if (opt == "2") {
            std::cout << "Enter .vault file path to decrypt: ";
            std::string path; std::getline(std::cin, path);
            std::string pwd = read_password("Enter password: ");
            std::cout << "Remove .vault file after decryption? (y/N): ";
            std::string ans; std::getline(std::cin, ans);
            bool remove_original = (ans == "y" || ans == "Y");
            decrypt_file(path, pwd, remove_original);
        }
        else if (opt == "3") {
            std::cout << "Enter directory path to encrypt recursively: ";
            std::string path; std::getline(std::cin, path);
            std::string pwd = read_password("Enter password: ");
            std::string confirm = read_password("Confirm password: ");
            if (pwd != confirm) { std::cerr << "Passwords do not match. Aborting.\n"; continue; }
            std::cout << "Remove original files after encryption? (y/N): ";
            std::string ans; std::getline(std::cin, ans);
            bool remove_original = (ans == "y" || ans == "Y");
            process_directory_recursive(path, pwd, true, remove_original);
        }
        else if (opt == "4") {
            std::cout << "Enter directory path to decrypt recursively (.vault files): ";
            std::string path; std::getline(std::cin, path);
            std::string pwd = read_password("Enter password: ");
            std::cout << "Remove .vault files after decryption? (y/N): ";
            std::string ans; std::getline(std::cin, ans);
            bool remove_original = (ans == "y" || ans == "Y");
            process_directory_recursive(path, pwd, false, remove_original);
        }
        else if (opt == "5" || opt == "exit") {
            std::cout << "Goodbye.\n";
            break;
        }
        else {
            std::cerr << "Invalid option.\n";
        }
        std::cout << "\n";
    }

    return 0;
}
