/**
 * @file string_utils.cpp
 * @brief Implementation of string manipulation and analysis utilities
 * 
 * Implements string extraction, pattern matching, encoding conversion, entropy
 * calculation, and obfuscation detection for malware analysis. Provides utilities
 * for extracting both ASCII and Unicode strings from binary data, detecting
 * interesting patterns, and analyzing string characteristics.
 * 
 * **String Extraction Methods**:
 * - ASCII strings: Printable characters (0x20-0x7E)
 * - Unicode strings: UTF-16 LE encoded strings
 * - Base64 strings: Encoded data detection
 * - Hex strings: Hexadecimal encoded data
 * 
 * **Analysis Capabilities**:
 * - Entropy calculation for obfuscation detection
 * - Pattern matching (URLs, IPs, file paths, emails)
 * - String categorization (interesting vs noise)
 * - Encoding detection and conversion
 * 
 * **Interesting String Patterns**:
 * - URLs and network addresses
 * - File paths and registry keys
 * - Email addresses
 * - API function names
 * - Error messages and debug strings
 * - Cryptographic constants
 * 
 * @date 2025
 */

#include "paramite/utils/string_utils.hpp"

#include <spdlog/spdlog.h>

#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <regex>
#include <iomanip>
#include <set>

namespace paramite {
namespace utils {

// ============================================================================
// STRING EXTRACTION FROM FILES
// ============================================================================
// Reads file and extracts both ASCII and Unicode strings

std::vector<std::string> StringUtils::ExtractStrings(const std::filesystem::path& file_path,
                                                      std::size_t min_length) {
    std::ifstream file(file_path, std::ios::binary);
    if (!file.is_open()) {
        spdlog::error("Failed to open file: {}", file_path.string());
        return {};
    }

    // Read entire file into memory
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)),
                              std::istreambuf_iterator<char>());
    
    return ExtractStrings(data, min_length);
}

// ============================================================================
// STRING EXTRACTION FROM BINARY DATA
// ============================================================================
// Extracts both ASCII and Unicode strings from raw binary data
// Uses dual-pass extraction: ASCII first, then UTF-16 LE

std::vector<std::string> StringUtils::ExtractStrings(const std::vector<uint8_t>& data,
                                                      std::size_t min_length) {
    std::vector<std::string> strings;
    std::string current_string;
    
    // First pass: Extract ASCII strings (printable characters only)
    for (std::size_t i = 0; i < data.size(); ++i) {
        uint8_t byte = data[i];
        
        // Printable ASCII range: 0x20 (space) to 0x7E (tilde)
        if (std::isprint(byte) && byte < 128) {
            current_string += static_cast<char>(byte);
        } else {
            // Non-printable character found, save current string if long enough
            if (current_string.length() >= min_length) {
                strings.push_back(current_string);
            }
            current_string.clear();
        }
    }

    // Don't forget the last string if file ends with printable chars
    if (current_string.length() >= min_length) {
        strings.push_back(current_string);
    }
    
    // Second pass: Extract Unicode (UTF-16 LE) strings
    auto unicode_strings = ExtractUnicodeStrings(data, min_length);
    strings.insert(strings.end(), unicode_strings.begin(), unicode_strings.end());
    
    // Deduplicate using set (also sorts alphabetically as side effect)
    std::set<std::string> unique_strings(strings.begin(), strings.end());
    strings.assign(unique_strings.begin(), unique_strings.end());

    return strings;
}

// ============================================================================
// UNICODE STRING EXTRACTION
// ============================================================================
// Extracts UTF-16 Little Endian encoded strings
// Common in Windows executables and .NET assemblies

std::vector<std::string> StringUtils::ExtractUnicodeStrings(const std::vector<uint8_t>& data,
                                                            std::size_t min_length) {
    std::vector<std::string> strings;
    std::string current_string;
    
    // Parse as UTF-16 LE: 2 bytes per character
    // For ASCII subset: [char_byte][0x00]
    for (std::size_t i = 0; i + 1 < data.size(); i += 2) {
        uint8_t low = data[i];      // Character byte
        uint8_t high = data[i + 1];  // Should be 0 for ASCII range
        
        // Simple ASCII in UTF-16 LE: high byte is 0, low byte is printable
        if (high == 0 && std::isprint(low) && low < 128) {
            current_string += static_cast<char>(low);
        } else {
            if (current_string.length() >= min_length) {
                strings.push_back(current_string);
            }
            current_string.clear();
        }
    }
    
    if (current_string.length() >= min_length) {
        strings.push_back(current_string);
    }
    
    return strings;
}

// ============================================================================
// INTERESTING STRING DETECTION
// ============================================================================
// Heuristics to identify strings of potential interest in malware analysis

bool StringUtils::IsInterestingString(const std::string& str) {
    // Check for various malware-related patterns
    return IsURL(str) || 
           IsIPAddress(str) || 
           IsDomain(str) || 
           IsFilePath(str) ||
           IsRegistryKey(str) ||
           IsEmail(str) ||
           IsSuspiciousCommand(str) ||
           ContainsSuspiciousKeyword(str);
}

// Filter to interesting strings only
std::vector<std::string> StringUtils::FilterInterestingStrings(const std::vector<std::string>& strings) {
    std::vector<std::string> filtered;
    filtered.reserve(strings.size() / 10);  // Reserve approximate space
    
    for (const auto& str : strings) {
        if (IsInterestingString(str)) {
            filtered.push_back(str);
        }
    }
    
    spdlog::debug("Filtered {} interesting strings from {} total", 
                  filtered.size(), strings.size());
    
    return filtered;
}

// ============================================================================
// STRING MANIPULATION UTILITIES
// ============================================================================
// Basic string operations: trimming, casing, splitting, joining, replacing

// Trim whitespace
std::string StringUtils::Trim(const std::string& str) {
    auto start = std::find_if_not(str.begin(), str.end(), 
                                  [](unsigned char c) { return std::isspace(c); });
    auto end = std::find_if_not(str.rbegin(), str.rend(), 
                                [](unsigned char c) { return std::isspace(c); }).base();
    return (start < end) ? std::string(start, end) : std::string();
}

// Convert to lowercase
std::string StringUtils::ToLower(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(),
                  [](unsigned char c) { return std::tolower(c); });
    return result;
}

// Convert to uppercase
std::string StringUtils::ToUpper(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(),
                  [](unsigned char c) { return std::toupper(c); });
    return result;
}

// Split string by delimiter
std::vector<std::string> StringUtils::Split(const std::string& str, char delimiter) {
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream token_stream(str);
    
    while (std::getline(token_stream, token, delimiter)) {
        if (!token.empty()) {  // Skip empty tokens
            tokens.push_back(token);
        }
    }
    
    return tokens;
}

// Split by any whitespace
std::vector<std::string> StringUtils::SplitWhitespace(const std::string& str) {
    std::vector<std::string> tokens;
    std::istringstream iss(str);
    std::string token;
    
    while (iss >> token) {
        tokens.push_back(token);
    }
    
    return tokens;
}

// Join strings
std::string StringUtils::Join(const std::vector<std::string>& strings, 
                             const std::string& delimiter) {
    if (strings.empty()) {
        return "";
    }
    
    std::ostringstream oss;
    oss << strings[0];
    
    for (std::size_t i = 1; i < strings.size(); ++i) {
        oss << delimiter << strings[i];
    }
    
    return oss.str();
}

// Replace all occurrences
std::string StringUtils::ReplaceAll(const std::string& str,
                                   const std::string& from,
                                   const std::string& to) {
    if (from.empty()) {
        return str;
    }
    
    std::string result = str;
    std::size_t pos = 0;
    
    while ((pos = result.find(from, pos)) != std::string::npos) {
        result.replace(pos, from.length(), to);
        pos += to.length();
    }
    
    return result;
}

// Check if starts with
bool StringUtils::StartsWith(const std::string& str, const std::string& prefix) {
    return str.size() >= prefix.size() && 
           str.compare(0, prefix.size(), prefix) == 0;
}

// Check if ends with
bool StringUtils::EndsWith(const std::string& str, const std::string& suffix) {
    return str.size() >= suffix.size() && 
           str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}

// Contains substring
bool StringUtils::Contains(const std::string& str, const std::string& substring) {
    return str.find(substring) != std::string::npos;
}

// ============================================================================
// PATTERN MATCHING UTILITIES
// ============================================================================
// Detecting well-known patterns in strings: URLs, IPs, file paths, emails, etc.

// Check if IP address
bool StringUtils::IsIPAddress(const std::string& str) {
    // IPv4 pattern
    static const std::regex ipv4_pattern(
        R"(^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$)"
    );
    
    // IPv6 pattern (simplified)
    static const std::regex ipv6_pattern(
        R"(^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|::)$)"
    );
    
    return std::regex_match(str, ipv4_pattern) || std::regex_match(str, ipv6_pattern);
}

// Check if URL
bool StringUtils::IsURL(const std::string& str) {
    static const std::regex url_pattern(
        R"(^(https?|ftp|file)://[^\s/$.?#].[^\s]*$)",
        std::regex::icase
    );
    return std::regex_match(str, url_pattern);
}

// Check if domain
bool StringUtils::IsDomain(const std::string& str) {
    static const std::regex domain_pattern(
        R"(^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$)"
    );
    return std::regex_match(str, domain_pattern);
}

// Check if file path
bool StringUtils::IsFilePath(const std::string& str) {
    // Windows path patterns
    if (str.find(":\\") != std::string::npos || str.find("\\\\") != std::string::npos) {
        return true;
    }
    
    // Unix path patterns
    if (StartsWith(str, "/") || Contains(str, "/")) {
        // Check for common file extensions
        static const std::vector<std::string> extensions = {
            ".exe", ".dll", ".sys", ".bat", ".cmd", ".ps1", ".vbs", ".js",
            ".sh", ".py", ".pl", ".rb", ".jar", ".zip", ".rar", ".7z",
            ".doc", ".xls", ".pdf", ".txt", ".log", ".conf", ".ini"
        };
        
        for (const auto& ext : extensions) {
            if (EndsWith(ToLower(str), ext)) {
                return true;
            }
        }
        
        // Has slash and dot
        if (Contains(str, "/") && Contains(str, ".")) {
            return true;
        }
    }
    
    return false;
}

// Check if registry key
bool StringUtils::IsRegistryKey(const std::string& str) {
    static const std::vector<std::string> reg_roots = {
        "HKEY_LOCAL_MACHINE", "HKLM",
        "HKEY_CURRENT_USER", "HKCU",
        "HKEY_CLASSES_ROOT", "HKCR",
        "HKEY_USERS", "HKU",
        "HKEY_CURRENT_CONFIG", "HKCC"
    };
    
    for (const auto& root : reg_roots) {
        if (StartsWith(str, root)) {
            return true;
        }
    }
    
    return false;
}

// Check if email
bool StringUtils::IsEmail(const std::string& str) {
    static const std::regex email_pattern(
        R"(^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$)"
    );
    return std::regex_match(str, email_pattern);
}

// Check for suspicious commands
bool StringUtils::IsSuspiciousCommand(const std::string& str) {
    static const std::vector<std::string> suspicious_cmds = {
        "cmd.exe", "powershell", "wscript", "cscript", "mshta",
        "regsvr32", "rundll32", "certutil", "bitsadmin",
        "net user", "net localgroup", "schtasks", "at.exe",
        "/c ", "-encodedcommand", "-enc", "invoke-expression",
        "downloadstring", "downloadfile", "iex", "iwr",
        "bash -c", "sh -c", "eval", "exec", "system",
        "wget", "curl", "nc ", "netcat", "socat"
    };
    
    std::string lower = ToLower(str);
    
    for (const auto& cmd : suspicious_cmds) {
        if (Contains(lower, cmd)) {
            return true;
        }
    }
    
    return false;
}

// Contains suspicious keywords
bool StringUtils::ContainsSuspiciousKeyword(const std::string& str) {
    static const std::vector<std::string> keywords = {
        // Network
        "http://", "https://", "ftp://", "dns", "socket", "connect",
        "send", "recv", "upload", "download",
        
        // File operations
        ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js",
        "delete", "remove", "copy", "move", "create",
        
        // Registry
        "HKEY_", "SOFTWARE\\", "CurrentVersion\\Run",
        "regkey", "registry",
        
        // Process/System
        "process", "inject", "hook", "patch", "shellcode",
        "virtualalloc", "createremotethread", "writeprocessmemory",
        "kernel32", "ntdll", "advapi32",
        
        // Crypto
        "encrypt", "decrypt", "crypto", "cipher", "key",
        "aes", "rsa", "base64",
        
        // Anti-analysis
        "debugger", "sandbox", "vm", "virtual", "vmware",
        "virtualbox", "qemu", "wireshark", "ollydbg",
        "isdebuggerpresent", "checkremotedebuggerpresent",
        
        // Persistence
        "startup", "autorun", "scheduled", "service",
        "winlogon", "userinit",
        
        // Credential theft
        "password", "credential", "lsass", "mimikatz",
        "token", "privesc", "administrator"
    };
    
    std::string lower = ToLower(str);
    
    for (const auto& keyword : keywords) {
        if (Contains(lower, keyword)) {
            return true;
        }
    }
    
    return false;
}

// ============================================================================
// REGULAR EXPRESSION UTILITIES
// ============================================================================
// Escape sequences for regex special characters

// Escape special characters for regex
std::string StringUtils::EscapeRegex(const std::string& str) {
    static const std::regex special_chars(R"([-[\]{}()*+?.,\^$|#\s])");
    return std::regex_replace(str, special_chars, R"(\$&)");
}

// ============================================================================
// STRING ENCODING CONVERSIONS
// ============================================================================
// Hex and Base64 encoding/decoding utilities

// Convert to hex string
std::string StringUtils::ToHex(const std::string& str) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    
    for (unsigned char c : str) {
        oss << std::setw(2) << static_cast<int>(c);
    }
    
    return oss.str();
}

// Convert from hex string
std::string StringUtils::FromHex(const std::string& hex) {
    std::string result;
    
    for (std::size_t i = 0; i + 1 < hex.length(); i += 2) {
        std::string byte_string = hex.substr(i, 2);
        char byte = static_cast<char>(std::stoi(byte_string, nullptr, 16));
        result += byte;
    }
    
    return result;
}

// Convert to Base64
std::string StringUtils::ToBase64(const std::string& str) {
    static const char base64_chars[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    std::string result;
    int val = 0;
    int valb = -6;
    
    for (unsigned char c : str) {
        val = (val << 8) + c;
        valb += 8;
        
        while (valb >= 0) {
            result.push_back(base64_chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    
    if (valb > -6) {
        result.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
    }
    
    while (result.size() % 4) {
        result.push_back('=');
    }
    
    return result;
}

// Convert from Base64
std::string StringUtils::FromBase64(const std::string& base64) {
    static const std::string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    std::string result;
    std::vector<int> lookup(256, -1);
    
    for (int i = 0; i < 64; ++i) {
        lookup[base64_chars[i]] = i;
    }
    
    int val = 0;
    int valb = -8;
    
    for (unsigned char c : base64) {
        if (lookup[c] == -1) break;
        val = (val << 6) + lookup[c];
        valb += 6;
        
        if valb >= 0) {
            result.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    
    return result;
}

// ============================================================================
// STRING SIMILARITY AND DISTANCE
// ============================================================================
// Levenshtein distance and similarity percentage calculations

// Calculate Levenshtein distance
std::size_t StringUtils::LevenshteinDistance(const std::string& s1, 
                                             const std::string& s2) {
    const std::size_t m = s1.size();
    const std::size_t n = s2.size();
    
    if (m == 0) return n;
    if (n == 0) return m;
    
    std::vector<std::vector<std::size_t>> costs(m + 1, std::vector<std::size_t>(n + 1));
    
    for (std::size_t i = 0; i <= m; ++i) {
        costs[i][0] = i;
    }
    
    for (std::size_t j = 0; j <= n; ++j) {
        costs[0][j] = j;
    }
    
    for (std::size_t i = 1; i <= m; ++i) {
        for (std::size_t j = 1; j <= n; ++j) {
            std::size_t cost = (s1[i - 1] == s2[j - 1]) ? 0 : 1;
            costs[i][j] = std::min({
                costs[i - 1][j] + 1,      // deletion
                costs[i][j - 1] + 1,      // insertion
                costs[i - 1][j - 1] + cost // substitution
            });
        }
    }
    
    return costs[m][n];
}

// Calculate similarity percentage
double StringUtils::Similarity(const std::string& s1, const std::string& s2) {
    std::size_t max_len = std::max(s1.length(), s2.length());
    if (max_len == 0) return 100.0;
    
    std::size_t distance = LevenshteinDistance(s1, s2);
    return 100.0 * (1.0 - static_cast<double>(distance) / max_len);
}

// ============================================================================
// STRING SANITIZATION AND TRUNCATION
// ============================================================================
// Preparing strings for safe display or logging

// Sanitize string for safe output
std::string StringUtils::Sanitize(const std::string& str) {
    std::string result;
    result.reserve(str.length());
    
    for (char c : str) {
        if (std::isprint(static_cast<unsigned char>(c))) {
            result += c;
        } else {
            result += '.';
        }
    }
    
    return result;
}

// Truncate string
std::string StringUtils::Truncate(const std::string& str, 
                                 std::size_t max_length,
                                 const std::string& suffix) {
    if (str.length() <= max_length) {
        return str;
    }
    
    return str.substr(0, max_length - suffix.length()) + suffix;
}

} // namespace utils
} // namespace paramite