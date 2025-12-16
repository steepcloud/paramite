/**
 * @file string_utils.hpp
 * @brief String manipulation and analysis utilities for malware analysis
 * 
 * Provides comprehensive string processing capabilities including extraction
 * from binary data, pattern detection (IPs, URLs, domains), encoding/decoding,
 * and similarity comparison. Optimized for malware analysis workflows.
 * 
 * @date 2025
 */

#pragma once

#include <string>
#include <vector>
#include <filesystem>
#include <cstdint>

namespace paramite {
namespace utils {

/**
 * @class StringUtils
 * @brief Comprehensive string utilities for malware analysis
 * 
 * Provides static methods for:
 * - String extraction from binaries (ASCII and Unicode)
 * - IOC pattern detection (IPs, URLs, domains, emails, file paths)
 * - String manipulation (trim, split, join, replace)
 * - Encoding/decoding (hex, base64)
 * - Similarity analysis (Levenshtein distance)
 * - Suspicious pattern detection
 * 
 * All methods are static - no instantiation required.
 * 
 * **Usage Example**:
 * @code
 * // Extract strings from malware binary
 * auto strings = StringUtils::ExtractStrings("/path/to/malware.exe", 4);
 * 
 * // Filter for interesting patterns
 * auto interesting = StringUtils::FilterInterestingStrings(strings);
 * 
 * // Check for specific patterns
 * for (const auto& str : interesting) {
 *     if (StringUtils::IsIPAddress(str)) {
 *         std::cout << "Found IP: " << str << std::endl;
 *     }
 *     if (StringUtils::IsURL(str)) {
 *         std::cout << "Found URL: " << str << std::endl;
 *     }
 * }
 * 
 * // Decode obfuscated data
 * std::string decoded = StringUtils::FromBase64(encoded_payload);
 * @endcode
 */
class StringUtils {
public:
    /***************************************************************************
     * String Extraction
     ***************************************************************************/
    
    /**
     * @brief Extract ASCII strings from binary file
     * 
     * Reads file and extracts printable ASCII strings that meet minimum length
     * requirement. Useful for extracting IOCs and readable text from executables.
     * 
     * @param file_path Path to binary file
     * @param min_length Minimum string length (default: 4)
     * @return Vector of extracted strings
     * 
     * @throws std::runtime_error if file cannot be read
     * 
     * **Performance**: ~1-2 seconds for 10MB executable
     * 
     * **Example**:
     * @code
     * auto strings = StringUtils::ExtractStrings("malware.exe", 6);
     * std::cout << "Found " << strings.size() << " strings" << std::endl;
     * @endcode
     */
    static std::vector<std::string> ExtractStrings(const std::filesystem::path& file_path,
                                                    std::size_t min_length = 4);
    
    /**
     * @brief Extract ASCII strings from binary data in memory
     * 
     * @param data Binary data buffer
     * @param min_length Minimum string length
     * @return Vector of extracted strings
     */
    static std::vector<std::string> ExtractStrings(const std::vector<uint8_t>& data,
                                                    std::size_t min_length = 4);
    
    /**
     * @brief Extract Unicode (UTF-16 LE) strings from binary data
     * 
     * Extracts wide-character strings commonly used in Windows executables.
     * Handles UTF-16 Little Endian encoding.
     * 
     * @param data Binary data buffer
     * @param min_length Minimum string length (in characters, not bytes)
     * @return Vector of extracted Unicode strings (converted to UTF-8)
     */
    static std::vector<std::string> ExtractUnicodeStrings(const std::vector<uint8_t>& data,
                                                          std::size_t min_length = 4);
    
    /***************************************************************************
     * Pattern Detection
     ***************************************************************************/
    
    /**
     * @brief Check if string contains interesting patterns (IOCs, keywords)
     * 
     * Tests string for various patterns of interest:
     * - IP addresses
     * - URLs and domains
     * - File paths
     * - Email addresses
     * - Suspicious keywords (cmd.exe, powershell, wget, etc.)
     * 
     * @param str String to check
     * @return true if string is considered interesting
     * 
     * **Use Case**: Filtering extracted strings to reduce noise
     */
    static bool IsInterestingString(const std::string& str);
    
    /**
     * @brief Filter list of strings to only interesting ones
     * 
     * @param strings Input string vector
     * @return Filtered vector containing only interesting strings
     * 
     * **Example**:
     * @code
     * auto all_strings = ExtractStrings("sample.exe");
     * auto interesting = FilterInterestingStrings(all_strings);
     * // interesting now contains only IOCs and suspicious strings
     * @endcode
     */
    static std::vector<std::string> FilterInterestingStrings(const std::vector<std::string>& strings);
    
    /***************************************************************************
     * Basic String Manipulation
     ***************************************************************************/
    
    /**
     * @brief Trim whitespace from both ends of string
     * @param str Input string
     * @return Trimmed string
     */
    static std::string Trim(const std::string& str);
    
    /**
     * @brief Convert string to lowercase
     * @param str Input string
     * @return Lowercase string
     */
    static std::string ToLower(const std::string& str);
    
    /**
     * @brief Convert string to uppercase
     * @param str Input string
     * @return Uppercase string
     */
    static std::string ToUpper(const std::string& str);
    
    /**
     * @brief Split string by delimiter
     * 
     * @param str Input string
     * @param delimiter Character to split on
     * @return Vector of substrings
     * 
     * **Example**:
     * @code
     * auto parts = StringUtils::Split("192.168.1.1", '.');
     * // parts = ["192", "168", "1", "1"]
     * @endcode
     */
    static std::vector<std::string> Split(const std::string& str, char delimiter);
    
    /**
     * @brief Split string by any whitespace
     * @param str Input string
     * @return Vector of non-empty substrings
     */
    static std::vector<std::string> SplitWhitespace(const std::string& str);
    
    /**
     * @brief Join strings with delimiter
     * 
     * @param strings Vector of strings to join
     * @param delimiter Separator string
     * @return Joined string
     * 
     * **Example**:
     * @code
     * std::vector<std::string> parts = {"192", "168", "1", "1"};
     * auto ip = StringUtils::Join(parts, ".");  // "192.168.1.1"
     * @endcode
     */
    static std::string Join(const std::vector<std::string>& strings, const std::string& delimiter);
    
    /**
     * @brief Replace all occurrences of substring
     * 
     * @param str Input string
     * @param from Substring to find
     * @param to Replacement substring
     * @return Modified string
     */
    static std::string ReplaceAll(const std::string& str, const std::string& from, const std::string& to);
    
    /***************************************************************************
     * String Checking
     ***************************************************************************/
    
    /**
     * @brief Check if string starts with prefix
     * @param str String to check
     * @param prefix Prefix to test
     * @return true if str starts with prefix
     */
    static bool StartsWith(const std::string& str, const std::string& prefix);
    
    /**
     * @brief Check if string ends with suffix
     * @param str String to check
     * @param suffix Suffix to test
     * @return true if str ends with suffix
     */
    static bool EndsWith(const std::string& str, const std::string& suffix);
    
    /**
     * @brief Check if string contains substring
     * @param str String to search in
     * @param substring Substring to find
     * @return true if substring found
     */
    static bool Contains(const std::string& str, const std::string& substring);
    
    /***************************************************************************
     * IOC Pattern Matching
     ***************************************************************************/
    
    /**
     * @brief Check if string is a valid IPv4 address
     * 
     * Validates format: X.X.X.X where X is 0-255
     * 
     * @param str String to validate
     * @return true if valid IPv4 address
     * 
     * **Example**:
     * @code
     * IsIPAddress("192.168.1.1");    // true
     * IsIPAddress("256.1.1.1");      // false
     * IsIPAddress("not.an.ip");      // false
     * @endcode
     */
    static bool IsIPAddress(const std::string& str);
    
    /**
     * @brief Check if string is a valid URL
     * 
     * Matches http://, https://, ftp:// URLs
     * 
     * @param str String to validate
     * @return true if valid URL format
     */
    static bool IsURL(const std::string& str);
    
    /**
     * @brief Check if string is a valid domain name
     * 
     * Validates DNS domain format (e.g., example.com, sub.domain.org)
     * 
     * @param str String to validate
     * @return true if valid domain format
     */
    static bool IsDomain(const std::string& str);
    
    /**
     * @brief Check if string looks like a file path
     * 
     * Detects Windows (C:\...) and Unix (/...) path formats
     * 
     * @param str String to check
     * @return true if appears to be file path
     */
    static bool IsFilePath(const std::string& str);
    
    /**
     * @brief Check if string is a Windows registry key
     * 
     * Matches HKEY_* registry paths
     * 
     * @param str String to check
     * @return true if appears to be registry key
     */
    static bool IsRegistryKey(const std::string& str);
    
    /**
     * @brief Check if string is a valid email address
     * 
     * Basic email format validation (user@domain.tld)
     * 
     * @param str String to validate
     * @return true if valid email format
     */
    static bool IsEmail(const std::string& str);
    
    /**
     * @brief Check if string contains suspicious shell commands
     * 
     * Detects common malicious commands: cmd.exe, powershell, wget, curl,
     * base64, eval, exec, nc (netcat), etc.
     * 
     * @param str String to check
     * @return true if contains suspicious commands
     */
    static bool IsSuspiciousCommand(const std::string& str);
    
    /**
     * @brief Check if string contains malware-related keywords
     * 
     * Checks for keywords like: backdoor, keylogger, ransomware, trojan,
     * rootkit, exploit, payload, shellcode, etc.
     * 
     * @param str String to check
     * @return true if contains suspicious keywords
     */
    static bool ContainsSuspiciousKeyword(const std::string& str);
    
    /***************************************************************************
     * Encoding/Decoding
     ***************************************************************************/
    
    /**
     * @brief Escape special regex characters in string
     * 
     * Escapes: . * + ? ^ $ ( ) [ ] { } | \
     * 
     * @param str String to escape
     * @return Escaped string safe for regex
     */
    static std::string EscapeRegex(const std::string& str);
    
    /**
     * @brief Convert string to hexadecimal representation
     * 
     * @param str Input string
     * @return Hex string (e.g., "48656C6C6F" for "Hello")
     */
    static std::string ToHex(const std::string& str);
    
    /**
     * @brief Convert hexadecimal string to binary string
     * 
     * @param hex Hex string (e.g., "48656C6C6F")
     * @return Decoded string (e.g., "Hello")
     * 
     * @throws std::invalid_argument if hex string is invalid
     */
    static std::string FromHex(const std::string& hex);
    
    /**
     * @brief Encode string to Base64
     * 
     * @param str Input string
     * @return Base64-encoded string
     * 
     * **Use Case**: Encoding binary data for text transmission
     */
    static std::string ToBase64(const std::string& str);
    
    /**
     * @brief Decode Base64 string
     * 
     * @param base64 Base64-encoded string
     * @return Decoded string
     * 
     * @throws std::invalid_argument if base64 string is invalid
     * 
     * **Use Case**: Decoding obfuscated malware payloads
     */
    static std::string FromBase64(const std::string& base64);
    
    /***************************************************************************
     * String Comparison
     ***************************************************************************/
    
    /**
     * @brief Calculate Levenshtein distance between two strings
     * 
     * Computes minimum number of single-character edits (insertions,
     * deletions, substitutions) needed to change one string into another.
     * 
     * @param s1 First string
     * @param s2 Second string
     * @return Edit distance (0 = identical)
     * 
     * **Complexity**: O(n*m) where n, m are string lengths
     * 
     * **Example**:
     * @code
     * auto distance = StringUtils::LevenshteinDistance("kitten", "sitting");
     * // distance = 3 (k?s, e?i, insert g)
     * @endcode
     */
    static std::size_t LevenshteinDistance(const std::string& s1, const std::string& s2);
    
    /**
     * @brief Calculate similarity ratio between strings
     * 
     * Returns normalized similarity score based on Levenshtein distance.
     * 1.0 = identical, 0.0 = completely different
     * 
     * @param s1 First string
     * @param s2 Second string
     * @return Similarity score (0.0 to 1.0)
     * 
     * **Formula**: 1.0 - (distance / max(len(s1), len(s2)))
     * 
     * **Example**:
     * @code
     * auto similarity = StringUtils::Similarity("hello", "hallo");
     * // similarity ? 0.8 (very similar)
     * @endcode
     */
    static double Similarity(const std::string& s1, const std::string& s2);
    
    /***************************************************************************
     * Utility Functions
     ***************************************************************************/
    
    /**
     * @brief Sanitize string for safe display/storage
     * 
     * Removes or escapes potentially dangerous characters (NUL, control chars).
     * Useful for preventing injection attacks when displaying untrusted strings.
     * 
     * @param str Input string
     * @return Sanitized string
     */
    static std::string Sanitize(const std::string& str);
    
    /**
     * @brief Truncate string to maximum length
     * 
     * @param str Input string
     * @param max_length Maximum allowed length
     * @param suffix Suffix to append if truncated (default: "...")
     * @return Truncated string
     * 
     * **Example**:
     * @code
     * auto short_str = StringUtils::Truncate("very long string here", 10);
     * // short_str = "very lo..."
     * @endcode
     */
    static std::string Truncate(const std::string& str, std::size_t max_length, 
                                const std::string& suffix = "...");
};

} // namespace utils
} // namespace paramite