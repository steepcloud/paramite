/**
 * @file static_analyzer.hpp
 * @brief Static analysis engine for pre-execution malware inspection
 * 
 * Provides comprehensive static analysis capabilities for various file formats
 * including PE executables, ELF binaries, scripts, and archives. Performs
 * format-specific parsing, string extraction, entropy calculation, packer
 * detection, and signature matching without executing the sample.
 * 
 * @date 2025
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <set>
#include <optional>
#include <filesystem>
#include <memory>

namespace paramite {
namespace analyzers {

/**
 * @enum FileType
 * @brief Supported file formats for static analysis
 * 
 * Identifies the format of the malware sample to determine which
 * analysis techniques to apply. Detection is based on magic bytes,
 * file structure, and extension validation.
 */
enum class FileType {
    PE_EXECUTABLE,      ///< Windows Portable Executable (.exe, .dll, .sys)
    ELF_EXECUTABLE,     ///< Linux Executable and Linkable Format
    MACH_O,             ///< macOS Mach-O binary
    SCRIPT_BASH,        ///< Bash/Shell script
    SCRIPT_PYTHON,      ///< Python script (.py)
    SCRIPT_PERL,        ///< Perl script (.pl)
    SCRIPT_POWERSHELL,  ///< PowerShell script (.ps1)
    SCRIPT_JAVASCRIPT,  ///< JavaScript file (.js)
    DOCUMENT_PDF,       ///< Adobe PDF document
    DOCUMENT_OFFICE,    ///< Microsoft Office file (.doc, .xls, .ppt)
    ARCHIVE_ZIP,        ///< ZIP archive
    ARCHIVE_RAR,        ///< RAR archive
    ARCHIVE_TAR,        ///< TAR archive
    UNKNOWN             ///< Unrecognized file format
};

/**
 * @struct PEAnalysis
 * @brief Windows PE (Portable Executable) format analysis results
 * 
 * Contains detailed information extracted from PE file headers, sections,
 * imports/exports, resources, and digital signatures. Used for Windows
 * executables, DLLs, and drivers.
 * 
 * **Key Analysis Points**:
 * - Compiler and linker identification
 * - Section entropy for packer detection
 * - Import table for behavior prediction
 * - Digital signature validation
 * - Resource analysis (icons, manifests, version info)
 */
struct PEAnalysis {
    std::string architecture;           ///< CPU architecture (x86, x86_64, ARM)
    std::string subsystem;              ///< Windows subsystem (GUI, Console, Native)
    std::string compiler;               ///< Detected compiler (MSVC, GCC, MinGW, Delphi)
    std::string linker_version;         ///< Linker version string
    
    // PE Header Information
    uint32_t timestamp;                 ///< Compilation timestamp (Unix epoch)
    uint32_t checksum;                  ///< PE checksum value
    uint32_t entry_point;               ///< Entry point RVA
    
    /**
     * @struct Section
     * @brief PE section information
     */
    struct Section {
        std::string name;                          ///< Section name (.text, .data, .rsrc, etc.)
        uint32_t virtual_address;                  ///< Virtual address (RVA)
        uint32_t virtual_size;                     ///< Size in memory
        uint32_t raw_size;                         ///< Size on disk
        double entropy;                            ///< Shannon entropy (0-8)
        std::vector<std::string> characteristics;  ///< Section flags (EXECUTE, WRITE, READ)
    };
    std::vector<Section> sections;      ///< All PE sections
    
    // Import/Export Tables
    std::vector<std::string> imported_dlls;       ///< DLLs in import table
    std::vector<std::string> imported_functions;  ///< Imported function names
    std::vector<std::string> exported_functions;  ///< Exported function names (for DLLs)
    
    // Resources
    std::vector<std::string> resources;  ///< Resource types and names
    
    // Anomaly Detection
    std::vector<std::string> suspicious_sections;  ///< Sections with unusual characteristics
    std::vector<std::string> suspicious_imports;   ///< Suspicious API calls
    bool has_debug_info{false};                    ///< Debug directory present
    bool is_signed{false};                         ///< Has digital signature
    std::string signature_issuer;                  ///< Certificate issuer name
    bool signature_valid{false};                   ///< Signature verification result
};

/**
 * @struct ELFAnalysis
 * @brief Linux ELF (Executable and Linkable Format) analysis results
 * 
 * Parses ELF headers, sections, symbols, and security features for
 * Linux/Unix executables, shared libraries, and kernel modules.
 * 
 * **Security Features Checked**:
 * - Stack canaries (stack protection)
 * - NX bit (non-executable stack)
 * - PIE (Position Independent Executable)
 * - RELRO (Relocation Read-Only)
 */
struct ELFAnalysis {
    std::string architecture;           ///< CPU architecture (x86, x86_64, ARM, MIPS, RISC-V)
    std::string abi;                    ///< ABI (SystemV, GNU, Linux)
    std::string file_class;             ///< ELF class (32-bit, 64-bit)
    std::string endianness;             ///< Byte order (Little, Big)
    
    // ELF Header
    uint64_t entry_point;               ///< Entry point address
    std::string type;                   ///< ELF type (EXEC, DYN, REL, CORE)
    
    /**
     * @struct Section
     * @brief ELF section information
     */
    struct Section {
        std::string name;                ///< Section name (.text, .rodata, .bss, etc.)
        std::string type;                ///< Section type (PROGBITS, NOBITS, DYNAMIC, etc.)
        uint64_t address;                ///< Virtual address
        uint64_t size;                   ///< Section size
        double entropy;                  ///< Shannon entropy
        std::vector<std::string> flags;  ///< Section flags (ALLOC, WRITE, EXECINSTR)
    };
    std::vector<Section> sections;      ///< All ELF sections
    
    // Symbol Table
    std::vector<std::string> imported_libraries;  ///< Shared libraries in DT_NEEDED
    std::vector<std::string> imported_symbols;    ///< External symbols referenced
    std::vector<std::string> exported_symbols;    ///< Symbols exported by this binary
    
    // Security Hardening Features
    bool has_stack_canary{false};       ///< Stack protection enabled
    bool has_nx_bit{false};             ///< Non-executable stack
    bool has_pie{false};                ///< Position independent
    bool has_relro{false};              ///< Relocation read-only
    bool is_stripped{false};            ///< Debug symbols removed
    
    // Anomaly Detection
    std::vector<std::string> suspicious_sections;  ///< Unusual sections
    std::vector<std::string> suspicious_symbols;   ///< Suspicious function names
};

/**
 * @struct ScriptAnalysis
 * @brief Script-based malware analysis results
 * 
 * Analyzes interpreted languages (Bash, Python, PowerShell, etc.) for
 * suspicious commands, obfuscation techniques, and malicious patterns.
 * Particularly effective for detecting fileless malware and living-off-the-land attacks.
 */
struct ScriptAnalysis {
    std::string language;                         ///< Detected language
    std::string interpreter;                      ///< Interpreter path
    std::vector<std::string> shebang;            ///< Shebang line components
    
    // Content Analysis
    std::vector<std::string> suspicious_commands;  ///< Dangerous commands (wget, curl, base64, eval)
    std::vector<std::string> obfuscated_sections;  ///< Obfuscated code blocks
    std::vector<std::string> network_operations;   ///< Network-related commands
    std::vector<std::string> file_operations;      ///< File I/O commands
    std::vector<std::string> system_calls;         ///< System command execution
    
    // Obfuscation Detection
    bool is_base64_encoded{false};       ///< Contains Base64 encoding
    bool is_hex_encoded{false};          ///< Contains hex encoding
    bool is_obfuscated{false};           ///< Likely obfuscated
    double obfuscation_score{0.0};       ///< Obfuscation confidence (0-100)
};

/**
 * @struct StringAnalysis
 * @brief Extracted strings and pattern analysis
 * 
 * Extracts and categorizes strings from binary data to identify
 * network indicators, file paths, URLs, and suspicious keywords.
 * Uses regex patterns for IOC extraction.
 */
struct StringAnalysis {
    std::vector<std::string> all_strings;           ///< All extracted strings
    std::vector<std::string> interesting_strings;   ///< Filtered interesting strings
    std::vector<std::string> ip_addresses;          ///< IPv4/IPv6 addresses
    std::vector<std::string> urls;                  ///< HTTP/HTTPS URLs
    std::vector<std::string> domains;               ///< Domain names
    std::vector<std::string> file_paths;            ///< Windows/Unix file paths
    std::vector<std::string> registry_keys;         ///< Windows registry keys
    std::vector<std::string> email_addresses;       ///< Email addresses
    std::vector<std::string> crypto_keys;           ///< Base64 keys, PEM blocks
    std::vector<std::string> suspicious_keywords;   ///< Malware-related keywords
    
    int total_count{0};         ///< Total strings extracted
    int printable_count{0};     ///< ASCII printable strings
    int unicode_count{0};       ///< Unicode (UTF-16) strings
};

/**
 * @struct EntropyAnalysis
 * @brief File and section entropy analysis for packer detection
 * 
 * Calculates Shannon entropy to detect packed, compressed, or encrypted
 * sections. High entropy (>7.0) typically indicates packing or encryption.
 * 
 * **Entropy Interpretation**:
 * - 0.0-4.0: Low (plaintext, structured data)
 * - 4.0-6.0: Medium (compiled code)
 * - 6.0-7.0: High (compressed)
 * - 7.0-8.0: Very high (encrypted/packed)
 */
struct EntropyAnalysis {
    double overall_entropy{0.0};                   ///< Whole-file entropy
    double max_section_entropy{0.0};               ///< Highest section entropy
    std::string highest_entropy_section;           ///< Section with max entropy
    
    std::vector<std::pair<std::string, double>> section_entropies;  ///< Per-section entropy values
    
    // Packing Indicators
    bool likely_packed{false};         ///< High confidence of packing
    bool likely_encrypted{false};      ///< Likely encrypted
    bool likely_compressed{false};     ///< Likely compressed
    double packing_confidence{0.0};    ///< Packing confidence (0-100)
};

/**
 * @struct SignatureMatch
 * @brief Malware signature matching result
 * 
 * Represents a successful match against a YARA rule or pattern signature.
 * Used for malware family identification and classification.
 */
struct SignatureMatch {
    std::string signature_name;              ///< Signature/rule name
    std::string malware_family;              ///< Identified malware family
    std::vector<std::string> matched_patterns;  ///< Specific patterns that matched
    int confidence_score{0};                 ///< Match confidence (0-100)
    std::string description;                 ///< Signature description
    std::vector<std::string> references;     ///< External references (URLs, CVEs)
};

/**
 * @struct StaticAnalysisReport
 * @brief Complete static analysis report
 * 
 * Aggregates all static analysis results including file metadata,
 * format-specific analysis, string extraction, entropy calculation,
 * and threat scoring. This is the primary output of the StaticAnalyzer.
 */
struct StaticAnalysisReport {
    // File Metadata
    std::filesystem::path file_path;    ///< Analyzed file path
    std::string filename;               ///< Filename only
    std::size_t file_size{0};          ///< File size in bytes
    std::string md5;                    ///< MD5 hash
    std::string sha1;                   ///< SHA-1 hash
    std::string sha256;                 ///< SHA-256 hash
    std::string ssdeep;                 ///< Fuzzy hash for similarity matching
    
    // File Type Identification
    FileType file_type;                 ///< Detected file type
    std::string mime_type;              ///< MIME type
    std::vector<std::string> magic_bytes;  ///< First bytes (hex)
    
    // Format-Specific Analysis (only one will be populated)
    std::optional<PEAnalysis> pe_analysis;      ///< PE analysis results (if PE file)
    std::optional<ELFAnalysis> elf_analysis;    ///< ELF analysis results (if ELF file)
    std::optional<ScriptAnalysis> script_analysis;  ///< Script analysis (if script)
    
    // Universal Analysis
    StringAnalysis string_analysis;     ///< String extraction results
    EntropyAnalysis entropy_analysis;   ///< Entropy analysis
    
    // Signature Matching
    std::vector<SignatureMatch> signature_matches;  ///< YARA/pattern matches
    
    // Threat Indicators
    std::vector<std::string> suspicious_indicators;    ///< Suspicious patterns found
    std::vector<std::string> packer_detections;        ///< Detected packers/protectors
    std::vector<std::string> anti_analysis_techniques; ///< Anti-VM, anti-debug, etc.
    
    // Threat Assessment
    int threat_score{0};              ///< Aggregate threat score (0-100)
    int suspicion_level{0};           ///< Suspicion level (0-10)
    bool likely_malicious{false};     ///< High confidence of malicious intent
    
    // Timing Information
    std::string analysis_timestamp;              ///< ISO 8601 timestamp
    std::chrono::milliseconds analysis_duration{0};  ///< Analysis time
};

/**
 * @class StaticAnalyzer
 * @brief Static analysis engine for pre-execution malware inspection
 * 
 * Performs comprehensive static analysis without executing the sample.
 * Supports multiple file formats and provides detailed insights into
 * file structure, embedded strings, entropy characteristics, and
 * malware signatures.
 * 
 * **Capabilities**:
 * - Multi-format parsing (PE, ELF, scripts, archives)
 * - String and IOC extraction
 * - Entropy-based packer detection
 * - YARA signature matching
 * - Import/export analysis
 * - Security feature detection
 * - Automated threat scoring
 * 
 * **Thread Safety**: NOT thread-safe. Create separate instances for concurrent use.
 * 
 * **Usage Example**:
 * @code
 * StaticAnalyzer::Config config;
 * config.extract_strings = true;
 * config.enable_yara_scanning = true;
 * config.yara_rules_path = "./yara_rules";
 * 
 * StaticAnalyzer analyzer(config);
 * auto report = analyzer.Analyze("/path/to/malware.exe");
 * 
 * std::cout << "File Type: " << FileTypeToString(report.file_type) << std::endl;
 * std::cout << "Threat Score: " << report.threat_score << "/100" << std::endl;
 * 
 * if (report.pe_analysis) {
 *     std::cout << "PE Architecture: " << report.pe_analysis->architecture << std::endl;
 *     std::cout << "Imported DLLs: " << report.pe_analysis->imported_dlls.size() << std::endl;
 * }
 * @endcode
 */
class StaticAnalyzer {
public:
    /**
     * @struct Config
     * @brief Static analyzer configuration
     */
    struct Config {
        // Analysis Feature Toggles
        bool analyze_pe{true};            ///< Enable PE analysis
        bool analyze_elf{true};           ///< Enable ELF analysis
        bool analyze_scripts{true};       ///< Enable script analysis
        bool extract_strings{true};       ///< Extract embedded strings
        bool calculate_entropy{true};     ///< Calculate entropy
        bool check_signatures{true};      ///< Run signature matching
        bool detect_packers{true};        ///< Detect packers/obfuscators
        bool analyze_imports{true};       ///< Analyze import tables
        
        // String Extraction Settings
        std::size_t min_string_length{4};     ///< Minimum string length to extract
        std::size_t max_string_length{1024};  ///< Maximum string length
        bool extract_unicode{true};           ///< Extract UTF-16 strings
        
        // Entropy Thresholds
        double high_entropy_threshold{7.0};    ///< Threshold for packed detection
        double medium_entropy_threshold{6.0};  ///< Threshold for compression
        
        // Signature Matching
        std::filesystem::path yara_rules_path{"./rules"};  ///< YARA rules directory
        bool enable_yara_scanning{false};                  ///< Enable YARA scanning
        
        // Performance Limits
        std::size_t max_strings_to_extract{10000};          ///< Limit strings to prevent memory issues
        std::size_t max_file_size{100 * 1024 * 1024};      ///< Max file size (100MB default)
        
        bool verbose_logging{false};  ///< Enable verbose debug output
    };

    /**
     * @brief Construct analyzer with custom configuration
     * @param config Configuration parameters
     */
    explicit StaticAnalyzer(const Config& config);
    
    /**
     * @brief Construct analyzer with default configuration
     */
    explicit StaticAnalyzer();
    
    ~StaticAnalyzer() = default;

    StaticAnalyzer(const StaticAnalyzer&) = delete;
    StaticAnalyzer& operator=(const StaticAnalyzer&) = delete;

    /**
     * @brief Perform comprehensive static analysis on a file
     * 
     * Orchestrates the complete static analysis workflow:
     * 1. File type detection
     * 2. Hash calculation (MD5, SHA-1, SHA-256, ssdeep)
     * 3. Format-specific analysis (PE/ELF/Script)
     * 4. String extraction and IOC identification
     * 5. Entropy calculation
     * 6. Packer detection
     * 7. Signature matching
     * 8. Threat scoring
     * 
     * @param file_path Path to file to analyze
     * @return Complete static analysis report
     * 
     * @throws std::runtime_error if file cannot be read
     * @throws std::runtime_error if file exceeds size limit
     * 
     * **Performance**: Typically 1-5 seconds for executables <10MB
     */
    StaticAnalysisReport Analyze(const std::filesystem::path& file_path);

    /**
     * @brief Detect file type using magic bytes and structure analysis
     * 
     * Uses magic byte signatures and structural validation to accurately
     * identify file format. More reliable than extension-based detection.
     * 
     * @param file_path Path to file
     * @return Detected file type enum
     * 
     * **Detection Methods**:
     * - Magic bytes (MZ for PE, 7F 45 4C 46 for ELF)
     * - Shebang parsing for scripts
     * - Archive signature detection
     */
    FileType DetectFileType(const std::filesystem::path& file_path);

    /**
     * @brief Analyze Windows PE executable structure
     * 
     * Parses PE headers, sections, import/export tables, resources,
     * and digital signatures. Identifies compiler, linker, and packer.
     * 
     * @param file_path Path to PE file
     * @return PE analysis results
     * 
     * @throws std::runtime_error if file is not valid PE
     */
    PEAnalysis AnalyzePE(const std::filesystem::path& file_path);

    /**
     * @brief Analyze Linux ELF executable structure
     * 
     * Parses ELF headers, sections, symbol tables, and dynamic linking
     * information. Checks for security hardening features.
     * 
     * @param file_path Path to ELF file
     * @return ELF analysis results
     * 
     * @throws std::runtime_error if file is not valid ELF
     */
    ELFAnalysis AnalyzeELF(const std::filesystem::path& file_path);

    /**
     * @brief Analyze script file content
     * 
     * Parses script syntax, identifies dangerous commands, detects
     * obfuscation techniques, and extracts IOCs from script content.
     * 
     * @param file_path Path to script file
     * @return Script analysis results
     * 
     * **Detected Threats**:
     * - Command injection
     * - Base64/hex encoding
     * - Obfuscated code
     * - Network operations
     * - Privilege escalation attempts
     */
    ScriptAnalysis AnalyzeScript(const std::filesystem::path& file_path);

    /**
     * @brief Extract and categorize strings from file
     * 
     * Extracts ASCII and Unicode strings, then categorizes them into
     * IOC types (IPs, URLs, paths) and identifies suspicious keywords.
     * 
     * @param file_path Path to file
     * @return String analysis results with categorized strings
     * 
     * **Extraction Process**:
     * 1. Read file into memory
     * 2. Extract ASCII strings (configurable minimum length)
     * 3. Extract Unicode (UTF-16) strings
     * 4. Apply regex patterns for IOC extraction
     * 5. Filter suspicious keywords
     */
    StringAnalysis ExtractStrings(const std::filesystem::path& file_path);

    /**
     * @brief Calculate file and section entropy
     * 
     * Computes Shannon entropy for the entire file and individual sections
     * to detect packing, compression, or encryption.
     * 
     * @param file_path Path to file
     * @return Entropy analysis with packing indicators
     * 
     * **Entropy Formula**: H(X) = -? P(xi) * log2(P(xi))
     * where P(xi) is the probability of byte value xi
     */
    EntropyAnalysis CalculateEntropy(const std::filesystem::path& file_path);

    /**
     * @brief Detect known packers and obfuscators
     * 
     * Uses signature-based detection and heuristics to identify
     * common packers (UPX, ASPack, Themida, VMProtect, etc.)
     * 
     * @param file_path Path to file
     * @return List of detected packer names
     * 
     * **Detection Methods**:
     * - Signature patterns in PE sections
     * - Section name heuristics (.upx, .aspack)
     * - Entry point analysis
     * - Import table characteristics
     */
    std::vector<std::string> DetectPackers(const std::filesystem::path& file_path);

    /**
     * @brief Match file against YARA malware signatures
     * 
     * Scans file with YARA rules for malware family identification
     * and behavior classification.
     * 
     * @param file_path Path to file
     * @return Vector of signature matches
     * 
     * @note Requires YARA rules configured in config.yara_rules_path
     */
    std::vector<SignatureMatch> MatchSignatures(const std::filesystem::path& file_path);

    /**
     * @brief Calculate aggregate threat score
     * 
     * Combines multiple indicators to produce final threat score (0-100):
     * - Entropy score
     * - Suspicious imports
     * - Signature matches
     * - Anti-analysis techniques
     * - Packer detection
     * 
     * @param report Completed static analysis report
     * @return Threat score 0-100 (higher = more suspicious)
     */
    int CalculateThreatScore(const StaticAnalysisReport& report);

    /**
     * @brief Get current configuration
     * @return Reference to configuration structure
     */
    const Config& GetConfig() const { return config_; }

private:
    Config config_;  ///< Analyzer configuration

    // Internal helper methods
    std::vector<uint8_t> ReadMagicBytes(const std::filesystem::path& file_path, 
                                        std::size_t count = 16);
    bool IsPEFile(const std::filesystem::path& file_path);
    bool IsELFFile(const std::filesystem::path& file_path);
    std::optional<std::string> DetectScriptType(const std::filesystem::path& file_path);
    std::vector<std::string> ExtractASCIIStrings(const std::vector<uint8_t>& data,
                                                  std::size_t min_length);
    std::vector<std::string> ExtractUnicodeStrings(const std::vector<uint8_t>& data,
                                                    std::size_t min_length);
    double CalculateShannonEntropy(const std::vector<uint8_t>& data);
    bool IsInterestingString(const std::string& str);
    std::vector<std::string> FindSuspiciousKeywords(const std::vector<std::string>& strings);
    void ParsePEHeaders(const std::filesystem::path& file_path, PEAnalysis& analysis);
    void ParseELFHeaders(const std::filesystem::path& file_path, ELFAnalysis& analysis);
    void AnalyzeScriptContent(const std::string& content, ScriptAnalysis& analysis);
    bool DetectObfuscation(const std::string& content);
    std::vector<std::string> DetectAntiAnalysis(const StaticAnalysisReport& report);
    std::string FileTypeToString(FileType type) const;
    std::string DetermineMIMEType(const std::filesystem::path& file_path);
};

} // namespace analyzers
} // namespace paramite