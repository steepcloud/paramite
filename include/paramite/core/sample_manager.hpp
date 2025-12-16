/**
 * @file sample_manager.hpp
 * @brief Malware sample intake, validation, and metadata extraction
 * 
 * Manages the complete lifecycle of malware sample processing including file
 * validation, hash calculation, static metadata extraction, and secure storage.
 * Serves as the entry point for all samples entering the analysis pipeline.
 * 
 * @date 2025
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <filesystem>
#include <optional>

namespace paramite {
namespace core {

/**
 * @struct SampleMetadata
 * @brief Complete metadata about a malware sample
 * 
 * Contains all identifying information and initial analysis results
 * for a submitted malware sample. Used throughout the analysis pipeline
 * to track sample properties.
 */
struct SampleMetadata {
    std::string filename;                       ///< Original filename
    std::string filepath;                       ///< Relative file path
    std::filesystem::path absolute_path;        ///< Full absolute path
    std::size_t file_size;                      ///< File size in bytes
    
    // Cryptographic Hashes
    std::string md5;         ///< MD5 hash (legacy compatibility)
    std::string sha1;        ///< SHA-1 hash
    std::string sha256;      ///< SHA-256 hash (primary identifier)
    
    // File Type Information
    std::string file_type;   ///< Detected file type (PE, ELF, script, etc.)
    std::string mime_type;   ///< MIME type
    
    // Static Analysis Results
    double entropy;                             ///< Shannon entropy (0.0-8.0)
    std::vector<std::string> interesting_strings;  ///< Notable extracted strings
    
    // Timestamps
    std::string submission_time;   ///< When sample was submitted (ISO 8601)
    std::string last_modified;     ///< File modification time
    
    // Additional Metadata
    std::map<std::string, std::string> additional_info;  ///< Custom key-value pairs
};

/**
 * @struct ValidationResult
 * @brief Result of sample file validation
 * 
 * Contains validation status, errors, and warnings encountered
 * during sample intake validation.
 */
struct ValidationResult {
    bool valid;                          ///< Overall validation status
    std::string error_message;           ///< Error description (if invalid)
    std::vector<std::string> warnings;   ///< Non-fatal warnings
};

/**
 * @class SampleManager
 * @brief Malware sample intake and metadata management
 * 
 * Responsible for the initial processing of submitted malware samples:
 * 
 * - **File Validation**: Size checks, magic byte verification, integrity validation
 * - **Hash Calculation**: MD5, SHA-1, SHA-256 for identification and deduplication
 * - **Static Metadata Extraction**: File type, entropy, strings
 * - **Secure Storage**: Copy samples to managed directory with hash-based naming
 * - **Safety Checks**: File size limits, dangerous pattern detection
 * 
 * **Thread Safety**: NOT thread-safe. Use separate instances for concurrent processing.
 * 
 * **Usage Example**:
 * @code
 * SampleManager::Config config;
 * config.samples_directory = "./samples";
 * config.max_file_size = 50 * 1024 * 1024;  // 50MB limit
 * config.enable_string_extraction = true;
 * 
 * SampleManager manager(config);
 * 
 * // Validate before processing
 * auto validation = manager.ValidateSample("/path/to/malware.exe");
 * if (!validation.valid) {
 *     std::cerr << "Invalid sample: " << validation.error_message << std::endl;
 *     return;
 * }
 * 
 * // Process the sample
 * auto metadata = manager.ProcessSample("/path/to/malware.exe");
 * if (metadata) {
 *     std::cout << "SHA-256: " << metadata->sha256 << std::endl;
 *     std::cout << "Entropy: " << metadata->entropy << std::endl;
 *     std::cout << "Type: " << metadata->file_type << std::endl;
 * }
 * @endcode
 */
class SampleManager {
public:
    /**
     * @struct Config
     * @brief Sample manager configuration
     */
    struct Config {
        std::filesystem::path samples_directory{"./samples"};   ///< Where to store samples
        std::filesystem::path reports_directory{"./reports"};   ///< Report output directory
        std::size_t max_file_size{100 * 1024 * 1024};          ///< Max size (100MB default)
        std::size_t min_file_size{1};                          ///< Min size (1 byte)
        bool enable_string_extraction{true};                    ///< Extract strings during intake
        std::size_t min_string_length{4};                      ///< Minimum string length to extract
        bool calculate_entropy{true};                           ///< Calculate Shannon entropy
        bool create_backup{true};                               ///< Keep original copy
    };

    /**
     * @brief Construct manager with custom configuration
     * @param config Sample manager configuration
     */
    explicit SampleManager(const Config& config);
    
    /**
     * @brief Construct manager with default configuration
     */
    explicit SampleManager();
    
    ~SampleManager() = default;

    SampleManager(const SampleManager&) = delete;
    SampleManager& operator=(const SampleManager&) = delete;
    SampleManager(SampleManager&&) = default;
    SampleManager& operator=(SampleManager&&) = default;

    /**
     * @brief Process a new malware sample through intake pipeline
     * 
     * Complete sample processing workflow:
     * 1. Validate file (size, existence, readability)
     * 2. Compute cryptographic hashes (MD5, SHA-1, SHA-256)
     * 3. Detect file type
     * 4. Calculate entropy
     * 5. Extract strings
     * 6. Store sample in managed directory
     * 7. Generate metadata
     * 
     * @param sample_path Path to malware sample file
     * @return SampleMetadata if successful, nullopt if validation fails
     * 
     * @throws std::runtime_error if critical processing error occurs
     * 
     * **Performance**: ~1-3 seconds for typical executable (<10MB)
     */
    std::optional<SampleMetadata> ProcessSample(const std::filesystem::path& sample_path);

    /**
     * @brief Validate sample file before processing
     * 
     * Performs pre-processing validation checks:
     * - File exists and is readable
     * - File size within configured limits
     * - File is not a directory or special file
     * - File has sufficient permissions
     * 
     * @param sample_path Path to sample file
     * @return ValidationResult with validation status and messages
     * 
     * **Example**:
     * @code
     * auto result = manager.ValidateSample("/path/to/file");
     * if (!result.valid) {
     *     std::cerr << "Validation failed: " << result.error_message << std::endl;
     *     for (const auto& warning : result.warnings) {
     *         std::cout << "Warning: " << warning << std::endl;
     *     }
     * }
     * @endcode
     */
    ValidationResult ValidateSample(const std::filesystem::path& sample_path) const;

    /**
     * @brief Compute cryptographic hashes for file
     * 
     * Calculates multiple hash types for file identification and
     * deduplication. Reads file once and computes all hashes in parallel.
     * 
     * @param file_path Path to file to hash
     * @return Map of algorithm name to hash value
     * 
     * **Returned Hashes**:
     * - "md5": 32-character MD5 hex hash
     * - "sha1": 40-character SHA-1 hex hash
     * - "sha256": 64-character SHA-256 hex hash
     * 
     * **Example**:
     * @code
     * auto hashes = manager.ComputeHashes("/path/to/file");
     * std::cout << "SHA-256: " << hashes["sha256"] << std::endl;
     * @endcode
     */
    std::map<std::string, std::string> ComputeHashes(const std::filesystem::path& file_path) const;

    /**
     * @brief Perform static analysis on sample
     * 
     * Populates metadata structure with static analysis results:
     * - File type detection (magic bytes + extension)
     * - Entropy calculation (compression/packing indicator)
     * - String extraction (ASCII and Unicode)
     * - Dangerous pattern detection
     * 
     * @param sample_path Path to sample file
     * @param metadata Metadata structure to populate (modified in-place)
     * 
     * **Note**: This is a lightweight analysis; full static analysis
     * is performed later by StaticAnalyzer component
     */
    void PerformStaticAnalysis(const std::filesystem::path& sample_path, SampleMetadata& metadata);

    /**
     * @brief Get current configuration
     * @return Reference to configuration structure
     */
    const Config& GetConfig() const { return config_; }

    /**
     * @brief Update manager configuration
     * @param config New configuration
     * @note Changes apply to future operations only
     */
    void SetConfig(const Config& config) { config_ = config; }

private:
    Config config_;  ///< Manager configuration

    /**
     * @brief Detect file type using magic bytes and extension analysis
     * 
     * Uses magic byte signatures and file extension to determine type.
     * More reliable than extension-only detection.
     * 
     * @param file_path Path to file
     * @return File type string (e.g., "PE32", "ELF64", "Bash script")
     */
    std::string DetectFileType(const std::filesystem::path& file_path) const;

    /**
     * @brief Calculate Shannon entropy of file
     * 
     * Computes Shannon entropy H(X) = -? P(x) * log2(P(x))
     * where P(x) is probability of byte value x.
     * 
     * @param file_path Path to file
     * @return Entropy value (0.0 to 8.0)
     * 
     * **Interpretation**:
     * - 0.0-4.0: Low (plaintext, structured data)
     * - 4.0-6.5: Medium (compiled code)
     * - 6.5-7.5: High (compressed)
     * - 7.5-8.0: Very high (encrypted/packed)
     */
    double CalculateEntropy(const std::filesystem::path& file_path) const;

    /**
     * @brief Extract printable strings from file
     * 
     * Extracts ASCII and Unicode strings for IOC identification
     * and behavioral analysis hints.
     * 
     * @param file_path Path to file
     * @param min_length Minimum string length (default: 4)
     * @return Vector of extracted strings
     * 
     * **Performance**: ~500ms for 10MB file
     */
    std::vector<std::string> ExtractStrings(const std::filesystem::path& file_path, 
                                            std::size_t min_length = 4) const;

    /**
     * @brief Copy sample to managed samples directory
     * 
     * Creates hash-based directory structure and stores sample with
     * SHA-256 as filename for easy deduplication.
     * 
     * @param sample_path Source sample path
     * @param sha256_hash SHA-256 hash of sample
     * @return Path where sample was stored
     * 
     * **Storage Structure**: ./samples/{first_2_chars_of_hash}/{sha256}
     * Example: ./samples/ab/abc123def456...
     */
    std::filesystem::path StoreSample(const std::filesystem::path& sample_path,
                                      const std::string& sha256_hash);

    /**
     * @brief Get current timestamp in ISO 8601 format
     * 
     * @return Timestamp string (e.g., "2025-01-15T14:30:00Z")
     */
    std::string GetCurrentTimestamp() const;

    /**
     * @brief Check for dangerous patterns in file
     * 
     * Performs basic heuristic checks for suspicious characteristics:
     * - Unusual entropy
     * - Suspicious strings (cmd.exe, powershell, etc.)
     * - Embedded executables
     * - Script obfuscation
     * 
     * @param file_path Path to file
     * @return Vector of warning messages
     */
    std::vector<std::string> CheckDangerousPatterns(const std::filesystem::path& file_path) const;
};

} // namespace core
} // namespace paramite
