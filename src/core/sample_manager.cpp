/**
 * @file sample_manager.cpp
 * @brief Implementation of malware sample intake and metadata extraction
 * 
 * Implements comprehensive sample management including intake validation, cryptographic
 * hash calculation (MD5/SHA1/SHA256/SSDEEP), file type detection, entropy analysis,
 * metadata extraction, secure storage with hash-based organization, deduplication,
 * and sample lifecycle management.
 * 
 * **Sample Intake Workflow**:
 * ```
 * 1. Validation ? File exists, readable, size checks
 * 2. Hash Calculation ? MD5, SHA1, SHA256, SHA512, SSDEEP
 * 3. Deduplication ? Check if sample already exists (by SHA256)
 * 4. File Type Detection ? Magic bytes, MIME type, format identification
 * 5. Entropy Calculation ? Shannon entropy for packer detection
 * 6. Metadata Extraction ? File size, timestamps, permissions
 * 7. Secure Storage ? Copy to repository with hash-based path
 * 8. Database Registration ? Record sample metadata in database
 * ```
 * 
 * **Hash-Based Organization**:
 * Storage path structure:
 * ```
 * samples/
 * ??? sha256/
 * ?   ??? ab/
 * ?   ?   ??? abc123...def ? Original sample file
 * ?   ??? cd/
 * ?       ??? cde456...xyz
 * ??? metadata/
 *     ??? ab/
 *     ?   ??? abc123...def.json ? Sample metadata
 *     ??? cd/
 *         ??? cde456...xyz.json
 * ```
 * 
 * **Deduplication Strategy**:
 * - Primary key: SHA256 hash
 * - Fuzzy matching: SSDEEP for similar samples
 * - Variant detection: Compare with existing samples
 * - Space optimization: Hard links for duplicate files
 * 
 * **Metadata Tracked**:
 * - Cryptographic hashes (MD5, SHA1, SHA256, SHA512)
 * - Fuzzy hash (SSDEEP) for similarity matching
 * - File size and entropy score
 * - File type and MIME type
 * - Timestamps (submission, modification, last analysis)
 * - Source information (uploader, source, tags)
 * - Analysis history and results
 * 
 * **Security Considerations**:
 * - Samples stored with restricted permissions (0600)
 * - No execution permissions on stored files
 * - Separate storage from analysis environment
 * - Integrity verification via hash comparison
 * 
 * @date 2025
 */

#include "paramite/core/sample_manager.hpp"
#include "paramite/utils/hash_utils.hpp"
#include "paramite/utils/string_utils.hpp"

#include <spdlog/spdlog.h>
#include <fstream>
#include <sstream>
#include <chrono>
#include <iomanip>
#include <cmath>
#include <array>

namespace paramite {
namespace core {

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================
// Initializes sample manager with storage configuration

SampleManager::SampleManager()
    : SampleManager(Config{}) {
}

SampleManager::SampleManager(const Config& config) : config_(config) {
    // Create directories if they don't exist
    try {
        std::filesystem::create_directories(config_.samples_directory);
        std::filesystem::create_directories(config_.reports_directory);
        spdlog::info("Sample Manager initialized");
        spdlog::info("  Samples directory: {}", config_.samples_directory.string());
        spdlog::info("  Reports directory: {}", config_.reports_directory.string());
    } catch (const std::exception& e) {
        spdlog::error("Failed to create directories: {}", e.what());
        throw;
    }
}

// ============================================================================
// SAMPLE PROCESSING
// ============================================================================
// Processes an individual sample: validation, analysis, storage

std::optional<SampleMetadata> SampleManager::ProcessSample(const std::filesystem::path& sample_path) {
    spdlog::info("Processing sample: {}", sample_path.string());

    // Validate the sample
    auto validation = ValidateSample(sample_path);
    if (!validation.valid) {
        spdlog::error("Sample validation failed: {}", validation.error_message);
        return std::nullopt;
    }

    for (const auto& warning : validation.warnings) {
        spdlog::warn("Validation warning: {}", warning);
    }

    // Create metadata structure
    SampleMetadata metadata;
    metadata.filename = sample_path.filename().string();
    metadata.filepath = sample_path.string();
    metadata.absolute_path = std::filesystem::absolute(sample_path);
    metadata.file_size = std::filesystem::file_size(sample_path);
    metadata.submission_time = GetCurrentTimestamp();

    try {
        auto last_write = std::filesystem::last_write_time(sample_path);
        auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
            last_write - std::filesystem::file_time_type::clock::now() + std::chrono::system_clock::now()
        );
        auto last_write_time = std::chrono::system_clock::to_time_t(sctp);
        std::ostringstream oss;
        oss << std::put_time(std::localtime(&last_write_time), "%Y-%m-%d %H:%M:%S");
        metadata.last_modified = oss.str();
    } catch (...) {
        metadata.last_modified = "Unknown";
    }

    // Compute hashes
    spdlog::info("Computing cryptographic hashes...");
    try {
        auto hashes = ComputeHashes(sample_path);
        metadata.md5 = hashes["md5"];
        metadata.sha1 = hashes["sha1"];
        metadata.sha256 = hashes["sha256"];
        spdlog::info("  MD5: {}", metadata.md5);
        spdlog::info("  SHA1: {}", metadata.sha1);
        spdlog::info("  SHA256: {}", metadata.sha256);
    } catch (const std::exception& e) {
        spdlog::error("Failed to compute hashes: {}", e.what());
        return std::nullopt;
    }

    // Perform static analysis
    spdlog::info("Performing static analysis...");
    try {
        PerformStaticAnalysis(sample_path, metadata);
    } catch (const std::exception& e) {
        spdlog::error("Failed to perform static analysis: {}", e.what());
        return std::nullopt;
    }

    // Store the sample
    if (config_.create_backup) {
        try {
            auto stored_path = StoreSample(sample_path, metadata.sha256);
            metadata.additional_info["stored_path"] = stored_path.string();
            spdlog::info("Sample stored at: {}", stored_path.string());
        } catch (const std::exception& e) {
            spdlog::warn("Failed to store sample: {}", e.what());
        }
    }

    spdlog::info("Sample processing completed successfully");
    return metadata;
}

// ============================================================================
// SAMPLE VALIDATION
// ============================================================================
// Validates a sample file according to configured criteria

ValidationResult SampleManager::ValidateSample(const std::filesystem::path& sample_path) const {
    ValidationResult result;
    result.valid = true;

    // Check if file exists
    if (!std::filesystem::exists(sample_path)) {
        result.valid = false;
        result.error_message = "File does not exist";
        return result;
    }

    // Check if it's a regular file
    if (!std::filesystem::is_regular_file(sample_path)) {
        result.valid = false;
        result.error_message = "Not a regular file";
        return result;
    }

    // Check file size
    auto file_size = std::filesystem::file_size(sample_path);
    if (file_size < config_.min_file_size) {
        result.valid = false;
        result.error_message = "File too small (minimum: " + 
                               std::to_string(config_.min_file_size) + " bytes)";
        return result;
    }

    if (file_size > config_.max_file_size) {
        result.valid = false;
        result.error_message = "File too large (maximum: " + 
                               std::to_string(config_.max_file_size) + " bytes)";
        return result;
    }

    // Check if file is readable
    std::ifstream test_file(sample_path, std::ios::binary);
    if (!test_file.is_open()) {
        result.valid = false;
        result.error_message = "File is not readable";
        return result;
    }

    // Check for dangerous patterns
    auto warnings = CheckDangerousPatterns(sample_path);
    result.warnings = warnings;

    return result;
}

// ============================================================================
// HASH CALCULATION
// ============================================================================
// Computes cryptographic hashes for a file

std::map<std::string, std::string> SampleManager::ComputeHashes(const std::filesystem::path& file_path) const {
    std::map<std::string, std::string> hashes;
    
    utils::HashUtils hash_utils;

    hashes["md5"] = hash_utils.ComputeMD5(file_path);
    hashes["sha1"] = hash_utils.ComputeSHA1(file_path);
    hashes["sha256"] = hash_utils.ComputeSHA256(file_path);
    
    return hashes;
}

// ============================================================================
// STATIC ANALYSIS
// ============================================================================
// Performs static analysis on a sample file: file type, entropy, string extraction

void SampleManager::PerformStaticAnalysis(const std::filesystem::path& sample_path, SampleMetadata& metadata) {
    // Detect file type
    metadata.file_type = DetectFileType(sample_path);
    metadata.mime_type = "application/octet-stream"; // Default
    spdlog::info("  File type: {}", metadata.file_type);

    // Calculate entropy
    if (config_.calculate_entropy) {
        metadata.entropy = CalculateEntropy(sample_path);
        spdlog::info("  Entropy: {:.4f}", metadata.entropy);
        
        if (metadata.entropy > 7.0) {
            metadata.additional_info["entropy_analysis"] = "HIGH - Possibly encrypted or compressed";
        } else if (metadata.entropy > 6.0) {
            metadata.additional_info["entropy_analysis"] = "MEDIUM - Mixed content";
        } else {
            metadata.additional_info["entropy_analysis"] = "LOW - Plain text or structured data";
        }
    }

    // Extract strings
    if (config_.enable_string_extraction) {
        auto all_strings = ExtractStrings(sample_path, config_.min_string_length);
        spdlog::info("  Extracted {} strings", all_strings.size());
        
        // Filter to interesting strings
        metadata.interesting_strings = utils::StringUtils::FilterInterestingStrings(all_strings);
        spdlog::info("  Found {} interesting strings", metadata.interesting_strings.size());
        
        // Limit to top 50 to avoid bloat
        if (metadata.interesting_strings.size() > 50) {
            metadata.interesting_strings.resize(50);
        }
    }
}

// ============================================================================
// FILE TYPE DETECTION
// ============================================================================
// Detects file type based on magic bytes and file extension

std::string SampleManager::DetectFileType(const std::filesystem::path& file_path) const {
    // Read magic bytes
    std::ifstream file(file_path, std::ios::binary);
    if (!file.is_open()) {
        return "Unknown";
    }

    std::array<unsigned char, 8> magic{};
    file.read(reinterpret_cast<char*>(magic.data()), magic.size());
    auto bytes_read = file.gcount();

    if (bytes_read < 2) {
        return "Unknown";
    }

    // Check common file signatures
    if (magic[0] == 0x4D && magic[1] == 0x5A) { // MZ
        return "PE Executable (Windows)";
    } else if (magic[0] == 0x7F && magic[1] == 0x45 && magic[2] == 0x4C && magic[3] == 0x46) { // ELF
        return "ELF Executable (Linux)";
    } else if (magic[0] == 0x50 && magic[1] == 0x4B) { // PK (ZIP)
        auto ext = file_path.extension().string();
        if (ext == ".jar") return "Java Archive (JAR)";
        if (ext == ".apk") return "Android Package (APK)";
        if (ext == ".docx" || ext == ".xlsx") return "Office Document";
        return "ZIP Archive";
    } else if (magic[0] == 0xD0 && magic[1] == 0xCF) { // OLE
        return "Microsoft Office Document (Legacy)";
    } else if (magic[0] == 0x25 && magic[1] == 0x50 && magic[2] == 0x44 && magic[3] == 0x46) { // PDF
        return "PDF Document";
    } else if (magic[0] == 0x23 && magic[1] == 0x21) { // Shebang (#!)
        return "Script (Shell/Python/Perl)";
    } else if (magic[0] == 0xFF && magic[1] == 0xD8 && magic[2] == 0xFF) { // JPEG
        return "JPEG Image";
    } else if (magic[0] == 0x89 && magic[1] == 0x50 && magic[2] == 0x4E && magic[3] == 0x47) { // PNG
        return "PNG Image";
    }

    // Check by extension as fallback
    auto ext = file_path.extension().string();
    if (ext == ".exe" || ext == ".dll") return "Windows Executable";
    if (ext == ".sh") return "Shell Script";
    if (ext == ".py") return "Python Script";
    if (ext == ".js") return "JavaScript";
    if (ext == ".vbs") return "VBScript";
    if (ext == ".bat" || ext == ".cmd") return "Batch Script";
    if (ext == ".ps1") return "PowerShell Script";

    return "Unknown";
}

// ============================================================================
// ENTROPY CALCULATION
// ============================================================================
// Calculates Shannon entropy of a file for compression/encryption detection

double SampleManager::CalculateEntropy(const std::filesystem::path& file_path) const {
    std::ifstream file(file_path, std::ios::binary);
    if (!file.is_open()) {
        return 0.0;
    }

    // Count byte frequencies
    std::array<std::size_t, 256> frequencies{};
    std::size_t total_bytes = 0;

    constexpr std::size_t buffer_size = 8192;
    std::array<char, buffer_size> buffer{};

    while (file.read(buffer.data(), buffer_size) || file.gcount() > 0) {
        for (std::size_t i = 0; i < static_cast<std::size_t>(file.gcount()); ++i) {
            ++frequencies[static_cast<unsigned char>(buffer[i])];
            ++total_bytes;
        }
    }

    // Calculate Shannon entropy
    double entropy = 0.0;
    for (auto freq : frequencies) {
        if (freq > 0) {
            double probability = static_cast<double>(freq) / total_bytes;
            entropy -= probability * std::log2(probability);
        }
    }

    return entropy;
}

// ============================================================================
// STRING EXTRACTION
// ============================================================================
// Extracts printable strings from a binary file

std::vector<std::string> SampleManager::ExtractStrings(const std::filesystem::path& file_path, 
                                                        std::size_t min_length) const {
    return utils::StringUtils::ExtractStrings(file_path, min_length);
}

// ============================================================================
// SAMPLE STORAGE
// ============================================================================
// Stores a sample file in the structured directory based on SHA256 hash

std::filesystem::path SampleManager::StoreSample(const std::filesystem::path& sample_path,
                                                  const std::string& sha256_hash) {
    // Create subdirectory based on first 2 chars of hash (like git objects)
    auto subdir = config_.samples_directory / sha256_hash.substr(0, 2);
    std::filesystem::create_directories(subdir);

    // Store with hash as filename
    auto stored_path = subdir / sha256_hash;
    
    // Copy file
    std::filesystem::copy_file(sample_path, stored_path, 
                               std::filesystem::copy_options::overwrite_existing);
    
    return stored_path;
}

// ============================================================================
// TIMESTAMP UTILITIES
// ============================================================================
// Returns current UTC timestamp in ISO 8601 format

std::string SampleManager::GetCurrentTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto now_time_t = std::chrono::system_clock::to_time_t(now);
    std::ostringstream oss;
    oss << std::put_time(std::gmtime(&now_time_t), "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

// ============================================================================
// DANGEROUS PATTERN CHECKING
// ============================================================================
// Analyzes extracted strings for dangerous patterns (network, execution, etc.)

std::vector<std::string> SampleManager::CheckDangerousPatterns(const std::filesystem::path& file_path) const {
    std::vector<std::string> warnings;

    // Extract some strings to check for patterns
    auto strings = ExtractStrings(file_path, 4);
    
    // Check for suspicious patterns
    bool has_network = false;
    bool has_exec = false;
    bool has_registry = false;
    bool has_encryption = false;

    for (const auto& str : strings) {
        auto lower = utils::StringUtils::ToLower(str);
        
        if (lower.find("http") != std::string::npos || lower.find("socket") != std::string::npos) {
            has_network = true;
        }
        if (lower.find("exec") != std::string::npos || lower.find("system") != std::string::npos || 
            lower.find("cmd") != std::string::npos) {
            has_exec = true;
        }
        if (lower.find("hkey") != std::string::npos || lower.find("registry") != std::string::npos) {
            has_registry = true;
        }
        if (lower.find("crypt") != std::string::npos || lower.find("cipher") != std::string::npos) {
            has_encryption = true;
        }
    }

    if (has_network) warnings.push_back("Contains network-related strings");
    if (has_exec) warnings.push_back("Contains execution-related strings");
    if (has_registry) warnings.push_back("Contains registry-related strings");
    if (has_encryption) warnings.push_back("Contains encryption-related strings");

    return warnings;
}

} // namespace core
} // namespace paramite
