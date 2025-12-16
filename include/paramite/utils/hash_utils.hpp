/**
 * @file hash_utils.hpp
 * @brief Cryptographic hashing and file integrity verification utilities
 * 
 * Provides comprehensive hashing capabilities for malware analysis including
 * cryptographic hashes (MD5, SHA-1, SHA-256), fuzzy hashing (ssdeep) for
 * similarity detection, and PE import hashing (imphash) for malware family
 * identification. All hash computations are optimized for large binary files.
 * 
 * @date 2025
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <optional>
#include <filesystem>
#include <cstdint>
#include <chrono>

namespace paramite {
namespace utils {

/**
 * @enum HashAlgorithm
 * @brief Supported cryptographic and fuzzy hash algorithms
 * 
 * Provides various hashing algorithms suitable for different malware
 * analysis purposes:
 * - Cryptographic hashes for unique identification
 * - Fuzzy hashes for similarity matching
 * - Import hashes for malware family clustering
 */
enum class HashAlgorithm {
    MD5,        ///< MD5 (128-bit, fast but deprecated for security)
    SHA1,       ///< SHA-1 (160-bit, legacy)
    SHA256,     ///< SHA-256 (256-bit, recommended for file identification)
    SHA512,     ///< SHA-512 (512-bit, highest security)
    SSDEEP,     ///< ssdeep fuzzy hash (context-triggered piecewise hashing)
    IMPHASH,    ///< PE import hash (for malware family identification)
    TLSH        ///< Trend Micro Locality Sensitive Hash (similarity detection)
};

/**
 * @struct HashResult
 * @brief Comprehensive hash calculation result
 * 
 * Contains multiple hash types computed from a single file. Allows
 * flexible matching against different hash types and provides timing
 * information for performance analysis.
 * 
 * **Usage**:
 * @code
 * HashUtils hasher;
 * auto result = hasher.ComputeFileHashes("/path/to/malware.exe");
 * 
 * std::cout << "SHA-256: " << result.sha256 << std::endl;
 * std::cout << "MD5: " << result.md5 << std::endl;
 * if (result.ssdeep) {
 *     std::cout << "ssdeep: " << *result.ssdeep << std::endl;
 * }
 * @endcode
 */
struct HashResult {
    std::string md5;                        ///< MD5 hash (32 hex characters)
    std::string sha1;                       ///< SHA-1 hash (40 hex characters)
    std::string sha256;                     ///< SHA-256 hash (64 hex characters)
    std::string sha512;                     ///< SHA-512 hash (128 hex characters)
    std::optional<std::string> ssdeep;      ///< ssdeep fuzzy hash (if enabled)
    std::optional<std::string> imphash;     ///< Import hash (PE files only)
    std::optional<std::string> tlsh;        ///< TLSH (if enabled)
    
    std::filesystem::path file_path;        ///< Source file path
    std::size_t file_size{0};              ///< File size in bytes
    
    std::chrono::milliseconds computation_time{0};  ///< Time taken to compute all hashes
};

/**
 * @struct FuzzyHashComparison
 * @brief Result of fuzzy hash similarity comparison
 * 
 * Provides similarity score between two fuzzy hashes (ssdeep or TLSH).
 * Used for identifying similar or variant malware samples.
 * 
 * **Interpretation**:
 * - Score 0: No similarity
 * - Score 1-25: Minor similarities
 * - Score 25-50: Some similarities (possibly related)
 * - Score 50-75: Significant similarities (likely related)
 * - Score 75-100: Very similar (same family/variant)
 */
struct FuzzyHashComparison {
    int similarity_score{0};      ///< Similarity score 0-100 (higher = more similar)
    std::string hash1;            ///< First hash
    std::string hash2;            ///< Second hash
    bool is_similar{false};       ///< Exceeds similarity threshold
    int threshold{75};            ///< Threshold used for is_similar (default: 75)
};

/**
 * @struct HashConfig
 * @brief Configuration for hash computation
 * 
 * Controls which hash algorithms to compute and performance settings.
 * Allows selective hash computation to optimize for speed or completeness.
 */
struct HashConfig {
    // Hash Algorithm Selection
    bool compute_md5{true};            ///< Compute MD5 (fast, commonly used)
    bool compute_sha1{true};           ///< Compute SHA-1 (legacy support)
    bool compute_sha256{true};         ///< Compute SHA-256 (recommended)
    bool compute_sha512{false};        ///< Compute SHA-512 (slower, higher security)
    bool compute_ssdeep{true};         ///< Compute ssdeep fuzzy hash
    bool compute_imphash{true};        ///< Compute PE import hash
    bool compute_tlsh{false};          ///< Compute TLSH (requires library)
    
    // Performance Settings
    std::size_t buffer_size{8192};     ///< File read buffer size (8KB default)
    bool use_parallel{true};           ///< Compute hashes in parallel threads
    
    // Verification
    bool verify_after_hash{false};     ///< Re-hash to verify correctness
};

/**
 * @class HashUtils
 * @brief Cryptographic hashing and file integrity utilities
 * 
 * Comprehensive hashing toolkit for malware analysis. Supports:
 * - Multiple cryptographic hash algorithms (MD5, SHA-1, SHA-256, SHA-512)
 * - Fuzzy hashing for similarity matching (ssdeep, TLSH)
 * - Import hashing for PE malware family identification
 * - File integrity verification
 * - Parallel hash computation for performance
 * 
 * **Thread Safety**: Instance methods are NOT thread-safe. Create separate
 * instances for concurrent use or use static methods.
 * 
 * **Performance**: Multi-threaded hashing can process ~500MB/s on modern CPUs.
 * 
 * **Usage Example**:
 * @code
 * // Configure which hashes to compute
 * HashUtils::HashConfig config;
 * config.compute_sha256 = true;
 * config.compute_ssdeep = true;
 * config.compute_md5 = true;
 * 
 * HashUtils hasher(config);
 * 
 * // Compute all configured hashes at once
 * auto result = hasher.ComputeFileHashes("/path/to/malware.exe");
 * 
 * std::cout << "SHA-256: " << result.sha256 << std::endl;
 * std::cout << "File Size: " << result.file_size << " bytes" << std::endl;
 * 
 * // Compare with known sample using fuzzy hash
 * if (result.ssdeep) {
 *     auto comparison = hasher.CompareFuzzyHashes(
 *         *result.ssdeep,
 *         "known_malware_ssdeep_hash"
 *     );
 *     
 *     if (comparison.is_similar) {
 *         std::cout << "Sample is " << comparison.similarity_score 
 *                   << "% similar to known malware" << std::endl;
 *     }
 * }
 * @endcode
 */
class HashUtils {
public:
    /**
     * @brief Construct hasher with custom configuration
     * @param config Hash computation configuration
     */
    explicit HashUtils(const HashConfig& config = HashConfig{});
    
    ~HashUtils();

    /**
     * @brief Compute all configured hashes for a file
     * 
     * Efficiently computes multiple hash types in a single file pass.
     * If parallel computation is enabled, hashes are computed concurrently
     * for better performance.
     * 
     * @param file_path Path to file to hash
     * @return HashResult containing all computed hashes
     * 
     * @throws std::runtime_error if file cannot be read
     * 
     * **Performance**: ~1-3 seconds for 10MB file (all hashes enabled)
     * 
     * **Example**:
     * @code
     * HashUtils hasher;
     * auto result = hasher.ComputeFileHashes("malware.exe");
     * std::cout << "SHA-256: " << result.sha256 << std::endl;
     * @endcode
     */
    HashResult ComputeFileHashes(const std::filesystem::path& file_path);

    /**
     * @brief Compute specific hash algorithm for a file
     * 
     * @param file_path Path to file
     * @param algorithm Hash algorithm to use
     * @return Hash string (hex-encoded for cryptographic hashes)
     * 
     * @throws std::runtime_error if file cannot be read
     * @throws std::invalid_argument if algorithm not supported
     */
    std::string ComputeFileHash(const std::filesystem::path& file_path,
                               HashAlgorithm algorithm);

    /**
     * @brief Compute hash of string data
     * 
     * @param data String to hash
     * @param algorithm Hash algorithm to use
     * @return Hash string
     * 
     * **Use Case**: Hashing passwords, tokens, or small data
     */
    std::string ComputeStringHash(const std::string& data,
                                  HashAlgorithm algorithm);

    /**
     * @brief Compute hash of binary data
     * 
     * @param data Binary data buffer
     * @param algorithm Hash algorithm to use
     * @return Hash string
     */
    std::string ComputeDataHash(const std::vector<uint8_t>& data,
                               HashAlgorithm algorithm);

    /***************************************************************************
     * Individual Hash Methods (MD5)
     ***************************************************************************/
    
    /**
     * @brief Compute MD5 hash of file
     * 
     * @param file_path Path to file
     * @return 32-character hex MD5 hash
     * 
     * @note MD5 is cryptographically broken but still widely used for
     *       malware identification due to legacy database compatibility
     */
    std::string ComputeMD5(const std::filesystem::path& file_path);
    
    /**
     * @brief Compute MD5 hash of string
     * @param data String to hash
     * @return MD5 hash
     */
    std::string ComputeMD5(const std::string& data);
    
    /**
     * @brief Compute MD5 hash of binary data
     * @param data Binary buffer
     * @return MD5 hash
     */
    std::string ComputeMD5(const std::vector<uint8_t>& data);

    /***************************************************************************
     * Individual Hash Methods (SHA-1)
     ***************************************************************************/
    
    /**
     * @brief Compute SHA-1 hash of file
     * 
     * @param file_path Path to file
     * @return 40-character hex SHA-1 hash
     * 
     * @note SHA-1 is deprecated for security but still used in malware
     *       analysis for legacy compatibility
     */
    std::string ComputeSHA1(const std::filesystem::path& file_path);
    std::string ComputeSHA1(const std::string& data);
    std::string ComputeSHA1(const std::vector<uint8_t>& data);

    /***************************************************************************
     * Individual Hash Methods (SHA-256)
     ***************************************************************************/
    
    /**
     * @brief Compute SHA-256 hash of file
     * 
     * @param file_path Path to file
     * @return 64-character hex SHA-256 hash
     * 
     * @note SHA-256 is the recommended hash for file identification.
     *       It provides strong collision resistance and is widely supported.
     */
    std::string ComputeSHA256(const std::filesystem::path& file_path);
    std::string ComputeSHA256(const std::string& data);
    std::string ComputeSHA256(const std::vector<uint8_t>& data);

    /***************************************************************************
     * Individual Hash Methods (SHA-512)
     ***************************************************************************/
    
    /**
     * @brief Compute SHA-512 hash of file
     * 
     * @param file_path Path to file
     * @return 128-character hex SHA-512 hash
     * 
     * @note SHA-512 provides highest security but is slower than SHA-256.
     *       Rarely needed for malware analysis.
     */
    std::string ComputeSHA512(const std::filesystem::path& file_path);
    std::string ComputeSHA512(const std::string& data);
    std::string ComputeSHA512(const std::vector<uint8_t>& data);

    /***************************************************************************
     * Fuzzy and Specialized Hashes
     ***************************************************************************/
    
    /**
     * @brief Compute ssdeep fuzzy hash
     * 
     * ssdeep uses context-triggered piecewise hashing to create fuzzy
     * signatures that can match similar (but not identical) files.
     * Essential for detecting malware variants and polymorphic samples.
     * 
     * @param file_path Path to file
     * @return ssdeep hash string (format: blocksize:hash1:hash2)
     * 
     * @throws std::runtime_error if ssdeep library not available
     * 
     * **Use Case**: Detecting malware variants with minor modifications
     * 
     * **Example Output**: "3:AXGBicFlgVNhBGcL6:AXGHsNhxLn"
     */
    std::string ComputeSSDeep(const std::filesystem::path& file_path);

    /**
     * @brief Compute PE import hash (imphash)
     * 
     * Hashes the import table of a PE executable to create a signature
     * based on imported DLLs and functions. Identical imphashs indicate
     * similar functionality, useful for malware family clustering.
     * 
     * @param pe_file Path to PE executable
     * @return Import hash (MD5 of normalized import table), or nullopt if not PE
     * 
     * **Use Case**: Grouping malware samples by functionality
     * 
     * **Note**: Only works with valid PE files (.exe, .dll, .sys)
     */
    std::optional<std::string> ComputeImpHash(const std::filesystem::path& pe_file);

    /**
     * @brief Compute TLSH (Trend Micro Locality Sensitive Hash)
     * 
     * Advanced fuzzy hash designed for malware detection and clustering.
     * Provides better performance than ssdeep for large-scale comparisons.
     * 
     * @param file_path Path to file
     * @return TLSH hash, or nullopt if file too small (< 50 bytes)
     * 
     * @throws std::runtime_error if TLSH library not available
     * 
     * @note TLSH requires minimum file size of ~50 bytes
     */
    std::optional<std::string> ComputeTLSH(const std::filesystem::path& file_path);

    /***************************************************************************
     * Fuzzy Hash Comparison
     ***************************************************************************/
    
    /**
     * @brief Compare two fuzzy hashes for similarity
     * 
     * Computes similarity score between ssdeep hashes. Higher scores
     * indicate more similar files.
     * 
     * @param hash1 First ssdeep hash
     * @param hash2 Second ssdeep hash
     * @param threshold Similarity threshold for is_similar flag (default: 75)
     * @return Comparison result with similarity score
     * 
     * **Similarity Interpretation**:
     * - 0-25: Likely unrelated
     * - 25-50: Possibly related
     * - 50-75: Likely related (same family)
     * - 75-100: Very similar (minor variant)
     * 
     * **Example**:
     * @code
     * auto hash1 = hasher.ComputeSSDeep("malware1.exe");
     * auto hash2 = hasher.ComputeSSDeep("malware2.exe");
     * 
     * auto comparison = hasher.CompareFuzzyHashes(hash1, hash2, 50);
     * if (comparison.is_similar) {
     *     std::cout << "Samples are " << comparison.similarity_score 
     *               << "% similar" << std::endl;
     * }
     * @endcode
     */
    FuzzyHashComparison CompareFuzzyHashes(const std::string& hash1,
                                          const std::string& hash2,
                                          int threshold = 75);

    /***************************************************************************
     * File Integrity Verification
     ***************************************************************************/
    
    /**
     * @brief Verify file hash against expected value
     * 
     * Computes specified hash of file and compares with expected value.
     * Used for integrity verification and sample identification.
     * 
     * @param file_path File to verify
     * @param expected_hash Expected hash value (hex string)
     * @param algorithm Hash algorithm to use (default: SHA-256)
     * @return true if hash matches expected value
     * 
     * @note Hash comparison is case-insensitive
     * 
     * **Example**:
     * @code
     * if (hasher.VerifyFileHash("sample.exe", known_sha256)) {
     *     std::cout << "Sample verified!" << std::endl;
     * }
     * @endcode
     */
    bool VerifyFileHash(const std::filesystem::path& file_path,
                       const std::string& expected_hash,
                       HashAlgorithm algorithm = HashAlgorithm::SHA256);

    /**
     * @brief Verify file against complete HashResult
     * 
     * Verifies all non-empty hashes in HashResult against file.
     * Useful for comprehensive integrity checking.
     * 
     * @param file_path File to verify
     * @param expected_hashes Expected hash values
     * @return true if all non-empty hashes match
     */
    bool VerifyFile(const std::filesystem::path& file_path,
                   const HashResult& expected_hashes);

    /***************************************************************************
     * Similarity Search
     ***************************************************************************/
    
    /**
     * @brief Find similar files using fuzzy hashing
     * 
     * Compares target fuzzy hash against multiple candidate hashes to
     * identify similar samples. Useful for clustering malware variants.
     * 
     * @param target_hash Target ssdeep hash to match
     * @param candidate_hashes List of candidate hashes to compare against
     * @param min_similarity Minimum similarity score to include (0-100)
     * @return Vector of comparisons exceeding minimum similarity, sorted by score (descending)
     * 
     * **Use Case**: Finding related samples in large malware corpus
     * 
     * **Example**:
     * @code
     * auto similar = hasher.FindSimilarFiles(
     *     target_ssdeep,
     *     database_hashes,
     *     60  // 60% similarity threshold
     * );
     * 
     * std::cout << "Found " << similar.size() << " similar samples" << std::endl;
     * for (const auto& match : similar) {
     *     std::cout << "  Similarity: " << match.similarity_score << "%" << std::endl;
     * }
     * @endcode
     */
    std::vector<FuzzyHashComparison> FindSimilarFiles(
        const std::string& target_hash,
        const std::vector<std::string>& candidate_hashes,
        int min_similarity = 50
    );

private:
    HashConfig config_;  ///< Hasher configuration
    
    // Internal implementation details (pimpl idiom could be used here)
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace utils
} // namespace paramite