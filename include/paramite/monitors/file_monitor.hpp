/**
 * @file file_monitor.hpp
 * @brief Real-time filesystem operation monitoring for malware analysis
 * 
 * Provides comprehensive tracking of file system operations during malware
 * execution with pattern detection for ransomware, droppers, and data exfiltration.
 * Integrates with strace and inotify for complete coverage of file activities.
 * 
 * @date 2025
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <set>
#include <filesystem>
#include <chrono>
#include <functional>
#include <optional>
#include <mutex>

namespace paramite {
namespace monitors {

/**
 * @enum FileOperation
 * @brief Types of file system operations
 * 
 * Comprehensive set of file operations that can be monitored
 * during malware execution.
 */
enum class FileOperation {
    CREATE,      ///< File creation
    DELETE,      ///< File deletion
    MODIFY,      ///< Content modification
    READ,        ///< Read operation
    WRITE,       ///< Write operation
    RENAME,      ///< File rename/move
    CHMOD,       ///< Permission change
    CHOWN,       ///< Owner change
    SYMLINK,     ///< Symbolic link creation
    HARDLINK,    ///< Hard link creation
    TRUNCATE,    ///< File truncation
    COPY,        ///< File copy
    MOVE,        ///< File move
    OPEN,        ///< File open
    CLOSE,       ///< File close
    STAT,        ///< Metadata read
    ACCESS       ///< Access attempt
};

/**
 * @enum FileAccessMode
 * @brief File access permissions
 */
enum class FileAccessMode {
    READ_ONLY,    ///< Read-only access
    WRITE_ONLY,   ///< Write-only access
    READ_WRITE,   ///< Read and write access
    APPEND,       ///< Append mode
    EXECUTE,      ///< Execute permission
    UNKNOWN       ///< Unknown or mixed mode
};

/**
 * @struct FileEvent
 * @brief Detailed information about a file system operation
 * 
 * Captures complete context of a file operation including process information,
 * file metadata, timing, and suspicion indicators.
 */
struct FileEvent {
    // Operation Details
    FileOperation operation;                 ///< Type of operation
    std::filesystem::path file_path;         ///< Target file path
    std::filesystem::path original_path;     ///< Original path (for rename/move)
    FileAccessMode access_mode;              ///< Access mode
    
    // Process Information
    int pid{0};                  ///< Process ID
    std::string process_name;    ///< Process name
    std::string process_path;    ///< Process executable path
    int uid{0};                  ///< User ID
    int gid{0};                  ///< Group ID
    
    // File Metadata
    std::size_t file_size{0};               ///< File size in bytes
    std::string file_type;                  ///< Detected file type
    std::string mime_type;                  ///< MIME type
    std::optional<std::string> file_hash;   ///< SHA-256 hash (for new/modified files)
    
    // Permissions
    std::string permissions;     ///< Unix permissions (e.g., "0644")
    std::string owner;           ///< File owner name
    std::string group;           ///< File group name
    
    // Timing
    std::chrono::system_clock::time_point timestamp;  ///< When operation occurred
    std::chrono::microseconds duration{0};            ///< Operation duration
    
    // Threat Assessment
    bool is_suspicious{false};       ///< Flagged as suspicious
    std::string suspicion_reason;    ///< Why flagged as suspicious
    int suspicion_score{0};          ///< Suspicion score (0-100)
    
    // System Call Details
    std::string syscall_name;                ///< System call name (e.g., "open", "unlink")
    int syscall_return_code{0};              ///< Syscall return value
    std::vector<std::string> syscall_args;   ///< Syscall arguments
};

/**
 * @struct FileStatistics
 * @brief Aggregate statistics of file operations
 * 
 * Provides summary statistics and analytics about observed file operations
 * for pattern detection and reporting.
 */
struct FileStatistics {
    // Operation Counts
    std::map<FileOperation, int> operation_counts;  ///< Count by operation type
    int total_operations{0};                        ///< Total operations observed
    
    // File Counts
    int files_created{0};    ///< Number of files created
    int files_deleted{0};    ///< Number of files deleted
    int files_modified{0};   ///< Number of files modified
    int files_read{0};       ///< Number of files read
    
    // Size Statistics
    std::size_t total_bytes_written{0};  ///< Total bytes written
    std::size_t total_bytes_read{0};     ///< Total bytes read
    
    // Suspicious Activity
    int suspicious_operations{0};                    ///< Count of suspicious operations
    std::vector<std::string> suspicious_patterns;    ///< Detected patterns
    
    // Top Files
    std::vector<std::pair<std::filesystem::path, int>> most_accessed_files;  ///< Most accessed files
    
    // File Extensions
    std::map<std::string, int> file_extension_counts;  ///< Files by extension
    
    // Directory Hotspots
    std::vector<std::pair<std::filesystem::path, int>> hot_directories;  ///< Most active directories
};

/**
 * @struct FileMonitorConfig
 * @brief Configuration for file system monitoring
 */
struct FileMonitorConfig {
    // Monitoring Scope
    std::vector<std::filesystem::path> monitored_directories;  ///< Specific directories to monitor
    bool monitor_all_filesystem{true};                         ///< Monitor entire filesystem
    bool recursive_monitoring{true};                           ///< Recursively monitor subdirectories
    
    // Filters
    std::set<std::string> excluded_paths;       ///< Paths to exclude from monitoring
    std::set<std::string> excluded_extensions;  ///< File extensions to ignore
    std::set<std::string> excluded_processes;   ///< Processes to ignore
    bool ignore_system_processes{true};         ///< Ignore kernel/system processes
    
    // What to Monitor
    bool track_file_creation{true};      ///< Track new files
    bool track_file_deletion{true};      ///< Track file deletions
    bool track_file_modification{true};  ///< Track content changes
    bool track_file_reads{true};         ///< Track read operations
    bool track_permission_changes{true}; ///< Track chmod/chown
    bool track_symlinks{true};           ///< Track symlink creation
    
    // Hash Calculation
    bool calculate_hashes{true};                                ///< Calculate file hashes
    std::size_t max_file_size_for_hash{10 * 1024 * 1024};     ///< Max size for hashing (10MB)
    
    // Performance
    int max_events_per_second{1000};        ///< Rate limit
    std::size_t max_buffered_events{10000}; ///< Event buffer size
    bool enable_rate_limiting{true};        ///< Enable rate limiting
    
    // Detection
    bool detect_encryption{true};               ///< Detect file encryption patterns
    bool detect_mass_deletion{true};            ///< Detect mass file deletion
    bool detect_sensitive_file_access{true};    ///< Monitor sensitive files
    std::vector<std::string> sensitive_file_patterns;  ///< Patterns for sensitive files
    
    // Output
    bool verbose_logging{false};                      ///< Enable verbose logging
    std::filesystem::path log_file{"file_monitor.log"};  ///< Log file path
};

/// Callback function type for file events
using FileEventCallback = std::function<void(const FileEvent&)>;

/**
 * @class FileMonitor
 * @brief Real-time file system operation monitor
 * 
 * Monitors and analyzes file system operations during malware execution to detect:
 * - **Ransomware**: Mass file encryption, ransom note creation
 * - **Droppers**: Creation of additional malware payloads
 * - **Data Exfiltration**: Large file reads, staging areas
 * - **Persistence**: Modifications to startup locations
 * - **Sensitive File Access**: Password files, SSH keys, credentials
 * 
 * **Monitoring Methods**:
 * - strace parsing for syscall-level detail
 * - inotify for kernel-level filesystem events
 * - Baseline comparison for before/after analysis
 * 
 * **Thread Safety**: NOT thread-safe. Use from single thread or add external synchronization.
 * 
 * **Usage Example**:
 * @code
 * FileMonitor::Config config;
 * config.monitor_all_filesystem = true;
 * config.detect_encryption = true;
 * config.calculate_hashes = true;
 * 
 * FileMonitor monitor(config);
 * 
 * // Register callback for real-time alerts
 * monitor.RegisterCallback([](const FileEvent& event) {
 *     if (event.is_suspicious) {
 *         std::cout << "Suspicious: " << event.suspicion_reason << std::endl;
 *     }
 * });
 * 
 * // Start monitoring
 * monitor.Start();
 * 
 * // ... execute malware ...
 * 
 * // Stop and analyze
 * monitor.Stop();
 * 
 * auto created = monitor.GetCreatedFiles();
 * auto deleted = monitor.GetDeletedFiles();
 * auto stats = monitor.GetStatistics();
 * 
 * // Detect specific behaviors
 * auto [ransomware_score, ransomware_desc] = monitor.DetectRansomwareBehavior();
 * if (ransomware_score > 75) {
 *     std::cout << "Ransomware detected: " << ransomware_desc << std::endl;
 * }
 * @endcode
 */
class FileMonitor {
public:
    /**
     * @brief Construct file monitor with configuration
     * @param config Monitoring configuration
     */
    explicit FileMonitor(const FileMonitorConfig& config = FileMonitorConfig{});
    
    ~FileMonitor();

    FileMonitor(const FileMonitor&) = delete;
    FileMonitor& operator=(const FileMonitor&) = delete;

    /**
     * @brief Start monitoring filesystem operations
     * 
     * Creates baseline snapshot and begins event collection.
     * 
     * @return true if monitoring started successfully
     */
    bool Start();

    /**
     * @brief Stop monitoring and finalize collection
     */
    void Stop();

    /**
     * @brief Check if monitoring is currently active
     * @return true if monitoring
     */
    bool IsMonitoring() const { return is_monitoring_; }

    /**
     * @brief Register callback for file events
     * 
     * Callback is invoked for each file event in real-time.
     * Useful for immediate alerting or custom processing.
     * 
     * @param callback Function to call for each event
     */
    void RegisterCallback(FileEventCallback callback);

    /**
     * @brief Get all captured file events
     * @return Vector of all events
     */
    std::vector<FileEvent> GetEvents() const;

    /**
     * @brief Get events filtered by operation type
     * @param op Operation type to filter
     * @return Filtered events
     */
    std::vector<FileEvent> GetEventsByOperation(FileOperation op) const;

    /**
     * @brief Get all events for specific file path
     * @param path File path to filter
     * @return Events affecting this path
     */
    std::vector<FileEvent> GetEventsByPath(const std::filesystem::path& path) const;

    /**
     * @brief Get only suspicious events
     * @return Events flagged as suspicious
     */
    std::vector<FileEvent> GetSuspiciousEvents() const;

    /**
     * @brief Get aggregate file operation statistics
     * @return FileStatistics structure
     */
    FileStatistics GetStatistics() const;

    /**
     * @brief Get list of files created during monitoring
     * @return Vector of created file paths
     */
    std::vector<std::filesystem::path> GetCreatedFiles() const;

    /**
     * @brief Get list of files deleted during monitoring
     * @return Vector of deleted file paths
     */
    std::vector<std::filesystem::path> GetDeletedFiles() const;

    /**
     * @brief Get list of files modified during monitoring
     * @return Vector of modified file paths
     */
    std::vector<std::filesystem::path> GetModifiedFiles() const;

    /**
     * @brief Get file changes comparison (before/after)
     * 
     * @return Map of file path to change description
     */
    std::map<std::filesystem::path, std::string> GetFileChanges() const;

    /**
     * @brief Detect ransomware behavior patterns
     * 
     * Analyzes events for ransomware indicators:
     * - Mass file modifications
     * - File extension changes (to .encrypted, .locked, etc.)
     * - Ransom note creation (README.txt)
     * - Rapid encryption patterns
     * 
     * @return Pair of (confidence score 0-100, description)
     */
    std::pair<int, std::string> DetectRansomwareBehavior() const;

    /**
     * @brief Detect dropper behavior patterns
     * 
     * Identifies malware creating additional payloads or tools.
     * 
     * @return Pair of (confidence score, description)
     */
    std::pair<int, std::string> DetectDropperBehavior() const;

    /**
     * @brief Detect data exfiltration patterns
     * 
     * Looks for staging areas, large file reads, compression.
     * 
     * @return Pair of (confidence score, description)
     */
    std::pair<int, std::string> DetectExfiltration() const;

    /**
     * @brief Export events to JSON format
     * @return JSON string of all events
     */
    std::string ExportToJSON() const;

    /**
     * @brief Get current configuration
     * @return Reference to config
     */
    const FileMonitorConfig& GetConfig() const { return config_; }

    /**
     * @brief Clear all collected events
     */
    void ClearEvents();

private:
    FileMonitorConfig config_;           ///< Configuration
    bool is_monitoring_{false};          ///< Monitoring active flag
    std::vector<FileEvent> events_;      ///< Collected events
    mutable std::mutex events_mutex_;    ///< Thread synchronization
    std::vector<FileEventCallback> callbacks_;  ///< Registered callbacks
    std::map<std::filesystem::path, std::string> baseline_hashes_;  ///< Baseline state
    std::set<std::filesystem::path> baseline_files_;                ///< Initial file list
    mutable FileStatistics statistics_;  ///< Aggregate statistics

    // Internal methods
    void CreateBaseline();
    void ParseStraceOutput(const std::string& line);
    void ParseInotifyEvent(const void* event_data);
    void ProcessEvent(FileEvent& event);
    void AnalyzeEvent(FileEvent& event);
    int CalculateSuspicionScore(const FileEvent& event) const;
    bool ShouldMonitorPath(const std::filesystem::path& path) const;
    bool IsSensitiveFile(const std::filesystem::path& path) const;
    std::optional<std::string> CalculateFileHash(const std::filesystem::path& path);
    std::string DetectFileType(const std::filesystem::path& path) const;
    std::string DetectMIMEType(const std::filesystem::path& path) const;
    bool IsEncryptionPattern(const FileEvent& event) const;
    bool IsMassOperation(FileOperation op, int count, std::chrono::milliseconds timespan) const;
    std::string GetFileExtension(const std::filesystem::path& path) const;
    void UpdateStatistics(const FileEvent& event);
    void NotifyCallbacks(const FileEvent& event);
    std::vector<std::string> ParseSyscallArgs(const std::string& args_str);
    FileAccessMode ParseAccessMode(const std::string& flags) const;
    std::string FileOperationToString(FileOperation op) const;
    void LogEvent(const FileEvent& event);
};

} // namespace monitors
} // namespace paramite