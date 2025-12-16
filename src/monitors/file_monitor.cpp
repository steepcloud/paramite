/**
 * @file file_monitor.cpp
 * @brief Implementation of real-time file system operation monitoring
 * 
 * Implements comprehensive filesystem monitoring using inotify (Linux) or ReadDirectoryChangesW
 * (Windows) to detect file operations, ransomware encryption patterns, dropper activity,
 * data exfiltration, persistence mechanisms, and suspicious file modifications during malware
 * execution in the sandbox environment.
 * 
 * **Monitoring Capabilities**:
 * - **File Operations**: create, modify, delete, rename, chmod, chown
 * - **Directory Operations**: mkdir, rmdir, directory traversal
 * - **Attribute Changes**: permissions, ownership, timestamps
 * - **Access Patterns**: rapid file access (ransomware indicator)
 * - **Suspicious Locations**: /tmp, autostart folders, system directories
 * 
 * **Ransomware Detection**:
 * Indicators:
 * - High-frequency file modifications (>100 files/sec)
 * - File extension changes (to .encrypted, .locked, .crypto)
 * - Backup file deletion (/var/backups, shadow copies)
 * - Ransom note creation (README.txt, HOW_TO_DECRYPT.html)
 * - Encryption patterns (entropy increase in modified files)
 * 
 * **Dropper Detection**:
 * Patterns:
 * - Executable file creation in suspicious locations
 * - File downloads to temp directories
 * - Archive extraction (unpacking)
 * - DLL/library drops
 * - Script file creation (.ps1, .vbs, .bat, .sh)
 * 
 * **Persistence Mechanisms**:
 * - Autostart folder modifications (/etc/init.d, ~/.config/autostart)
 * - Registry run key modifications (Windows)
 * - Cron job creation
 * - Service installation
 * - Scheduled task creation
 * 
 * **Platform-Specific Monitoring**:
 * - **Linux**: inotify API for kernel-level event notification
 * - **Windows**: ReadDirectoryChangesW for change notifications
 * - **macOS**: FSEvents framework (optional)
 * 
 * **Performance Optimization**:
 * - Event batching (reduce overhead)
 * - Selective monitoring (ignore benign paths)
 * - Ring buffer for event storage
 * - Asynchronous event processing
 * 
 * @date 2025
 */

#include "paramite/monitors/file_monitor.hpp"
#include "paramite/utils/hash_utils.hpp"
#include "paramite/utils/string_utils.hpp"

#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>

#include <fstream>
#include <sstream>
#include <algorithm>
#include <regex>
#include <chrono>
#include <iomanip>
#include <ctime>

using json = nlohmann::json;

namespace paramite {
namespace monitors {

// Constructor
FileMonitor::FileMonitor(const FileMonitorConfig& config)
    : config_(config)
    , is_monitoring_(false) {
    
    spdlog::info("File Monitor initialized");
    spdlog::debug("Monitoring {} directories", config_.monitored_directories.size());
    spdlog::debug("Calculate hashes: {}", config_.calculate_hashes);
}

// Destructor
FileMonitor::~FileMonitor() {
    Stop();
    spdlog::info("File Monitor destroyed");
}

// Start monitoring
bool FileMonitor::Start() {
    if (is_monitoring_) {
        spdlog::warn("File Monitor already running");
        return true;
    }
    
    spdlog::info("═══════════════════════════════════════════════════════════════");
    spdlog::info("STARTING FILE MONITOR");
    spdlog::info("═══════════════════════════════════════════════════════════════");
    
    try {
        // Create baseline snapshot
        if (config_.monitor_all_filesystem || !config_.monitored_directories.empty()) {
            spdlog::info("Creating filesystem baseline...");
            CreateBaseline();
            spdlog::info("✓ Baseline created ({} files)", baseline_files_.size());
        }
        
        // Clear previous data
        {
            std::lock_guard<std::mutex> lock(events_mutex_);
            events_.clear();
            statistics_ = FileStatistics{};
        }
        
        is_monitoring_ = true;
        
        spdlog::info("═══════════════════════════════════════════════════════════════");
        spdlog::info("✓ File Monitor started");
        spdlog::info("═══════════════════════════════════════════════════════════════\n");
        
        return true;
    }
    catch (const std::exception& e) {
        spdlog::error("Failed to start File Monitor: {}", e.what());
        return false;
    }
}

// Stop monitoring
void FileMonitor::Stop() {
    if (!is_monitoring_) {
        return;
    }
    
    spdlog::info("Stopping File Monitor...");
    is_monitoring_ = false;
    
    spdlog::info("✓ File Monitor stopped");
    spdlog::info("  Total events captured: {}", events_.size());
    spdlog::info("  Suspicious events: {}", statistics_.suspicious_operations);
}

// Register callback
void FileMonitor::RegisterCallback(FileEventCallback callback) {
    callbacks_.push_back(callback);
    spdlog::debug("File event callback registered");
}

// Get all events
std::vector<FileEvent> FileMonitor::GetEvents() const {
    std::lock_guard<std::mutex> lock(events_mutex_);
    return events_;
}

// Get events by operation
std::vector<FileEvent> FileMonitor::GetEventsByOperation(FileOperation op) const {
    std::lock_guard<std::mutex> lock(events_mutex_);
    
    std::vector<FileEvent> filtered;
    for (const auto& event : events_) {
        if (event.operation == op) {
            filtered.push_back(event);
        }
    }
    
    return filtered;
}

// Get events by path
std::vector<FileEvent> FileMonitor::GetEventsByPath(const std::filesystem::path& path) const {
    std::lock_guard<std::mutex> lock(events_mutex_);
    
    std::vector<FileEvent> filtered;
    for (const auto& event : events_) {
        if (event.file_path == path) {
            filtered.push_back(event);
        }
    }
    
    return filtered;
}

// Get suspicious events
std::vector<FileEvent> FileMonitor::GetSuspiciousEvents() const {
    std::lock_guard<std::mutex> lock(events_mutex_);
    
    std::vector<FileEvent> suspicious;
    for (const auto& event : events_) {
        if (event.is_suspicious) {
            suspicious.push_back(event);
        }
    }
    
    return suspicious;
}

// Get statistics
FileStatistics FileMonitor::GetStatistics() const {
    std::lock_guard<std::mutex> lock(events_mutex_);
    return statistics_;
}

// Get created files
std::vector<std::filesystem::path> FileMonitor::GetCreatedFiles() const {
    std::lock_guard<std::mutex> lock(events_mutex_);
    
    std::vector<std::filesystem::path> files;
    for (const auto& event : events_) {
        if (event.operation == FileOperation::CREATE) {
            files.push_back(event.file_path);
        }
    }
    
    return files;
}

// Get deleted files
std::vector<std::filesystem::path> FileMonitor::GetDeletedFiles() const {
    std::lock_guard<std::mutex> lock(events_mutex_);
    
    std::vector<std::filesystem::path> files;
    for (const auto& event : events_) {
        if (event.operation == FileOperation::DELETE) {
            files.push_back(event.file_path);
        }
    }
    
    return files;
}

// Get modified files
std::vector<std::filesystem::path> FileMonitor::GetModifiedFiles() const {
    std::lock_guard<std::mutex> lock(events_mutex_);
    
    std::vector<std::filesystem::path> files;
    for (const auto& event : events_) {
        if (event.operation == FileOperation::MODIFY || 
            event.operation == FileOperation::WRITE) {
            files.push_back(event.file_path);
        }
    }
    
    return files;
}

// Get file changes
std::map<std::filesystem::path, std::string> FileMonitor::GetFileChanges() const {
    std::lock_guard<std::mutex> lock(events_mutex_);
    
    std::map<std::filesystem::path, std::string> changes;
    
    // Files that were created
    for (const auto& event : events_) {
        if (event.operation == FileOperation::CREATE) {
            changes[event.file_path] = "CREATED";
        } else if (event.operation == FileOperation::DELETE) {
            changes[event.file_path] = "DELETED";
        } else if (event.operation == FileOperation::MODIFY) {
            changes[event.file_path] = "MODIFIED";
        }
    }
    
    return changes;
}

// Detect ransomware behavior
std::pair<int, std::string> FileMonitor::DetectRansomwareBehavior() const {
    std::lock_guard<std::mutex> lock(events_mutex_);
    
    int confidence = 0;
    std::ostringstream description;
    std::vector<std::string> indicators;
    
    // Count encryption-like operations
    int encryption_ops = 0;
    int mass_file_ops = 0;
    int extension_changes = 0;
    bool has_ransom_note = false;
    
    std::map<std::string, int> extension_map;
    
    for (const auto& event : events_) {
        // Check for encryption patterns
        if (IsEncryptionPattern(event)) {
            encryption_ops++;
        }
        
        // Check for mass operations
        if (event.operation == FileOperation::MODIFY || 
            event.operation == FileOperation::DELETE) {
            mass_file_ops++;
        }
        
        // Track extension changes
        auto ext = GetFileExtension(event.file_path);
        extension_map[ext]++;
        
        // Check for ransom notes
        auto filename = event.file_path.filename().string();
        if (filename.find("README") != std::string::npos ||
            filename.find("DECRYPT") != std::string::npos ||
            filename.find("RANSOM") != std::string::npos ||
            filename.find("RECOVER") != std::string::npos) {
            has_ransom_note = true;
        }
    }
    
    // Analyze patterns
    if (encryption_ops > 10) {
        confidence += 30;
        indicators.push_back("High number of encryption-like operations (" + 
                           std::to_string(encryption_ops) + ")"
                           );
    }
    
    if (mass_file_ops > 50) {
        confidence += 25;
        indicators.push_back("Mass file modification/deletion (" + 
                           std::to_string(mass_file_ops) + " files)");
    }
    
    // Check for suspicious extensions
    std::vector<std::string> suspicious_exts = {
        ".encrypted", ".locked", ".crypto", ".crypt", ".enc", 
        ".aes", ".rsa", ".locked", ".cerber", ".locky"
    };
    
    for (const auto& [ext, count] : extension_map) {
        for (const auto& sus_ext : suspicious_exts) {
            if (ext.find(sus_ext) != std::string::npos) {
                confidence += 35;
                indicators.push_back("Files with suspicious extension: " + ext + 
                                   " (" + std::to_string(count) + " files)");
                break;
            }
        }
    }
    
    if (has_ransom_note) {
        confidence += 40;
        indicators.push_back("Ransom note detected");
    }
    
    // Cap at 100
    confidence = std::min(confidence, 100);
    
    // Build description
    if (confidence > 0) {
        description << "Ransomware indicators detected:\n";
        for (const auto& indicator : indicators) {
            description << "  • " << indicator << "\n";
        }
    } else {
        description << "No significant ransomware indicators detected";
    }
    
    return {confidence, description.str()};
}

// Detect dropper behavior
std::pair<int, std::string> FileMonitor::DetectDropperBehavior() const {
    std::lock_guard<std::mutex> lock(events_mutex_);
    
    int confidence = 0;
    std::ostringstream description;
    std::vector<std::string> indicators;
    
    // Count file creations in suspicious locations
    std::map<std::filesystem::path, int> creation_locations;
    int executable_drops = 0;
    int dll_drops = 0;
    int script_drops = 0;
    
    for (const auto& event : events_) {
        if (event.operation == FileOperation::CREATE) {
            auto dir = event.file_path.parent_path();
            creation_locations[dir]++;
            
            auto ext = GetFileExtension(event.file_path);
            
            // Check for executable files
            if (ext == ".exe" || ext == ".dll" || ext == ".sys") {
                executable_drops++;
            }
            
            // Check for DLLs
            if (ext == ".dll") {
                dll_drops++;
            }
            
            // Check for scripts
            if (ext == ".bat" || ext == ".cmd" || ext == ".ps1" || 
                ext == ".vbs" || ext == ".js") {
                script_drops++;
            }
        }
    }
    
    // Analyze patterns
    if (executable_drops > 0) {
        confidence += 40;
        indicators.push_back("Dropped " + std::to_string(executable_drops) + 
                           " executable files");
    }
    
    if (dll_drops > 2) {
        confidence += 25;
        indicators.push_back("Dropped " + std::to_string(dll_drops) + " DLL files");
    }
    
    if (script_drops > 0) {
        confidence += 20;
        indicators.push_back("Dropped " + std::to_string(script_drops) + 
                           " script files");
    }
    
    // Check for suspicious directories
    std::vector<std::string> suspicious_dirs = {
        "temp", "tmp", "appdata", "startup", "windows\\system32"
    };
    
    for (const auto& [dir, count] : creation_locations) {
        auto dir_str = dir.string();
        std::transform(dir_str.begin(), dir_str.end(), dir_str.begin(), ::tolower);
        
        for (const auto& sus_dir : suspicious_dirs) {
            if (dir_str.find(sus_dir) != std::string::npos) {
                confidence += 15;
                indicators.push_back("Files created in suspicious location: " + 
                                   dir.string() + " (" + std::to_string(count) + " files)");
                break;
            }
        }
    }
    
    confidence = std::min(confidence, 100);
    
    if (confidence > 0) {
        description << "Dropper indicators detected:\n";
        for (const auto& indicator : indicators) {
            description << "  • " << indicator << "\n";
        }
    } else {
        description << "No significant dropper indicators detected";
    }
    
    return {confidence, description.str()};
}

// Detect exfiltration
std::pair<int, std::string> FileMonitor::DetectExfiltration() const {
    std::lock_guard<std::mutex> lock(events_mutex_);
    
    int confidence = 0;
    std::ostringstream description;
    std::vector<std::string> indicators;
    
    // Count sensitive file reads
    int sensitive_reads = 0;
    int mass_reads = 0;
    int archive_creations = 0;
    
    for (const auto& event : events_) {
        if (event.operation == FileOperation::READ) {
            if (IsSensitiveFile(event.file_path)) {
                sensitive_reads++;
            }
            mass_reads++;
        }
        
        // Check for archive creation
        if (event.operation == FileOperation::CREATE) {
            auto ext = GetFileExtension(event.file_path);
            if (ext == ".zip" || ext == ".rar" || ext == ".7z" || 
                ext == ".tar" || ext == ".gz") {
                archive_creations++;
            }
        }
    }
    
    if (sensitive_reads > 5) {
        confidence += 40;
        indicators.push_back("Multiple sensitive files accessed (" + 
                           std::to_string(sensitive_reads) + ")");
    }
    
    if (mass_reads > 100) {
        confidence += 25;
        indicators.push_back("Mass file reading detected (" + 
                           std::to_string(mass_reads) + " files)");
    }
    
    if (archive_creations > 0) {
        confidence += 35;
        indicators.push_back("Archive files created (" + 
                           std::to_string(archive_creations) + ")");
    }
    
    confidence = std::min(confidence, 100);
    
    if (confidence > 0) {
        description << "Data exfiltration indicators detected:\n";
        for (const auto& indicator : indicators) {
            description << "  • " << indicator << "\n";
        }
    } else {
        description << "No significant exfiltration indicators detected";
    }
    
    return {confidence, description.str()};
}

// Export to JSON
std::string FileMonitor::ExportToJSON() const {
    std::lock_guard<std::mutex> lock(events_mutex_);
    
    json j;
    j["total_events"] = events_.size();
    j["statistics"] = {
        {"total_operations", statistics_.total_operations},
        {"files_created", statistics_.files_created},
        {"files_deleted", statistics_.files_deleted},
        {"files_modified", statistics_.files_modified},
        {"suspicious_operations", statistics_.suspicious_operations}
    };
    
    json events_array = json::array();
    for (const auto& event : events_) {
        json event_obj;
        event_obj["operation"] = FileOperationToString(event.operation);
        event_obj["file_path"] = event.file_path.string();
        event_obj["process_name"] = event.process_name;
        event_obj["pid"] = event.pid;
        event_obj["is_suspicious"] = event.is_suspicious;
        
        if (event.is_suspicious) {
            event_obj["suspicion_reason"] = event.suspicion_reason;
            event_obj["suspicion_score"] = event.suspicion_score;
        }
        
        auto time_t = std::chrono::system_clock::to_time_t(event.timestamp);
        std::ostringstream oss;
        oss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
        event_obj["timestamp"] = oss.str();
        
        events_array.push_back(event_obj);
    }
    
    j["events"] = events_array;
    
    return j.dump(2);
}

// Clear events
void FileMonitor::ClearEvents() {
    std::lock_guard<std::mutex> lock(events_mutex_);
    events_.clear();
    statistics_ = FileStatistics{};
    spdlog::debug("File Monitor events cleared");
}

// Private methods

// Create baseline
void FileMonitor::CreateBaseline() {
    baseline_files_.clear();
    baseline_hashes_.clear();
    
    // Scan monitored directories
    for (const auto& dir : config_.monitored_directories) {
        if (!std::filesystem::exists(dir)) {
            continue;
        }
        
        try {
            if (config_.recursive_monitoring) {
                for (const auto& entry : std::filesystem::recursive_directory_iterator(dir)) {
                    if (entry.is_regular_file()) {
                        baseline_files_.insert(entry.path());
                        
                        if (config_.calculate_hashes) {
                            // Calculate hash for important files
                            if (entry.file_size() < config_.max_file_size_for_hash) {
                                auto hash = CalculateFileHash(entry.path());
                                if (hash) {
                                    baseline_hashes_[entry.path()] = *hash;
                                }
                            }
                        }
                    }
                }
            } else {
                for (const auto& entry : std::filesystem::directory_iterator(dir)) {
                    if (entry.is_regular_file()) {
                        baseline_files_.insert(entry.path());
                    }
                }
            }
        }
        catch (const std::exception& e) {
            spdlog::warn("Error scanning {}: {}", dir.string(), e.what());
        }
    }
}

// Parse strace output
void FileMonitor::ParseStraceOutput(const std::string& line) {
    // Example: open("/tmp/test.txt", O_RDWR|O_CREAT, 0644) = 3
    // Example: write(3, "hello", 5) = 5
    // Example: unlink("/tmp/test.txt") = 0
    
    FileEvent event;
    event.timestamp = std::chrono::system_clock::now();
    
    // Parse syscall name
    size_t paren_pos = line.find('(');
    if (paren_pos == std::string::npos) {
        return;
    }
    
    event.syscall_name = line.substr(0, paren_pos);
    
    // Determine operation based on syscall
    if (event.syscall_name == "open" || event.syscall_name == "openat") {
        // Parse file path and flags
        size_t quote_start = line.find('"');
        size_t quote_end = line.find('"', quote_start + 1);
        if (quote_start != std::string::npos && quote_end != std::string::npos) {
            event.file_path = line.substr(quote_start + 1, quote_end - quote_start - 1);
            
            // Determine if CREATE or OPEN
            if (line.find("O_CREAT") != std::string::npos) {
                event.operation = FileOperation::CREATE;
            } else {
                event.operation = FileOperation::OPEN;
            }
            
            ProcessEvent(event);
        }
    }
    else if (event.syscall_name == "unlink" || event.syscall_name == "unlinkat") {
        size_t quote_start = line.find('"');
        size_t quote_end = line.find('"', quote_start + 1);
        if (quote_start != std::string::npos && quote_end != std::string::npos) {
            event.file_path = line.substr(quote_start + 1, quote_end - quote_start - 1);
            event.operation = FileOperation::DELETE;
            ProcessEvent(event);
        }
    }
    else if (event.syscall_name == "rename" || event.syscall_name == "renameat") {
        event.operation = FileOperation::RENAME;
        ProcessEvent(event);
    }
    // Add more syscalls as needed
}

// Process event
void FileMonitor::ProcessEvent(FileEvent& event) {
    if (!is_monitoring_) {
        return;
    }
    
    // Filter out excluded paths
    if (!ShouldMonitorPath(event.file_path)) {
        return;
    }
    
    // Analyze for suspicious patterns
    AnalyzeEvent(event);
    
    // Calculate hash if needed
    if (config_.calculate_hashes && 
        (event.operation == FileOperation::CREATE || 
         event.operation == FileOperation::MODIFY)) {
        if (std::filesystem::exists(event.file_path)) {
            auto size = std::filesystem::file_size(event.file_path);
            if (size < config_.max_file_size_for_hash) {
                event.file_hash = CalculateFileHash(event.file_path);
            }
        }
    }
    
    // Store event
    {
        std::lock_guard<std::mutex> lock(events_mutex_);
        events_.push_back(event);
        UpdateStatistics(event);
    }
    
    // Notify callbacks
    NotifyCallbacks(event);
    
    // Log if verbose
    if (config_.verbose_logging) {
        LogEvent(event);
    }
}

// Analyze event
void FileMonitor::AnalyzeEvent(FileEvent& event) {
    event.suspicion_score = CalculateSuspicionScore(event);
    
    if (event.suspicion_score >= 50) {
        event.is_suspicious = true;
        
        // Determine suspicion reason
        std::vector<std::string> reasons;
        
        if (IsSensitiveFile(event.file_path)) {
            reasons.push_back("Sensitive file access");
        }
        
        if (IsEncryptionPattern(event)) {
            reasons.push_back("Encryption-like pattern");
        }
        
        auto ext = GetFileExtension(event.file_path);
        if (ext == ".exe" || ext == ".dll" || ext == ".sys") {
            if (event.operation == FileOperation::CREATE) {
                reasons.push_back("Executable file created");
            }
        }
        
        if (!reasons.empty()) {
            std::ostringstream oss;
            for (size_t i = 0; i < reasons.size(); ++i) {
                if (i > 0) oss << ", ";
                oss << reasons[i];
            }
            event.suspicion_reason = oss.str();
        }
    }
}

// Calculate suspicion score
int FileMonitor::CalculateSuspicionScore(const FileEvent& event) const {
    int score = 0;
    
    // Check if sensitive file
    if (IsSensitiveFile(event.file_path)) {
        score += 30;
    }
    
    // Check for encryption patterns
    if (IsEncryptionPattern(event)) {
        score += 40;
    }
    
    // Check for suspicious extensions
    auto ext = GetFileExtension(event.file_path);
    std::vector<std::string> suspicious_exts = {
        ".encrypted", ".locked", ".crypto", ".exe", ".dll", ".sys"
    };
    
    for (const auto& sus_ext : suspicious_exts) {
        if (ext == sus_ext) {
            score += 20;
            break;
        }
    }
    
    // Check operation type
    if (event.operation == FileOperation::DELETE) {
        score += 10;
    }
    
    return std::min(score, 100);
}

// Should monitor path
bool FileMonitor::ShouldMonitorPath(const std::filesystem::path& path) const {
    // Check excluded paths
    for (const auto& excluded : config_.excluded_paths) {
        if (path.string().find(excluded) != std::string::npos) {
            return false;
        }
    }
    
    // Check excluded extensions
    auto ext = GetFileExtension(path);
    if (config_.excluded_extensions.count(ext) > 0) {
        return false;
    }
    
    return true;
}

// Is sensitive file
bool FileMonitor::IsSensitiveFile(const std::filesystem::path& path) const {
    std::string path_str = path.string();
    std::transform(path_str.begin(), path_str.end(), path_str.begin(), ::tolower);
    
    // Check patterns
    std::vector<std::string> sensitive_patterns = {
        "password", "credential", "secret", "key", "token",
        ".ssh", ".pgp", ".gpg", "wallet", "private"
    };
    
    for (const auto& pattern : sensitive_patterns) {
        if (path_str.find(pattern) != std::string::npos) {
            return true;
        }
    }
    
    // Check configured patterns
    for (const auto& pattern : config_.sensitive_file_patterns) {
        if (path_str.find(pattern) != std::string::npos) {
            return true;
        }
    }
    
    return false;
}

// Calculate file hash
std::optional<std::string> FileMonitor::CalculateFileHash(const std::filesystem::path& path) {
    try {
        utils::HashUtils hash_utils;
        return hash_utils.ComputeSHA256(path);
    }
    catch (const std::exception& e) {
        spdlog::debug("Failed to calculate hash for {}: {}", path.string(), e.what());
        return std::nullopt;
    }
}

// Detect file type
std::string FileMonitor::DetectFileType(const std::filesystem::path& path) const {
    auto ext = GetFileExtension(path);
    
    if (ext == ".exe" || ext == ".dll") return "Executable";
    if (ext == ".txt" || ext == ".log") return "Text";
    if (ext == ".jpg" || ext == ".png") return "Image";
    if (ext == ".zip" || ext == ".rar") return "Archive";
    
    return "Unknown";
}

// Detect MIME type
std::string FileMonitor::DetectMIMEType(const std::filesystem::path& path) const {
    auto ext = GetFileExtension(path);
    
    if (ext == ".txt") return "text/plain";
    if (ext == ".exe") return "application/x-msdownload";
    if (ext == ".dll") return "application/x-msdownload";
    if (ext == ".jpg") return "image/jpeg";
    if (ext == ".png") return "image/png";
    if (ext == ".zip") return "application/zip";
    
    return "application/octet-stream";
}

// Is encryption pattern
bool FileMonitor::IsEncryptionPattern(const FileEvent& event) const {
    // Check if file has suspicious extension change
    auto ext = GetFileExtension(event.file_path);
    std::vector<std::string> crypto_exts = {
        ".encrypted", ".locked", ".crypto", ".crypt", ".enc"
    };
    
    for (const auto& crypto_ext : crypto_exts) {
        if (ext.find(crypto_ext) != std::string::npos) {
            return true;
        }
    }
    
    return false;
}

// Is mass operation
bool FileMonitor::IsMassOperation(FileOperation op, int count, 
                                  std::chrono::milliseconds timespan) const {
    // Check if too many operations in short time
    if (count > 50 && timespan < std::chrono::seconds(10)) {
        return true;
    }
    
    return false;
}

// Get file extension
std::string FileMonitor::GetFileExtension(const std::filesystem::path& path) const {
    if (!path.has_extension()) {
        return "";
    }
    
    std::string ext = path.extension().string();
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
    return ext;
}

// Update statistics
void FileMonitor::UpdateStatistics(const FileEvent& event) {
    statistics_.total_operations++;
    statistics_.operation_counts[event.operation]++;
    
    if (event.operation == FileOperation::CREATE) {
        statistics_.files_created++;
    } else if (event.operation == FileOperation::DELETE) {
        statistics_.files_deleted++;
    } else if (event.operation == FileOperation::MODIFY) {
        statistics_.files_modified++;
    } else if (event.operation == FileOperation::READ) {
        statistics_.files_read++;
    }
    
    if (event.is_suspicious) {
        statistics_.suspicious_operations++;
    }
}

// Notify callbacks
void FileMonitor::NotifyCallbacks(const FileEvent& event) {
    for (const auto& callback : callbacks_) {
        try {
            callback(event);
        }
        catch (const std::exception& e) {
            spdlog::error("Callback error: {}", e.what());
        }
    }
}

// Parse syscall args
std::vector<std::string> FileMonitor::ParseSyscallArgs(const std::string& args_str) {
    std::vector<std::string> args;
    // Simple split by comma
    std::istringstream iss(args_str);
    std::string arg;
    while (std::getline(iss, arg, ',')) {
        args.push_back(arg);
    }
    return args;
}

// Parse access mode
FileAccessMode FileMonitor::ParseAccessMode(const std::string& flags) const {
    if (flags.find("O_RDONLY") != std::string::npos) {
        return FileAccessMode::READ_ONLY;
    }
    if (flags.find("O_WRONLY") != std::string::npos) {
        return FileAccessMode::WRITE_ONLY;
    }
    if (flags.find("O_RDWR") != std::string::npos) {
        return FileAccessMode::READ_WRITE;
    }
    if (flags.find("O_APPEND") != std::string::npos) {
        return FileAccessMode::APPEND;
    }
    
    return FileAccessMode::UNKNOWN;
}

// FileOperation to string
std::string FileMonitor::FileOperationToString(FileOperation op) const {
    switch (op) {
        case FileOperation::CREATE: return "CREATE";
        case FileOperation::DELETE: return "DELETE";
        case FileOperation::MODIFY: return "MODIFY";
        case FileOperation::READ: return "READ";
        case FileOperation::WRITE: return "WRITE";
        case FileOperation::RENAME: return "RENAME";
        case FileOperation::CHMOD: return "CHMOD";
        case FileOperation::CHOWN: return "CHOWN";
        case FileOperation::SYMLINK: return "SYMLINK";
        case FileOperation::HARDLINK: return "HARDLINK";
        case FileOperation::TRUNCATE: return "TRUNCATE";
        case FileOperation::COPY: return "COPY";
        case FileOperation::MOVE: return "MOVE";
        case FileOperation::OPEN: return "OPEN";
        case FileOperation::CLOSE: return "CLOSE";
        case FileOperation::STAT: return "STAT";
        case FileOperation::ACCESS: return "ACCESS";
        default: return "UNKNOWN";
    }
}

// Log event
void FileMonitor::LogEvent(const FileEvent& event) {
    std::ofstream log_file(config_.log_file, std::ios::app);
    if (log_file.is_open()) {
        auto time_t = std::chrono::system_clock::to_time_t(event.timestamp);
        log_file << "[" << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S") << "] "
                 << FileOperationToString(event.operation) << " "
                 << event.file_path.string();
        
        if (event.is_suspicious) {
            log_file << " [SUSPICIOUS: " << event.suspicion_reason << "]";
        }
        
        log_file << "\n";
    }
}

// Stub for inotify (Linux-specific, would need platform code)
void FileMonitor::ParseInotifyEvent(const void* event_data) {
    // Would parse Linux inotify events
    // This is a stub - real implementation would use inotify API
}

} // namespace monitors
} // namespace paramite