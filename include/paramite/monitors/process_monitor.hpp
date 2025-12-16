/**
 * @file process_monitor.hpp
 * @brief Process, thread, and memory operation monitoring for injection detection
 * 
 * Provides comprehensive tracking of process lifecycle, thread operations, and memory
 * manipulations with specialized detection for process injection, privilege escalation,
 * and process hollowing techniques. Builds hierarchical process trees and tracks
 * parent-child relationships for behavioral analysis.
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
#include <cstdint>
#include <mutex>

namespace paramite {
namespace monitors {

/**
 * @enum ProcessEvent
 * @brief Types of process lifecycle events
 */
enum class ProcessEvent {
    CREATED,      ///< New process created
    TERMINATED,   ///< Process terminated normally
    EXEC,         ///< execve() system call (process replacement)
    FORK,         ///< fork() system call
    CLONE,        ///< clone() system call
    VFORK,        ///< vfork() system call
    EXIT,         ///< exit() system call
    KILLED,       ///< Killed by signal (SIGKILL, SIGTERM)
    CRASHED,      ///< Crashed (SIGSEGV, SIGABRT)
    SUSPENDED,    ///< Process suspended (SIGSTOP)
    RESUMED       ///< Process resumed (SIGCONT)
};

/**
 * @enum ThreadEvent
 * @brief Types of thread operations
 */
enum class ThreadEvent {
    CREATED,          ///< Thread created
    TERMINATED,       ///< Thread terminated
    REMOTE_CREATED,   ///< Thread created in another process (INJECTION!)
    SUSPENDED,        ///< Thread suspended
    RESUMED,          ///< Thread resumed
    CONTEXT_MODIFIED  ///< Thread context modified (ptrace)
};

/**
 * @enum MemoryOperation
 * @brief Types of memory operations
 */
enum class MemoryOperation {
    ALLOCATE,      ///< Memory allocation (malloc, mmap)
    FREE,          ///< Memory deallocation
    PROTECT,       ///< Permission change (mprotect) - RWX changes
    READ,          ///< Memory read
    WRITE,         ///< Memory write
    MAP,           ///< Memory mapping (mmap)
    UNMAP,         ///< Memory unmapping
    REMOTE_READ,   ///< Read another process's memory (ptrace)
    REMOTE_WRITE   ///< Write to another process (INJECTION!)
};

/**
 * @struct ProcessInfo
 * @brief Complete information about a process
 * 
 * Contains comprehensive process metadata including executable information,
 * resource usage, permissions, and threat assessment.
 */
struct ProcessInfo {
    // Identifiers
    int pid{0};      ///< Process ID
    int ppid{0};     ///< Parent process ID
    std::string name;     ///< Process name
    std::string path;     ///< Full executable path
    std::string cmdline;  ///< Complete command line
    std::vector<std::string> args;                 ///< Command-line arguments
    std::map<std::string, std::string> environment;  ///< Environment variables
    
    // User/Permissions
    int uid{0};      ///< User ID
    int gid{0};      ///< Group ID
    int euid{0};     ///< Effective user ID
    int egid{0};     ///< Effective group ID
    std::string username;                    ///< Username
    std::vector<std::string> capabilities;   ///< Linux capabilities
    
    // Timing
    std::chrono::system_clock::time_point start_time;  ///< Process start time
    std::chrono::system_clock::time_point end_time;    ///< Process end time
    std::chrono::milliseconds lifetime{0};             ///< Process lifetime
    
    // Resource Usage
    std::size_t memory_usage_kb{0};   ///< Memory consumption
    float cpu_usage_percent{0.0f};    ///< CPU utilization
    int thread_count{0};              ///< Number of threads
    int file_descriptor_count{0};     ///< Open file descriptors
    
    // Binary Information
    std::string binary_hash;     ///< SHA-256 of executable
    std::string binary_type;     ///< File type (ELF, PE, script)
    bool is_signed{false};       ///< Digital signature present
    std::optional<std::string> signature;  ///< Signature details
    
    // Threat Assessment
    bool is_suspicious{false};       ///< Flagged as suspicious
    std::string suspicion_reason;    ///< Why flagged
    int suspicion_score{0};          ///< Score (0-100)
    std::vector<std::string> iocs;   ///< Associated IOCs
};

/**
 * @struct ProcessCreationEvent
 * @brief Event representing process creation
 */
struct ProcessCreationEvent {
    ProcessEvent event_type;     ///< Type of event
    ProcessInfo process;         ///< Process information
    std::chrono::system_clock::time_point timestamp;  ///< When occurred
    
    // Parent Information
    int parent_pid{0};           ///< Parent process ID
    std::string parent_name;     ///< Parent process name
    std::string parent_path;     ///< Parent executable path
    
    // Creation Details
    std::string syscall_name;                ///< System call used (fork, clone, execve)
    std::vector<std::string> syscall_args;   ///< System call arguments
    int syscall_return_code{0};              ///< Return value
    
    // Analysis
    bool is_suspicious{false};       ///< Suspicious creation
    std::string suspicion_reason;    ///< Reason
    int suspicion_score{0};          ///< Score
};

/**
 * @struct ThreadInfo
 * @brief Information about a thread
 */
struct ThreadInfo {
    int tid{0};      ///< Thread ID
    int pid{0};      ///< Parent process ID
    std::string name;  ///< Thread name
    
    // State
    std::string state;   ///< State (Running, Sleeping, Zombie)
    int priority{0};     ///< Priority
    int nice{0};         ///< Nice value
    
    // Resources
    float cpu_usage_percent{0.0f};  ///< CPU usage
    std::size_t stack_size_kb{0};   ///< Stack size
    
    // Timing
    std::chrono::system_clock::time_point start_time;  ///< Thread start
    std::chrono::milliseconds cpu_time{0};             ///< CPU time consumed
    
    // Context (CPU registers)
    uint64_t instruction_pointer{0};  ///< RIP/EIP
    uint64_t stack_pointer{0};        ///< RSP/ESP
    uint64_t base_pointer{0};         ///< RBP/EBP
};

/**
 * @struct ThreadOperationEvent
 * @brief Event representing thread operation
 */
struct ThreadOperationEvent {
    ThreadEvent event_type;      ///< Event type
    ThreadInfo thread;           ///< Thread information
    std::chrono::system_clock::time_point timestamp;
    
    // Remote Thread Details (Injection Detection)
    std::optional<int> target_pid;         ///< Target process (if remote)
    std::optional<uint64_t> start_address; ///< Thread start address
    
    // Analysis
    bool is_suspicious{false};
    std::string suspicion_reason;
    int suspicion_score{0};
};

/**
 * @struct MemoryOperationEvent
 * @brief Event representing memory operation
 */
struct MemoryOperationEvent {
    MemoryOperation operation;   ///< Operation type
    int pid{0};                  ///< Process ID
    std::string process_name;    ///< Process name
    
    // Memory Details
    uint64_t address{0};             ///< Memory address
    std::size_t size{0};             ///< Operation size
    std::string permissions;         ///< New permissions (rwx, r-x, etc.)
    std::string original_permissions;  ///< Original permissions
    
    // Remote Operations (Injection Detection)
    std::optional<int> target_pid;         ///< Target process
    std::optional<std::string> target_process;  ///< Target process name
    
    // Timing
    std::chrono::system_clock::time_point timestamp;
    
    // System Call Details
    std::string syscall_name;                ///< System call (mmap, mprotect, ptrace)
    std::vector<std::string> syscall_args;   ///< Arguments
    int syscall_return_code{0};              ///< Return value
    
    // Analysis
    bool is_suspicious{false};
    std::string suspicion_reason;
    int suspicion_score{0};
};

/**
 * @struct ProcessTreeNode
 * @brief Node in hierarchical process tree
 */
struct ProcessTreeNode {
    ProcessInfo process;                   ///< Process information
    std::vector<ProcessTreeNode> children; ///< Child processes
    int depth{0};                          ///< Tree depth
    bool is_root{false};                   ///< Root process
};

/**
 * @struct ProcessStatistics
 * @brief Aggregate process monitoring statistics
 */
struct ProcessStatistics {
    // Process Counts
    int total_processes{0};       ///< Total processes observed
    int processes_created{0};     ///< Processes created
    int processes_terminated{0};  ///< Processes terminated
    int processes_crashed{0};     ///< Processes that crashed
    
    // Thread Counts
    int total_threads{0};            ///< Total threads
    int threads_created{0};          ///< Threads created
    int remote_threads_created{0};   ///< Remote threads (INJECTION indicator)
    
    // Memory Operations
    int memory_allocations{0};             ///< Memory allocations
    int memory_protections_changed{0};     ///< Permission changes
    int remote_memory_operations{0};       ///< Remote operations (INJECTION)
    std::size_t total_memory_allocated_kb{0};  ///< Total memory allocated
    
    // Suspicious Activity
    int suspicious_processes{0};      ///< Suspicious process count
    int injection_attempts{0};        ///< Detected injection attempts
    int privilege_escalations{0};     ///< Privilege escalation attempts
    
    // Resource Usage
    float peak_cpu_usage{0.0f};            ///< Peak CPU usage
    std::size_t peak_memory_usage_kb{0};   ///< Peak memory usage
    
    // Process Relationships
    int max_process_tree_depth{0};  ///< Maximum tree depth
    std::vector<std::pair<std::string, int>> most_spawned_processes;  ///< Most spawned
};

/**
 * @struct ProcessMonitorConfig
 * @brief Configuration for process monitoring
 */
struct ProcessMonitorConfig {
    // Monitoring Toggles
    bool monitor_process_creation{true};     ///< Monitor process creation
    bool monitor_process_termination{true};  ///< Monitor process termination
    bool monitor_thread_operations{true};    ///< Monitor thread operations
    bool monitor_memory_operations{true};    ///< Monitor memory operations
    bool monitor_privilege_changes{true};    ///< Monitor privilege escalation
    
    // Tracking Options
    bool track_process_tree{true};              ///< Build process tree
    bool track_resource_usage{true};            ///< Track CPU/memory
    bool calculate_hashes{true};                ///< Hash executables
    bool capture_environment_variables{true};   ///< Capture env vars
    bool capture_command_lines{true};           ///< Capture command lines
    
    // Detection Features
    bool detect_injection{true};               ///< Detect process injection
    bool detect_privilege_escalation{true};    ///< Detect privilege escalation
    bool detect_process_hollowing{true};       ///< Detect process hollowing
    bool detect_suspicious_parents{true};      ///< Detect unusual parent-child (Word?cmd.exe)
    
    // Filters
    std::set<std::string> excluded_processes;  ///< Processes to exclude
    bool exclude_system_processes{true};       ///< Exclude system processes
    bool exclude_kernel_threads{true};         ///< Exclude kernel threads
    
    // Performance
    int max_events_per_second{1000};              ///< Rate limit
    std::size_t max_buffered_events{10000};       ///< Buffer size
    std::chrono::milliseconds polling_interval{100};  ///< Polling frequency
    
    // Output
    bool verbose_logging{false};                      ///< Verbose logging
    std::filesystem::path log_file{"process_monitor.log"};  ///< Log file
};

/// Callback function types for process events
using ProcessEventCallback = std::function<void(const ProcessCreationEvent&)>;
using ThreadEventCallback = std::function<void(const ThreadOperationEvent&)>;
using MemoryEventCallback = std::function<void(const MemoryOperationEvent&)>;

/**
 * @class ProcessMonitor
 * @brief Process, thread, and memory operation monitor for injection detection
 * 
 * Comprehensive process monitoring solution that:
 * - **Tracks** process creation, termination, and lifecycle events
 * - **Detects** process injection techniques (DLL injection, code injection)
 * - **Monitors** thread operations including remote thread creation
 * - **Analyzes** memory operations for suspicious RWX allocations
 * - **Builds** hierarchical process execution trees
 * - **Identifies** privilege escalation attempts
 * - **Detects** process hollowing and parent process spoofing
 * 
 * **Detection Techniques**:
 * - Remote thread creation (CreateRemoteThread equivalent)
 * - Remote memory writes (ptrace, process_vm_writev)
 * - RWX memory allocations (executable + writable)
 * - Suspicious parent-child relationships (Word spawning PowerShell)
 * - Privilege escalation (UID/GID changes)
 * - Process hollowing (exec after suspicious memory operations)
 * 
 * **Thread Safety**: NOT thread-safe. Use from single thread.
 * 
 * **Usage Example**:
 * @code
 * ProcessMonitorConfig config;
 * config.detect_injection = true;
 * config.detect_privilege_escalation = true;
 * config.track_process_tree = true;
 * 
 * ProcessMonitor monitor(config);
 * 
 * // Register callbacks for real-time detection
 * monitor.RegisterProcessCallback([](const ProcessCreationEvent& event) {
 *     if (event.is_suspicious) {
 *         std::cout << "Suspicious process: " << event.process.name 
 *                   << " (" << event.suspicion_reason << ")" << std::endl;
 *     }
 * });
 * 
 * monitor.RegisterThreadCallback([](const ThreadOperationEvent& event) {
 *     if (event.event_type == ThreadEvent::REMOTE_CREATED) {
 *         std::cout << "INJECTION DETECTED: Remote thread created!" << std::endl;
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
 * // Get results
 * auto process_tree = monitor.GetProcessTree();
 * auto suspicious = monitor.GetSuspiciousProcesses();
 * auto remote_threads = monitor.GetRemoteThreads();
 * 
 * // Detect injection
 * auto [injection_score, injection_desc] = monitor.DetectInjection();
 * if (injection_score > 75) {
 *     std::cout << "Injection detected: " << injection_desc << std::endl;
 * }
 * @endcode
 */
class ProcessMonitor {
public:
    /**
     * @brief Construct process monitor with configuration
     * @param config Monitoring configuration
     */
    explicit ProcessMonitor(const ProcessMonitorConfig& config = ProcessMonitorConfig{});
    
    ~ProcessMonitor();

    ProcessMonitor(const ProcessMonitor&) = delete;
    ProcessMonitor& operator=(const ProcessMonitor&) = delete;

    /**
     * @brief Start process monitoring
     * 
     * Creates baseline snapshot and begins monitoring process events.
     * 
     * @return true if monitoring started successfully
     */
    bool Start();

    /**
     * @brief Stop process monitoring
     */
    void Stop();

    /**
     * @brief Check if monitoring is currently active
     * @return true if monitoring
     */
    bool IsMonitoring() const { return is_monitoring_; }

    /**
     * @brief Register callback for process events
     * @param callback Function to call for each process event
     */
    void RegisterProcessCallback(ProcessEventCallback callback);
    
    /**
     * @brief Register callback for thread events
     * @param callback Function to call for each thread event
     */
    void RegisterThreadCallback(ThreadEventCallback callback);
    
    /**
     * @brief Register callback for memory operation events
     * @param callback Function to call for each memory event
     */
    void RegisterMemoryCallback(MemoryEventCallback callback);

    /**
     * @brief Get all captured process events
     * @return Vector of process events
     */
    std::vector<ProcessCreationEvent> GetProcessEvents() const;

    /**
     * @brief Get all captured thread events
     * @return Vector of thread events
     */
    std::vector<ThreadOperationEvent> GetThreadEvents() const;

    /**
     * @brief Get all memory operation events
     * @return Vector of memory events
     */
    std::vector<MemoryOperationEvent> GetMemoryEvents() const;

    /**
     * @brief Get list of processes created during monitoring
     * @return Vector of ProcessInfo
     */
    std::vector<ProcessInfo> GetCreatedProcesses() const;

    /**
     * @brief Get hierarchical process execution tree
     * @return Process tree root node
     */
    ProcessTreeNode GetProcessTree() const;

    /**
     * @brief Get process information by PID
     * @param pid Process ID
     * @return ProcessInfo if found
     */
    std::optional<ProcessInfo> GetProcess(int pid) const;

    /**
     * @brief Get all threads for a specific process
     * @param pid Process ID
     * @return Vector of ThreadInfo
     */
    std::vector<ThreadInfo> GetThreads(int pid) const;

    /**
     * @brief Get aggregate process monitoring statistics
     * @return ProcessStatistics structure
     */
    ProcessStatistics GetStatistics() const;

    /**
     * @brief Detect process injection techniques
     * 
     * Analyzes events for injection indicators:
     * - Remote thread creation
     * - Remote memory writes
     * - RWX memory allocations
     * - ptrace usage
     * 
     * @return Pair of (confidence score 0-100, description)
     */
    std::pair<int, std::string> DetectInjection() const;

    /**
     * @brief Detect privilege escalation attempts
     * 
     * Identifies UID/GID changes, capability additions, or
     * exploitation of SUID binaries.
     * 
     * @return Pair of (confidence score, description)
     */
    std::pair<int, std::string> DetectPrivilegeEscalation() const;

    /**
     * @brief Detect process hollowing technique
     * 
     * Looks for suspicious sequence of memory operations
     * followed by exec.
     * 
     * @return Pair of (confidence score, description)
     */
    std::pair<int, std::string> DetectProcessHollowing() const;

    /**
     * @brief Get processes flagged as suspicious
     * @return Vector of suspicious ProcessInfo
     */
    std::vector<ProcessInfo> GetSuspiciousProcesses() const;

    /**
     * @brief Get remote thread creation events (injection indicators)
     * @return Vector of remote thread events
     */
    std::vector<ThreadOperationEvent> GetRemoteThreads() const;

    /**
     * @brief Get remote memory operation events (injection indicators)
     * @return Vector of remote memory operations
     */
    std::vector<MemoryOperationEvent> GetRemoteMemoryOperations() const;

    /**
     * @brief Export monitoring data to JSON
     * @return JSON string
     */
    std::string ExportToJSON() const;

    /**
     * @brief Get current configuration
     * @return Reference to config
     */
    const ProcessMonitorConfig& GetConfig() const { return config_; }

    /**
     * @brief Clear all collected data
     */
    void ClearData();

private:
    ProcessMonitorConfig config_;                         ///< Configuration
    bool is_monitoring_{false};                           ///< Monitoring flag
    std::vector<ProcessCreationEvent> process_events_;    ///< Process events
    std::vector<ThreadOperationEvent> thread_events_;     ///< Thread events
    std::vector<MemoryOperationEvent> memory_events_;     ///< Memory events
    mutable std::mutex events_mutex_;                     ///< Synchronization
    std::map<int, ProcessInfo> active_processes_;         ///< Active processes
    std::map<int, std::vector<ThreadInfo>> active_threads_;  ///< Active threads
    ProcessTreeNode process_tree_;                        ///< Process tree
    std::vector<ProcessEventCallback> process_callbacks_;  ///< Callbacks
    std::vector<ThreadEventCallback> thread_callbacks_;
    std::vector<MemoryEventCallback> memory_callbacks_;
    mutable ProcessStatistics statistics_;                ///< Statistics
    std::set<int> baseline_pids_;                         ///< Baseline processes

    // Internal methods
    void CreateBaseline();
    void MonitorProcesses();
    void MonitorThreads();
    void MonitorMemory();
    void ParseStraceOutput(const std::string& line);
    void ParseProcFilesystem();
    std::optional<ProcessInfo> ReadProcessInfo(int pid);
    std::optional<ThreadInfo> ReadThreadInfo(int pid, int tid);
    void BuildProcessTree();
    void AddToProcessTree(const ProcessInfo& process);
    void AnalyzeProcessEvent(ProcessCreationEvent& event);
    void AnalyzeThreadEvent(ThreadOperationEvent& event);
    void AnalyzeMemoryEvent(MemoryOperationEvent& event);
    bool IsSuspiciousParent(const std::string& parent, const std::string& child) const;
    bool IsInjectionPattern(const MemoryOperationEvent& event) const;
    bool IsPrivilegeEscalation(int old_uid, int new_uid, int old_gid, int new_gid) const;
    int CalculateProcessSuspicionScore(const ProcessInfo& process) const;
    std::optional<std::string> CalculateBinaryHash(const std::filesystem::path& path);
    std::string DetectBinaryType(const std::filesystem::path& path) const;
    void UpdateStatistics(const ProcessCreationEvent& event);
    void UpdateStatistics(const ThreadOperationEvent& event);
    void UpdateStatistics(const MemoryOperationEvent& event);
    void NotifyProcessCallbacks(const ProcessCreationEvent& event);
    void NotifyThreadCallbacks(const ThreadOperationEvent& event);
    void NotifyMemoryCallbacks(const MemoryOperationEvent& event);
    std::string ProcessEventToString(ProcessEvent event) const;
    std::string ThreadEventToString(ThreadEvent event) const;
    std::string MemoryOperationToString(MemoryOperation op) const;
    void LogEvent(const std::string& event);
};

} // namespace monitors
} // namespace paramite