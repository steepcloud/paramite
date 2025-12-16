/**
 * @file syscall_monitor.hpp
 * @brief System call monitoring and behavioral pattern detection
 * 
 * Provides low-level system call tracking using strace with comprehensive argument
 * parsing, pattern detection for known attack techniques, and behavioral analysis.
 * Serves as the foundation for all other monitoring components by capturing the
 * complete system call trace of malware execution.
 * 
 * @date 2025
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <set>
#include <chrono>
#include <functional>
#include <optional>
#include <cstdint>
#include <variant>
#include <mutex>

namespace paramite {
namespace monitors {

/**
 * @enum SyscallCategory
 * @brief High-level categorization of system calls
 */
enum class SyscallCategory {
    PROCESS,    ///< Process management (fork, clone, exec, exit)
    FILE,       ///< File operations (open, read, write, close, stat)
    NETWORK,    ///< Network operations (socket, connect, send, recv)
    MEMORY,     ///< Memory management (mmap, mprotect, brk, munmap)
    IPC,        ///< Inter-Process Communication (pipe, msgget, semget, shmget)
    SIGNAL,     ///< Signal handling (kill, signal, sigaction)
    TIME,       ///< Time operations (gettimeofday, nanosleep)
    SECURITY,   ///< Security operations (setuid, setgid, capset, ptrace)
    SYSTEM,     ///< System information (uname, sysinfo, reboot)
    UNKNOWN     ///< Unrecognized category
};

/**
 * @brief Syscall argument type variant
 * 
 * Represents different types of syscall arguments for type-safe parsing.
 */
using SyscallArg = std::variant<
    long,                                ///< Integer value or pointer
    std::string,                         ///< String or file path
    std::vector<uint8_t>,               ///< Binary buffer
    std::map<std::string, std::string>  ///< Structured data (e.g., stat struct)
>;

/**
 * @struct SyscallEvent
 * @brief Complete information about a system call invocation
 * 
 * Captures all details of a system call including arguments, return value,
 * process context, timing, and threat assessment.
 */
struct SyscallEvent {
    // Syscall Identification
    int syscall_number{0};       ///< System call number
    std::string syscall_name;    ///< System call name (e.g., "open", "fork")
    SyscallCategory category;    ///< High-level category
    
    // Arguments
    std::vector<SyscallArg> arguments;                ///< Parsed arguments
    std::map<std::string, std::string> parsed_args;   ///< Human-readable args
    
    // Return Value
    long return_value{0};                    ///< Return value
    std::optional<std::string> error_message;  ///< Error string (if failed)
    int errno_value{0};                      ///< errno value
    
    // Process Context
    int pid{0};                  ///< Process ID
    int tid{0};                  ///< Thread ID
    std::string process_name;    ///< Process name
    std::string process_path;    ///< Process executable path
    int uid{0};                  ///< User ID
    int gid{0};                  ///< Group ID
    
    // Timing
    std::chrono::system_clock::time_point timestamp;  ///< When syscall occurred
    std::chrono::microseconds duration{0};            ///< Syscall duration
    
    // Stack Trace (if enabled)
    std::vector<std::string> backtrace;  ///< Call stack
    
    // Analysis
    bool is_suspicious{false};       ///< Flagged as suspicious
    std::string suspicion_reason;    ///< Why flagged
    int suspicion_score{0};          ///< Score (0-100)
    
    // Raw Data
    std::string raw_line;  ///< Original strace line
};

/**
 * @struct SyscallPattern
 * @brief Syscall sequence pattern for attack technique detection
 * 
 * Defines a sequence of system calls that indicate a specific attack
 * technique or malicious behavior (mapped to MITRE ATT&CK).
 */
struct SyscallPattern {
    std::string name;                        ///< Pattern name
    std::string description;                 ///< Description
    std::vector<std::string> syscall_sequence;  ///< Expected syscall sequence
    int confidence_threshold{80};            ///< Confidence threshold (0-100)
    std::string attack_technique;            ///< MITRE ATT&CK technique ID
};

/**
 * @struct SyscallStatistics
 * @brief Aggregate statistics for system call monitoring
 */
struct SyscallStatistics {
    // Call Counts
    std::map<std::string, int> syscall_counts;     ///< Count by syscall name
    std::map<SyscallCategory, int> category_counts;  ///< Count by category
    int total_syscalls{0};                         ///< Total syscalls observed
    
    // Timing Statistics
    std::map<std::string, std::chrono::microseconds> average_durations;  ///< Avg duration
    std::map<std::string, std::chrono::microseconds> total_durations;    ///< Total duration
    
    // Errors
    int failed_syscalls{0};                ///< Failed syscall count
    std::map<std::string, int> error_counts;  ///< Errors by type
    
    // Suspicious Activity
    int suspicious_syscalls{0};                  ///< Suspicious syscall count
    std::vector<std::string> detected_patterns;  ///< Detected attack patterns
    
    // Performance
    std::size_t syscalls_per_second{0};              ///< Syscall rate
    std::chrono::milliseconds monitoring_duration{0};  ///< Monitoring duration
    
    // Top Lists
    std::vector<std::pair<std::string, int>> most_frequent_syscalls;           ///< Top syscalls
    std::vector<std::pair<std::string, std::chrono::microseconds>> slowest_syscalls;  ///< Slowest syscalls
};

/**
 * @struct SyscallMonitorConfig
 * @brief Configuration for system call monitoring
 */
struct SyscallMonitorConfig {
    // Monitoring Scope
    bool monitor_all_syscalls{true};                ///< Monitor all syscalls
    std::set<std::string> monitored_syscalls;       ///< Specific syscalls (if not all)
    std::set<SyscallCategory> monitored_categories;  ///< Specific categories
    
    // Filters
    std::set<std::string> excluded_syscalls;   ///< Syscalls to exclude
    std::set<int> excluded_pids;               ///< PIDs to exclude
    bool exclude_successful_reads{false};      ///< Reduce noise from reads
    
    // Detail Level
    bool capture_arguments{true};       ///< Capture syscall arguments
    bool capture_return_values{true};   ///< Capture return values
    bool capture_errors{true};          ///< Capture error details
    bool capture_backtrace{false};      ///< Capture stack traces (slow)
    std::size_t max_arg_length{1024};      ///< Maximum argument string length
    std::size_t max_buffer_capture{256};   ///< Maximum buffer capture size
    
    // Detection Features
    bool detect_suspicious_patterns{true};  ///< Detect attack patterns
    bool detect_evasion_techniques{true};   ///< Detect evasion
    bool detect_anti_debugging{true};       ///< Detect anti-debug
    std::vector<SyscallPattern> custom_patterns;  ///< Custom patterns
    
    // Performance
    int max_syscalls_per_second{100000};      ///< Rate limit
    std::size_t max_buffered_syscalls{1000000};  ///< Buffer size
    bool enable_rate_limiting{false};         ///< Enable rate limiting
    
    // strace Settings
    std::string strace_binary{"/usr/bin/strace"};        ///< strace binary path
    std::vector<std::string> strace_args{"-f", "-tt", "-T", "-v"};  ///< strace arguments
    bool follow_forks{true};                             ///< Follow fork/clone
    bool follow_threads{true};                           ///< Follow threads
    
    // Output
    bool verbose_logging{false};                        ///< Verbose logging
    std::string log_file{"syscall_monitor.log"};        ///< Log file path
    bool save_raw_strace{true};                         ///< Save raw strace output
    std::string strace_output_file{"strace.log"};       ///< strace output file
};

/// Callback function type for syscall events
using SyscallEventCallback = std::function<void(const SyscallEvent&)>;

/**
 * @class SyscallMonitor
 * @brief Low-level system call monitoring and behavioral analysis
 * 
 * Comprehensive system call monitoring solution that:
 * - **Captures** all system calls using strace with full argument details
 * - **Parses** complex arguments (structs, flags, file descriptors)
 * - **Detects** attack patterns through syscall sequence analysis
 * - **Identifies** evasion techniques and anti-debugging
 * - **Provides** foundation data for other monitors (file, network, process)
 * - **Maps** behaviors to MITRE ATT&CK techniques
 * 
 * **Detection Capabilities**:
 * - Anti-debugging (ptrace checks, breakpoint detection)
 * - Process injection (ptrace + process_vm_writev)
 * - Privilege escalation (setuid, setgid, capabilities)
 * - Ransomware patterns (mass file open/write/rename)
 * - Data exfiltration (file read + network send)
 * 
 * **Thread Safety**: NOT thread-safe. Use from single thread.
 * 
 * **Usage Example**:
 * @code
 * SyscallMonitorConfig config;
 * config.monitor_all_syscalls = true;
 * config.detect_suspicious_patterns = true;
 * config.capture_arguments = true;
 * config.save_raw_strace = true;
 * 
 * SyscallMonitor monitor(config);
 * 
 * // Register callback for real-time detection
 * monitor.RegisterCallback([](const SyscallEvent& event) {
 *     if (event.is_suspicious) {
 *         std::cout << "Suspicious syscall: " << event.syscall_name 
 *                   << " (" << event.suspicion_reason << ")" << std::endl;
 *     }
 * });
 * 
 * // Start monitoring (attach to existing process)
 * monitor.Start(malware_pid);
 * 
 * // Or start monitoring new process
 * monitor.Start(0, "/path/to/malware.exe", {"--arg1", "--arg2"});
 * 
 * // ... wait for execution ...
 * 
 * // Stop and analyze
 * monitor.Stop();
 * 
 * auto syscalls = monitor.GetSyscalls();
 * auto stats = monitor.GetStatistics();
 * 
 * // Detect specific patterns
 * auto [anti_debug_score, anti_debug_desc] = monitor.DetectAntiDebugging();
 * auto detected_patterns = monitor.DetectPatterns();
 * 
 * if (anti_debug_score > 75) {
 *     std::cout << "Anti-debugging detected: " << anti_debug_desc << std::endl;
 * }
 * 
 * // Get raw strace for detailed analysis
 * std::string strace_output = monitor.GetRawStraceOutput();
 * @endcode
 */
class SyscallMonitor {
public:
    /**
     * @brief Construct syscall monitor with configuration
     * @param config Monitoring configuration
     */
    explicit SyscallMonitor(const SyscallMonitorConfig& config = SyscallMonitorConfig{});
    
    ~SyscallMonitor();

    SyscallMonitor(const SyscallMonitor&) = delete;
    SyscallMonitor& operator=(const SyscallMonitor&) = delete;

    /**
     * @brief Start monitoring system calls
     * 
     * Can either attach to an existing process or spawn and trace a new one.
     * 
     * @param pid Process ID to trace (0 to spawn new process)
     * @param executable If pid=0, path to executable to trace
     * @param args If pid=0, command-line arguments for executable
     * @return true if monitoring started successfully
     * 
     * **Example - Attach to existing**:
     * @code
     * monitor.Start(1234);  // Attach to PID 1234
     * @endcode
     * 
     * **Example - Spawn new**:
     * @code
     * monitor.Start(0, "/bin/malware", {"-v", "--debug"});
     * @endcode
     */
    bool Start(int pid = 0, 
               const std::string& executable = "",
               const std::vector<std::string>& args = {});

    /**
     * @brief Stop system call monitoring
     */
    void Stop();

    /**
     * @brief Check if monitoring is currently active
     * @return true if monitoring
     */
    bool IsMonitoring() const { return is_monitoring_; }

    /**
     * @brief Register callback for syscall events
     * @param callback Function to call for each syscall
     */
    void RegisterCallback(SyscallEventCallback callback);

    /**
     * @brief Get all captured system calls
     * @return Vector of all syscall events
     */
    std::vector<SyscallEvent> GetSyscalls() const;

    /**
     * @brief Get syscalls filtered by name
     * @param name Syscall name (e.g., "open", "connect")
     * @return Filtered syscalls
     */
    std::vector<SyscallEvent> GetSyscallsByName(const std::string& name) const;

    /**
     * @brief Get syscalls filtered by category
     * @param category Syscall category
     * @return Filtered syscalls
     */
    std::vector<SyscallEvent> GetSyscallsByCategory(SyscallCategory category) const;

    /**
     * @brief Get only failed system calls
     * @return Syscalls that returned error
     */
    std::vector<SyscallEvent> GetFailedSyscalls() const;

    /**
     * @brief Get only suspicious system calls
     * @return Flagged syscalls
     */
    std::vector<SyscallEvent> GetSuspiciousSyscalls() const;

    /**
     * @brief Get aggregate syscall statistics
     * @return SyscallStatistics structure
     */
    SyscallStatistics GetStatistics() const;

    /**
     * @brief Detect anti-debugging techniques
     * 
     * Analyzes syscalls for anti-debugging indicators:
     * - ptrace(PTRACE_TRACEME) - check if already traced
     * - Reading /proc/self/status for TracerPid
     * - Hardware breakpoint checks
     * 
     * @return Pair of (confidence score 0-100, description)
     */
    std::pair<int, std::string> DetectAntiDebugging() const;

    /**
     * @brief Detect evasion techniques
     * 
     * Identifies various evasion tactics:
     * - VM detection (CPUID, DMI checks)
     * - Sandbox detection (timing attacks, artifact checks)
     * - Analysis evasion (sleep before execution)
     * 
     * @return Pair of (confidence score, description)
     */
    std::pair<int, std::string> DetectEvasionTechniques() const;

    /**
     * @brief Detect privilege escalation attempts
     * 
     * @return Pair of (confidence score, description)
     */
    std::pair<int, std::string> DetectPrivilegeEscalation() const;

    /**
     * @brief Detect known syscall patterns
     * 
     * Matches syscall sequences against known attack patterns.
     * 
     * @return Vector of detected patterns
     */
    std::vector<SyscallPattern> DetectPatterns() const;

    /**
     * @brief Get syscall sequence for specific process
     * @param pid Process ID
     * @return Ordered list of syscall names
     */
    std::vector<std::string> GetSyscallSequence(int pid) const;

    /**
     * @brief Get syscall frequency distribution
     * @return Map of syscall name to count
     */
    std::map<std::string, int> GetSyscallFrequency() const;

    /**
     * @brief Get chronological syscall timeline
     * @return Vector of (timestamp, syscall name) pairs
     */
    std::vector<std::pair<std::chrono::system_clock::time_point, std::string>> 
        GetTimeline() const;

    /**
     * @brief Export syscall data to JSON
     * @return JSON string
     */
    std::string ExportToJSON() const;

    /**
     * @brief Get raw strace output
     * @return Complete strace output as string
     */
    std::string GetRawStraceOutput() const;

    /**
     * @brief Get current configuration
     * @return Reference to config
     */
    const SyscallMonitorConfig& GetConfig() const { return config_; }

    /**
     * @brief Clear all captured data
     */
    void ClearData();

    /**
     * @brief Add custom detection pattern
     * @param pattern SyscallPattern to add
     */
    void AddPattern(const SyscallPattern& pattern);

private:
    SyscallMonitorConfig config_;           ///< Configuration
    bool is_monitoring_{false};             ///< Monitoring active flag
    std::vector<SyscallEvent> syscalls_;    ///< Captured syscalls
    mutable std::mutex syscalls_mutex_;     ///< Thread synchronization
    int monitored_pid_{0};                  ///< Monitored process ID
    std::set<int> monitored_tids_;          ///< Monitored thread IDs
    std::vector<SyscallEventCallback> callbacks_;  ///< Event callbacks
    mutable SyscallStatistics statistics_;  ///< Statistics
    std::vector<SyscallPattern> patterns_;  ///< Detection patterns
    int strace_pid_{0};                     ///< strace process ID
    int strace_stdout_fd_{-1};              ///< strace stdout file descriptor
    std::string strace_output_;             ///< Raw strace output

    // Internal methods
    bool LaunchStrace(int pid, const std::string& executable,
                     const std::vector<std::string>& args);
    void ReadStraceOutput();
    std::optional<SyscallEvent> ParseStraceLine(const std::string& line);
    std::vector<SyscallArg> ParseArguments(const std::string& args_str,
                                           const std::string& syscall_name);
    long ParseReturnValue(const std::string& ret_str, int& errno_val);
    SyscallCategory CategorizeSyscall(const std::string& syscall_name) const;
    int GetSyscallNumber(const std::string& syscall_name) const;
    void AnalyzeSyscall(SyscallEvent& event);
    int CalculateSuspicionScore(const SyscallEvent& event) const;
    bool MatchesPattern(const std::vector<std::string>& sequence,
                       const SyscallPattern& pattern) const;
    bool IsAntiDebuggingSyscall(const SyscallEvent& event) const;
    bool IsPrivilegeEscalationSyscall(const SyscallEvent& event) const;
    std::string FormatArgument(const SyscallArg& arg) const;
    std::string ParseFileDescriptor(long fd) const;
    std::string ParseFlags(const std::string& flags_str) const;
    std::string ParseProtectionFlags(long prot) const;
    std::string ParseSignal(int signum) const;
    void UpdateStatistics(const SyscallEvent& event);
    void NotifyCallbacks(const SyscallEvent& event);
    void StopStrace();
    std::string CategoryToString(SyscallCategory category) const;
    void LoadDefaultPatterns();
    void LogEvent(const std::string& event);
};

/**
 * @namespace patterns
 * @brief Pre-defined syscall patterns for common attack techniques
 */
namespace patterns {

/// Anti-debugging detection pattern
const SyscallPattern ANTI_DEBUG_PTRACE = {
    "Anti-Debug: ptrace",
    "Process checks for debugger using ptrace",
    {"ptrace"},
    90,
    "T1622"  ///< MITRE: Debugger Evasion
};

/// Process injection pattern
const SyscallPattern PROCESS_INJECTION = {
    "Process Injection",
    "Process injects code into another process",
    {"ptrace", "process_vm_writev", "ptrace"},
    85,
    "T1055"  ///< MITRE: Process Injection
};

/// Privilege escalation pattern
const SyscallPattern PRIVILEGE_ESCALATION = {
    "Privilege Escalation",
    "Process attempts to gain elevated privileges",
    {"setuid", "setgid"},
    80,
    "T1548"  ///< MITRE: Abuse Elevation Control Mechanism
};

/// Ransomware encryption pattern
const SyscallPattern RANSOMWARE_ENCRYPTION = {
    "Ransomware Encryption",
    "Mass file encryption pattern",
    {"open", "read", "write", "close", "rename"},
    75,
    "T1486"  ///< MITRE: Data Encrypted for Impact
};

/// Data exfiltration pattern
const SyscallPattern DATA_EXFILTRATION = {
    "Data Exfiltration",
    "Large data transfer over network",
    {"open", "read", "socket", "connect", "send"},
    70,
    "T1041"  ///< MITRE: Exfiltration Over C2 Channel
};

} // namespace patterns

} // namespace monitors
} // namespace paramite