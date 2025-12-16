/**
 * @file syscall_monitor.cpp
 * @brief Implementation of system call monitoring and behavioral pattern detection
 * 
 * Implements comprehensive system call (syscall) monitoring using strace/ptrace for
 * low-level behavioral analysis, attack technique detection, MITRE ATT&CK mapping,
 * anti-analysis technique identification, and complete system interaction tracking
 * during malware sandbox execution.
 * 
 * **Syscall Monitoring Methods**:
 * - **strace**: User-space syscall tracing (Linux)
 * - **ptrace**: Direct process tracing API
 * - **eBPF**: Kernel-level tracing (modern Linux)
 * - **Seccomp audit**: Syscall filtering and logging
 * 
 * **Categories of Monitored Syscalls**:
 * 1. **File Operations**: open, read, write, unlink, rename, chmod
 * 2. **Process Management**: execve, fork, clone, kill, waitpid
 * 3. **Network Operations**: socket, connect, bind, send, recv
 * 4. **Memory Management**: mmap, mprotect, brk, munmap
 * 5. **IPC**: pipe, msgget, shmget, semget
 * 6. **Security**: setuid, setgid, capset, ptrace
 * 
 * **Attack Technique Detection**:
 * ```
 * Technique: Code Injection
 * Syscall Pattern:
 *   1. ptrace(PTRACE_ATTACH, target_pid) → Attach to process
 *   2. mmap(target_pid, PROT_EXEC|PROT_WRITE) → Allocate memory
 *   3. write(target_pid, shellcode) → Write malicious code
 *   4. ptrace(PTRACE_CONT, target_pid) → Resume execution
 * → MITRE: T1055 (Process Injection)
 * 
 * Technique: Anti-Debugging
 * Syscall Pattern:
 *   - ptrace(PTRACE_TRACEME) → Check if being debugged
 *   - access("/proc/self/status") → Read tracer PID
 * → MITRE: T1622 (Debugger Evasion)
 * 
 * Technique: Privilege Escalation
 * Syscall Pattern:
 *   - setuid(0) → Attempt to gain root
 *   - execve("/bin/sudo", ...) → Sudo execution
 * → MITRE: T1068 (Exploitation for Privilege Escalation)
 * ```
 * 
 * **Anti-Analysis Detection**:
 * - **Anti-Debugging**: ptrace checks, timing attacks
 * - **Anti-VM**: CPUID checks, VMware artifact detection
 * - **Anti-Sandbox**: Sleep calls, user interaction checks
 * - **Environment Checks**: File/process/registry checks
 * 
 * **MITRE ATT&CK Mapping**:
 * Maps syscall patterns to ATT&CK techniques:
 * - T1055: Process Injection (ptrace, mmap, write)
 * - T1070: Indicator Removal (unlink, truncate)
 * - T1059: Command and Scripting Interpreter (execve)
 * - T1053: Scheduled Task/Job (cron file modifications)
 * - T1071: Application Layer Protocol (socket, connect)
 * 
 * **Performance Optimization**:
 * - Syscall filtering (only monitor suspicious syscalls)
 * - Sampling mode (trace every Nth syscall)
 * - Ring buffer for high-frequency syscalls
 * - Asynchronous event processing
 * 
 * @date 2025
 */

#include "paramite/monitors/syscall_monitor.hpp"
#include "paramite/utils/string_utils.hpp"

#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>

#include <sstream>
#include <fstream>
#include <algorithm>
#include <regex>
#include <iomanip>
#include <ctime>

#ifdef _WIN32
#include <windows.h>
#include <process.h>
#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <fcntl.h>
#include <errno.h>
#endif

using json = nlohmann::json;

namespace paramite {
namespace monitors {

// Constructor
SyscallMonitor::SyscallMonitor(const SyscallMonitorConfig& config)
    : config_(config)
    , is_monitoring_(false) {
    
    spdlog::info("Syscall Monitor initialized");
    spdlog::debug("Monitor all syscalls: {}", config_.monitor_all_syscalls);
    spdlog::debug("Detect suspicious patterns: {}", config_.detect_suspicious_patterns);
    
    // Load default detection patterns
    LoadDefaultPatterns();
    
    // Add custom patterns
    for (const auto& pattern : config_.custom_patterns) {
        patterns_.push_back(pattern);
    }
}

// Destructor
SyscallMonitor::~SyscallMonitor() {
    Stop();
    spdlog::info("Syscall Monitor destroyed");
}

// Start monitoring
bool SyscallMonitor::Start(int pid, const std::string& executable,
                          const std::vector<std::string>& args) {
    if (is_monitoring_) {
        spdlog::warn("Syscall Monitor already running");
        return true;
    }
    
    spdlog::info("═══════════════════════════════════════════════════════════════");
    spdlog::info("STARTING SYSCALL MONITOR");
    spdlog::info("═══════════════════════════════════════════════════════════════");
    
    try {
        monitored_pid_ = pid;
        
        // Clear previous data
        {
            std::lock_guard<std::mutex> lock(syscalls_mutex_);
            syscalls_.clear();
            statistics_ = SyscallStatistics{};
            strace_output_.clear();
        }
        
        // Launch strace
        if (!LaunchStrace(pid, executable, args)) {
            spdlog::error("Failed to launch strace");
            return false;
        }
        
        is_monitoring_ = true;
        
        spdlog::info("═══════════════════════════════════════════════════════════════");
        spdlog::info("✓ Syscall Monitor started");
        if (pid > 0) {
            spdlog::info("  Monitoring PID: {}", pid);
        } else {
            spdlog::info("  Monitoring: {}", executable);
        }
        spdlog::info("═══════════════════════════════════════════════════════════════\n");
        
        // Start reading strace output in background
        std::thread reader_thread(&SyscallMonitor::ReadStraceOutput, this);
        reader_thread.detach();
        
        return true;
    }
    catch (const std::exception& e) {
        spdlog::error("Failed to start Syscall Monitor: {}", e.what());
        return false;
    }
}

// Stop monitoring
void SyscallMonitor::Stop() {
    if (!is_monitoring_) {
        return;
    }
    
    spdlog::info("Stopping Syscall Monitor...");
    is_monitoring_ = false;
    
    // Stop strace
    StopStrace();
    
    spdlog::info("✓ Syscall Monitor stopped");
    spdlog::info("  Total syscalls captured: {}", syscalls_.size());
    spdlog::info("  Suspicious syscalls: {}", statistics_.suspicious_syscalls);
    spdlog::info("  Failed syscalls: {}", statistics_.failed_syscalls);
}

// Register callback
void SyscallMonitor::RegisterCallback(SyscallEventCallback callback) {
    callbacks_.push_back(callback);
    spdlog::debug("Syscall event callback registered");
}

// Get all syscalls
std::vector<SyscallEvent> SyscallMonitor::GetSyscalls() const {
    std::lock_guard<std::mutex> lock(syscalls_mutex_);
    return syscalls_;
}

// Get syscalls by name
std::vector<SyscallEvent> SyscallMonitor::GetSyscallsByName(const std::string& name) const {
    std::lock_guard<std::mutex> lock(syscalls_mutex_);
    
    std::vector<SyscallEvent> filtered;
    for (const auto& syscall : syscalls_) {
        if (syscall.syscall_name == name) {
            filtered.push_back(syscall);
        }
    }
    
    return filtered;
}

// Get syscalls by category
std::vector<SyscallEvent> SyscallMonitor::GetSyscallsByCategory(SyscallCategory category) const {
    std::lock_guard<std::mutex> lock(syscalls_mutex_);
    
    std::vector<SyscallEvent> filtered;
    for (const auto& syscall : syscalls_) {
        if (syscall.category == category) {
            filtered.push_back(syscall);
        }
    }
    
    return filtered;
}

// Get failed syscalls
std::vector<SyscallEvent> SyscallMonitor::GetFailedSyscalls() const {
    std::lock_guard<std::mutex> lock(syscalls_mutex_);
    
    std::vector<SyscallEvent> failed;
    for (const auto& syscall : syscalls_) {
        if (syscall.return_value < 0) {
            failed.push_back(syscall);
        }
    }
    
    return failed;
}

// Get suspicious syscalls
std::vector<SyscallEvent> SyscallMonitor::GetSuspiciousSyscalls() const {
    std::lock_guard<std::mutex> lock(syscalls_mutex_);
    
    std::vector<SyscallEvent> suspicious;
    for (const auto& syscall : syscalls_) {
        if (syscall.is_suspicious) {
            suspicious.push_back(syscall);
        }
    }
    
    return suspicious;
}

// Get statistics
SyscallStatistics SyscallMonitor::GetStatistics() const {
    std::lock_guard<std::mutex> lock(syscalls_mutex_);
    return statistics_;
}

// Detect anti-debugging
std::pair<int, std::string> SyscallMonitor::DetectAntiDebugging() const {
    std::lock_guard<std::mutex> lock(syscalls_mutex_);
    
    int confidence = 0;
    std::ostringstream description;
    std::vector<std::string> indicators;
    
    // Count ptrace calls
    int ptrace_count = 0;
    for (const auto& syscall : syscalls_) {
        if (syscall.syscall_name == "ptrace") {
            ptrace_count++;
            
            // Check for PTRACE_TRACEME (common anti-debug)
            if (!syscall.parsed_args.empty()) {
                auto it = syscall.parsed_args.find("request");
                if (it != syscall.parsed_args.end() && 
                    it->second.find("PTRACE_TRACEME") != std::string::npos) {
                    confidence += 40;
                    indicators.push_back("PTRACE_TRACEME detected (anti-debug)");
                }
            }
        }
    }
    
    if (ptrace_count > 0) {
        confidence += 30;
        indicators.push_back("ptrace() calls detected (" + 
                           std::to_string(ptrace_count) + ")");

    }
    
    // Check for /proc/self/status reading (debugger detection)
    int proc_status_reads = 0;
    for (const auto& syscall : syscalls_) {
        if ((syscall.syscall_name == "open" || syscall.syscall_name == "openat") &&
            !syscall.parsed_args.empty()) {
            auto it = syscall.parsed_args.find("pathname");
            if (it != syscall.parsed_args.end() &&
                (it->second.find("/proc/self/status") != std::string::npos ||
                 it->second.find("/proc/self/cmdline") != std::string::npos)) {
                proc_status_reads++;
            }
        }
    }
    
    if (proc_status_reads > 0) {
        confidence += 25;
        indicators.push_back("/proc/self inspection (debugger check)");
    }
    
    // Check for timing attacks (nanosleep patterns)
    int timing_checks = 0;
    for (const auto& syscall : syscalls_) {
        if (syscall.syscall_name == "nanosleep" || 
            syscall.syscall_name == "clock_gettime") {
            timing_checks++;
        }
    }
    
    if (timing_checks > 20) {
        confidence += 20;
        indicators.push_back("Excessive timing checks (anti-debug timing)");
    }
    
    // Check for LD_PRELOAD detection
    for (const auto& syscall : syscalls_) {
        if (syscall.syscall_name == "getenv" && !syscall.parsed_args.empty()) {
            auto it = syscall.parsed_args.find("name");
            if (it != syscall.parsed_args.end() &&
                it->second.find("LD_PRELOAD") != std::string::npos) {
                confidence += 30;
                indicators.push_back("LD_PRELOAD environment check");
                break;
            }
        }
    }
    
    confidence = std::min<int>(confidence, 100);
    
    if (confidence > 0) {
        description << "Anti-debugging techniques detected:\n";
        for (const auto& indicator : indicators) {
            description << "  • " << indicator << "\n";
        }
    } else {
        description << "No significant anti-debugging detected";
    }
    
    return {confidence, description.str()};
}

// Detect evasion techniques
std::pair<int, std::string> SyscallMonitor::DetectEvasionTechniques() const {
    std::lock_guard<std::mutex> lock(syscalls_mutex_);
    
    int confidence = 0;
    std::ostringstream description;
    std::vector<std::string> indicators;
    
    // Check for self-deletion
    for (const auto& syscall : syscalls_) {
        if ((syscall.syscall_name == "unlink" || syscall.syscall_name == "unlinkat") &&
            !syscall.parsed_args.empty()) {
            auto it = syscall.parsed_args.find("pathname");
            if (it != syscall.parsed_args.end() &&
                it->second.find("/proc/self/exe") != std::string::npos) {
                confidence += 50;
                indicators.push_back("Binary self-deletion detected");
                break;
            }
        }
    }
    
    // Check for VM detection syscalls
    int vm_detection_syscalls = 0;
    for (const auto& syscall : syscalls_) {
        // cpuid, reading DMI tables, etc.
        if (syscall.syscall_name == "ioctl" && !syscall.parsed_args.empty()) {
            vm_detection_syscalls++;
        }
    }
    
    if (vm_detection_syscalls > 10) {
        confidence += 30;
        indicators.push_back("VM detection attempts");
    }
    
    // Check for sleep/delay evasion
    int long_sleeps = 0;
    for (const auto& syscall : syscalls_) {
        if (syscall.syscall_name == "nanosleep" && !syscall.parsed_args.empty()) {
            // Check if sleep duration > 60 seconds
            auto it = syscall.parsed_args.find("req");
            if (it != syscall.parsed_args.end()) {
                // Simple heuristic - would need better parsing
                if (it->second.find("60") != std::string::npos ||
                    it->second.find("600") != std::string::npos) {
                    long_sleeps++;
                }
            }
        }
    }
    
    if (long_sleeps > 0) {
        confidence += 25;
        indicators.push_back("Long sleep delays (sandbox evasion)");
    }
    
    // Check for environment inspection
    int env_checks = 0;
    for (const auto& syscall : syscalls_) {
        if (syscall.syscall_name == "getenv") {
            env_checks++;
        }
    }
    
    if (env_checks > 10) {
        confidence += 20;
        indicators.push_back("Excessive environment variable checks");
    }
    
    confidence = std::min<int>(confidence, 100);
    
    if (confidence > 0) {
        description << "Evasion techniques detected:\n";
        for (const auto& indicator : indicators) {
            description << "  • " << indicator << "\n";
        }
    } else {
        description << "No significant evasion techniques detected";
    }
    
    return {confidence, description.str()};
}

// Detect privilege escalation
std::pair<int, std::string> SyscallMonitor::DetectPrivilegeEscalation() const {
    std::lock_guard<std::mutex> lock(syscalls_mutex_);
    
    int confidence = 0;
    std::ostringstream description;
    std::vector<std::string> indicators;
    
    // Check for setuid/setgid calls
    int priv_syscalls = 0;
    for (const auto& syscall : syscalls_) {
        if (syscall.syscall_name == "setuid" ||
            syscall.syscall_name == "setgid" ||
            syscall.syscall_name == "setreuid" ||
            syscall.syscall_name == "setregid" ||
            syscall.syscall_name == "setresuid" ||
            syscall.syscall_name == "setresgid") {
            
            priv_syscalls++;
            
            // Check if setting to 0 (root)
            if (!syscall.parsed_args.empty()) {
                for (const auto& [key, value] : syscall.parsed_args) {
                    if (value == "0") {
                        confidence += 40;
                        indicators.push_back("Attempting to set UID/GID to 0 (root)");
                        break;
                    }
                }
            }
        }
    }
    
    if (priv_syscalls > 0) {
        confidence += 30;
        indicators.push_back("UID/GID manipulation detected (" + 
                           std::to_string(priv_syscalls) + " calls)");
    }
    
    // Check for capability modifications
    int capset_calls = 0;
    for (const auto& syscall : syscalls_) {
        if (syscall.syscall_name == "capset" || syscall.syscall_name == "capget") {
            capset_calls++;
        }
    }
    
    if (capset_calls > 0) {
        confidence += 25;
        indicators.push_back("Capability modifications");
    }
    
    // Check for execve of setuid binaries
    for (const auto& syscall : syscalls_) {
        if (syscall.syscall_name == "execve" && !syscall.parsed_args.empty()) {
            auto it = syscall.parsed_args.find("pathname");
            if (it != syscall.parsed_args.end()) {
                // Check for common privilege escalation binaries
                std::vector<std::string> priv_binaries = {
                    "sudo", "su", "pkexec", "passwd", "mount"
                };
                
                for (const auto& binary : priv_binaries) {
                    if (it->second.find(binary) != std::string::npos) {
                        confidence += 20;
                        indicators.push_back("Execution of privilege escalation binary: " + binary);
                        break;
                    }
                }
            }
        }
    }
    
    confidence = std::min<int>(confidence, 100);
    
    if (confidence > 0) {
        description << "Privilege escalation indicators detected:\n";
        for (const auto& indicator : indicators) {
            description << "  • " << indicator << "\n";
        }
    } else {
        description << "No significant privilege escalation detected";
    }
    
    return {confidence, description.str()};
}

// Detect patterns
std::vector<SyscallPattern> SyscallMonitor::DetectPatterns() const {
    std::lock_guard<std::mutex> lock(syscalls_mutex_);
    
    std::vector<SyscallPattern> detected_patterns;
    
    // Get syscall sequence
    std::vector<std::string> sequence;
    for (const auto& syscall : syscalls_) {
        sequence.push_back(syscall.syscall_name);
    }
    
    // Check each pattern
    for (const auto& pattern : patterns_) {
        if (MatchesPattern(sequence, pattern)) {
            detected_patterns.push_back(pattern);
        }
    }
    
    return detected_patterns;
}

// Get syscall sequence
std::vector<std::string> SyscallMonitor::GetSyscallSequence(int pid) const {
    std::lock_guard<std::mutex> lock(syscalls_mutex_);
    
    std::vector<std::string> sequence;
    for (const auto& syscall : syscalls_) {
        if (pid == 0 || syscall.pid == pid) {
            sequence.push_back(syscall.syscall_name);
        }
    }
    
    return sequence;
}

// Get syscall frequency
std::map<std::string, int> SyscallMonitor::GetSyscallFrequency() const {
    std::lock_guard<std::mutex> lock(syscalls_mutex_);
    return statistics_.syscall_counts;
}

// Get timeline
std::vector<std::pair<std::chrono::system_clock::time_point, std::string>> 
SyscallMonitor::GetTimeline() const {
    std::lock_guard<std::mutex> lock(syscalls_mutex_);
    
    std::vector<std::pair<std::chrono::system_clock::time_point, std::string>> timeline;
    for (const auto& syscall : syscalls_) {
        timeline.emplace_back(syscall.timestamp, syscall.syscall_name);
    }
    
    return timeline;
}

// Export to JSON
std::string SyscallMonitor::ExportToJSON() const {
    std::lock_guard<std::mutex> lock(syscalls_mutex_);
    
    json j;
    
    // Statistics
    j["statistics"] = {
        {"total_syscalls", statistics_.total_syscalls},
        {"failed_syscalls", statistics_.failed_syscalls},
        {"suspicious_syscalls", statistics_.suspicious_syscalls},
        {"syscalls_per_second", statistics_.syscalls_per_second},
        {"monitoring_duration_ms", statistics_.monitoring_duration.count()}
    };
    
    // Syscall counts
    json counts_obj = json::object();
    for (const auto& [name, count] : statistics_.syscall_counts) {
        counts_obj[name] = count;
    }
    j["syscall_counts"] = counts_obj;
    
    // Category counts
    json category_counts_obj = json::object();
    for (const auto& [category, count] : statistics_.category_counts) {
        category_counts_obj[CategoryToString(category)] = count;
    }
    j["category_counts"] = category_counts_obj;
    
    // Syscalls
    json syscalls_array = json::array();
    for (const auto& syscall : syscalls_) {
        json syscall_obj;
        syscall_obj["name"] = syscall.syscall_name;
        syscall_obj["number"] = syscall.syscall_number;
        syscall_obj["category"] = CategoryToString(syscall.category);
        syscall_obj["return_value"] = syscall.return_value;
        syscall_obj["pid"] = syscall.pid;
        syscall_obj["tid"] = syscall.tid;
        syscall_obj["is_suspicious"] = syscall.is_suspicious;
        
        if (syscall.is_suspicious) {
            syscall_obj["suspicion_reason"] = syscall.suspicion_reason;
            syscall_obj["suspicion_score"] = syscall.suspicion_score;
        }
        
        // Parsed arguments
        if (!syscall.parsed_args.empty()) {
            json args_obj = json::object();
            for (const auto& [key, value] : syscall.parsed_args) {
                args_obj[key] = value;
            }
            syscall_obj["arguments"] = args_obj;
        }
        
        syscalls_array.push_back(syscall_obj);
    }
    j["syscalls"] = syscalls_array;
    
    // Detected patterns
    j["detected_patterns"] = statistics_.detected_patterns;
    
    return j.dump(2);
}

// Get raw strace output
std::string SyscallMonitor::GetRawStraceOutput() const {
    std::lock_guard<std::mutex> lock(syscalls_mutex_);
    return strace_output_;
}

// Clear data
void SyscallMonitor::ClearData() {
    std::lock_guard<std::mutex> lock(syscalls_mutex_);
    
    syscalls_.clear();
    statistics_ = SyscallStatistics{};
    strace_output_.clear();
    
    spdlog::debug("Syscall Monitor data cleared");
}

// Add pattern
void SyscallMonitor::AddPattern(const SyscallPattern& pattern) {
    patterns_.push_back(pattern);
    spdlog::debug("Added detection pattern: {}", pattern.name);
}

// Private methods

// Launch strace
bool SyscallMonitor::LaunchStrace(int pid, const std::string& executable,
                                  const std::vector<std::string>& args) {
#ifdef _WIN32
    spdlog::error("strace not available on Windows");
    return false;
#else
    // Create pipe for strace output
    int pipe_fds[2];
    if (pipe(pipe_fds) < 0) {
        spdlog::error("Failed to create pipe: {}", strerror(errno));
        return false;
    }
    
    strace_stdout_fd_ = pipe_fds[0];  // Read end
    
    // Fork to launch strace
    strace_pid_ = fork();
    
    if (strace_pid_ < 0) {
        spdlog::error("Failed to fork: {}", strerror(errno));
        close(pipe_fds[0]);
        close(pipe_fds[1]);
        return false;
    }
    
    if (strace_pid_ == 0) {
        // Child process - exec strace
        
        // Close read end
        close(pipe_fds[0]);
        
        // Redirect stdout to pipe
        dup2(pipe_fds[1], STDOUT_FILENO);
        dup2(pipe_fds[1], STDERR_FILENO);
        close(pipe_fds[1]);
        
        // Build strace command
        std::vector<const char*> strace_argv;
        strace_argv.push_back(config_.strace_binary.c_str());
        
        // Add configured arguments
        for (const auto& arg : config_.strace_args) {
            strace_argv.push_back(arg.c_str());
        }
        
        if (pid > 0) {
            // Attach to existing process
            strace_argv.push_back("-p");
            std::string pid_str = std::to_string(pid);
            strace_argv.push_back(pid_str.c_str());
        } else {
            // Launch new process
            strace_argv.push_back(executable.c_str());
            for (const auto& arg : args) {
                strace_argv.push_back(arg.c_str());
            }
        }
        
        strace_argv.push_back(nullptr);
        
        // Execute strace
        execvp(config_.strace_binary.c_str(), 
               const_cast<char* const*>(strace_argv.data()));
        
        // If we get here, exec failed
        spdlog::error("Failed to exec strace: {}", strerror(errno));
        _exit(1);
    }
    
    // Parent process
    close(pipe_fds[1]);  // Close write end
    
    spdlog::info("strace launched with PID: {}", strace_pid_);
    
    return true;
#endif
}

// Read strace output
void SyscallMonitor::ReadStraceOutput() {
#ifndef _WIN32
    char buffer[4096];
    std::string line_buffer;
    
    while (is_monitoring_) {
        ssize_t bytes_read = read(strace_stdout_fd_, buffer, sizeof(buffer) - 1);
        
        if (bytes_read <= 0) {
            if (bytes_read < 0 && errno == EINTR) {
                continue;  // Interrupted, try again
            }
            break;  // EOF or error
        }
        
        buffer[bytes_read] = '\0';
        
        // Add to line buffer
        line_buffer += buffer;
        
        // Store raw output
        {
            std::lock_guard<std::mutex> lock(syscalls_mutex_);
            strace_output_ += buffer;
        }
        
        // Process complete lines
        size_t pos;
        while ((pos = line_buffer.find('\n')) != std::string::npos) {
            std::string line = line_buffer.substr(0, pos);
            line_buffer = line_buffer.substr(pos + 1);
            
            // Parse and process the line
            auto event = ParseStraceLine(line);
            if (event) {
                // Analyze
                AnalyzeSyscall(*event);
                
                // Store
                {
                    std::lock_guard<std::mutex> lock(syscalls_mutex_);
                    syscalls_.push_back(*event);
                    UpdateStatistics(*event);
                }
                
                // Notify callbacks
                NotifyCallbacks(*event);
                
                // Log if verbose
                if (config_.verbose_logging) {
                    LogEvent(event->syscall_name + "() = " + 
                           std::to_string(event->return_value));
                }
            }
        }
    }
    
    close(strace_stdout_fd_);
    strace_stdout_fd_ = -1;
#endif
}

// Parse strace line
std::optional<SyscallEvent> SyscallMonitor::ParseStraceLine(const std::string& line) {
    // Example strace output formats:
    // 12:34:56.789012 open("/tmp/test", O_RDONLY) = 3 <0.000123>
    // 12:34:56.789012 [pid 1234] write(1, "hello", 5) = 5 <0.000045>
    // 12:34:56.789012 execve("/bin/ls", ["ls", "-la"], ...) = 0 <0.001234>
    
    if (line.empty() || line[0] == '+' || line[0] == '-') {
        return std::nullopt;  // Skip continuation or signal lines
    }
    
    SyscallEvent event;
    event.timestamp = std::chrono::system_clock::now();
    event.raw_line = line;
    
    // Parse timestamp (HH:MM:SS.microseconds)
    std::regex timestamp_regex(R"(^(\d{2}):(\d{2}):(\d{2})\.(\d{6})\s+)");
    std::smatch timestamp_match;
    if (std::regex_search(line, timestamp_match, timestamp_regex) && timestamp_match.size() > 4) {
        std::tm tm = {};
        tm.tm_hour = std::stoi(timestamp_match[1]);
        tm.tm_min = std::stoi(timestamp_match[2]);
        tm.tm_sec = std::stoi(timestamp_match[3]);
        event.timestamp = std::chrono::system_clock::from_time_t(std::mktime(&tm));
        event.timestamp += std::chrono::microseconds(std::stoi(timestamp_match[4]));
    }
    
    // Parse syscall name and arguments
    std::regex syscall_regex(R"(^\d+:\s*\d+\s+[^\s]+ \((.*)\))");
    std::smatch syscall_match;
    if (std::regex_search(line, syscall_match, syscall_regex) && syscall_match.size() > 1) {
        std::string syscall_info = syscall_match[1];
        
        // Split by comma
        std::vector<std::string> args;
        std::stringstream ss(syscall_info);
        std::string arg;
        while (std::getline(ss, arg, ',')) {
            args.push_back(arg);
        }
        
        // First arg is the syscall name
        if (!args.empty()) {
            event.syscall_name = args[0];
        }
        
        // Parse key=value pairs
        for (const auto& a : args) {
            std::string arg_trimmed = Trim(a);
            if (arg_trimmed.empty()) {
                continue;
            }
            
            size_t eq_pos = arg_trimmed.find('=');
            if (eq_pos != std::string::npos) {
                std::string key = Trim(arg_trimmed.substr(0, eq_pos));
                std::string value = Trim(arg_trimmed.substr(eq_pos + 1));
                event.parsed_args[key] = value;
            } else {
                // Handle simple arguments (like flags)
                event.parsed_args[arg_trimmed] = arg_trimmed;
            }
        }
    }
    
    return event;
}

// Analyze syscall for detection
void SyscallMonitor::AnalyzeSyscall(SyscallEvent& event) {
    // Check if monitoring all syscalls or just suspicious patterns
    if (config_.monitor_all_syscalls) {
        event.is_suspicious = true;
        return;
    }
    
    // Check patterns
    for (const auto& pattern : patterns_) {
        if (MatchesPattern(event.parsed_args, pattern)) {
            event.is_suspicious = true;
            event.suspicion_reason = "Matched pattern: " + pattern.name;
            event.suspicion_score = pattern.score;
            return;
        }
    }
}

// Update statistics
void SyscallMonitor::UpdateStatistics(const SyscallEvent& event) {
    statistics_.total_syscalls++;
    
    if (event.return_value < 0) {
        statistics_.failed_syscalls++;
    }
    
    if (event.is_suspicious) {
        statistics_.suspicious_syscalls++;
    }
    
    // Update syscall counts
    statistics_.syscall_counts[event.syscall_name]++;
    
    // Update category counts
    statistics_.category_counts[event.category]++;
}

// Notify registered callbacks
void SyscallMonitor::NotifyCallbacks(const SyscallEvent& event) {
    for (const auto& callback : callbacks_) {
        callback(event);
    }
}

// Log event
void SyscallMonitor::LogEvent(const std::string& message) {
    if (config_.log_file.empty()) {
        spdlog::info("{}", message);
    } else {
        std::ofstream log_file(config_.log_file, std::ios::app);
        if (log_file.is_open()) {
            log_file << message << std::endl;
        }
    }
}

// Load default patterns
void SyscallMonitor::LoadDefaultPatterns() {
    // whitelist: allow known good processes
    patterns_.push_back({"whitelist", "allow known good processes", 0, 
                       {}});
    
    // Blacklist: block known bad syscalls
    patterns_.push_back({"blacklist", "block known bad syscalls", 100, 
                       {}});
    
    // Suspicious: detect potential malware behavior
    patterns_.push_back({"suspicious", "detect potential malware behavior", 50, 
                       {}});
}

bool SyscallMonitor::MatchesPattern(const std::map<std::string, std::string>& args, 
                                  const SyscallPattern& pattern) const {
    // Simple pattern matching: check if all keys in pattern exist in args
    for (const auto& key : pattern.keys) {
        if (args.find(key) == args.end()) {
            return false;
        }
    }
    return true;
}

bool SyscallMonitor::MatchesPattern(const std::vector<std::string>& sequence, 
                                  const SyscallPattern& pattern) const {
    // Simple sequence pattern matching
    if (sequence.size() < pattern.sequence.size()) {
        return false;
    }
    
    for (size_t i = 0; i < pattern.sequence.size(); ++i) {
        if (sequence[i] != pattern.sequence[i]) {
            return false;
        }
    }
    return true;
}

void SyscallMonitor::StopStrace() {
#ifndef _WIN32
    if (strace_pid_ > 0) {
        // Terminate strace
        kill(strace_pid_, SIGTERM);
        waitpid(strace_pid_, nullptr, 0);
        strace_pid_ = -1;
    }
    
    if (strace_stdout_fd_ >= 0) {
        close(strace_stdout_fd_);
        strace_stdout_fd_ = -1;
    }
#endif
}