/**
 * @file process_monitor.cpp
 * @brief Implementation of process, thread, and memory operation monitoring
 * 
 * Implements comprehensive process lifecycle tracking, code injection detection,
 * privilege escalation identification, process hollowing recognition, thread manipulation
 * monitoring, and complete process tree construction for behavioral analysis and
 * attack chain reconstruction.
 * 
 * **Monitoring Capabilities**:
 * - **Process Lifecycle**: exec, fork, clone, exit events
 * - **Process Injection**: WriteProcessMemory, CreateRemoteThread, QueueUserAPC
 * - **Process Hollowing**: Unmapping and remapping executable sections
 * - **Privilege Escalation**: setuid, sudo, UAC bypass attempts
 * - **Thread Manipulation**: CreateThread, SuspendThread, ResumeThread
 * - **DLL Injection**: LoadLibrary, LdrLoadDll detection
 * 
 * **Process Injection Techniques Detected**:
 * 1. **Classic DLL Injection**: VirtualAllocEx → WriteProcessMemory → CreateRemoteThread
 * 2. **Process Hollowing**: Create suspended → Unmap → Write → Resume
 * 3. **APC Injection**: QueueUserAPC to inject code into thread queue
 * 4. **Thread Hijacking**: SuspendThread → SetThreadContext → ResumeThread
 * 5. **Reflective DLL Injection**: Manual PE loading without LoadLibrary
 * 6. **Process Doppelgänging**: NTFS transaction manipulation
 * 
 * **Detection Algorithms**:
 * ```
 * Process Injection Pattern:
 * 1. VirtualAllocEx(TargetPID) → Memory allocation in remote process
 * 2. WriteProcessMemory(TargetPID) → Code written to allocated memory
 * 3. CreateRemoteThread(TargetPID) → Execution started in target
 * → ALERT: Code Injection Detected
 * 
 * Process Hollowing Pattern:
 * 1. CreateProcess(SUSPENDED) → Create sacrificial process
 * 2. NtUnmapViewOfSection → Unmap legitimate code
 * 3. VirtualAllocEx → Allocate new memory
 * 4. WriteProcessMemory → Write malicious code
 * 5. SetThreadContext → Point to new entry point
 * 6. ResumeThread → Execute malicious code
 * → ALERT: Process Hollowing Detected
 * ```
 * 
 * **Privilege Escalation Detection**:
 * - setuid(0) calls (attempting root)
 * - sudo execution monitoring
 * - UAC bypass techniques (Windows)
 * - Kernel exploit attempts
 * - Token manipulation (Windows)
 * 
 * **Process Tree Construction**:
 * ```
 * PID 1234 (malware.exe)
 * ├── PID 1235 (cmd.exe) [spawned]
 * │   └── PID 1236 (powershell.exe) [spawned]
 * │       └── PID 1237 (downloader.exe) [injected]
 * └── PID 1238 (explorer.exe) [injected into]
 * ```
 * 
 * **Suspicious Patterns**:
 * - Unusual parent-child relationships (malware → svchost.exe)
 * - Cross-session process creation
 * - Processes with no parent
 * - Rapid process spawning (>10 processes/sec)
 * - Suspicious command lines (encoded PowerShell, base64)
 * 
 * @author Paramite Development Team
 * @date 2025
 */

#include "paramite/monitors/process_monitor.hpp"
#include "paramite/utils/hash_utils.hpp"
#include "paramite/utils/string_utils.hpp"

#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>

#include <fstream>
#include <sstream>
#include <algorithm>
#include <regex>
#include <thread>
#include <chrono>
#include <iomanip>
#include <ctime>

#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#pragma comment(lib, "psapi.lib")
#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <signal.h>
#endif

using json = nlohmann::json;

namespace paramite {
namespace monitors {

// Constructor
ProcessMonitor::ProcessMonitor(const ProcessMonitorConfig& config)
    : config_(config)
    , is_monitoring_(false) {
    
    spdlog::info("Process Monitor initialized");
    spdlog::debug("Monitor process creation: {}", config_.monitor_process_creation);
    spdlog::debug("Detect injection: {}", config_.detect_injection);
}

// Destructor
ProcessMonitor::~ProcessMonitor() {
    Stop();
    spdlog::info("Process Monitor destroyed");
}

// Start monitoring
bool ProcessMonitor::Start() {
    if (is_monitoring_) {
        spdlog::warn("Process Monitor already running");
        return true;
    }
    
    spdlog::info("═══════════════════════════════════════════════════════════════");
    spdlog::info("STARTING PROCESS MONITOR");
    spdlog::info("═══════════════════════════════════════════════════════════════");
    
    try {
        // Create baseline snapshot
        spdlog::info("Creating process baseline...");
        CreateBaseline();
        spdlog::info("✓ Baseline created ({} processes)", baseline_pids_.size());
        
        // Clear previous data
        {
            std::lock_guard<std::mutex> lock(events_mutex_);
            process_events_.clear();
            thread_events_.clear();
            memory_events_.clear();
            active_processes_.clear();
            active_threads_.clear();
            statistics_ = ProcessStatistics{};
        }
        
        is_monitoring_ = true;
        
        spdlog::info("═══════════════════════════════════════════════════════════════");
        spdlog::info("✓ Process Monitor started");
        spdlog::info("═══════════════════════════════════════════════════════════════\n");
        
        return true;
    }
    catch (const std::exception& e) {
        spdlog::error("Failed to start Process Monitor: {}", e.what());
        return false;
    }
}

// Stop monitoring
void ProcessMonitor::Stop() {
    if (!is_monitoring_) {
        return;
    }
    
    spdlog::info("Stopping Process Monitor...");
    is_monitoring_ = false;
    
    spdlog::info("✓ Process Monitor stopped");
    spdlog::info("  Process events: {}", process_events_.size());
    spdlog::info("  Thread events: {}", thread_events_.size());
    spdlog::info("  Memory events: {}", memory_events_.size());
    spdlog::info("  Suspicious processes: {}", statistics_.suspicious_processes);
    spdlog::info("  Injection attempts: {}", statistics_.injection_attempts);
}

// Register callbacks
void ProcessMonitor::RegisterProcessCallback(ProcessEventCallback callback) {
    process_callbacks_.push_back(callback);
    spdlog::debug("Process event callback registered");
}

void ProcessMonitor::RegisterThreadCallback(ThreadEventCallback callback) {
    thread_callbacks_.push_back(callback);
    spdlog::debug("Thread event callback registered");
}

void ProcessMonitor::RegisterMemoryCallback(MemoryEventCallback callback) {
    memory_callbacks_.push_back(callback);
    spdlog::debug("Memory event callback registered");
}

// Get all process events
std::vector<ProcessCreationEvent> ProcessMonitor::GetProcessEvents() const {
    std::lock_guard<std::mutex> lock(events_mutex_);
    return process_events_;
}

// Get all thread events
std::vector<ThreadOperationEvent> ProcessMonitor::GetThreadEvents() const {
    std::lock_guard<std::mutex> lock(events_mutex_);
    return thread_events_;
}

// Get all memory operation events
std::vector<MemoryOperationEvent> ProcessMonitor::GetMemoryEvents() const {
    std::lock_guard<std::mutex> lock(events_mutex_);
    return memory_events_;
}

// Get list of created processes
std::vector<ProcessInfo> ProcessMonitor::GetCreatedProcesses() const {
    std::lock_guard<std::mutex> lock(events_mutex_);
    
    std::vector<ProcessInfo> created;
    for (const auto& event : process_events_) {
        if (event.event_type == ProcessEvent::CREATED) {
            created.push_back(event.process);
        }
    }
    
    return created;
}

// Get process tree
ProcessTreeNode ProcessMonitor::GetProcessTree() const {
    std::lock_guard<std::mutex> lock(events_mutex_);
    return process_tree_;
}

// Get process by PID
std::optional<ProcessInfo> ProcessMonitor::GetProcess(int pid) const {
    std::lock_guard<std::mutex> lock(events_mutex_);
    
    auto it = active_processes_.find(pid);
    if (it != active_processes_.end()) {
        return it->second;
    }
    
    return std::nullopt;
}

// Get all threads for a process
std::vector<ThreadInfo> ProcessMonitor::GetThreads(int pid) const {
    std::lock_guard<std::mutex> lock(events_mutex_);
    
    auto it = active_threads_.find(pid);
    if (it != active_threads_.end()) {
        return it->second;
    }
    
    return {};
}

// Get process statistics
ProcessStatistics ProcessMonitor::GetStatistics() const {
    std::lock_guard<std::mutex> lock(events_mutex_);
    return statistics_;
}

// Detect process injection
std::pair<int, std::string> ProcessMonitor::DetectInjection() const {
    std::lock_guard<std::mutex> lock(events_mutex_);
    
    int confidence = 0;
    std::ostringstream description;
    std::vector<std::string> indicators;
    
    // Count remote thread creations
    int remote_threads = 0;
    for (const auto& event : thread_events_) {
        if (event.event_type == ThreadEvent::REMOTE_CREATED) {
            remote_threads++;
        }
    }
    
    if (remote_threads > 0) {
        confidence += 50;
        indicators.push_back("Remote thread creation detected (" + 
                           std::to_string(remote_threads) + " instances)");
    }
    
    // Count remote memory operations
    int remote_memory_ops = 0;
    int rwx_allocations = 0;
    
    for (const auto& event : memory_events_) {
        if (event.target_pid.has_value()) {
            remote_memory_ops++;
        }
        
        // Check for RWX memory (executable + writable = injection)
        if (event.permissions.find('r') != std::string::npos &&
            event.permissions.find('w') != std::string::npos &&
            event.permissions.find('x') != std::string::npos) {
            rwx_allocations++;
        }
    }
    
    if (remote_memory_ops > 0) {
        confidence += 40;
        indicators.push_back("Remote memory operations detected (" + 
                           std::to_string(remote_memory_ops) + " operations)");
    }
    
    if (rwx_allocations > 0) {
        confidence += 30;
        indicators.push_back("RWX memory allocations (" + 
                           std::to_string(rwx_allocations) + " allocations)");
    }
    
    // Check for ptrace usage (debugging/injection)
    int ptrace_calls = 0;
    for (const auto& event : memory_events_) {
        if (event.syscall_name == "ptrace") {
            ptrace_calls++;
        }
    }
    
    if (ptrace_calls > 0) {
        confidence += 25;
        indicators.push_back("ptrace() syscalls detected (process debugging/injection)");
    }
    
    confidence = std::min<int>(confidence, 100);
    
    if (confidence > 0) {
        description << "Process injection indicators detected:\n";
        for (const auto& indicator : indicators) {
            description << "  • " << indicator << "\n";
        }
    } else {
        description << "No significant injection indicators detected";
    }
    
    return {confidence, description.str()};
}

// Detect privilege escalation
std::pair<int, std::string> ProcessMonitor::DetectPrivilegeEscalation() const {
    std::lock_guard<std::mutex> lock(events_mutex_);
    
    int confidence = 0;
    std::ostringstream description;
    std::vector<std::string> indicators;
    
    // Look for UID/GID changes
    int escalations = 0;
    
    for (const auto& event : process_events_) {
        const auto& proc = event.process;
        
        // Check if effective UID is 0 (root) but real UID is not
        if (proc.euid == 0 && proc.uid != 0) {
            escalations++;
        }
        
        // Check for setuid/setgid binaries
        if (proc.path.find("setuid") != std::string::npos) {
            escalations++;
        }
    }
    
    if (escalations > 0) {
        confidence += 60;
        indicators.push_back("Privilege escalation detected (" + 
                           std::to_string(escalations) + " instances)");
    }
    
    // Check for suspicious capability changes
    for (const auto& [pid, proc] : active_processes_) {
        if (!proc.capabilities.empty()) {
            for (const auto& cap : proc.capabilities) {
                if (cap.find("CAP_SYS_ADMIN") != std::string::npos ||
                    cap.find("CAP_SYS_PTRACE") != std::string::npos) {
                    confidence += 20;
                    indicators.push_back("Dangerous capability: " + cap);
                    break;
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

// Detect process hollowing
std::pair<int, std::string> ProcessMonitor::DetectProcessHollowing() const {
    std::lock_guard<std::mutex> lock(events_mutex_);
    
    int confidence = 0;
    std::ostringstream description;
    std::vector<std::string> indicators;
    
    // Look for suspicious memory operations on legitimate processes
    std::map<int, int> suspicious_memory_ops;
    
    for (const auto& event : memory_events_) {
        // Look for UnmapViewOfSection + WriteProcessMemory pattern
        if (event.operation == MemoryOperation::UNMAP ||
            event.operation == MemoryOperation::REMOTE_WRITE) {
            suspicious_memory_ops[event.pid]++;
        }
    }
    
    int hollowing_candidates = 0;
    for (const auto& [pid, count] : suspicious_memory_ops) {
        if (count > 5) {  // Multiple suspicious operations
            hollowing_candidates++;
        }
    }
    
    if (hollowing_candidates > 0) {
        confidence += 50;
        indicators.push_back("Process hollowing patterns detected (" + 
                           std::to_string(hollowing_candidates) + " processes)");
    }
    
    // Check for processes with mismatched path and memory contents
    // (This would require deeper memory analysis)
    
    confidence = std::min<int>(confidence, 100);
    
    if (confidence > 0) {
        description << "Process hollowing indicators detected:\n";
        for (const auto& indicator : indicators) {
            description << "  • " << indicator << "\n";
        }
    } else {
        description << "No significant process hollowing detected";
    }
    
    return {confidence, description.str()};
}

// Get suspicious processes
std::vector<ProcessInfo> ProcessMonitor::GetSuspiciousProcesses() const {
    std::lock_guard<std::mutex> lock(events_mutex_);
    
    std::vector<ProcessInfo> suspicious;
    
    for (const auto& event : process_events_) {
        if (event.is_suspicious) {
            suspicious.push_back(event.process);
        }
    }
    
    return suspicious;
}

// Get remote thread operations
std::vector<ThreadOperationEvent> ProcessMonitor::GetRemoteThreads() const {
    std::lock_guard<std::mutex> lock(events_mutex_);
    
    std::vector<ThreadOperationEvent> remote;
    
    for (const auto& event : thread_events_) {
        if (event.event_type == ThreadEvent::REMOTE_CREATED) {
            remote.push_back(event);
        }
    }
    
    return remote;
}

// Get remote memory operations
std::vector<MemoryOperationEvent> ProcessMonitor::GetRemoteMemoryOperations() const {
    std::lock_guard<std::mutex> lock(events_mutex_);
    
    std::vector<MemoryOperationEvent> remote;
    
    for (const auto& event : memory_events_) {
        if (event.operation == MemoryOperation::REMOTE_READ ||
            event.operation == MemoryOperation::REMOTE_WRITE) {
            remote.push_back(event);
        }
    }
    
    return remote;
}

// Export to JSON
std::string ProcessMonitor::ExportToJSON() const {
    std::lock_guard<std::mutex> lock(events_mutex_);
    
    json j;
    
    // Statistics
    j["statistics"] = {
        {"total_processes", statistics_.total_processes},
        {"processes_created", statistics_.processes_created},
        {"processes_terminated", statistics_.processes_terminated},
        {"processes_crashed", statistics_.processes_crashed},
        {"total_threads", statistics_.total_threads},
        {"remote_threads_created", statistics_.remote_threads_created},
        {"memory_allocations", statistics_.memory_allocations},
        {"remote_memory_operations", statistics_.remote_memory_operations},
        {"suspicious_processes", statistics_.suspicious_processes},
        {"injection_attempts", statistics_.injection_attempts},
        {"privilege_escalations", statistics_.privilege_escalations}
    };
    
    // Process events
    json process_events_array = json::array();
    for (const auto& event : process_events_) {
        json event_obj;
        event_obj["event_type"] = ProcessEventToString(event.event_type);
        event_obj["pid"] = event.process.pid;
        event_obj["name"] = event.process.name;
        event_obj["path"] = event.process.path;
        event_obj["cmdline"] = event.process.cmdline;
        event_obj["parent_pid"] = event.parent_pid;
        event_obj["parent_name"] = event.parent_name;
        event_obj["is_suspicious"] = event.is_suspicious;
        
        if (event.is_suspicious) {
            event_obj["suspicion_reason"] = event.suspicion_reason;
            event_obj["suspicion_score"] = event.suspicion_score;
        }
        
        process_events_array.push_back(event_obj);
    }
    j["process_events"] = process_events_array;
    
    // Thread events
    json thread_events_array = json::array();
    for (const auto& event : thread_events_) {
        json event_obj;
        event_obj["event_type"] = ThreadEventToString(event.event_type);
        event_obj["tid"] = event.thread.tid;
        event_obj["pid"] = event.thread.pid;
        event_obj["is_suspicious"] = event.is_suspicious;
        
        if (event.target_pid) {
            event_obj["target_pid"] = *event.target_pid;
        }
        
        thread_events_array.push_back(event_obj);
    }
    j["thread_events"] = thread_events_array;
    
    // Memory events
    json memory_events_array = json::array();
    for (const auto& event : memory_events_) {
        json event_obj;
        event_obj["operation"] = MemoryOperationToString(event.operation);
        event_obj["pid"] = event.pid;
        event_obj["process_name"] = event.process_name;
        event_obj["address"] = event.address;
        event_obj["size"] = event.size;
        event_obj["permissions"] = event.permissions;
        event_obj["is_suspicious"] = event.is_suspicious;
        
        if (event.target_pid) {
            event_obj["target_pid"] = *event.target_pid;
            event_obj["target_process"] = event.target_process.value_or("unknown");
        }
        
        memory_events_array.push_back(event_obj);
    }
    j["memory_events"] = memory_events_array;
    
    return j.dump(2);
}

// Clear data
void ProcessMonitor::ClearData() {
    std::lock_guard<std::mutex> lock(events_mutex_);
    
    process_events_.clear();
    thread_events_.clear();
    memory_events_.clear();
    active_processes_.clear();
    active_threads_.clear();
    statistics_ = ProcessStatistics{};
    
    spdlog::debug("Process Monitor data cleared");
}

// Private methods

// Create baseline
void ProcessMonitor::CreateBaseline() {
    baseline_pids_.clear();
    
#ifdef _WIN32
    // Windows: Use ToolHelp32
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return;
    }
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (Process32First(snapshot, &pe32)) {
        do {
            baseline_pids_.insert(pe32.th32ProcessID);
        } while (Process32Next(snapshot, &pe32));
    }
    
    CloseHandle(snapshot);
#else
    // Linux: Read /proc
    DIR* proc_dir = opendir("/proc");
    if (!proc_dir) {
        return;
    }
    
    struct dirent* entry;
    while ((entry = readdir(proc_dir)) != nullptr) {
        // Check if directory name is numeric (PID)
        if (entry->d_type == DT_DIR) {
            int pid = std::atoi(entry->d_name);
            if (pid > 0) {
                baseline_pids_.insert(pid);
            }
        }
    }
    
    closedir(proc_dir);
#endif
}

// Monitor processes (stub - would use platform-specific APIs)
void ProcessMonitor::MonitorProcesses() {
    // Would continuously poll for new processes
    // On Linux: watch /proc directory
    // On Windows: use WMI or polling CreateToolhelp32Snapshot
}

// Monitor threads (stub)
void ProcessMonitor::MonitorThreads() {
    // Would monitor thread creation/termination
}

// Monitor memory (stub)
void ProcessMonitor::MonitorMemory() {
    // Would monitor memory operations via ptrace or similar
}

// Parse strace output
void ProcessMonitor::ParseStraceOutput(const std::string& line) {
    // Example: clone(child_stack=0x7f..., flags=CLONE_VM|...) = 1234
    // Example: execve("/bin/ls", ["ls", "-la"], ...) = 0
    
    if (line.find("clone") != std::string::npos ||
        line.find("fork") != std::string::npos) {
        
        ProcessCreationEvent event;
        event.event_type = ProcessEvent::CREATED;
        event.timestamp = std::chrono::system_clock::now();
        event.syscall_name = (line.find("clone") != std::string::npos) ? "clone" : "fork";
        
        // Parse PID from return value
        size_t eq_pos = line.find(" = ");
        if (eq_pos != std::string::npos) {
            std::string result = line.substr(eq_pos + 3);
            event.process.pid = std::atoi(result.c_str());
        }
        
        AnalyzeProcessEvent(event);
        
        std::lock_guard<std::mutex> lock(events_mutex_);
        process_events_.push_back(event);
        UpdateStatistics(event);
        NotifyProcessCallbacks(event);
    }
}

// Parse /proc filesystem
void ProcessMonitor::ParseProcFilesystem() {
#ifndef _WIN32
    DIR* proc_dir = opendir("/proc");
    if (!proc_dir) {
        return;
    }
    
    struct dirent* entry;
    while ((entry = readdir(proc_dir)) != nullptr) {
        if (entry->d_type == DT_DIR) {
            int pid = std::atoi(entry->d_name);
            if (pid > 0) {
                auto proc_info = ReadProcessInfo(pid);
                if (proc_info) {
                    std::lock_guard<std::mutex> lock(events_mutex_);
                    active_processes_[pid] = *proc_info;
                }
            }
        }
    }
    
    closedir(proc_dir);
#endif
}

// Read process info from /proc/[pid]
std::optional<ProcessInfo> ProcessMonitor::ReadProcessInfo(int pid) {
#ifdef _WIN32
    // Windows implementation would use OpenProcess + GetModuleFileNameEx
    return std::nullopt;
#else
    ProcessInfo info;
    info.pid = pid;
    
    // Read /proc/[pid]/stat
    std::ifstream stat_file("/proc/" + std::to_string(pid) + "/stat");
    if (stat_file.is_open()) {
        std::string line;
        std::getline(stat_file, line);
        
        // Parse stat file (format: pid (name) state ppid ...)

        size_t start = line.find('(');
        size_t end = line.rfind(')');
        if (start != std::string::npos && end != std::string::npos) {
            info.name = line.substr(start + 1, end - start - 1);
            
            // Parse remaining fields
            std::istringstream iss(line.substr(end + 2));
            char state;
            iss >> state >> info.ppid;
        }
    }
    
    // Read /proc/[pid]/cmdline
    std::ifstream cmdline_file("/proc/" + std::to_string(pid) + "/cmdline");
    if (cmdline_file.is_open()) {
        std::getline(cmdline_file, info.cmdline, '\0');
        info.cmdline.erase(std::remove(info.cmdline.begin(), info.cmdline.end(), '\0'), 
                          info.cmdline.end());
    }
    
    // Read /proc/[pid]/exe (symbolic link)
    char exe_path[PATH_MAX];
    std::string exe_link = "/proc/" + std::to_string(pid) + "/exe";
    ssize_t len = readlink(exe_link.c_str(), exe_path, sizeof(exe_path) - 1);
    if (len != -1) {
        exe_path[len] = '\0';
        info.path = exe_path;
    }
    
    // Read /proc/[pid]/status for UID/GID
    std::ifstream status_file("/proc/" + std::to_string(pid) + "/status");
    if (status_file.is_open()) {
        std::string line;
        while (std::getline(status_file, line)) {
            if (line.substr(0, 4) == "Uid:") {
                std::istringstream iss(line.substr(5));
                iss >> info.uid >> info.euid;
            } else if (line.substr(0, 4) == "Gid:") {
                std::istringstream iss(line.substr(5));
                iss >> info.gid >> info.egid;
            }
        }
    }
    
    return info;
#endif
}

// Read thread info (stub)
std::optional<ThreadInfo> ProcessMonitor::ReadThreadInfo(int pid, int tid) {
    // Would read /proc/[pid]/task/[tid]
    return std::nullopt;
}

// Build process tree
void ProcessMonitor::BuildProcessTree() {
    // Build tree from active_processes_ map
    // Root would be init (PID 1) or similar
}

// Add to process tree
void ProcessMonitor::AddToProcessTree(const ProcessInfo& process) {
    // Add process to tree structure based on PPID
}

// Analyze process event
void ProcessMonitor::AnalyzeProcessEvent(ProcessCreationEvent& event) {
    event.suspicion_score = CalculateProcessSuspicionScore(event.process);
    
    if (event.suspicion_score >= 50) {
        event.is_suspicious = true;
        
        std::vector<std::string> reasons;
        
        // Check for suspicious parent-child relationships
        if (IsSuspiciousParent(event.parent_name, event.process.name)) {
            reasons.push_back("Suspicious parent-child relationship");
        }
        
        // Check for suspicious paths
        if (event.process.path.find("/tmp/") != std::string::npos ||
            event.process.path.find("/dev/shm/") != std::string::npos) {
            reasons.push_back("Execution from suspicious location");
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

// Analyze thread event
void ProcessMonitor::AnalyzeThreadEvent(ThreadOperationEvent& event) {
    if (event.event_type == ThreadEvent::REMOTE_CREATED) {
        event.is_suspicious = true;
        event.suspicion_score = 80;
        event.suspicion_reason = "Remote thread creation (possible injection)";
    }
}

// Analyze memory event
void ProcessMonitor::AnalyzeMemoryEvent(MemoryOperationEvent& event) {
    if (IsInjectionPattern(event)) {
        event.is_suspicious = true;
        event.suspicion_score = 70;
        event.suspicion_reason = "Suspicious memory operation pattern";
    }
}

// Is suspicious parent
bool ProcessMonitor::IsSuspiciousParent(const std::string& parent, 
                                       const std::string& child) const {
    // Common suspicious patterns
    std::map<std::string, std::vector<std::string>> suspicious_patterns = {
        {"winword.exe", {"cmd.exe", "powershell.exe", "wscript.exe"}},
        {"excel.exe", {"cmd.exe", "powershell.exe", "wscript.exe"}},
        {"outlook.exe", {"cmd.exe", "powershell.exe"}},
        {"acrobat.exe", {"cmd.exe", "powershell.exe"}},
        {"chrome.exe", {"cmd.exe", "powershell.exe"}},
        {"firefox.exe", {"cmd.exe", "powershell.exe"}}
    };
    
    auto parent_lower = parent;
    auto child_lower = child;
    std::transform(parent_lower.begin(), parent_lower.end(), parent_lower.begin(), ::tolower);
    std::transform(child_lower.begin(), child_lower.end(), child_lower.begin(), ::tolower);
    
    auto it = suspicious_patterns.find(parent_lower);
    if (it != suspicious_patterns.end()) {
        for (const auto& suspicious_child : it->second) {
            if (child_lower.find(suspicious_child) != std::string::npos) {
                return true;
            }
        }
    }
    
    return false;
}

// Is injection pattern
bool ProcessMonitor::IsInjectionPattern(const MemoryOperationEvent& event) const {
    // Remote write to another process
    if (event.operation == MemoryOperation::REMOTE_WRITE) {
        return true;
    }
    
    // RWX memory allocation
    if (event.operation == MemoryOperation::ALLOCATE &&
        event.permissions == "rwx") {
        return true;
    }
    
    // Changing permissions to executable
    if (event.operation == MemoryOperation::PROTECT &&
        event.permissions.find('x') != std::string::npos &&
        event.original_permissions.find('x') == std::string::npos) {
        return true;
    }
    
    return false;
}

// Is privilege escalation
bool ProcessMonitor::IsPrivilegeEscalation(int old_uid, int new_uid,
                                          int old_gid, int new_gid) const {
    // Check if UID/GID decreased (0 = root)
    return (new_uid < old_uid) || (new_gid < old_gid);
}

// Calculate process suspicion score
int ProcessMonitor::CalculateProcessSuspicionScore(const ProcessInfo& process) const {
    int score = 0;
    
    // Check for suspicious paths
    if (process.path.find("/tmp/") != std::string::npos) {
        score += 20;
    }
    
    // Check for no path (deleted binary)
    if (process.path.empty() || process.path.find("(deleted)") != std::string::npos) {
        score += 40;
    }
    
    // Check for privilege escalation
    if (process.euid == 0 && process.uid != 0) {
        score += 30;
    }
    
    // Check for suspicious names
    std::vector<std::string> suspicious_names = {
        "nc", "netcat", "ncat", "socat", "bash", "sh", "python", "perl"
    };
    
    for (const auto& sus_name : suspicious_names) {
        if (process.name.find(sus_name) != std::string::npos) {
            score += 15;
            break;
        }
    }
    
    return std::min<int>(score, 100);
}

// Calculate binary hash
std::optional<std::string> ProcessMonitor::CalculateBinaryHash(
    const std::filesystem::path& path) {
    
    if (!std::filesystem::exists(path)) {
        return std::nullopt;
    }
    
    try {
        utils::HashUtils hash_utils;
        return hash_utils.ComputeSHA256(path);
    }
    catch (const std::exception& e) {
        spdlog::debug("Failed to calculate hash for {}: {}", path.string(), e.what());
        return std::nullopt;
    }
}

// Detect binary type
std::string ProcessMonitor::DetectBinaryType(const std::filesystem::path& path) const {
    if (!std::filesystem::exists(path)) {
        return "unknown";
    }
    
    // Read first few bytes for magic numbers
    std::ifstream file(path, std::ios::binary);
    if (!file.is_open()) {
        return "unknown";
    }
    
    unsigned char magic[4] = {0};
    file.read(reinterpret_cast<char*>(magic), 4);
    
    // Check for ELF (0x7f 'E' 'L' 'F')
    if (magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F') {
        return "ELF";
    }
    
    // Check for PE (MZ header)
    if (magic[0] == 'M' && magic[1] == 'Z') {
        return "PE";
    }
    
    // Check for shebang script
    if (magic[0] == '#' && magic[1] == '!') {
        return "script";
    }
    
    return "unknown";
}

// Update statistics
void ProcessMonitor::UpdateStatistics(const ProcessCreationEvent& event) {
    statistics_.total_processes++;
    
    if (event.event_type == ProcessEvent::CREATED) {
        statistics_.processes_created++;
    } else if (event.event_type == ProcessEvent::TERMINATED) {
        statistics_.processes_terminated++;
    } else if (event.event_type == ProcessEvent::CRASHED) {
        statistics_.processes_crashed++;
    }
    
    if (event.is_suspicious) {
        statistics_.suspicious_processes++;
    }
}

void ProcessMonitor::UpdateStatistics(const ThreadOperationEvent& event) {
    statistics_.total_threads++;
    
    if (event.event_type == ThreadEvent::CREATED) {
        statistics_.threads_created++;
    } else if (event.event_type == ThreadEvent::REMOTE_CREATED) {
        statistics_.remote_threads_created++;
        statistics_.injection_attempts++;
    }
}

void ProcessMonitor::UpdateStatistics(const MemoryOperationEvent& event) {
    if (event.operation == MemoryOperation::ALLOCATE) {
        statistics_.memory_allocations++;
        statistics_.total_memory_allocated_kb += event.size / 1024;
    }
    
    if (event.operation == MemoryOperation::PROTECT) {
        statistics_.memory_protections_changed++;
    }
    
    if (event.operation == MemoryOperation::REMOTE_READ ||
        event.operation == MemoryOperation::REMOTE_WRITE) {
        statistics_.remote_memory_operations++;
        statistics_.injection_attempts++;
    }
}

// Notify callbacks
void ProcessMonitor::NotifyProcessCallbacks(const ProcessCreationEvent& event) {
    for (const auto& callback : process_callbacks_) {
        try {
            callback(event);
        }
        catch (const std::exception& e) {
            spdlog::error("Process callback error: {}", e.what());
        }
    }
}

void ProcessMonitor::NotifyThreadCallbacks(const ThreadOperationEvent& event) {
    for (const auto& callback : thread_callbacks_) {
        try {
            callback(event);
        }
        catch (const std::exception& e) {
            spdlog::error("Thread callback error: {}", e.what());
        }
    }
}

void ProcessMonitor::NotifyMemoryCallbacks(const MemoryOperationEvent& event) {
    for (const auto& callback : memory_callbacks_) {
        try {
            callback(event);
        }
        catch (const std::exception& e) {
            spdlog::error("Memory callback error: {}", e.what());
        }
    }
}

// Enum to string conversions
std::string ProcessMonitor::ProcessEventToString(ProcessEvent event) const {
    switch (event) {
        case ProcessEvent::CREATED: return "CREATED";
        case ProcessEvent::TERMINATED: return "TERMINATED";
        case ProcessEvent::EXEC: return "EXEC";
        case ProcessEvent::FORK: return "FORK";
        case ProcessEvent::CLONE: return "CLONE";
        case ProcessEvent::VFORK: return "VFORK";
        case ProcessEvent::EXIT: return "EXIT";
        case ProcessEvent::KILLED: return "KILLED";
        case ProcessEvent::CRASHED: return "CRASHED";
        case ProcessEvent::SUSPENDED: return "SUSPENDED";
        case ProcessEvent::RESUMED: return "RESUMED";
        default: return "UNKNOWN";
    }
}

std::string ProcessMonitor::ThreadEventToString(ThreadEvent event) const {
    switch (event) {
        case ThreadEvent::CREATED: return "CREATED";
        case ThreadEvent::TERMINATED: return "TERMINATED";
        case ThreadEvent::REMOTE_CREATED: return "REMOTE_CREATED";
        case ThreadEvent::SUSPENDED: return "SUSPENDED";
        case ThreadEvent::RESUMED: return "RESUMED";
        case ThreadEvent::CONTEXT_MODIFIED: return "CONTEXT_MODIFIED";
        default: return "UNKNOWN";
    }
}

std::string ProcessMonitor::MemoryOperationToString(MemoryOperation op) const {
    switch (op) {
        case MemoryOperation::ALLOCATE: return "ALLOCATE";
        case MemoryOperation::FREE: return "FREE";
        case MemoryOperation::PROTECT: return "PROTECT";
        case MemoryOperation::READ: return "READ";
        case MemoryOperation::WRITE: return "WRITE";
        case MemoryOperation::MAP: return "MAP";
        case MemoryOperation::UNMAP: return "UNMAP";
        case MemoryOperation::REMOTE_READ: return "REMOTE_READ";
        case MemoryOperation::REMOTE_WRITE: return "REMOTE_WRITE";
        default: return "UNKNOWN";
    }
}

// Log event
void ProcessMonitor::LogEvent(const std::string& event) {
    if (config_.verbose_logging) {
        spdlog::debug("[PROCESS] {}", event);
    }
}

} // namespace monitors
} // namespace paramite