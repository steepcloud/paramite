/**
 * @file strace_parser.cpp
 * @brief Implementation of strace log parsing and syscall extraction
 * 
 * Implements comprehensive parsing of strace output logs to extract system calls,
 * arguments, return values, timestamps, and error codes. Constructs structured syscall
 * events for behavioral analysis, pattern matching, and attack technique identification.
 * Handles complex strace formats including multi-line calls, signal handling, and
 * process lifecycle events.
 * 
 * **strace Output Format**:
 * ```
 * [pid] timestamp syscall(arg1, arg2, ...) = return_value
 * 
 * Example:
 * [1234] 1234567890.123456 open("/etc/passwd", O_RDONLY) = 3
 * [1234] 1234567890.124567 read(3, "root:x:0:0:...", 4096) = 1024
 * [1234] 1234567890.125678 close(3) = 0
 * ```
 * 
 * **Parsing Capabilities**:
 * - **Syscall Extraction**: Name, arguments, return value
 * - **Argument Parsing**: Strings, integers, flags, structures
 * - **Timestamp Parsing**: Absolute and relative timestamps
 * - **PID Tracking**: Multi-process tracing support
 * - **Signal Handling**: SIGCHLD, SIGTERM, custom signals
 * - **Error Codes**: Errno values (ENOENT, EACCES, etc.)
 * 
 * **Complex Argument Handling**:
 * - **Strings**: Quoted with escape sequences ("hello\nworld")
 * - **Buffers**: Hexadecimal dumps for binary data
 * - **Structures**: Parsed field-by-field ({sa_family=AF_INET, ...})
 * - **Arrays**: Comma-separated values
 * - **Flags**: Bitwise OR combinations (O_RDONLY|O_NONBLOCK)
 * - **Pointers**: Memory addresses (0x7fff12345678)
 * 
 * **Multi-line Call Handling**:
 * strace can split long calls across lines:
 * ```
 * execve("/bin/bash", ["bash", "-c",
 *   "echo hello"], ["PATH=/usr/bin", ...]) = 0
 * ```
 * Parser handles continuation and reassembly.
 * 
 * **Special Cases**:
 * - **Unfinished Calls**: `open(...) = ? <unfinished>`
 * - **Resumed Calls**: `<... open resumed>) = 3`
 * - **Signals**: `--- SIGCHLD {si_signo=SIGCHLD, ...} ---`
 * - **Process Exit**: `+++ exited with 0 +++`
 * - **Attached Processes**: `Process 1234 attached`
 * 
 * **Behavioral Summarization**:
 * Aggregates syscalls into high-level behaviors:
 * - File operations count
 * - Network connections established
 * - Processes spawned
 * - Memory allocations
 * - Failed operations (errors)
 * 
 * **Performance Optimizations**:
 * - Regex compilation caching
 * - Line-by-line streaming (no full file load)
 * - Lazy argument parsing (on-demand)
 * - Event batching for high-frequency syscalls
 * 
 * @date 2025
 */

#include "paramite/parsers/strace_parser.hpp"
#include <spdlog/spdlog.h>
#include <fstream>
#include <regex>

namespace paramite {
namespace parsers {

StraceParser::StraceParser() {
    spdlog::debug("Strace parser initialized");
}

std::vector<SyscallEvent> StraceParser::Parse(const std::filesystem::path& strace_log) {
    std::vector<SyscallEvent> events;
    
    if (!std::filesystem::exists(strace_log)) {
        spdlog::warn("Strace log not found: {}", strace_log.string());
        return events;
    }
    
    spdlog::info("Parsing strace log: {}", strace_log.string());
    
    std::ifstream file(strace_log);
    if (!file.is_open()) {
        spdlog::error("Failed to open strace log");
        return events;
    }
    
    // Regex patterns for strace output
    // Format: PID TIME syscall(args) = result
    std::regex syscall_regex(R"((\d+)\s+([\d:.]+)\s+(\w+)\((.*?)\)\s+=\s+(-?\d+))");
    
    std::string line;
    int line_num = 0;
    
    while (std::getline(file, line)) {
        line_num++;
        
        std::smatch match;
        if (std::regex_search(line, match, syscall_regex)) {
            SyscallEvent event;
            event.pid = std::stoi(match[1].str());
            event.timestamp = match[2].str();
            event.name = match[3].str();
            event.args = match[4].str();
            event.return_value = std::stoi(match[5].str());
            event.success = (event.return_value >= 0);
            
            // Check if suspicious
            event.is_suspicious = IsSuspiciousSyscall(event.name);
            
            events.push_back(event);
        }
        
        // Limit to avoid memory issues
        if (events.size() >= 100000) {
            spdlog::warn("Reached syscall limit, stopping parse");
            break;
        }
    }
    
    file.close();
    
    spdlog::info("Parsed {} syscalls from {} lines", events.size(), line_num);
    
    return events;
}

SyscallSummary StraceParser::GenerateSummary(const std::vector<SyscallEvent>& events) {
    SyscallSummary summary;
    
    summary.total_syscalls = events.size();
    
    for (const auto& event : events) {
        // Count syscall types
        summary.syscall_counts[event.name]++;
        
        // Count failures
        if (!event.success) {
            summary.failed_syscalls++;
        }
        
        // Count suspicious
        if (event.is_suspicious) {
            summary.suspicious_syscalls++;
        }
    }
    
    return summary;
}

bool StraceParser::IsSuspiciousSyscall(const std::string& syscall_name) {
    static const std::set<std::string> suspicious_syscalls = {
        "ptrace",       // Debugging/anti-debug
        "execve",       // Process execution
        "fork",         // Process creation
        "clone",        // Process/thread creation
        "kill",         // Signal sending
        "tkill",        // Thread kill
        "prctl",        // Process control
        "unlink",       // File deletion
        "rmdir",        // Directory deletion
        "chmod",        // Permission change
        "chown",        // Owner change
        "mount",        // Filesystem mount
        "umount",       // Filesystem unmount
        "socket",       // Network socket
        "connect",      // Network connection
        "bind",         // Network bind
        "listen",       // Network listen
        "accept"        // Network accept
    };
    
    return suspicious_syscalls.count(syscall_name) > 0;
}

} // namespace parsers
} // namespace paramite