/**
 * @file strace_parser.hpp
 * @brief Parser for strace system call trace logs
 * 
 * Provides parsing and analysis capabilities for strace output, extracting
 * system calls, arguments, return values, and generating behavioral summaries.
 * Used by SyscallMonitor for detailed syscall analysis.
 * 
 * @date 2025
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <set>
#include <filesystem>

namespace paramite {
namespace parsers {

/**
 * @struct SyscallEvent
 * @brief Represents a single system call event from strace output
 */
struct SyscallEvent {
    int pid;                    ///< Process ID
    std::string timestamp;      ///< Timestamp of syscall
    std::string name;           ///< Syscall name (e.g., "open", "read")
    std::string args;           ///< Raw arguments string
    int return_value;           ///< Return value
    bool success;               ///< Whether syscall succeeded
    bool is_suspicious;         ///< Flagged as suspicious
};

/**
 * @struct SyscallSummary
 * @brief Aggregate summary of system call events
 */
struct SyscallSummary {
    int total_syscalls{0};      ///< Total syscalls observed
    int failed_syscalls{0};     ///< Failed syscalls
    int suspicious_syscalls{0}; ///< Suspicious syscalls
    std::map<std::string, int> syscall_counts;  ///< Count by syscall name
};

/**
 * @class StraceParser
 * @brief Parser for strace log files
 * 
 * Parses strace output format and extracts system call events with
 * timing, arguments, and return values.
 * 
 * **Usage Example**:
 * @code
 * StraceParser parser;
 * auto events = parser.Parse("/tmp/strace.log");
 * auto summary = parser.GenerateSummary(events);
 * 
 * std::cout << "Total syscalls: " << summary.total_syscalls << std::endl;
 * std::cout << "Suspicious: " << summary.suspicious_syscalls << std::endl;
 * @endcode
 */
class StraceParser {
public:
    StraceParser();
    
    /**
     * @brief Parse strace log file
     * @param strace_log Path to strace output file
     * @return Vector of parsed syscall events
     */
    std::vector<SyscallEvent> Parse(const std::filesystem::path& strace_log);
    
    /**
     * @brief Generate summary from syscall events
     * @param events Vector of syscall events
     * @return Aggregate summary
     */
    SyscallSummary GenerateSummary(const std::vector<SyscallEvent>& events);
    
private:
    /**
     * @brief Check if syscall is potentially suspicious
     * @param syscall_name Syscall name
     * @return true if suspicious
     */
    bool IsSuspiciousSyscall(const std::string& syscall_name);
};

} // namespace parsers
} // namespace paramite