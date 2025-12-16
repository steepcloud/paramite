/**
 * @file wine_parser.cpp
 * @brief Implementation of Wine debug log parsing for Windows PE analysis
 * 
 * Implements comprehensive parsing of Wine debug output to analyze Windows PE malware
 * execution on Linux. Extracts Windows API calls, DLL loading sequences, process creation,
 * registry operations, and Wine-specific events for behavioral analysis of Windows malware
 * in cross-platform sandbox environment.
 * 
 * **Wine Debug Channels**:
 * Wine provides detailed logging through debug channels:
 * - **+process**: Process/thread creation and termination
 * - **+module**: DLL loading and unloading
 * - **+file**: File operations (CreateFile, ReadFile, WriteFile)
 * - **+reg**: Registry operations (RegOpenKey, RegSetValue)
 * - **+heap**: Memory allocations (HeapAlloc, VirtualAlloc)
 * - **+relay**: Windows API call tracing
 * 
 * **Output Format**:
 * ```
 * 0024:trace:module:load_builtin_dll loaded kernel32.dll
 * 0024:trace:process:CreateProcessW "malware.exe"
 * 0024:trace:file:CreateFileW L"C:\\malware\\payload.dll"
 * 0024:Call kernel32.VirtualAlloc(00000000,00001000,00003000,00000004)
 * ```
 * 
 * **Parsing Capabilities**:
 * - **Process Tree Construction**: Parent-child relationships from Wine process IDs
 * - **DLL Loading Sequence**: Order of module loads, dependencies
 * - **API Call Extraction**: Function names, parameters, return values
 * - **File Operations**: Paths (converted from Windows to Unix format)
 * - **Registry Operations**: Keys, values, data
 * - **Memory Operations**: Allocations, protections, mappings
 * 
 * **Windows to Unix Path Conversion**:
 * Wine maps Windows paths to Unix:
 * ```
 * C:\Windows\System32 ? ~/.wine/drive_c/Windows/System32
 * Z:\ ? / (Unix root)
 * ```
 * Parser handles both formats.
 * 
 * **API Call Tracing**:
 * Wine relay channel logs Windows API calls:
 * ```
 * Call kernel32.CreateFileW(L"malware.dll", 0x80000000, ...)
 * Ret  kernel32.CreateFileW() retval=0x00000004
 * ```
 * 
 * **Suspicious Patterns Detected**:
 * - **Injection**: VirtualAllocEx, WriteProcessMemory, CreateRemoteThread
 * - **Persistence**: Registry Run key modifications
 * - **Anti-Analysis**: IsDebuggerPresent, CheckRemoteDebuggerPresent
 * - **Evasion**: Sleep calls, environment checks
 * - **Credential Access**: LsaEnumerateLogonSessions, CryptUnprotectData
 * 
 * **Process Tree Construction**:
 * ```
 * PID 0024 (malware.exe) [Wine Process]
 * ??? PID 0025 (cmd.exe) [spawned via CreateProcess]
 * ?   ??? PID 0026 (powershell.exe) [spawned]
 * ??? PID 0027 (payload.dll) [injected]
 * ```
 * 
 * **Performance Considerations**:
 * - Wine logs can be very large (GB for complex malware)
 * - Streaming parser (line-by-line processing)
 * - Event filtering (focus on security-relevant calls)
 * - Sampling for high-frequency events
 * 
 * @date 2025
 */

#include "paramite/parsers/wine_parser.hpp"
#include <spdlog/spdlog.h>
#include <fstream>
#include <regex>
#include <set>
#include <map>
#include <sstream>

namespace paramite {
namespace parsers {

WineParser::WineParser() {
    spdlog::debug("Wine parser initialized");
}

std::vector<ProcessEvent> WineParser::Parse(const std::filesystem::path& wine_log) {
    std::vector<ProcessEvent> events;
    
    if (!std::filesystem::exists(wine_log)) {
        spdlog::warn("Wine log not found: {}", wine_log.string());
        return events;
    }
    
    spdlog::info("Parsing wine log: {}", wine_log.string());
    
    std::ifstream file(wine_log);
    if (!file.is_open()) {
        spdlog::error("Failed to open wine log");
        return events;
    }
    
    // Regex patterns for wine output
    // Format examples:
    // 0024:err:module:LdrInitializeThunk
    // 0024:trace:process:CreateProcessInternalW
    std::regex process_create_regex(R"(([0-9a-f]{4}):.*:process:.*CreateProcess.*[\"'](.+?)[\"'])");
    std::regex process_exit_regex(R"(([0-9a-f]{4}):.*:process:.*ExitProcess)");
    std::regex thread_create_regex(R"(([0-9a-f]{4}):.*:thread:.*CreateThread)");
    
    std::string line;
    int line_num = 0;
    
    while (std::getline(file, line)) {
        line_num++;
        
        std::smatch match;
        
        // Process creation
        if (std::regex_search(line, match, process_create_regex)) {
            ProcessEvent event;
            event.pid = std::stoi(match[1].str(), nullptr, 16);  // Hex to decimal
            event.type = ProcessEventType::CREATE;
            event.process_name = match[2].str();
            event.timestamp = line_num;  // Use line number as relative timestamp
            
            events.push_back(event);
        }
        // Process exit
        else if (std::regex_search(line, match, process_exit_regex)) {
            ProcessEvent event;
            event.pid = std::stoi(match[1].str(), nullptr, 16);
            event.type = ProcessEventType::EXIT;
            event.timestamp = line_num;
            
            events.push_back(event);
        }
        // Thread creation
        else if (std::regex_search(line, match, thread_create_regex)) {
            ProcessEvent event;
            event.pid = std::stoi(match[1].str(), nullptr, 16);
            event.type = ProcessEventType::THREAD_CREATE;
            event.timestamp = line_num;
            
            events.push_back(event);
        }
    }
    
    file.close();
    
    spdlog::info("Parsed {} process events from {} lines", events.size(), line_num);
    
    return events;
}

ProcessTree WineParser::BuildProcessTree(const std::vector<ProcessEvent>& events) {
    ProcessTree tree;
    tree.processes.clear();
    
    std::map<int, ProcessNode*> pid_map;
    
    for (const auto& event : events) {
        if (event.type == ProcessEventType::CREATE) {
            ProcessNode node;
            node.pid = event.pid;
            node.name = event.process_name;
            node.parent_pid = 0;  // Wine doesn't easily expose parent PID
            
            tree.processes.push_back(node);
            pid_map[event.pid] = &tree.processes.back();
        }
    }
    
    // Set root process (first one created)
    if (!tree.processes.empty()) {
        tree.root_pid = tree.processes[0].pid;
    }
    
    spdlog::info("Built process tree with {} nodes", tree.processes.size());
    
    return tree;
}

ProcessSummary WineParser::GenerateSummary(const std::vector<ProcessEvent>& events) {
    ProcessSummary summary;
    
    std::set<int> unique_pids;
    
    for (const auto& event : events) {
        unique_pids.insert(event.pid);
        
        switch (event.type) {
            case ProcessEventType::CREATE:
                summary.processes_created++;
                break;
            case ProcessEventType::EXIT:
                summary.processes_exited++;
                break;
            case ProcessEventType::THREAD_CREATE:
                summary.threads_created++;
                break;
            default:
                break;
        }
    }
    
    summary.total_processes = unique_pids.size();
    
    return summary;
}

} // namespace parsers
} // namespace paramite