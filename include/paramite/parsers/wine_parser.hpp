/**
 * @file wine_parser.hpp
 * @brief Parser for Wine debug logs (Windows PE execution on Linux)
 * 
 * Provides parsing and analysis capabilities for Wine debug output when executing
 * Windows PE malware on Linux. Extracts process creation, module loading, and
 * builds hierarchical process trees.
 * 
 * @date 2025
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <filesystem>

namespace paramite {
namespace parsers {

/**
 * @enum ProcessEventType
 * @brief Types of process events in Wine logs
 */
enum class ProcessEventType {
    CREATE,         ///< Process creation
    EXIT,           ///< Process termination
    THREAD_CREATE,  ///< Thread creation
    MODULE_LOAD     ///< DLL/module loading
};

/**
 * @struct ProcessEvent
 * @brief Represents a process event from Wine logs
 */
struct ProcessEvent {
    int pid;                    ///< Process ID
    int parent_pid{0};          ///< Parent process ID
    ProcessEventType type;      ///< Event type
    std::string process_name;   ///< Process name
    std::string command_line;   ///< Command line
    int timestamp{0};           ///< Relative timestamp (line number)
};

/**
 * @struct ProcessNode
 * @brief Node in hierarchical process tree
 */
struct ProcessNode {
    int pid;                       ///< Process ID
    int parent_pid;                ///< Parent PID
    std::string name;              ///< Process name
    std::string path;              ///< Full path
    std::vector<int> children;     ///< Child PIDs
};

/**
 * @struct ProcessTree
 * @brief Hierarchical process execution tree
 */
struct ProcessTree {
    int root_pid{0};                      ///< Root process PID
    std::vector<ProcessNode> processes;   ///< All processes in tree
};

/**
 * @struct ProcessSummary
 * @brief Summary of process events
 */
struct ProcessSummary {
    int total_processes{0};      ///< Total processes observed
    int processes_created{0};    ///< Processes created
    int processes_exited{0};     ///< Processes exited
    int threads_created{0};      ///< Threads created
};

/**
 * @class WineParser
 * @brief Parser for Wine debug output logs
 * 
 * Parses Wine debug logs generated during Windows PE malware execution
 * to extract process events, build execution trees, and generate summaries.
 * 
 * **Usage Example**:
 * @code
 * WineParser parser;
 * auto events = parser.Parse("/tmp/wine_debug.log");
 * auto tree = parser.BuildProcessTree(events);
 * auto summary = parser.GenerateSummary(events);
 * 
 * std::cout << "Processes created: " << summary.processes_created << std::endl;
 * std::cout << "Root PID: " << tree.root_pid << std::endl;
 * @endcode
 */
class WineParser {
public:
    WineParser();
    
    /**
     * @brief Parse Wine debug log file
     * @param wine_log Path to Wine log file
     * @return Vector of process events
     */
    std::vector<ProcessEvent> Parse(const std::filesystem::path& wine_log);
    
    /**
     * @brief Build hierarchical process tree from events
     * @param events Vector of process events
     * @return ProcessTree structure
     */
    ProcessTree BuildProcessTree(const std::vector<ProcessEvent>& events);
    
    /**
     * @brief Generate summary of process events
     * @param events Vector of process events
     * @return ProcessSummary structure
     */
    ProcessSummary GenerateSummary(const std::vector<ProcessEvent>& events);
};

} // namespace parsers
} // namespace paramite