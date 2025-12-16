/**
 * @file behavior_analyzer.hpp
 * @brief Behavioral analysis engine for detecting malicious patterns in malware execution
 * 
 * This module provides comprehensive behavioral analysis capabilities by parsing
 * system monitoring data (strace, tcpdump, filesystem events) and correlating
 * them against known malicious behavior patterns. It supports MITRE ATT&CK framework
 * mapping and automated threat scoring.
 * 
 * @date 2025
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <set>
#include <memory>
#include <chrono>
#include <optional>

namespace paramite {
namespace analyzers {

/**
 * @enum EventType
 * @brief Categories of behavioral events that can be observed during dynamic analysis
 * 
 * These event types represent the various system-level activities that malware
 * might perform during execution. Each type corresponds to specific monitoring
 * data sources (syscalls, network traffic, file system events).
 */
enum class EventType {
    PROCESS_CREATED,           ///< New process spawned (fork, execve)
    PROCESS_TERMINATED,        ///< Process exit or kill
    FILE_CREATED,             ///< File creation or write operation
    FILE_MODIFIED,            ///< Existing file modification
    FILE_DELETED,             ///< File removal operation
    NETWORK_CONNECTION,       ///< TCP/UDP connection establishment
    NETWORK_DNS_QUERY,        ///< DNS resolution request
    REGISTRY_MODIFIED,        ///< Configuration file modification (Linux equivalent to Windows registry)
    SERVICE_CREATED,          ///< Systemd service installation
    SCHEDULED_TASK,           ///< Cron job creation
    PRIVILEGE_ESCALATION,     ///< Attempt to elevate privileges (setuid, sudo)
    CODE_INJECTION,           ///< Process memory manipulation
    ANTI_DEBUG,               ///< Anti-debugging technique detected
    PERSISTENCE_MECHANISM,    ///< Persistence installation (autostart, services)
    DATA_EXFILTRATION,        ///< Large outbound data transfer
    UNKNOWN                   ///< Unclassified event
};

/**
 * @enum ThreatLevel
 * @brief Severity classification for detected threats
 * 
 * Uses Oddworld-themed names for threat levels, ranging from safe
 * to critical. These levels are determined by aggregating individual
 * event severity scores and pattern match confidence.
 */
enum class ThreatLevel {
    SAFE,           ///< No suspicious behavior detected
    LOW,            ///< Minor anomalies, likely benign
    MEDIUM,         ///< Suspicious behavior requiring attention
    HIGH,           ///< Clearly malicious activity detected
    CRITICAL        ///< Immediate threat with severe impact
};

/**
 * @enum MitreTactic
 * @brief MITRE ATT&CK framework tactics
 * 
 * Maps detected behaviors to adversarial tactics as defined in the
 * MITRE ATT&CK framework for enterprise systems.
 * 
 * @see https://attack.mitre.org/tactics/enterprise/
 */
enum class MitreTactic {
    INITIAL_ACCESS,          ///< Initial entry into target system
    EXECUTION,               ///< Code execution techniques
    PERSISTENCE,             ///< Maintaining foothold on system
    PRIVILEGE_ESCALATION,    ///< Obtaining higher-level permissions
    DEFENSE_EVASION,         ///< Avoiding detection mechanisms
    CREDENTIAL_ACCESS,       ///< Stealing account credentials
    DISCOVERY,               ///< Environment and network reconnaissance
    LATERAL_MOVEMENT,        ///< Moving through the network
    COLLECTION,              ///< Gathering data of interest
    COMMAND_AND_CONTROL,     ///< Communicating with C2 infrastructure
    EXFILTRATION,           ///< Stealing data from network
    IMPACT                  ///< Manipulating, interrupting, or destroying systems/data
};

/**
 * @struct BehaviorEvent
 * @brief Represents a single behavioral observation from monitoring data
 * 
 * Each event corresponds to a specific action performed by the analyzed
 * malware sample, such as a system call, network connection, or file operation.
 * Events include contextual information and severity scoring for threat assessment.
 */
struct BehaviorEvent {
    EventType type;                                      ///< Category of the event
    std::chrono::system_clock::time_point timestamp;    ///< When the event occurred
    std::string process_name;                           ///< Name of the process that generated the event
    int process_id;                                     ///< PID of the generating process
    std::string details;                                ///< Human-readable event description
    std::map<std::string, std::string> attributes;      ///< Additional structured metadata (syscall args, IPs, etc.)
    
    int severity_score{0};                              ///< Threat score 0-100, higher = more suspicious
    std::vector<std::string> tags;                      ///< Categorization tags (e.g., "persistence", "network")
};

/**
 * @struct BehaviorPattern
 * @brief Definition of a malicious behavior pattern used for threat detection
 * 
 * Patterns define specific behavioral signatures that indicate malicious activity.
 * Each pattern includes indicators (keywords, regex patterns) to match against events,
 * MITRE ATT&CK mapping, and base severity scoring.
 * 
 * Example patterns: process injection, persistence mechanisms, credential theft
 */
struct BehaviorPattern {
    std::string pattern_id;                    ///< Unique pattern identifier (e.g., "P001")
    std::string name;                          ///< Human-readable pattern name
    std::string description;                   ///< Detailed description of the malicious behavior
    EventType event_type;                      ///< Primary event type this pattern matches
    std::vector<std::string> indicators;       ///< Keywords or regex patterns to match
    int base_severity{50};                     ///< Base severity score (0-100)
    MitreTactic tactic;                        ///< Associated MITRE ATT&CK tactic
    std::string technique_id;                  ///< MITRE technique ID (e.g., "T1055" for Process Injection)
    std::vector<std::string> references;       ///< External references (URLs, research papers)
};

/**
 * @struct PatternMatch
 * @brief Result of matching a behavior pattern against observed events
 * 
 * When a pattern successfully matches one or more events, this structure
 * contains the matched pattern, all matching events, confidence scoring,
 * and extracted indicators of compromise (IOCs).
 */
struct PatternMatch {
    BehaviorPattern pattern;                    ///< The matched pattern definition
    std::vector<BehaviorEvent> matching_events; ///< All events that matched this pattern
    int confidence_score{0};                    ///< Match confidence 0-100, based on event count and quality
    std::string evidence;                       ///< Summary of evidence supporting the match
    std::vector<std::string> iocs;             ///< Extracted indicators (IPs, domains, file paths)
};

/**
 * @struct BehaviorAnalysisReport
 * @brief Comprehensive report of behavioral analysis results
 * 
 * Contains all findings from behavioral analysis including detected events,
 * pattern matches, threat scoring, MITRE ATT&CK mapping, extracted IOCs,
 * timeline information, and actionable recommendations.
 * 
 * This is the primary output of the BehaviorAnalyzer component.
 */
struct BehaviorAnalysisReport {
    // Overall Assessment
    ThreatLevel overall_threat_level;          ///< Aggregate threat classification
    int total_events{0};                       ///< Total number of events observed
    int suspicious_events{0};                  ///< Count of events exceeding severity threshold
    int threat_score{0};                       ///< Aggregate threat score (0-1000)
    
    // Event Data
    std::vector<BehaviorEvent> all_events;              ///< Complete event log
    std::vector<BehaviorEvent> suspicious_events_list;  ///< Filtered list of high-severity events
    
    // Pattern Matching Results
    std::vector<PatternMatch> matched_patterns;         ///< All successfully matched patterns
    
    // MITRE ATT&CK Framework Mapping
    std::map<MitreTactic, std::vector<std::string>> mitre_techniques;  ///< Tactics ? Technique IDs
    
    // Indicators of Compromise
    std::set<std::string> network_iocs;        ///< IP addresses and domains contacted
    std::set<std::string> file_iocs;           ///< Suspicious file paths
    std::set<std::string> process_iocs;        ///< Process names and commands
    std::set<std::string> registry_iocs;       ///< Modified configuration keys
    
    // Timeline Information
    std::chrono::system_clock::time_point analysis_start;  ///< Analysis start timestamp
    std::chrono::system_clock::time_point analysis_end;    ///< Analysis completion timestamp
    std::chrono::milliseconds duration{0};                 ///< Total analysis duration
    
    // Actionable Intelligence
    std::vector<std::string> recommendations;  ///< Security recommendations based on findings
    std::string executive_summary;             ///< High-level summary for non-technical stakeholders
};

/**
 * @class BehaviorAnalyzer
 * @brief Core behavioral analysis engine for malware behavior detection and classification
 * 
 * The BehaviorAnalyzer interprets raw monitoring data from various sources (system call traces,
 * network captures, file system events) and identifies malicious behavior patterns. It provides:
 * 
 * - Multi-source event parsing (strace, tcpdump, inotify)
 * - Pattern matching against behavior signatures
 * - Automated threat scoring and classification
 * - MITRE ATT&CK framework mapping
 * - IOC extraction for threat intelligence
 * - Comprehensive reporting with recommendations
 * 
 * **Thread Safety**: This class is NOT thread-safe. Create separate instances for concurrent analyses.
 * 
 * **Usage Example**:
 * @code
 * BehaviorAnalyzer::Config config;
 * config.min_severity_threshold = 50;
 * config.enable_mitre_mapping = true;
 * 
 * BehaviorAnalyzer analyzer(config);
 * 
 * auto report = analyzer.AnalyzeBehavior(
 *     "/tmp/strace.log",
 *     "/tmp/capture.pcap",
 *     file_changes
 * );
 * 
 * std::cout << "Threat Level: " << analyzer.ThreatLevelToString(report.overall_threat_level) << std::endl;
 * std::cout << "Matched Patterns: " << report.matched_patterns.size() << std::endl;
 * @endcode
 */
class BehaviorAnalyzer {
public:
    /**
     * @struct Config
     * @brief Configuration parameters for behavioral analysis
     */
    struct Config {
        int min_severity_threshold{30};        ///< Minimum severity (0-100) for event to be flagged
        int max_events_to_track{10000};        ///< Maximum events to store (prevents memory exhaustion)
        bool enable_mitre_mapping{true};       ///< Enable MITRE ATT&CK framework mapping
        bool enable_ioc_extraction{true};      ///< Enable IOC extraction from events
        bool verbose_logging{false};           ///< Enable detailed debug logging
        
        // Threat Scoring Weights (multipliers for specific threat categories)
        int process_injection_weight{200};     ///< Weight for process injection behaviors
        int persistence_weight{150};           ///< Weight for persistence mechanisms
        int network_exfil_weight{100};         ///< Weight for data exfiltration
        int file_encryption_weight{250};       ///< Weight for ransomware indicators
        int privilege_escalation_weight{180};  ///< Weight for privilege escalation
    };

    /**
     * @brief Construct analyzer with custom configuration
     * @param config Configuration parameters
     */
    explicit BehaviorAnalyzer(const Config& config);
    
    /**
     * @brief Construct analyzer with default configuration
     */
    explicit BehaviorAnalyzer();
    
    ~BehaviorAnalyzer() = default;

    // Prevent copying to avoid unintended state sharing
    BehaviorAnalyzer(const BehaviorAnalyzer&) = delete;
    BehaviorAnalyzer& operator=(const BehaviorAnalyzer&) = delete;

    /**
     * @brief Perform comprehensive behavioral analysis on monitoring data
     * 
     * Orchestrates the complete analysis pipeline:
     * 1. Parse monitoring logs into structured events
     * 2. Match events against malicious behavior patterns
     * 3. Calculate threat scores and classifications
     * 4. Map to MITRE ATT&CK framework
     * 5. Extract indicators of compromise
     * 6. Generate executive summary and recommendations
     * 
     * @param strace_log Path to strace system call trace output
     * @param tcpdump_log Path to tcpdump PCAP network capture
     * @param file_changes Vector of file system change notifications
     * @return Complete behavioral analysis report
     * 
     * @throws std::runtime_error if critical parsing errors occur
     * 
     * @note This method may take significant time for large log files
     * 
     * **Example**:
     * @code
     * std::vector<std::string> fs_changes = { "CREATE /tmp/malware.sh", "MODIFY /etc/crontab" };
     * auto report = analyzer.AnalyzeBehavior("/var/log/strace.out", "/tmp/traffic.pcap", fs_changes);
     * @endcode
     */
    BehaviorAnalysisReport AnalyzeBehavior(
        const std::string& strace_log,
        const std::string& tcpdump_log,
        const std::vector<std::string>& file_changes
    );

    /**
     * @brief Parse strace system call trace into behavioral events
     * 
     * Extracts system call information from strace output and classifies
     * them into behavioral events (process creation, file access, network activity).
     * Automatically assigns severity scores based on syscall type and arguments.
     * 
     * @param strace_log Path to strace output file
     * @return Vector of parsed behavioral events
     * 
     * **Supported syscalls**: execve, fork, clone, open, openat, connect, sendto,
     * ptrace, setuid, setgid, and more
     * 
     * **Example strace format**:
     * @code
     * 12345 execve("/bin/bash", [...], [...]) = 0
     * 12345 open("/etc/passwd", O_RDONLY) = 3
     * @endcode
     */
    std::vector<BehaviorEvent> ParseStraceLog(const std::string& strace_log);

    /**
     * @brief Parse network packet capture into network behavioral events
     * 
     * Analyzes tcpdump PCAP files to extract network connections and DNS queries.
     * Identifies suspicious domains, ports, and connection patterns.
     * 
     * @param tcpdump_log Path to PCAP file or tcpdump text output
     * @return Vector of network-related behavioral events
     * 
     * **Detection capabilities**:
     * - Suspicious TLDs (.onion, .tk)
     * - Common C2 ports (4444, 31337, 6667)
     * - Pastebin and file-sharing services
     * - Unusual DNS query patterns
     */
    std::vector<BehaviorEvent> ParseNetworkLog(const std::string& tcpdump_log);

    /**
     * @brief Parse file system change notifications into file operation events
     * 
     * Processes inotify-style file change notifications and classifies them
     * into file operation events. Detects suspicious file locations and
     * persistence mechanisms.
     * 
     * @param file_changes Vector of file change strings (e.g., "CREATE /tmp/malware.sh")
     * @return Vector of file operation behavioral events
     * 
     * **Suspicious patterns detected**:
     * - Modifications to /etc/cron*, systemd services
     * - Changes to ~/.bashrc, ~/.ssh/authorized_keys
     * - Ransomware file extensions (.encrypted, .locked)
     * - README.txt creation (ransom notes)
     */
    std::vector<BehaviorEvent> ParseFileChanges(const std::vector<std::string>& file_changes);

    /**
     * @brief Match observed events against known malicious behavior patterns
     * 
     * Iterates through all loaded patterns and checks each event for matches.
     * Calculates confidence scores based on number of matches and event severity.
     * 
     * @param events Vector of behavioral events to analyze
     * @return Vector of successful pattern matches with evidence
     * 
     * @note Confidence score calculation considers both quantity and quality of matches
     */
    std::vector<PatternMatch> MatchPatterns(const std::vector<BehaviorEvent>& events);

    /**
     * @brief Calculate aggregate threat score from pattern matches
     * 
     * Computes weighted threat score (0-1000) based on:
     * - Pattern base severity
     * - Match confidence
     * - MITRE tactic-specific weights
     * - Number of distinct patterns matched
     * 
     * @param matches Vector of pattern matches
     * @return Threat score (0-1000), capped at 1000
     * 
     * **Scoring formula**: ? (pattern_severity � confidence � tactic_weight) / 100
     */
    int CalculateThreatScore(const std::vector<PatternMatch>& matches);

    /**
     * @brief Map pattern matches to MITRE ATT&CK framework
     * 
     * Organizes matched patterns by their associated MITRE ATT&CK tactics
     * and extracts technique IDs for threat intelligence reporting.
     * 
     * @param matches Vector of pattern matches
     * @return Map of tactics to technique ID vectors
     * 
     * **Example output**:
     * @code
     * {
     *   PERSISTENCE: ["T1053", "T1543"],
     *   DEFENSE_EVASION: ["T1055", "T1140"]
     * }
     * @endcode
     */
    std::map<MitreTactic, std::vector<std::string>> MapToMitreAttack(
        const std::vector<PatternMatch>& matches
    );

    /**
     * @brief Extract indicators of compromise (IOCs) from events
     * 
     * Extracts and categorizes IOCs into network, file, process, and registry indicators.
     * Filters out common benign indicators to reduce false positives.
     * 
     * @param events Vector of behavioral events
     * @param report Report structure to populate with IOCs
     * 
     * **Extracted IOC types**:
     * - Network: IP addresses, domains, URLs
     * - File: Suspicious file paths, created/modified files
     * - Process: Process names and command lines
     * - Registry: Modified configuration keys
     */
    void ExtractIOCs(const std::vector<BehaviorEvent>& events, BehaviorAnalysisReport& report);

    /**
     * @brief Generate executive summary of analysis findings
     * 
     * Creates human-readable summary suitable for non-technical stakeholders.
     * Includes threat level, key findings, MITRE mapping, and recommendations.
     * 
     * @param report Complete analysis report
     * @return Formatted executive summary string
     */
    std::string GenerateExecutiveSummary(const BehaviorAnalysisReport& report);

    /**
     * @brief Get currently loaded behavior patterns
     * @return Reference to pattern vector
     */
    const std::vector<BehaviorPattern>& GetPatterns() const { return patterns_; }

    /**
     * @brief Add custom behavior pattern for detection
     * 
     * Allows extending the analyzer with custom malware family signatures
     * or organization-specific behavioral indicators.
     * 
     * @param pattern Pattern definition to add
     * 
     * **Example**:
     * @code
     * BehaviorPattern custom;
     * custom.pattern_id = "CUSTOM001";
     * custom.name = "Custom Backdoor";
     * custom.indicators = {"custom_backdoor.sh", "/tmp/.hidden"};
     * custom.base_severity = 85;
     * analyzer.AddPattern(custom);
     * @endcode
     */
    void AddPattern(const BehaviorPattern& pattern);

    /**
     * @brief Load behavior patterns from JSON configuration file
     * 
     * Imports pattern definitions from external JSON file for easy updates
     * without recompilation. Useful for threat intelligence feed integration.
     * 
     * @param patterns_file Path to JSON patterns file
     * @return true if patterns loaded successfully, false on error
     * 
     * **JSON format**:
     * @code
     * {
     *   "patterns": [
     *     {
     *       "id": "P007",
     *       "name": "DLL Injection",
     *       "indicators": ["CreateRemoteThread", "WriteProcessMemory"],
     *       "severity": 90,
     *       "technique_id": "T1055.001"
     *     }
     *   ]
     * }
     * @endcode
     */
    bool LoadPatternsFromFile(const std::string& patterns_file);

private:
    Config config_;                            ///< Analyzer configuration
    std::vector<BehaviorPattern> patterns_;    ///< Loaded behavior patterns

    /**
     * @brief Initialize default malicious behavior pattern library
     * 
     * Loads built-in patterns covering common malware behaviors:
     * - Process injection
     * - Persistence mechanisms
     * - Credential theft
     * - Network exfiltration
     * - Privilege escalation
     * - Ransomware activity
     */
    void InitializeDefaultPatterns();

    /**
     * @brief Check if a single event matches a behavior pattern
     * 
     * @param event Event to check
     * @param pattern Pattern to match against
     * @return true if event matches pattern indicators
     */
    bool EventMatchesPattern(const BehaviorEvent& event, const BehaviorPattern& pattern) const;

    /**
     * @brief Calculate confidence score for a pattern match
     * 
     * Confidence is based on:
     * - Number of matching events (more = higher confidence)
     * - Average severity of matching events
     * - Event quality and context
     * 
     * @param events Matching events
     * @param pattern Matched pattern
     * @return Confidence score (0-100)
     */
    int CalculateConfidence(const std::vector<BehaviorEvent>& events, 
                           const BehaviorPattern& pattern) const;

    /**
     * @brief Convert numeric threat score to threat level enum
     * 
     * @param threat_score Numeric score (0-1000)
     * @return ThreatLevel enum value
     * 
     * **Thresholds**:
     * - 800+: CRITICAL
     * - 600-799: HIGH
     * - 400-599: MEDIUM
     * - 200-399: LOW
     * - 0-199: SAFE
     */
    ThreatLevel DetermineThreatLevel(int threat_score) const;

    /**
     * @brief Extract network IOCs (IPs, domains) from events
     * 
     * Uses regex to extract IP addresses and domain names from network events.
     * Filters out localhost and common benign domains.
     * 
     * @param events Event vector to scan
     * @return Set of unique network IOCs
     */
    std::set<std::string> ExtractNetworkIOCs(const std::vector<BehaviorEvent>& events) const;

    /**
     * @brief Extract file path IOCs from file operation events
     * 
     * Focuses on suspicious directories (/tmp, /etc, /root, /.ssh)
     * to reduce noise from normal file operations.
     * 
     * @param events Event vector to scan
     * @return Set of unique file path IOCs
     */
    std::set<std::string> ExtractFileIOCs(const std::vector<BehaviorEvent>& events) const;

    /**
     * @brief Extract process name IOCs from process events
     * 
     * @param events Event vector to scan
     * @return Set of unique process names
     */
    std::set<std::string> ExtractProcessIOCs(const std::vector<BehaviorEvent>& events) const;

    /**
     * @brief Generate security recommendations based on findings
     * 
     * Provides actionable recommendations tailored to detected threats:
     * - Immediate containment actions for high-severity threats
     * - IOC blocking guidance
     * - Forensic investigation steps
     * - Recovery procedures
     * 
     * @param report Analysis report
     * @return Vector of recommendation strings
     */
    std::vector<std::string> GenerateRecommendations(const BehaviorAnalysisReport& report) const;

    /**
     * @brief Convert EventType enum to human-readable string
     * @param type Event type enum value
     * @return String representation
     */
    std::string EventTypeToString(EventType type) const;

    /**
     * @brief Convert ThreatLevel enum to Oddworld-themed string
     * 
     * Returns emoji-decorated threat level strings:
     * - Mudokon Safe
     * - Minor Alert
     * - Slig Patrol
     * - Glukkon Alert
     * - Vykker Critical
     * 
     * @param level Threat level enum value
     * @return Themed string representation
     */
    std::string ThreatLevelToString(ThreatLevel level) const;

    /**
     * @brief Convert MitreTactic enum to string
     * @param tactic MITRE tactic enum value
     * @return String representation (e.g., "Privilege Escalation")
     */
    std::string MitreTacticToString(MitreTactic tactic) const;
};

} // namespace analyzers
} // namespace paramite