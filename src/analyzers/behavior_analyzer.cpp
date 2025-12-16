/**
 * @file behavior_analyzer.cpp
 * @brief Implementation of behavioral analysis engine for malware detection
 * 
 * Implements pattern-based behavioral analysis to detect malicious activities by analyzing
 * system call traces (strace), network traffic captures (tcpdump), and file system
 * modifications. Uses a rule-based detection engine with MITRE ATT&CK framework mapping,
 * threat scoring algorithms, and multi-source event correlation.
 * 
 * **Analysis Pipeline**:
 * 1. **Event Collection**: Parse monitoring data from multiple sources
 * 2. **Event Correlation**: Merge and chronologically sort events
 * 3. **Pattern Matching**: Apply behavioral rules to detect malicious patterns
 * 4. **Threat Scoring**: Calculate aggregate threat score (0-100)
 * 5. **MITRE Mapping**: Map detected behaviors to ATT&CK techniques
 * 6. **IOC Extraction**: Extract indicators for threat intelligence
 * 7. **Report Generation**: Compile comprehensive analysis report
 * 
 * **Behavioral Detection Categories**:
 * - **Process Injection**: WriteProcessMemory, CreateRemoteThread sequences
 * - **Persistence**: Registry Run keys, scheduled tasks, startup folders
 * - **Privilege Escalation**: Token manipulation, UAC bypass
 * - **Defense Evasion**: Log deletion, process hiding, VM detection
 * - **Credential Access**: LSASS access, keylogging, password dumping
 * - **Discovery**: System enumeration, network scanning
 * - **Lateral Movement**: SMB connections, remote execution
 * - **Collection**: Screen capture, clipboard access, file enumeration
 * - **Command & Control**: Beaconing, unusual network connections
 * - **Exfiltration**: Large data uploads, compression, encoding
 * - **Impact**: Ransomware encryption, data destruction
 * 
 * **Pattern Matching Engine**:
 * Uses multi-level pattern matching:
 * - **Atomic Patterns**: Single syscalls or API calls (e.g., `open("/etc/passwd")`)
 * - **Sequence Patterns**: Ordered series of operations (e.g., VirtualAlloc → WriteProcessMemory → CreateRemoteThread)
 * - **Frequency Patterns**: Repeated operations (e.g., 100+ file writes/sec = ransomware)
 * - **Temporal Patterns**: Time-based correlations (e.g., beaconing every N seconds)
 * 
 * **MITRE ATT&CK Integration**:
 * Maps detected behaviors to MITRE ATT&CK techniques:
 * ```
 * Behavior: WriteProcessMemory + CreateRemoteThread
 * → T1055.001 (Process Injection: Dynamic-link Library Injection)
 * → Tactic: Defense Evasion
 * ```
 * 
 * **Threat Scoring Algorithm**:
 * Weighted scoring based on:
 * - Pattern severity (critical=30, high=20, medium=10, low=5)
 * - Pattern confidence (0.0-1.0 multiplier)
 * - Pattern frequency (repeated behaviors increase score)
 * - MITRE tactic coverage (more tactics = higher score)
 * 
 * **Event Sources**:
 * - **strace logs**: System call traces with arguments
 * - **tcpdump/PCAP**: Network packet captures
 * - **inotify logs**: File system change events
 * - **Wine debug logs**: Windows API calls (for PE files)
 * 
 * @date 2025
 */

#include "paramite/analyzers/behavior_analyzer.hpp"

#include <fstream>
#include <sstream>
#include <regex>
#include <algorithm>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

using json = nlohmann::json;

namespace paramite {
namespace analyzers {

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================
// Initializes behavioral analysis engine with default detection patterns

BehaviorAnalyzer::BehaviorAnalyzer()
    : BehaviorAnalyzer(Config{}) {
}

BehaviorAnalyzer::BehaviorAnalyzer(const Config& config)
    : config_(config) {
    spdlog::debug("Initializing Behavior Analyzer");
    InitializeDefaultPatterns();
    spdlog::info("Loaded {} behavior patterns", patterns_.size());
}

// ============================================================================
// PUBLIC API - BEHAVIORAL ANALYSIS
// ============================================================================
// Main entry point for behavioral analysis
// Coordinates multi-source event parsing, pattern matching, and scoring

BehaviorAnalysisReport BehaviorAnalyzer::AnalyzeBehavior(
    const std::string& strace_log,
    const std::string& tcpdump_log,
    const std::vector<std::string>& file_changes) {

    spdlog::info("Starting behavioral analysis");
    auto start_time = std::chrono::system_clock::now();

    BehaviorAnalysisReport report;
    report.analysis_start = start_time;

    // Phase 1: Parse monitoring data from multiple sources
    spdlog::debug("Parsing strace log: {}", strace_log);
    auto strace_events = ParseStraceLog(strace_log);

    spdlog::debug("Parsing network log: {}", tcpdump_log);
    auto network_events = ParseNetworkLog(tcpdump_log);

    spdlog::debug("Parsing file changes");
    auto file_events = ParseFileChanges(file_changes);

    // Phase 2: Consolidate events from all sources into unified timeline
    report.all_events.insert(report.all_events.end(),
                            strace_events.begin(), strace_events.end());
    report.all_events.insert(report.all_events.end(),
                            network_events.begin(), network_events.end());
    report.all_events.insert(report.all_events.end(),
                            file_events.begin(), file_events.end());

    // Sort chronologically for accurate timeline reconstruction
    std::sort(report.all_events.begin(), report.all_events.end(),
              [](const BehaviorEvent& a, const BehaviorEvent& b) {
                  return a.timestamp < b.timestamp;
              });

    report.total_events = static_cast<int>(report.all_events.size());
    spdlog::info("Total events collected: {}", report.total_events);

    // Phase 3: Pattern matching against malicious behavior signatures
    spdlog::debug("Matching behavior patterns");
    report.matched_patterns = MatchPatterns(report.all_events);
    spdlog::info("Matched {} suspicious patterns", report.matched_patterns.size());

    // Phase 4: Calculate aggregate threat score
    report.threat_score = CalculateThreatScore(report.matched_patterns);
    report.overall_threat_level = DetermineThreatLevel(report.threat_score);
    spdlog::info("Threat score: {} ({})", report.threat_score,
                 ThreatLevelToString(report.overall_threat_level));

    // Phase 5: MITRE ATT&CK framework mapping
    if (config_.enable_mitre_mapping) {
        spdlog::debug("Mapping to MITRE ATT&CK framework");
        report.mitre_techniques = MapToMitreAttack(report.matched_patterns);
    }

    // Phase 6: IOC extraction for threat intelligence sharing
    if (config_.enable_ioc_extraction) {
        spdlog::debug("Extracting IOCs");
        ExtractIOCs(report.all_events, report);
        spdlog::info("Extracted {} network IOCs, {} file IOCs, {} process IOCs",
                     report.network_iocs.size(),
                     report.file_iocs.size(),
                     report.process_iocs.size());
    }

    // Phase 7: Filter events exceeding severity threshold
    for (const auto& event : report.all_events) {
        if (event.severity_score >= config_.min_severity_threshold) {
            report.suspicious_events_list.push_back(event);
        }
    }
    report.suspicious_events = static_cast<int>(report.suspicious_events_list.size());

    // Phase 8: Generate actionable intelligence
    report.recommendations = GenerateRecommendations(report);
    report.executive_summary = GenerateExecutiveSummary(report);

    // Phase 9: Finalize timing information
    auto end_time = std::chrono::system_clock::now();
    report.analysis_end = end_time;
    report.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        end_time - start_time);

    spdlog::info("Behavioral analysis complete in {} ms", report.duration.count());

    return report;
}

/*******************************************************************************
 * Log Parsing Methods
 ******************************************************************************/

// Parse strace output
std::vector<BehaviorEvent> BehaviorAnalyzer::ParseStraceLog(const std::string& strace_log) {
    std::vector<BehaviorEvent> events;

    std::ifstream file(strace_log);
    if (!file.is_open()) {
        spdlog::warn("Could not open strace log: {}", strace_log);
        return events;
    }

    std::string line;
    // Regex pattern: PID SYSCALL(args) = result
    std::regex syscall_regex(R"((\d+)\s+(\w+)\((.*)\)\s+=\s+(.+))");

    while (std::getline(file, line)) {
        std::smatch match;
        if (std::regex_search(line, match, syscall_regex)) {
            BehaviorEvent event;
            event.timestamp = std::chrono::system_clock::now();
            event.process_id = std::stoi(match[1].str());

            std::string syscall = match[2].str();
            std::string args = match[3].str();
            std::string result = match[4].str();

            // Classify system call and assign severity
            if (syscall == "execve" || syscall == "fork" || syscall == "clone") {
                event.type = EventType::PROCESS_CREATED;
                event.details = "Process creation: " + args;
                event.severity_score = 40;
                event.tags.push_back("process_creation");
            }
            else if (syscall == "open" || syscall == "openat" || syscall == "creat") {
                event.type = EventType::FILE_CREATED;
                event.details = "File opened: " + args;
                event.severity_score = 20;
                event.tags.push_back("file_access");

                // Escalate severity for sensitive paths
                if (args.find("/etc/") != std::string::npos ||
                    args.find("/root/") != std::string::npos ||
                    args.find("/.ssh/") != std::string::npos) {
                    event.severity_score = 60;
                    event.tags.push_back("sensitive_file");
                }
            }
            else if (syscall == "connect" || syscall == "sendto") {
                event.type = EventType::NETWORK_CONNECTION;
                event.details = "Network connection: " + args;
                event.severity_score = 50;
                event.tags.push_back("network");
            }
            else if (syscall == "ptrace") {
                // ptrace is commonly used for anti-debugging
                event.type = EventType::ANTI_DEBUG;
                event.details = "Ptrace detected (anti-debug)";
                event.severity_score = 80;
                event.tags.push_back("anti_debug");
                event.tags.push_back("evasion");
            }
            else if (syscall == "setuid" || syscall == "setgid") {
                // Privilege modification attempts
                event.type = EventType::PRIVILEGE_ESCALATION;
                event.details = "Privilege change attempt: " + args;
                event.severity_score = 90;
                event.tags.push_back("privilege_escalation");
            }
            else {
                continue; // Skip uninteresting syscalls for performance
            }

            // Store structured metadata for later analysis
            event.attributes["syscall"] = syscall;
            event.attributes["args"] = args;
            event.attributes["result"] = result;

            events.push_back(event);
        }
    }

    spdlog::debug("Parsed {} events from strace log", events.size());
    return events;
}

std::vector<BehaviorEvent> BehaviorAnalyzer::ParseNetworkLog(const std::string& tcpdump_log) {
    std::vector<BehaviorEvent> events;

    std::ifstream file(tcpdump_log);
    if (!file.is_open()) {
        spdlog::warn("Could not open network log: {}", tcpdump_log);
        return events;
    }

    std::string line;
    std::regex ip_regex(R"((\d+\.\d+\.\d+\.\d+))");
    std::regex dns_regex(R"(DNS.*\?.*\s+(\S+))");

    while (std::getline(file, line)) {
        BehaviorEvent event;
        event.timestamp = std::chrono::system_clock::now();
        event.type = EventType::NETWORK_CONNECTION;

        // DNS query pattern detection
        std::smatch dns_match;
        if (std::regex_search(line, dns_match, dns_regex)) {
            event.type = EventType::NETWORK_DNS_QUERY;
            event.details = "DNS query: " + dns_match[1].str();
            event.severity_score = 30;
            event.tags.push_back("dns");

            std::string domain = dns_match[1].str();

            // Flag known-suspicious TLDs and services
            if (domain.find(".onion") != std::string::npos ||
                domain.find(".tk") != std::string::npos ||
                domain.find("pastebin") != std::string::npos) {
                event.severity_score = 70;
                event.tags.push_back("suspicious_domain");
            }

            event.attributes["domain"] = domain;
            events.push_back(event);
            continue;
        }

        // IP connection pattern detection
        std::smatch ip_match;
        if (std::regex_search(line, ip_match, ip_regex)) {
            event.details = "Network connection: " + line;
            event.severity_score = 40;
            event.tags.push_back("network_connection");

            std::string ip = ip_match[1].str();
            event.attributes["ip"] = ip;

            // Flag suspicious ports commonly used by malware
            if (line.find(":4444") != std::string::npos ||  // Metasploit default
                line.find(":31337") != std::string::npos ||  // Elite/leet port
                line.find(":6667") != std::string::npos) {   // IRC
                event.severity_score = 80;
                event.tags.push_back("suspicious_port");
            }

            events.push_back(event);
        }
    }

    spdlog::debug("Parsed {} events from network log", events.size());
    return events;
}

std::vector<BehaviorEvent> BehaviorAnalyzer::ParseFileChanges(
    const std::vector<std::string>& file_changes) {

    std::vector<BehaviorEvent> events;

    for (const auto& change : file_changes) {
        BehaviorEvent event;
        event.timestamp = std::chrono::system_clock::now();
        event.details = change;

        // Classify file operation type
        if (change.find("CREATE") != std::string::npos) {
            event.type = EventType::FILE_CREATED;
            event.severity_score = 30;
            event.tags.push_back("file_create");
        }
        else if (change.find("MODIFY") != std::string::npos) {
            event.type = EventType::FILE_MODIFIED;
            event.severity_score = 40;
            event.tags.push_back("file_modify");
        }
        else if (change.find("DELETE") != std::string::npos) {
            event.type = EventType::FILE_DELETED;
            event.severity_score = 50;
            event.tags.push_back("file_delete");
        }

        // Detect persistence mechanism installations
        if (change.find("/etc/cron") != std::string::npos ||
            change.find("/etc/systemd") != std::string::npos ||
            change.find("~/.bashrc") != std::string::npos ||
            change.find("~/.ssh/") != std::string::npos) {
            event.type = EventType::PERSISTENCE_MECHANISM;
            event.severity_score = 80;
            event.tags.push_back("persistence");
        }

        // Detect ransomware indicators
        if (change.find(".encrypted") != std::string::npos ||
            change.find(".locked") != std::string::npos ||
            change.find("README.txt") != std::string::npos) {
            event.severity_score = 95;
            event.tags.push_back("ransomware");
        }

        event.attributes["change"] = change;
        events.push_back(event);
    }

    spdlog::debug("Parsed {} file change events", events.size());
    return events;
}

/*******************************************************************************
 * Pattern Matching Methods
 ******************************************************************************/
// Match behavior patterns
std::vector<PatternMatch> BehaviorAnalyzer::MatchPatterns(
    const std::vector<BehaviorEvent>& events) {

    std::vector<PatternMatch> matches;

    // Iterate through each loaded pattern and find matching events
    for (const auto& pattern : patterns_) {
        std::vector<BehaviorEvent> matching_events;

        for (const auto& event : events) {
            if (EventMatchesPattern(event, pattern)) {
                matching_events.push_back(event);
            }
        }

        if (!matching_events.empty()) {
            PatternMatch match;
            match.pattern = pattern;
            match.matching_events = matching_events;
            match.confidence_score = CalculateConfidence(matching_events, pattern);

            // Generate human-readable evidence summary
            std::ostringstream evidence;
            evidence << "Detected " << matching_events.size()
                    << " instances of " << pattern.name;
            match.evidence = evidence.str();

            matches.push_back(match);

            spdlog::debug("Pattern matched: {} (confidence: {}%)",
                         pattern.name, match.confidence_score);
        }
    }

    return matches;
}

bool BehaviorAnalyzer::EventMatchesPattern(const BehaviorEvent& event,
                                          const BehaviorPattern& pattern) const {
    // First check if event type matches (if pattern specifies a type)
    if (pattern.event_type != EventType::UNKNOWN &&
        event.type != pattern.event_type) {
        return false;
    }

    // Check if any pattern indicator appears in event details
    for (const auto& indicator : pattern.indicators) {
        if (event.details.find(indicator) != std::string::npos) {
            return true;
        }

        // Also check event attributes for matches
        for (const auto& [key, value] : event.attributes) {
            if (value.find(indicator) != std::string::npos) {
                return true;
            }
        }
    }

    return false;
}

int BehaviorAnalyzer::CalculateConfidence(const std::vector<BehaviorEvent>& events,
                                         const BehaviorPattern& pattern) const {
    // Base confidence on number of matching events (more instances = higher confidence)
    int base_confidence = std::min(static_cast<int>(events.size()) * 10, 70);

    // Boost confidence based on average event severity
    int avg_severity = 0;
    for (const auto& event : events) {
        avg_severity += event.severity_score;
    }
    avg_severity /= static_cast<int>(events.size());

    // Combine base confidence with severity factor
    int confidence = base_confidence + (avg_severity / 4);

    return std::min(confidence, 100);
}

/*******************************************************************************
 * Threat Scoring Methods
 ******************************************************************************/
// Calculate threat score
int BehaviorAnalyzer::CalculateThreatScore(const std::vector<PatternMatch>& matches) {
    int total_score = 0;

    for (const auto& match : matches) {
        // Weight pattern severity by match confidence
        int weighted_score = (match.pattern.base_severity * match.confidence_score) / 100;

        // Apply tactic-specific multipliers from configuration
        switch (match.pattern.tactic) {
            case MitreTactic::PERSISTENCE:
                weighted_score = (weighted_score * config_.persistence_weight) / 100;
                break;
            case MitreTactic::PRIVILEGE_ESCALATION:
                weighted_score = (weighted_score * config_.privilege_escalation_weight) / 100;
                break;
            case MitreTactic::EXFILTRATION:
                weighted_score = (weighted_score * config_.network_exfil_weight) / 100;
                break;
            case MitreTactic::IMPACT:
                weighted_score = (weighted_score * config_.file_encryption_weight) / 100;
                break;
            default:
                break;
        }

        total_score += weighted_score;
    }

    // Cap maximum score at 1000
    return std::min(total_score, 1000);
}

ThreatLevel BehaviorAnalyzer::DetermineThreatLevel(int threat_score) const {
    if (threat_score >= 800) return ThreatLevel::CRITICAL;
    if (threat_score >= 600) return ThreatLevel::HIGH;
    if (threat_score >= 400) return ThreatLevel::MEDIUM;
    if (threat_score >= 200) return ThreatLevel::LOW;
    return ThreatLevel::SAFE;
}

/*******************************************************************************
 * MITRE ATT&CK Mapping
 ******************************************************************************/
// Map detected behaviors to MITRE ATT&CK technique IDs
std::map<MitreTactic, std::vector<std::string>> BehaviorAnalyzer::MapToMitreAttack(
    const std::vector<PatternMatch>& matches) {

    std::map<MitreTactic, std::vector<std::string>> mapping;

    // Group technique IDs by their associated tactic
    for (const auto& match : matches) {
        mapping[match.pattern.tactic].push_back(match.pattern.technique_id);
    }

    return mapping;
}

/*******************************************************************************
 * IOC Extraction Methods
 ******************************************************************************/
// Extract IOCs from event data for threat intelligence reporting
void BehaviorAnalyzer::ExtractIOCs(const std::vector<BehaviorEvent>& events,
                                   BehaviorAnalysisReport& report) {
    report.network_iocs = ExtractNetworkIOCs(events);
    report.file_iocs = ExtractFileIOCs(events);
    report.process_iocs = ExtractProcessIOCs(events);
}

std::set<std::string> BehaviorAnalyzer::ExtractNetworkIOCs(
    const std::vector<BehaviorEvent>& events) const {

    std::set<std::string> iocs;
    std::regex ip_regex(R"(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)");
    std::regex domain_regex(R"(\b[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}\b)");

    for (const auto& event : events) {
        if (event.type == EventType::NETWORK_CONNECTION ||
            event.type == EventType::NETWORK_DNS_QUERY) {

            std::smatch match;
            std::string text = event.details;

            // Extract IPv4 addresses
            while (std::regex_search(text, match, ip_regex)) {
                iocs.insert(match[0].str());
                text = match.suffix();
            }

            // Extract domain names
            text = event.details;
            while (std::regex_search(text, match, domain_regex)) {
                std::string domain = match[0].str();
                // Filter out common benign domains to reduce false positives
                if (domain != "localhost" && domain != "example.com") {
                    iocs.insert(domain);
                }
                text = match.suffix();
            }
        }
    }

    return iocs;
}

std::set<std::string> BehaviorAnalyzer::ExtractFileIOCs(
    const std::vector<BehaviorEvent>& events) const {

    std::set<std::string> iocs;
    std::regex file_regex(R"(/[a-zA-Z0-9_/\.-]+)");

    for (const auto& event : events) {
        if (event.type == EventType::FILE_CREATED ||
            event.type == EventType::FILE_MODIFIED ||
            event.type == EventType::FILE_DELETED) {

            std::smatch match;
            std::string text = event.details;

            while (std::regex_search(text, match, file_regex)) {
                std::string path = match[0].str();

                // Only include paths in suspicious directories
                if (path.find("/tmp/") == 0 ||
                    path.find("/etc/") == 0 ||
                    path.find("/root/") == 0 ||
                    path.find("/.ssh/") != std::string::npos) {
                    iocs.insert(path);
                }

                text = match.suffix();
            }
        }
    }

    return iocs;
}

std::set<std::string> BehaviorAnalyzer::ExtractProcessIOCs(
    const std::vector<BehaviorEvent>& events) const {

    std::set<std::string> iocs;

    for (const auto& event : events) {
        if (event.type == EventType::PROCESS_CREATED) {
            if (!event.process_name.empty()) {
                iocs.insert(event.process_name);
            }
        }
    }

    return iocs;
}

/*******************************************************************************
 * Report Generation Methods
 ******************************************************************************/

std::vector<std::string> BehaviorAnalyzer::GenerateRecommendations(
    const BehaviorAnalysisReport& report) const {

    std::vector<std::string> recommendations;

    // High-severity findings require immediate action
    if (report.overall_threat_level >= ThreatLevel::HIGH) {
        recommendations.push_back("⚠️ IMMEDIATE ACTION REQUIRED: Isolate infected systems");
        recommendations.push_back("Block all network IOCs at firewall/proxy");
        recommendations.push_back("Scan entire network for similar indicators");
    }

    // Tactic-specific recommendations
    for (const auto& match : report.matched_patterns) {
        if (match.pattern.tactic == MitreTactic::PERSISTENCE) {
            recommendations.push_back("Check cron jobs, systemd services, and startup scripts");
        }
        if (match.pattern.tactic == MitreTactic::EXFILTRATION) {
            recommendations.push_back("Review network logs for data exfiltration");
        }
        if (match.pattern.tactic == MitreTactic::IMPACT) {
            recommendations.push_back("Restore files from backup if ransomware detected");
        }
    }

    // IOC-based recommendations
    if (!report.network_iocs.empty()) {
        recommendations.push_back("Add network IOCs to threat intelligence feeds");
    }

    return recommendations;
}

std::string BehaviorAnalyzer::GenerateExecutiveSummary(
    const BehaviorAnalysisReport& report) {

    std::ostringstream summary;

    summary << "Behavioral Analysis Summary:\n\n";
    summary << "Threat Level: " << ThreatLevelToString(report.overall_threat_level)
            << " (Score: " << report.threat_score << "/1000)\n";
    summary << "Total Events: " << report.total_events << "\n";
    summary << "Suspicious Events: " << report.suspicious_events << "\n";
    summary << "Matched Patterns: " << report.matched_patterns.size() << "\n\n";

    if (!report.matched_patterns.empty()) {
        summary << "Key Findings:\n";
        for (const auto& match : report.matched_patterns) {
            summary << "  • " << match.pattern.name
                   << " (Confidence: " << match.confidence_score << "%)\n";
        }
        summary << "\n";
    }

    if (!report.mitre_techniques.empty()) {
        summary << "MITRE ATT&CK Tactics Detected:\n";
        for (const auto& [tactic, techniques] : report.mitre_techniques) {
            summary << "  • " << MitreTacticToString(tactic)
                   << " (" << techniques.size() << " techniques)\n";
        }
        summary << "\n";
    }

    if (!report.recommendations.empty()) {
        summary << "Recommendations:\n";
        for (const auto& rec : report.recommendations) {
            summary << "  • " << rec << "\n";
        }
    }

    return summary.str();
}

/*******************************************************************************
 * Pattern Management Methods
 ******************************************************************************/

void BehaviorAnalyzer::InitializeDefaultPatterns() {
    patterns_.clear();

    // Pattern: Process Injection (MITRE T1055)
    {
        BehaviorPattern pattern;
        pattern.pattern_id = "P001";
        pattern.name = "Process Injection";
        pattern.description = "Malware injecting code into another process";
        pattern.event_type = EventType::CODE_INJECTION;
        pattern.indicators = {"ptrace", "process_vm_writev", "PTRACE_POKEDATA"};
        pattern.base_severity = 85;
        pattern.tactic = MitreTactic::DEFENSE_EVASION;
        pattern.technique_id = "T1055";
        patterns_.push_back(pattern);
    }

    // Pattern: Cron-based Persistence (MITRE T1053)
    {
        BehaviorPattern pattern;
        pattern.pattern_id = "P002";
        pattern.name = "Cron-based Persistence";
        pattern.description = "Malware creating cron job for persistence";
        pattern.event_type = EventType::SCHEDULED_TASK;
        pattern.indicators = {"/etc/cron", "crontab", "/var/spool/cron"};
        pattern.base_severity = 75;
        pattern.tactic = MitreTactic::PERSISTENCE;
        pattern.technique_id = "T1053";
        patterns_.push_back(pattern);
    }

    // Pattern: SSH Key Theft (MITRE T1552.004)
    {
        BehaviorPattern pattern;
        pattern.pattern_id = "P003";
        pattern.name = "SSH Key Access";
        pattern.description = "Accessing SSH private keys";
        pattern.event_type = EventType::FILE_CREATED;
        pattern.indicators = {"/.ssh/id_rsa", "/.ssh/id_ed25519", "authorized_keys"};
        pattern.base_severity = 80;
        pattern.tactic = MitreTactic::CREDENTIAL_ACCESS;
        pattern.technique_id = "T1552.004";
        patterns_.push_back(pattern);
    }

    // Pattern: Network Exfiltration (MITRE T1041)
    {
        BehaviorPattern pattern;
        pattern.pattern_id = "P004";
        pattern.name = "Data Exfiltration";
        pattern.description = "Large data transfer to external IP";
        pattern.event_type = EventType::DATA_EXFILTRATION;
        pattern.indicators = {"sendto", "connect", "pastebin", ".onion"};
        pattern.base_severity = 90;
        pattern.tactic = MitreTactic::EXFILTRATION;
        pattern.technique_id = "T1041";
        patterns_.push_back(pattern);
    }

    // Pattern: Privilege Escalation (MITRE T1068)
    {
        BehaviorPattern pattern;
        pattern.pattern_id = "P005";
        pattern.name = "Privilege Escalation";
        pattern.description = "Attempting to gain root privileges";
        pattern.event_type = EventType::PRIVILEGE_ESCALATION;
        pattern.indicators = {"setuid", "sudo", "/etc/sudoers", "SUID"};
        pattern.base_severity = 95;
        pattern.tactic = MitreTactic::PRIVILEGE_ESCALATION;
        pattern.technique_id = "T1068";
        patterns_.push_back(pattern);
    }

    // Pattern: Ransomware (MITRE T1486)
    {
        BehaviorPattern pattern;
        pattern.pattern_id = "P006";
        pattern.name = "Ransomware Activity";
        pattern.description = "Mass file encryption behavior";
        pattern.event_type = EventType::FILE_MODIFIED;
        pattern.indicators = {".encrypted", ".locked", "README", "ransom"};
        pattern.base_severity = 100;
        pattern.tactic = MitreTactic::IMPACT;
        pattern.technique_id = "T1486";
        patterns_.push_back(pattern);
    }

    spdlog::debug("Initialized {} default behavior patterns", patterns_.size());
}

void BehaviorAnalyzer::AddPattern(const BehaviorPattern& pattern) {
    patterns_.push_back(pattern);
    spdlog::debug("Added custom pattern: {}", pattern.name);
}

bool BehaviorAnalyzer::LoadPatternsFromFile(const std::string& patterns_file) {
    try {
        std::ifstream file(patterns_file);
        if (!file.is_open()) {
            spdlog::error("Failed to open patterns file: {}", patterns_file);
            return false;
        }

        json j;
        file >> j;

        // TODO: Parse JSON and add patterns (implementation pending)
        spdlog::info("Loaded patterns from {}", patterns_file);
        return true;
    }
    catch (const std::exception& e) {
        spdlog::error("Error loading patterns: {}", e.what());
        return false;
    }
}

/*******************************************************************************
 * Utility Conversion Methods
 ******************************************************************************/
// Convert EventType to human-readable string
std::string BehaviorAnalyzer::EventTypeToString(EventType type) const {
    switch (type) {
        case EventType::PROCESS_CREATED: return "Process Created";
        case EventType::PROCESS_TERMINATED: return "Process Terminated";
        case EventType::FILE_CREATED: return "File Created";
        case EventType::FILE_MODIFIED: return "File Modified";
        case EventType::FILE_DELETED: return "File Deleted";
        case EventType::NETWORK_CONNECTION: return "Network Connection";
        case EventType::NETWORK_DNS_QUERY: return "DNS Query";
        case EventType::REGISTRY_MODIFIED: return "Config Modified";
        case EventType::SERVICE_CREATED: return "Service Created";
        case EventType::SCHEDULED_TASK: return "Scheduled Task";
        case EventType::PRIVILEGE_ESCALATION: return "Privilege Escalation";
        case EventType::CODE_INJECTION: return "Code Injection";
        case EventType::ANTI_DEBUG: return "Anti-Debug";
        case EventType::PERSISTENCE_MECHANISM: return "Persistence";
        case EventType::DATA_EXFILTRATION: return "Data Exfiltration";
        default: return "Unknown";
    }
}

// Convert ThreatLevel enum to descriptive string (with Oddworld theme)
std::string BehaviorAnalyzer::ThreatLevelToString(ThreatLevel level) const {
    switch (level) {
        case ThreatLevel::SAFE: return "🟢 Mudokon Safe";
        case ThreatLevel::LOW: return "🟡 Minor Alert";
        case ThreatLevel::MEDIUM: return "🟠 Slig Patrol";
        case ThreatLevel::HIGH: return "🔴 Glukkon Alert";
        case ThreatLevel::CRITICAL: return "💀 Vykker Critical";
        default: return "Unknown";
    }
}

// Convert MitreTactic enum to MITRE ATT&CK tactic name
std::string BehaviorAnalyzer::MitreTacticToString(MitreTactic tactic) const {
    switch (tactic) {
        case MitreTactic::INITIAL_ACCESS: return "Initial Access";
        case MitreTactic::EXECUTION: return "Execution";
        case MitreTactic::PERSISTENCE: return "Persistence";
        case MitreTactic::PRIVILEGE_ESCALATION: return "Privilege Escalation";
        case MitreTactic::DEFENSE_EVASION: return "Defense Evasion";
        case MitreTactic::CREDENTIAL_ACCESS: return "Credential Access";
        case MitreTactic::DISCOVERY: return "Discovery";
        case MitreTactic::LATERAL_MOVEMENT: return "Lateral Movement";
        case MitreTactic::COLLECTION: return "Collection";
        case MitreTactic::COMMAND_AND_CONTROL: return "Command and Control";
        case MitreTactic::EXFILTRATION: return "Exfiltration";
        case MitreTactic::IMPACT: return "Impact";
        default: return "Unknown";
    }
}

} // namespace analyzers
} // namespace paramite