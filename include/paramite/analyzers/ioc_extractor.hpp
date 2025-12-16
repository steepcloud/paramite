/**
 * @file ioc_extractor.hpp
 * @brief Indicator of Compromise (IOC) extraction and threat intelligence integration
 * 
 * Provides comprehensive IOC extraction from analysis artifacts (network captures,
 * logs, file events, behavioral patterns) with validation, enrichment, and export
 * capabilities. Supports multiple export formats including STIX 2.0, YARA, Snort,
 * and integration with threat intelligence platforms (MISP).
 * 
 * @date 2025
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <set>
#include <optional>
#include <regex>
#include <memory>

namespace paramite {
namespace analyzers {

/**
 * @enum IOCType
 * @brief Categories of Indicators of Compromise
 * 
 * Defines the various types of IOCs that can be extracted from malware analysis.
 * Each type represents a different observable artifact that can indicate
 * malicious activity.
 */
enum class IOCType {
    IP_ADDRESS,          ///< IPv4 or IPv6 address
    DOMAIN_NAME,         ///< DNS domain name
    URL,                 ///< Full URL with protocol
    EMAIL,               ///< Email address
    FILE_PATH,           ///< File system path (Windows or Unix)
    FILE_HASH_MD5,       ///< MD5 file hash
    FILE_HASH_SHA1,      ///< SHA-1 file hash
    FILE_HASH_SHA256,    ///< SHA-256 file hash
    REGISTRY_KEY,        ///< Windows registry key or Linux config path
    MUTEX_NAME,          ///< Named mutex (process synchronization)
    PROCESS_NAME,        ///< Process or executable name
    SERVICE_NAME,        ///< System service name
    USER_AGENT,          ///< HTTP User-Agent string
    CVE_ID,              ///< CVE vulnerability identifier
    MITRE_TECHNIQUE,     ///< MITRE ATT&CK technique ID
    CUSTOM               ///< Custom IOC type
};

/**
 * @enum IOCConfidence
 * @brief Confidence level for IOC validity
 * 
 * Indicates the confidence that an extracted IOC is actually malicious.
 * Higher confidence levels mean the IOC is more likely to be actionable.
 */
enum class IOCConfidence {
    LOW,        ///< Possibly related to malicious activity
    MEDIUM,     ///< Likely related to malicious activity
    HIGH,       ///< Definitely related to malicious activity
    CONFIRMED   ///< Verified malicious (cross-referenced with threat intel)
};

/**
 * @enum IOCContext
 * @brief Context where IOC was discovered
 * 
 * Tracks the source or observation context of an IOC, which helps
 * in prioritization and validation.
 */
enum class IOCContext {
    NETWORK_TRAFFIC,      ///< Observed in network packet capture
    FILE_SYSTEM,          ///< Found in file system events
    PROCESS_MEMORY,       ///< Extracted from process memory dump
    SYSTEM_CALL,          ///< Appeared in system call trace
    CONFIGURATION,        ///< Found in config files or registry
    COMMAND_LINE,         ///< Appeared in command-line arguments
    ENVIRONMENT_VARIABLE, ///< Found in environment variables
    UNKNOWN               ///< Context not determined
};

/**
 * @struct IOC
 * @brief Represents a single Indicator of Compromise
 * 
 * Contains complete information about an observed indicator including
 * its value, confidence level, context, and enrichment data from
 * threat intelligence sources.
 * 
 * **Example**:
 * @code
 * IOC ioc;
 * ioc.type = IOCType::IP_ADDRESS;
 * ioc.value = "192.168.1.100";
 * ioc.confidence = IOCConfidence::HIGH;
 * ioc.context = IOCContext::NETWORK_TRAFFIC;
 * ioc.description = "C2 server connection";
 * ioc.tags = {"c2", "exfiltration"};
 * @endcode
 */
struct IOC {
    IOCType type;                ///< Type of indicator
    std::string value;           ///< Indicator value (IP, domain, hash, etc.)
    IOCConfidence confidence;    ///< Confidence in IOC validity
    IOCContext context;          ///< Where IOC was observed
    
    // Metadata
    std::string description;               ///< Human-readable description
    std::vector<std::string> tags;         ///< Categorization tags (c2, dropper, etc.)
    std::string first_seen;                ///< Timestamp of first observation
    std::string last_seen;                 ///< Timestamp of last observation
    int observation_count{1};              ///< Number of times observed
    
    // Related Information
    std::string associated_process;        ///< Process that generated this IOC
    std::string associated_file;           ///< File associated with this IOC
    std::map<std::string, std::string> attributes;  ///< Additional key-value attributes
    
    // Threat Intelligence Enrichment
    std::vector<std::string> threat_actor_groups;  ///< Known threat actors using this IOC
    std::vector<std::string> malware_families;     ///< Malware families associated with IOC
    std::vector<std::string> mitre_techniques;     ///< MITRE ATT&CK techniques
    
    /**
     * @brief Comparison operator for set/map storage
     */
    bool operator<(const IOC& other) const {
        return value < other.value;
    }
};

/**
 * @struct IOCCollection
 * @brief Organized collection of extracted IOCs
 * 
 * Groups IOCs by category (network, file, host, behavioral) and
 * maintains statistics and metadata about the collection.
 */
struct IOCCollection {
    std::set<IOC> network_iocs;      ///< Network-related IOCs (IPs, domains, URLs)
    std::set<IOC> file_iocs;         ///< File-related IOCs (paths, hashes)
    std::set<IOC> host_iocs;         ///< Host-based IOCs (processes, registry, services)
    std::set<IOC> behavioral_iocs;   ///< Behavioral IOCs (patterns, techniques)
    
    // Statistics
    int total_count{0};              ///< Total number of IOCs
    int high_confidence_count{0};    ///< Count of high/confirmed IOCs
    std::string collection_timestamp;  ///< When collection was created
    
    // Metadata
    std::string sample_hash;         ///< SHA-256 of analyzed sample
    std::string analysis_id;         ///< Analysis session identifier
    std::map<std::string, int> ioc_type_counts;  ///< Count by IOC type
};

/**
 * @enum ExportFormat
 * @brief Supported IOC export formats
 * 
 * Defines output formats for IOC export to support various threat
 * intelligence platforms and security tools.
 */
enum class ExportFormat {
    JSON,      ///< JSON format (human-readable, generic)
    STIX2,     ///< STIX 2.0 (Structured Threat Information Expression)
    CSV,       ///< CSV format (spreadsheet compatible)
    YARA,      ///< YARA rule format (for signature-based detection)
    SNORT,     ///< Snort IDS rules
    OPENIOC,   ///< OpenIOC XML format
    MISP       ///< MISP JSON format (threat intelligence platform)
};

/**
 * @class IOCExtractor
 * @brief Extracts and manages Indicators of Compromise from malware analysis
 * 
 * Comprehensive IOC extraction engine that:
 * - Extracts IOCs from multiple data sources (network, filesystem, processes)
 * - Validates and filters IOCs (whitelisting, private IP exclusion)
 * - Enriches IOCs with threat intelligence and geolocation data
 * - Deduplicates and prioritizes indicators
 * - Exports IOCs in multiple formats (JSON, STIX2, YARA, Snort)
 * - Integrates with threat intelligence platforms (MISP)
 * 
 * **Thread Safety**: NOT thread-safe. Create separate instances for concurrent use.
 * 
 * **Usage Example**:
 * @code
 * IOCExtractor::Config config;
 * config.extract_network_iocs = true;
 * config.exclude_private_ips = true;
 * config.min_confidence = IOCConfidence::MEDIUM;
 * 
 * IOCExtractor extractor(config);
 * 
 * // Extract from network capture
 * auto network_iocs = extractor.ExtractFromNetworkCapture("/tmp/traffic.pcap");
 * 
 * // Extract from logs
 * auto log_iocs = extractor.ExtractFromText(log_content);
 * 
 * // Merge collections
 * auto all_iocs = extractor.MergeCollections({network_iocs, log_iocs});
 * 
 * // Enrich with threat intelligence
 * extractor.EnrichIOCs(all_iocs);
 * 
 * // Export as STIX 2.0
 * std::string stix_output = extractor.ExportIOCs(all_iocs, ExportFormat::STIX2);
 * 
 * // Generate YARA rule
 * std::string yara_rule = extractor.GenerateYaraRule(all_iocs, "Malware_Family_X");
 * @endcode
 */
class IOCExtractor {
public:
    /**
     * @struct Config
     * @brief Configuration for IOC extraction
     */
    struct Config {
        // Extraction Toggles
        bool extract_network_iocs{true};      ///< Extract network indicators
        bool extract_file_iocs{true};         ///< Extract file indicators
        bool extract_host_iocs{true};         ///< Extract host-based indicators
        bool extract_behavioral_iocs{true};   ///< Extract behavioral patterns
        
        // Filtering Options
        IOCConfidence min_confidence{IOCConfidence::MEDIUM};  ///< Minimum confidence threshold
        bool exclude_private_ips{true};          ///< Filter out RFC1918 private IPs
        bool exclude_common_files{true};         ///< Filter out system files
        std::set<std::string> whitelist_domains; ///< Benign domains to exclude
        std::set<std::string> whitelist_ips;     ///< Benign IPs to exclude
        
        // Enrichment Options
        bool enable_threat_intel_lookup{false};  ///< Query threat intel databases
        bool enable_geolocation{false};          ///< Add geolocation data for IPs
        bool enable_domain_age_check{false};     ///< Check domain registration age
        
        // Performance Limits
        int max_iocs_per_type{1000};   ///< Maximum IOCs per type (prevent overload)
        bool deduplicate{true};        ///< Remove duplicate IOCs
    };

    /**
     * @brief Construct extractor with custom configuration
     * @param config Extraction configuration
     */
    explicit IOCExtractor(const Config& config);
    
    /**
     * @brief Construct extractor with default configuration
     */
    explicit IOCExtractor();
    
    ~IOCExtractor() = default;

    IOCExtractor(const IOCExtractor&) = delete;
    IOCExtractor& operator=(const IOCExtractor&) = delete;

    /**
     * @brief Extract IOCs from raw text (logs, memory dumps, strings)
     * 
     * Applies regex patterns to extract all recognizable IOCs from unstructured text.
     * Useful for processing log files, extracted strings, or memory dumps.
     * 
     * @param text Raw text to parse
     * @return IOCCollection containing extracted indicators
     * 
     * **Extracted Types**: IPs, domains, URLs, emails, file hashes, CVEs
     */
    IOCCollection ExtractFromText(const std::string& text);

    /**
     * @brief Extract IOCs from network packet capture
     * 
     * Parses PCAP file to extract network indicators including:
     * - Contacted IP addresses
     * - DNS queries and responses
     * - HTTP/HTTPS URLs
     * - User-Agent strings
     * 
     * @param pcap_file Path to PCAP file
     * @return IOCCollection with network indicators
     * 
     * @throws std::runtime_error if PCAP file cannot be parsed
     * 
     * **Note**: Requires tcpdump or Wireshark to be installed
     */
    IOCCollection ExtractFromNetworkCapture(const std::string& pcap_file);

    /**
     * @brief Extract IOCs from file system event log
     * 
     * Parses file change events to extract:
     * - Created/modified file paths
     * - Suspicious file locations
     * - File hashes (if available)
     * 
     * @param file_events Vector of file event strings (from inotify or similar)
     * @return IOCCollection with file-based indicators
     * 
     * **Event Format**: "CREATE /tmp/malware.sh" or "MODIFY /etc/crontab"
     */
    IOCCollection ExtractFromFileEvents(const std::vector<std::string>& file_events);

    /**
     * @brief Extract IOCs from process/syscall events
     * 
     * Analyzes process creation and system call logs to extract:
     * - Process names and paths
     * - Command-line arguments
     * - Mutex names
     * - Service names
     * 
     * @param process_events Vector of process event strings
     * @return IOCCollection with process-based indicators
     */
    IOCCollection ExtractFromProcessEvents(const std::vector<std::string>& process_events);

    /**
     * @brief Extract IOCs from behavioral analysis report JSON
     * 
     * Parses structured behavioral analysis results to extract high-confidence IOCs.
     * 
     * @param report_json JSON string of behavioral report
     * @return IOCCollection with behavioral indicators
     */
    IOCCollection ExtractFromBehaviorReport(const std::string& report_json);

    /**
     * @brief Merge multiple IOC collections into one
     * 
     * Combines IOCs from different sources, deduplicates, and updates
     * observation counts for recurring indicators.
     * 
     * @param collections Vector of IOC collections to merge
     * @return Merged IOCCollection
     * 
     * **Use Case**: Combining IOCs from static and dynamic analysis
     */
    IOCCollection MergeCollections(const std::vector<IOCCollection>& collections);

    /**
     * @brief Enrich IOCs with external threat intelligence
     * 
     * Queries threat intelligence sources to add:
     * - Known threat actor associations
     * - Malware family classifications
     * - Historical sightings
     * - Geolocation data (for IPs)
     * - WHOIS data (for domains)
     * 
     * @param collection IOC collection to enrich (modified in-place)
     * 
     * @note Requires API keys for threat intelligence services
     * @note This operation can be slow for large collections
     */
    void EnrichIOCs(IOCCollection& collection);

    /**
     * @brief Export IOCs in specified format
     * 
     * Converts IOC collection to requested format for sharing with
     * threat intelligence platforms or security tools.
     * 
     * @param collection IOC collection to export
     * @param format Desired output format
     * @return Formatted string (JSON, XML, CSV, etc.)
     * 
     * **Supported Formats**:
     * - JSON: Generic, human-readable
     * - STIX 2.0: Industry standard for threat intel sharing
     * - CSV: Spreadsheet-compatible
     * - OpenIOC: Mandiant IOC format
     * - MISP: For MISP platform import
     */
    std::string ExportIOCs(const IOCCollection& collection, ExportFormat format);

    /**
     * @brief Generate YARA rule from IOC collection
     * 
     * Creates a YARA detection rule based on extracted file IOCs
     * and behavioral patterns. Useful for creating signatures for
     * detection systems.
     * 
     * @param collection IOC collection
     * @param rule_name Name for the YARA rule
     * @return YARA rule as string
     * 
     * **Example Output**:
     * @code
     * rule Malware_Family_X {
     *     meta:
     *         description = "Auto-generated from IOC extraction"
     *         sample_hash = "abc123..."
     *     strings:
     *         $ip1 = "192.168.1.100"
     *         $domain1 = "evil.com"
     *     condition:
     *         any of them
     * }
     * @endcode
     */
    std::string GenerateYaraRule(const IOCCollection& collection, 
                                 const std::string& rule_name);

    /**
     * @brief Generate Snort IDS rules from network IOCs
     * 
     * Creates Snort intrusion detection rules for network IOCs
     * (IPs, domains, URLs) to enable network-level blocking.
     * 
     * @param collection IOC collection
     * @return Vector of Snort rule strings
     * 
     * **Example Output**:
     * @code
     * alert tcp any any -> 192.168.1.100 any (msg:"Malware C2 Traffic"; sid:1000001;)
     * alert tcp any any -> any 80 (msg:"Malware Domain"; content:"evil.com"; sid:1000002;)
     * @endcode
     */
    std::vector<std::string> GenerateSnortRules(const IOCCollection& collection);

    /**
     * @brief Submit IOCs to MISP threat intelligence platform
     * 
     * Uploads IOC collection to a MISP instance for sharing with
     * the broader security community.
     * 
     * @param collection IOC collection to submit
     * @param misp_url MISP server URL
     * @return true if submission successful
     * 
     * @throws std::runtime_error if MISP API authentication fails
     * 
     * @note Requires MISP API key configured in environment
     */
    bool SubmitToMISP(const IOCCollection& collection, const std::string& misp_url);

    /**
     * @brief Get statistics about IOC collection
     * 
     * @param collection IOC collection to analyze
     * @return Map of statistic names to counts
     * 
     * **Statistics Included**:
     * - Total IOCs
     * - IOCs by type (IP, domain, file, etc.)
     * - IOCs by confidence level
     * - IOCs by context
     */
    std::map<std::string, int> GetStatistics(const IOCCollection& collection) const;

    /**
     * @brief Filter IOCs by minimum confidence level
     * 
     * Creates new collection containing only IOCs meeting or exceeding
     * the specified confidence threshold.
     * 
     * @param collection Source collection
     * @param min_confidence Minimum confidence level
     * @return Filtered IOCCollection
     * 
     * **Use Case**: Exporting only high-confidence IOCs for blocking
     */
    IOCCollection FilterByConfidence(const IOCCollection& collection, 
                                     IOCConfidence min_confidence) const;

    /**
     * @brief Get current configuration
     * @return Reference to configuration structure
     */
    const Config& GetConfig() const { return config_; }

private:
    Config config_;
    
    // Compiled regex patterns for performance
    std::regex ip_regex_;        ///< IPv4 pattern
    std::regex domain_regex_;    ///< Domain name pattern
    std::regex url_regex_;       ///< URL pattern
    std::regex email_regex_;     ///< Email pattern
    std::regex md5_regex_;       ///< MD5 hash pattern
    std::regex sha1_regex_;      ///< SHA-1 hash pattern
    std::regex sha256_regex_;    ///< SHA-256 hash pattern
    std::regex cve_regex_;       ///< CVE ID pattern
    
    // Whitelists for filtering
    std::set<std::string> common_processes_;   ///< Common benign processes
    std::set<std::string> system_files_;       ///< System files to exclude
    std::set<std::string> private_ip_ranges_;  ///< RFC1918 private IP ranges

    void InitializePatterns();
    void InitializeWhitelists();
    std::vector<IOC> ExtractIPAddresses(const std::string& text, IOCContext context);
    std::vector<IOC> ExtractDomains(const std::string& text, IOCContext context);
    std::vector<IOC> ExtractURLs(const std::string& text, IOCContext context);
    std::vector<IOC> ExtractEmails(const std::string& text, IOCContext context);
    std::vector<IOC> ExtractFileHashes(const std::string& text, IOCContext context);
    std::vector<IOC> ExtractCVEs(const std::string& text, IOCContext context);
    std::vector<IOC> ExtractFilePaths(const std::string& text, IOCContext context);
    std::vector<IOC> ExtractProcessNames(const std::string& text, IOCContext context);
    bool IsValidIP(const std::string& ip) const;
    bool IsPrivateIP(const std::string& ip) const;
    bool IsValidDomain(const std::string& domain) const;
    bool IsWhitelistedDomain(const std::string& domain) const;
    bool IsCommonSystemFile(const std::string& file_path) const;
    IOCConfidence CalculateConfidence(const IOC& ioc) const;
    void DeduplicateIOCs(IOCCollection& collection);
    void EnrichWithThreatIntel(IOC& ioc);
    void EnrichWithGeolocation(IOC& ioc);
    std::string IOCTypeToString(IOCType type) const;
    std::string IOCConfidenceToString(IOCConfidence confidence) const;
    std::string IOCContextToString(IOCContext context) const;
    std::string ExportToJSON(const IOCCollection& collection);
    std::string ExportToSTIX2(const IOCCollection& collection);
    std::string ExportToCSV(const IOCCollection& collection);
    std::string ExportToOpenIOC(const IOCCollection& collection);
};

} // namespace analyzers
} // namespace paramite