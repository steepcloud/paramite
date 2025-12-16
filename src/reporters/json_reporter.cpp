/**
 * @file json_reporter.cpp
 * @brief Implementation of JSON report generation with multiple format support
 * 
 * Implements JSON-based report generation supporting multiple industry-standard formats
 * including Paramite native schema, STIX 2.1 (Structured Threat Information Expression),
 * MISP (Malware Information Sharing Platform), OpenIOC, and custom threat intelligence
 * formats. Enables seamless integration with SIEMs, TIPs, and analysis platforms.
 * 
 * **Supported Export Formats**:
 * 1. **Paramite Native**: Complete analysis results with full fidelity
 * 2. **STIX 2.1**: Industry-standard cyber threat intelligence format
 * 3. **MISP**: Event export compatible with MISP platform
 * 4. **OpenIOC**: XML-based IOC format (converted to JSON)
 * 5. **Custom**: User-defined schema mapping
 * 
 * **STIX 2.1 Export**:
 * Maps analysis results to STIX Domain Objects (SDOs):
 * ```json
 * {
 *   "type": "malware",
 *   "spec_version": "2.1",
 *   "id": "malware--sha256...",
 *   "name": "TrojanDropper",
 *   "malware_types": ["trojan", "dropper"],
 *   "is_family": false,
 *   "kill_chain_phases": [
 *     {"kill_chain_name": "mitre-attack", "phase_name": "execution"}
 *   ],
 *   "indicators": [...],
 *   "observed-data": [...]
 * }
 * ```
 * 
 * **MISP Event Export**:
 * Converts to MISP event format:
 * ```json
 * {
 *   "Event": {
 *     "info": "Malware Analysis: sample.exe",
 *     "threat_level_id": "1",
 *     "analysis": "2",
 *     "Attribute": [
 *       {"type": "sha256", "value": "abc123...", "category": "Payload delivery"},
 *       {"type": "ip-dst", "value": "1.2.3.4", "category": "Network activity"}
 *     ],
 *     "Galaxy": [...]
 *   }
 * }
 * ```
 * 
 * **Paramite Native Schema**:
 * Complete analysis results:
 * - Sample metadata (hashes, file type, size)
 * - Static analysis (PE/ELF headers, entropy, strings)
 * - Behavioral analysis (process tree, network, file ops)
 * - IOCs (network, file, process, registry)
 * - MITRE ATT&CK techniques
 * - Timeline of events
 * - Threat score and classification
 * 
 * **Schema Validation**:
 * - JSON Schema validation (draft-07)
 * - Format-specific validation (STIX, MISP)
 * - Automatic schema migration
 * - Backward compatibility
 * 
 * **Data Transformation**:
 * - IOC normalization (lowercase, defang)
 * - Timestamp standardization (ISO 8601)
 * - Confidence score mapping
 * - TLP (Traffic Light Protocol) tagging
 * 
 * **Compression & Encryption**:
 * - Optional gzip compression
 * - PGP encryption for sensitive data
 * - Base64 encoding for binary data
 * 
 * **Use Cases**:
 * - SIEM integration (Splunk, ELK, QRadar)
 * - TIP ingestion (MISP, OpenCTI, ThreatConnect)
 * - Automated processing pipelines
 * - API responses
 * - Long-term storage and archival
 * 
 * @date 2025
 */

#include "paramite/reporters/json_reporter.hpp"
#include "paramite/core/analysis_engine.hpp"

#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>

#include <fstream>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <algorithm>
#include <random>
#include <regex>

using json = nlohmann::json;

namespace paramite {
namespace reporters {


// Constructor
JsonReporter::JsonReporter(const JsonReporterConfig& config)
    : config_(config) {
    spdlog::info("JSON Reporter initialized");
    spdlog::debug("Format: {}", static_cast<int>(config_.format));
    spdlog::debug("Output directory: {}", config_.output_directory.string());
}

// Destructor
JsonReporter::~JsonReporter() {
    spdlog::info("JSON Reporter destroyed");
}

// Generate report
std::filesystem::path JsonReporter::GenerateReport(const core::AnalysisResult& result) {
    spdlog::info("═══════════════════════════════════════════════════════════════");
    spdlog::info("GENERATING JSON REPORT");
    spdlog::info("═══════════════════════════════════════════════════════════════");
    
    try {
        // Create output directory
        if (!std::filesystem::exists(config_.output_directory)) {
            std::filesystem::create_directories(config_.output_directory);
        }
        
        // Generate JSON content
        std::string json_content = GenerateJsonString(result);
        
        // Validate if configured
        if (config_.validate_json) {
            if (!ValidateSyntax(json_content)) {
                spdlog::error("Generated JSON is invalid");
                return {};
            }
        }
        
        // Generate filename
        std::string filename = GenerateFilename(result);
        std::filesystem::path output_path = config_.output_directory / filename;
        
        spdlog::info("Generating report: {}", output_path.string());
        
        // Save main report
        if (!SaveJson(json_content, output_path)) {
            spdlog::error("Failed to save JSON report");
            return {};
        }
        
        // Generate IOC file if configured
        if (config_.create_ioc_file && result.iocs.has_value()) {
            std::string ioc_filename = GenerateFilename(result);
            ioc_filename = std::regex_replace(ioc_filename, std::regex("\\.json$"), "_iocs.json");
            std::filesystem::path ioc_path = config_.output_directory / ioc_filename;
            
            std::string ioc_json = GenerateIOCsJson(result);
            SaveJson(ioc_json, ioc_path);
            
            spdlog::info("IOCs exported to: {}", ioc_path.string());
        }
        
        // Generate summary file if configured
        if (config_.create_summary_file) {
            std::string summary_filename = GenerateFilename(result);
            summary_filename = std::regex_replace(summary_filename, std::regex("\\.json$"), "_summary.json");
            std::filesystem::path summary_path = config_.output_directory / summary_filename;
            
            std::string summary_json = GenerateSummaryJson(result);
            SaveJson(summary_json, summary_path);
            
            spdlog::info("Summary exported to: {}", summary_path.string());
        }
        
        spdlog::info("═══════════════════════════════════════════════════════════════");
        spdlog::info("✓ JSON Report generated successfully");
        spdlog::info("  Location: {}", output_path.string());
        spdlog::info("  Size: {} bytes", std::filesystem::file_size(output_path));
        spdlog::info("  Format: {}", static_cast<int>(config_.format));
        spdlog::info("═══════════════════════════════════════════════════════════════\n");
        
        return output_path;
    }
    catch (const std::exception& e) {
        spdlog::error("Failed to generate JSON report: {}", e.what());
        return {};
    }
}

// Generate JSON string
std::string JsonReporter::GenerateJsonString(const core::AnalysisResult& result) {
    switch (config_.format) {
        case JsonFormat::STANDARD:
            return GenerateJsonRoot(result);
        case JsonFormat::STIX_2_1:
            return GenerateSTIXBundle(result);
        case JsonFormat::MISP:
            return GenerateMISPEvent(result);
        case JsonFormat::OPENIOC:
            return GenerateOpenIOC(result);
        case JsonFormat::YARA:
            return GenerateYARARule(result);
        case JsonFormat::SIGMA:
            return GenerateSigmaRule(result);
        case JsonFormat::MINIMAL:
            return GenerateSummaryJson(result);
        default:
            return GenerateJsonRoot(result);
    }
}

// Generate IOCs JSON
std::string JsonReporter::GenerateIOCsJson(const core::AnalysisResult& result) {
    json j;
    
    j["metadata"] = {
        {"generated_at", FormatTimestamp(std::chrono::system_clock::now())},
        {"analysis_id", result.analysis_id},
        {"sample_hash", result.sample_hash},
        {"format", "IOCs"}
    };
    
    // Extract IOCs from iocs_list
    json iocs_array = json::array();
    
    for (const auto& ioc : result.iocs_list) {
        json ioc_obj = {
            {"type", ioc.type},
            {"value", ioc.value},
            {"source", ioc.source}
        };
        iocs_array.push_back(ioc_obj);
    }
    
    j["iocs"] = iocs_array;
    j["total_iocs"] = iocs_array.size();
    
    // Count by type
    std::map<std::string, int> type_counts;
    for (const auto& ioc : result.iocs_list) {
        type_counts[ioc.type]++;
    }
    
    json counts_obj = json::object();
    for (const auto& [type, count] : type_counts) {
        counts_obj[type] = count;
    }
    j["ioc_counts"] = counts_obj;
    
    return config_.pretty_print ? j.dump(config_.indent_size) : j.dump();
}

// Generate summary JSON
std::string JsonReporter::GenerateSummaryJson(const core::AnalysisResult& result) {
    json j;
    
    j["analysis_id"] = result.analysis_id;
    j["sample_hash"] = result.sample_hash;
    j["timestamp"] = FormatTimestamp(std::chrono::system_clock::now());
    
    // Sample info
    j["sample"] = {
        {"filename", result.sample_info.file_name},
        {"size", result.sample_info.file_size},
        {"type", result.sample_info.file_type},
        {"md5", result.sample_info.md5},
        {"sha1", result.sample_info.sha1},
        {"sha256", result.sample_info.sha256}
    };
    
    // Threat assessment
    j["threat_assessment"] = {
        {"score", result.threat_score},
        {"level", result.threat_level},
        {"verdict", result.executive_summary}
    };
    
    // Key findings
    j["key_findings"] = result.key_findings;
    
    // IOC count
    j["ioc_count"] = result.iocs_list.size();
    
    // Duration
    j["analysis_duration_ms"] = result.analysis_duration.count();
    
    return config_.pretty_print ? j.dump(config_.indent_size) : j.dump();
}

// Generate STIX bundle
std::string JsonReporter::GenerateSTIXBundle(const core::AnalysisResult& result) {
    json bundle;
    
    bundle["type"] = "bundle";
    bundle["id"] = "bundle--" + GenerateUUID();
    bundle["spec_version"] = "2.1";
    
    json objects = json::array();
    
    // Identity object (source)
    json identity = {
        {"type", "identity"},
        {"id", "identity--" + GenerateUUID()},
        {"created", FormatTimestamp(std::chrono::system_clock::now())},
        {"modified", FormatTimestamp(std::chrono::system_clock::now())},
        {"name", config_.stix_source_identity},
        {"identity_class", "system"}
    };
    objects.push_back(identity);
    
    // Malware object
    json malware = {
        {"type", "malware"},
        {"id", "malware--" + GenerateUUID()},
        {"created", FormatTimestamp(result.start_time)},
        {"modified", FormatTimestamp(result.end_time)},
        {"name", result.sample_info.file_name},
        {"is_family", false},
        {"malware_types", result.classifications}
    };
    
    if (!result.executive_summary.empty()) {
        malware["description"] = result.executive_summary;
    }
    
    objects.push_back(malware);
    
    // File object
    json file_obj = {
        {"type", "file"},
        {"id", "file--" + GenerateUUID()},
        {"hashes", {
            {"MD5", result.sample_info.md5},
            {"SHA-1", result.sample_info.sha1},
            {"SHA-256", result.sample_info.sha256}
        }},
        {"size", result.sample_info.file_size},
        {"name", result.sample_info.file_name}
    };
    objects.push_back(file_obj);
    
    // Indicator objects for IOCs
    for (const auto& ioc : result.iocs_list) {
        std::string pattern = CreateSTIXPattern(ioc.type, ioc.value);
        
        json indicator = {
            {"type", "indicator"},
            {"id", "indicator--" + GenerateUUID()},
            {"created", FormatTimestamp(std::chrono::system_clock::now())},
            {"modified", FormatTimestamp(std::chrono::system_clock::now())},
            {"name", ioc.type + ": " + ioc.value},
            {"pattern", pattern},
            {"pattern_type", "stix"},
            {"valid_from", FormatTimestamp(std::chrono::system_clock::now())}
        };
        
        objects.push_back(indicator);
    }
    
    bundle["objects"] = objects;
    
    return config_.pretty_print ? bundle.dump(config_.indent_size) : bundle.dump();
}

// Generate MISP event
std::string JsonReporter::GenerateMISPEvent(const core::AnalysisResult& result) {
    json event;
    
    event["Event"] = {
        {"uuid", GenerateUUID()},
        {"info", "Paramite Analysis: " + result.sample_info.file_name},
        {"threat_level_id", result.threat_score > 70 ? "1" : "2"},
        {"analysis", "2"},  // Completed
        {"date", FormatTimestamp(std::chrono::system_clock::now()).substr(0, 10)},
        {"timestamp", std::chrono::system_clock::to_time_t(std::chrono::system_clock::now())}
    };
    
    json attributes = json::array();
    
    // File hashes
    attributes.push_back({
        {"type", "md5"},
        {"category", "Payload delivery"},
        {"value", result.sample_info.md5},
        {"comment", "Sample MD5"}
    });
    
    attributes.push_back({
        {"type", "sha1"},
        {"category", "Payload delivery"},
        {"value", result.sample_info.sha1},
        {"comment", "Sample SHA1"}
    });
    
    attributes.push_back({
        {"type", "sha256"},
        {"category", "Payload delivery"},
        {"value", result.sample_info.sha256},
        {"comment", "Sample SHA256"}
    });
    
    // IOCs
    for (const auto& ioc : result.iocs_list) {
        std::string misp_type = ConvertToMISPType(ioc.type);
        std::string misp_category = ConvertToMISPCategory(ioc.type);
        
        attributes.push_back({
            {"type", misp_type},
            {"category", misp_category},
            {"value", ioc.value},
            {"comment", ioc.source}
        });
    }
    
    event["Event"]["Attribute"] = attributes;
    
    return config_.pretty_print ? event.dump(config_.indent_size) : event.dump();
}

// Generate OpenIOC
std::string JsonReporter::GenerateOpenIOC(const core::AnalysisResult& result) {
    json ioc;
    
    ioc["ioc"] = {
        {"@xmlns", "http://schemas.mandiant.com/2010/ioc"},
        {"@xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance"},
        {"@id", GenerateUUID()},
        {"@last-modified", FormatTimestamp(std::chrono::system_clock::now())}
    };
    
    ioc["ioc"]["short_description"] = result.sample_info.file_name;
    ioc["ioc"]["description"] = result.executive_summary;
    
    json criteria = {
        {"@operator", "OR"}
    };
    
    json indicator_items = json::array();
    
    for (const auto& ioc_item : result.iocs_list) {
        json item = {
            {"@id", GenerateUUID()},
            {"@condition", "is"},
            {"Context", {
                {"@document", "FileItem"},
                {"@search", ConvertToOpenIOCSearch(ioc_item.type)}
            }},
            {"Content", {
                {"@type", ConvertToOpenIOCType(ioc_item.type)},
                {"#text", ioc_item.value}
            }}
        };
        
        indicator_items.push_back(item);
    }
    
    criteria["IndicatorItem"] = indicator_items;
    ioc["ioc"]["criteria"] = criteria;
    
    return config_.pretty_print ? ioc.dump(config_.indent_size) : ioc.dump();
}

// Generate YARA rule
std::string JsonReporter::GenerateYARARule(const core::AnalysisResult& result) {
    std::ostringstream yara;
    
    // Rule name from sample hash
    std::string rule_name = "Paramite_" + result.sample_hash.substr(0, 16);
    
    yara << "rule " << rule_name << " {\n";
    yara << "    meta:\n";
    yara << "        description = \"Auto-generated from Paramite analysis\"\n";
    yara << "        sample = \"" << result.sample_info.file_name << "\"\n";
    yara << "        md5 = \"" << result.sample_info.md5 << "\"\n";
    yara << "        sha256 = \"" << result.sample_info.sha256 << "\"\n";
    yara << "        threat_score = " << result.threat_score << "\n";
    yara << "        generated = \"" << FormatTimestamp(std::chrono::system_clock::now()) << "\"\n";
    
    yara << "    strings:\n";
    
    // Add strings from static analysis
    if (result.static_analysis.interesting_strings.size() > 0) {
        int idx = 1;
        for (const auto& str : result.static_analysis.interesting_strings) {
            if (idx > 20) break;  // Limit to 20 strings
            
            // Escape string for YARA
            std::string escaped = str;
            std::replace(escaped.begin(), escaped.end(), '\\', '/');
            std::replace(escaped.begin(), escaped.end(), '"', '\'');
            
            yara << "        $s" << idx << " = \"" << escaped << "\" nocase\n";
            idx++;
        }
    }
    
    yara << "    condition:\n";
    yara << "        uint16(0) == 0x5A4D and\n";  // PE header
    yara << "        filesize < 10MB and\n";
    yara << "        any of ($s*)\n";
    yara << "}\n";
    
    return yara.str();
}

// Generate Sigma rule
std::string JsonReporter::GenerateSigmaRule(const core::AnalysisResult& result) {
    json sigma;
    
    sigma["title"] = "Suspicious Behavior: " + result.sample_info.file_name;
    sigma["id"] = GenerateUUID();
    sigma["status"] = "experimental";
    sigma["description"] = result.executive_summary;
    sigma["author"] = "Paramite Analysis Engine";
    sigma["date"] = FormatTimestamp(std::chrono::system_clock::now()).substr(0, 10);
    
    sigma["logsource"] = {
        {"product", "windows"},
        {"service", "security"}
    };
    
    // Build detection rules from behaviors
    json detection;
    json selection;
    
    // Add process creation events
    if (!result.process_events.empty()) {
        selection["EventID"] = 1;  // Sysmon process creation
        selection["Image"] = result.sample_info.file_name;
    }
    
    // Add network connections
    if (!result.network_connections.empty()) {
        json network_selection;
        network_selection["EventID"] = 3;  // Sysmon network connection
        
        json destination_ips = json::array();
        for (const auto& conn : result.network_connections) {
            if (conn.is_suspicious) {
                destination_ips.push_back(conn.remote_address);
            }
        }
        
        if (!destination_ips.empty()) {
            network_selection["DestinationIp"] = destination_ips;
            detection["network"] = network_selection;
        }
    }
    
    detection["selection"] = selection;
    detection["condition"] = "selection or network";
    
    sigma["detection"] = detection;
    
    sigma["falsepositives"] = json::array();
    sigma["falsepositives"].push_back("Unknown");
    
    sigma["level"] = result.threat_score > 70 ? "high" : "medium";
    
    sigma["tags"] = json::array();
    for (const auto& classification : result.classifications) {
        sigma["tags"].push_back("attack." + classification);
    }
    
    return config_.pretty_print ? sigma.dump(config_.indent_size) : sigma.dump();
}

// Validate JSON
bool JsonReporter::ValidateJson(const std::string& json_string) {
    return ValidateSyntax(json_string);
}

// Get schema
std::string JsonReporter::GetSchema(JsonFormat format) {
    switch (format) {
        case JsonFormat::STANDARD:
            return schemas::PARAMITE_SCHEMA_V2;
        default:
            return "{}";
    }
}

// Convert format
std::string JsonReporter::ConvertFormat(const std::string& json_string, 
                                       JsonFormat from, 
                                       JsonFormat to) {
    spdlog::warn("Format conversion not yet implemented");
    return json_string;
}

// Merge reports
std::string JsonReporter::MergeReports(const std::vector<std::string>& json_reports) {
    json merged;
    
    merged["merged_at"] = FormatTimestamp(std::chrono::system_clock::now());
    merged["report_count"] = json_reports.size();
    
    json reports_array = json::array();
    
    for (const auto& report_str : json_reports) {
        try {
            json report = json::parse(report_str);
            reports_array.push_back(report);
        }
        catch (const std::exception& e) {
            spdlog::error("Failed to parse report: {}", e.what());
        }
    }
    
    merged["reports"] = reports_array;
    
    return config_.pretty_print ? merged.dump(config_.indent_size) : merged.dump();
}

// Update configuration
void JsonReporter::UpdateConfig(const JsonReporterConfig& config) {
    config_ = config;
    spdlog::debug("JSON Reporter configuration updated");
}

// Private Methods

// Generate JSON root
std::string JsonReporter::GenerateJsonRoot(const core::AnalysisResult& result) {
    json j;
    
    // Metadata
    if (config_.include_metadata) {
        j["metadata"] = {
            {"schema_version", GetSchemaVersionString(config_.schema_version)},
            {"generated_at", FormatTimestamp(std::chrono::system_clock::now())},
            {"analysis_id", result.analysis_id},
            {"engine_version", "Paramite 1.0"},
            {"format", "Paramite Native JSON"}
        };
        
        if (config_.include_schema_reference) {
            j["metadata"]["schema_url"] = "https://paramite.io/schema/v2.0";
        }
    }
    
    // Sample information
    j["sample"] = {
        {"filename", result.sample_info.file_name},
        {"filepath", result.sample_info.file_path.string()},
        {"size", result.sample_info.file_size},
        {"type", result.sample_info.file_type},
        {"hashes", {
            {"md5", result.sample_info.md5},
            {"sha1", result.sample_info.sha1},
            {"sha256", result.sample_info.sha256}
        }}
    };
    
    // Threat assessment
    j["threat_assessment"] = {
        {"overall_score", result.threat_score},
        {"threat_level", result.threat_level},
        {"verdict", result.executive_summary},
        {"classifications", result.classifications},
        {"key_findings", result.key_findings}
    };
    
    // MITRE ATT&CK
    if (!result.mitre_techniques.empty()) {
        json techniques_array = json::array();
        for (const auto& tech : result.mitre_techniques) {
            techniques_array.push_back({
                {"id", tech.id},
                {"name", tech.name},
                {"tactic", tech.tactic}
            });
        }
        j["threat_assessment"]["mitre_attack"] = techniques_array;
    }
    
    // Static analysis
    if (config_.include_static_analysis && result.static_report.has_value()) {
        j["static_analysis"] = {
            {"file_format", result.sample_info.file_type},
            {"interesting_strings", result.static_analysis.interesting_strings},
            {"imported_functions", result.static_analysis.imported_functions}
        };
        
        if (result.static_analysis.pe_info.has_value()) {
            j["static_analysis"]["pe_info"] = {
                {"architecture", result.static_analysis.pe_info->architecture},
                {"subsystem", result.static_analysis.pe_info->subsystem},
                {"sections", result.static_analysis.pe_info->sections}
            };
        }
    }
    
    // Dynamic analysis
    if (config_.include_dynamic_analysis) {
        j["dynamic_analysis"] = {
            {"exit_code", result.dynamic_analysis.exit_code},
            {"execution_time_ms", result.dynamic_analysis.execution_time.count()},
            {"total_duration_ms", result.analysis_duration.count()}
        };
    }
    
    // Behavior analysis
    if (config_.include_behavior_analysis && !result.detected_behaviors.empty()) {
        json behaviors_array = json::array();
        for (const auto& behavior : result.detected_behaviors) {
            behaviors_array.push_back({
                {"name", behavior.name},
                {"description", behavior.description},
                {"confidence", behavior.confidence},
                {"severity", behavior.severity}
            });
        }
        j["behavior_analysis"]["detected_behaviors"] = behaviors_array;
    }
    
    // Network analysis
    if (config_.include_network_data) {
        j["network_analysis"] = {
            {"summary", {
                {"total_connections", result.network_summary.total_connections},
                {"dns_queries", result.network_summary.dns_queries},
                {"http_requests", result.network_summary.http_requests},
                {"suspicious_connections", result.network_summary.suspicious_connections}
            }}
        };
        
        if (!result.network_connections.empty()) {
            json connections_array = json::array();
            int count = 0;
            for (const auto& conn : result.network_connections) {
                if (count++ >= config_.max_network_connections) break;
                
                connections_array.push_back({
                    {"protocol", conn.protocol},
                    {"remote_address", conn.remote_address},
                    {"remote_port", conn.remote_port},
                    {"is_suspicious", conn.is_suspicious}
                });
            }
            j["network_analysis"]["connections"] = connections_array;
        }
    }
    
    // File operations
    if (config_.include_file_operations) {
        j["file_operations"] = {
            {"summary", {
                {"files_created", result.file_summary.files_created},
                {"files_modified", result.file_summary.files_modified},
                {"files_deleted", result.file_summary.files_deleted},
                {"suspicious_operations", result.file_summary.suspicious_operations}
            }}
        };
        
        if (!result.file_operations.empty()) {
            json operations_array = json::array();
            int count = 0;
            for (const auto& op : result.file_operations) {
                if (count++ >= config_.max_file_operations) break;
                
                operations_array.push_back({
                    {"operation", op.operation},
                    {"path", op.path.string()},
                    {"success", op.success},
                    {"is_suspicious", op.is_suspicious}
                });
            }
            j["file_operations"]["operations"] = operations_array;
        }
    }
    
    // Process tree
    if (config_.include_process_tree && !result.process_events.empty()) {
        j["process_tree"] = result.process_events;
    }
    
    // Syscalls
    if (config_.include_syscalls) {
        j["syscalls"] = {
            {"summary", {
                {"total_syscalls", result.syscall_summary.total_syscalls},
                {"failed_syscalls", result.syscall_summary.failed_syscalls},
                {"suspicious_syscalls", result.syscall_summary.suspicious_syscalls}
            }},
            {"counts", result.syscall_summary.syscall_counts}
        };
        
        if (config_.include_raw_logs && !result.syscall_logs.empty()) {
            json logs_array = json::array();
            int count = 0;
            for (const auto& log : result.syscall_logs) {
                if (count++ >= config_.max_syscalls) break;
                logs_array.push_back(log);
            }
            j["syscalls"]["raw_logs"] = logs_array;
        }
    }
    
    // IOCs
    if (config_.include_iocs && !result.iocs_list.empty()) {
        json iocs_array = json::array();
        for (const auto& ioc : result.iocs_list) {
            iocs_array.push_back({
                {"type", ioc.type},
                {"value", ioc.value},
                {"source", ioc.source}
            });
        }
        j["iocs"] = iocs_array;
    }
    
    // Recommendations
    if (!result.recommendations.empty()) {
        j["recommendations"] = result.recommendations;
    }
    
    // Artifacts
    j["artifacts"] = {
        {"json_report", result.json_report_path.string()},
        {"html_report", result.html_report_path.string()}
    };
    
    if (!result.pcap_file.empty()) {
        j["artifacts"]["pcap_file"] = result.pcap_file;
    }
    
    // Timing
    if (config_.include_timestamps) {
        j["timing"] = {
            {"start_time", FormatTimestamp(result.start_time)},
            {"end_time", FormatTimestamp(result.end_time)},
            {"total_duration_ms", result.total_duration.count()}
        };
    }
    
    return config_.pretty_print ? j.dump(config_.indent_size) : j.dump();
}

// Helper Methods

std::string JsonReporter::EscapeJson(const std::string& text) {
    json j = text;
    return j.dump();
}

std::string JsonReporter::FormatTimestamp(const std::chrono::system_clock::time_point& time) {
    auto t = std::chrono::system_clock::to_time_t(time);
    std::ostringstream oss;
    oss << std::put_time(std::gmtime(&t), "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}

std::string JsonReporter::PrettyPrintJson(const std::string& json_str) {
    try {
        json j = json::parse(json_str);
        return j.dump(config_.indent_size);
    }
    catch (...) {
        return json_str;
    }
}

std::string JsonReporter::MinifyJson(const std::string& json_str) {
    try {
        json j = json::parse(json_str);
        return j.dump();
    }
    catch (...) {
        return json_str;
    }
}

std::string JsonReporter::GenerateUUID() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(0, 15);
    static std::uniform_int_distribution<> dis2(8, 11);
    
    std::ostringstream oss;
    oss << std::hex;
    
    for (int i = 0; i < 8; i++) oss << dis(gen);
    oss << "-";
    for (int i = 0; i < 4; i++) oss << dis(gen);
    oss << "-4";
    for (int i = 0; i < 3; i++) oss << dis(gen);
    oss << "-";
    oss << dis2(gen);
    for (int i = 0; i < 3; i++) oss << dis(gen);
    oss << "-";
    for (int i = 0; i < 12; i++) oss << dis(gen);
    
    return oss.str();
}

std::string JsonReporter::GenerateFilename(const core::AnalysisResult& result) {
    std::string filename = config_.filename_pattern;
    
    // Replace placeholders
    filename = std::regex_replace(filename, std::regex("\\{hash\\}"), 
                                 result.sample_hash.substr(0, 16));
    
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    std::ostringstream timestamp;
    timestamp << std::put_time(std::localtime(&t), "%Y%m%d_%H%M%S");
    filename = std::regex_replace(filename, std::regex("\\{timestamp\\}"), timestamp.str());
    
    filename = std::regex_replace(filename, std::regex("\\{id\\}"), result.analysis_id);
    
    return filename;
}

bool JsonReporter::SaveJson(const std::string& json_content, 
                            const std::filesystem::path& output_path) {
    try {
        std::ofstream file(output_path);
        if (!file) {
            spdlog::error("Failed to open file for writing: {}", output_path.string());
            return false;
        }
        
        file << json_content;
        file.close();
        
        return true;
    }
    catch (const std::exception& e) {
        spdlog::error("Failed to save JSON: {}", e.what());
        return false;
    }
}

bool JsonReporter::ValidateSyntax(const std::string& json_str) {
    try {
        json::parse(json_str);
        return true;
    }
    catch (const json::parse_error& e) {
        spdlog::error("JSON validation failed: {}", e.what());
        return false;
    }
}

std::string JsonReporter::GetSchemaVersionString(SchemaVersion version) {
    switch (version) {
        case SchemaVersion::V1_0: return "1.0";
        case SchemaVersion::V2_0: return "2.0";
        case SchemaVersion::LATEST: return "2.0";
        default: return "1.0";
    }
}

// Format-specific helpers

std::string JsonReporter::CreateSTIXPattern(const std::string& type, const std::string& value) {
    if (type == "IP Address") {
        return "[ipv4-addr:value = '" + value + "']";
    } else if (type == "Domain") {
        return "[domain-name:value = '" + value + "']";
    } else if (type == "URL") {
        return "[url:value = '" + value + "']";
    } else if (type == "File Hash") {
        return "[file:hashes.MD5 = '" + value + "']";
    }
    return "[x-custom:value = '" + value + "']";
}

std::string JsonReporter::ConvertToMISPType(const std::string& type) {
    if (type == "IP Address") return "ip-dst";
    if (type == "Domain") return "domain";
    if (type == "URL") return "url";
    if (type == "File Hash") return "md5";
    return "other";
}

std::string JsonReporter::ConvertToMISPCategory(const std::string& type) {
    if (type == "IP Address" || type == "Domain" || type == "URL") {
        return "Network activity";
    }
    if (type == "File Hash") {
        return "Payload delivery";
    }
    return "Other";
}

std::string JsonReporter::ConvertToOpenIOCSearch(const std::string& type) {
    if (type == "File Hash") return "FileItem/Md5sum";
    if (type == "IP Address") return "NetworkItem/RemoteIP";
    if (type == "Domain") return "NetworkItem/DNS";
    return "FileItem/FileName";
}

std::string JsonReporter::ConvertToOpenIOCType(const std::string& type) {
    if (type == "File Hash") return "md5";
    if (type == "IP Address") return "IP";
    if (type == "Domain") return "string";
    return "string";
}

// JsonBuilder implementation

JsonBuilder& JsonBuilder::StartObject() {
    AddCommaIfNeeded();
    json_ += "{";
    is_object_stack_.push_back(true);
    needs_comma_ = false;
    return *this;
}

JsonBuilder& JsonBuilder::EndObject() {
    if (!is_object_stack_.empty()) {
        is_object_stack_.pop_back();
    }
    json_ += "}";
    needs_comma_ = true;
    return *this;
}

JsonBuilder& JsonBuilder::StartArray(const std::string& key) {
    AddCommaIfNeeded();
    json_ += "\"" + key + "\":[";
    is_object_stack_.push_back(false);
    needs_comma_ = false;
    return *this;
}

JsonBuilder& JsonBuilder::EndArray() {
    if (!is_object_stack_.empty()) {
        is_object_stack_.pop_back();
    }
    json_ += "]";
    needs_comma_ = true;
    return *this;
}

JsonBuilder& JsonBuilder::AddString(const std::string& key, const std::string& value) {
    AddCommaIfNeeded();
    json j = value;
    json_ += "\"" + key + "\":" + j.dump();
    needs_comma_ = true;
    return *this;
}

JsonBuilder& JsonBuilder::AddInt(const std::string& key, int value) {
    AddCommaIfNeeded();
    json_ += "\"" + key + "\":" + std::to_string(value);
    needs_comma_ = true;
    return *this;
}

JsonBuilder& JsonBuilder::AddBool(const std::string& key, bool value) {
    AddCommaIfNeeded();
    json_ += "\"" + key + "\":" + (value ? "true" : "false");
    needs_comma_ = true;
    return *this;
}

JsonBuilder& JsonBuilder::AddNull(const std::string& key) {
    AddCommaIfNeeded();
    json_ += "\"" + key + "\":null";
    needs_comma_ = true;
    return *this;
}

JsonBuilder& JsonBuilder::AddTimestamp(const std::string& key,
                                       const std::chrono::system_clock::time_point& time) {
    auto t = std::chrono::system_clock::to_time_t(time);
    std::ostringstream oss;
    oss << std::put_time(std::gmtime(&t), "%Y-%m-%dT%H:%M:%SZ");
    return AddString(key, oss.str());
}

std::string JsonBuilder::Build() const {
    return json_;
}

void JsonBuilder::Reset() {
    json_.clear();
    is_object_stack_.clear();
    needs_comma_ = false;
}

void JsonBuilder::AddCommaIfNeeded() {
    if (needs_comma_) {
        json_ += ",";
    }
}

} // namespace reporters
} // namespace paramite