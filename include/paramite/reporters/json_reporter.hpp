/**
 * @file json_reporter.hpp
 * @brief Machine-readable JSON report generation with multiple format support
 * 
 * Provides comprehensive JSON report generation supporting multiple industry-standard
 * formats including STIX 2.1, MISP, OpenIOC, YARA, and Sigma. Enables automation,
 * API integration, and threat intelligence platform connectivity.
 * 
 * @date 2025
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <filesystem>
#include <optional>
#include <chrono>

namespace paramite {

// Forward declarations
namespace core {
    struct AnalysisResult;
}

namespace reporters {

/**
 * @enum JsonFormat
 * @brief Supported JSON output formats
 */
enum class JsonFormat {
    STANDARD,    ///< Paramite native format (most detailed)
    STIX_2_1,    ///< STIX 2.1 (Structured Threat Information Expression)
    MISP,        ///< MISP (Malware Information Sharing Platform)
    OPENIOC,     ///< OpenIOC format (Mandiant)
    YARA,        ///< YARA rule format
    SIGMA,       ///< Sigma rule format (SIEM detection)
    ELASTIC,     ///< ElasticSearch / ECS format
    SPLUNK,      ///< Splunk Common Information Model
    MINIMAL      ///< Minimal format (IOCs and summary only)
};

/**
 * @enum SchemaVersion
 * @brief JSON schema version
 */
enum class SchemaVersion {
    V1_0,    ///< Schema version 1.0 (legacy)
    V2_0,    ///< Schema version 2.0 (current)
    LATEST   ///< Always use latest version
};

/**
 * @struct JsonReporterConfig
 * @brief Configuration for JSON report generation
 */
struct JsonReporterConfig {
    // Output Format
    JsonFormat format{JsonFormat::STANDARD};         ///< Output format
    SchemaVersion schema_version{SchemaVersion::LATEST};  ///< Schema version
    
    // Content Options
    bool include_metadata{true};          ///< Include metadata section
    bool include_static_analysis{true};   ///< Include static analysis
    bool include_dynamic_analysis{true};  ///< Include dynamic analysis
    bool include_behavior_analysis{true}; ///< Include behavioral analysis
    bool include_network_data{true};      ///< Include network data
    bool include_file_operations{true};   ///< Include file operations
    bool include_process_tree{true};      ///< Include process tree
    bool include_syscalls{true};          ///< Include system calls
    bool include_iocs{true};              ///< Include IOCs
    bool include_raw_logs{false};         ///< Include raw logs (large)
    
    // Formatting
    bool pretty_print{true};              ///< Pretty print JSON
    int indent_size{2};                   ///< Indentation spaces
    bool include_timestamps{true};        ///< Include timestamps
    bool include_schema_reference{true};  ///< Include schema $ref
    
    // Data Filtering
    bool include_successful_operations{true};  ///< Include successful syscalls
    bool include_failed_operations{true};      ///< Include failed syscalls
    int max_syscalls{10000};                   ///< Max syscalls to include
    int max_network_connections{1000};         ///< Max network connections
    int max_file_operations{1000};             ///< Max file operations
    
    // IOC Options
    bool include_low_confidence_iocs{false};  ///< Include low confidence IOCs
    int min_ioc_confidence{70};               ///< Minimum IOC confidence (0-100)
    bool deduplicate_iocs{true};              ///< Remove duplicate IOCs
    
    // STIX Options
    std::string stix_source_identity{"Paramite Analysis Engine"};  ///< STIX source
    bool include_stix_relationships{true};     ///< Include STIX relationships
    bool include_stix_sightings{true};         ///< Include STIX sightings
    
    // Output
    std::filesystem::path output_directory{"./reports"};  ///< Output directory
    std::string filename_pattern{"{hash}_{timestamp}.json"};  ///< Filename pattern
    bool create_ioc_file{true};       ///< Create separate IOCs.json file
    bool create_summary_file{true};   ///< Create separate summary.json file
    
    // Validation
    bool validate_json{true};              ///< Validate JSON syntax
    bool validate_against_schema{false};   ///< Validate against JSON schema
    std::filesystem::path schema_file;     ///< External schema file path
};

/**
 * @struct JsonSection
 * @brief JSON section metadata
 */
struct JsonSection {
    std::string name;                               ///< Section name
    std::string version;                            ///< Section version
    std::chrono::system_clock::time_point generated_at;  ///< Generation time
    std::map<std::string, std::string> metadata;    ///< Additional metadata
};

/**
 * @class JsonReporter
 * @brief Machine-readable JSON report generator
 * 
 * Generates structured JSON reports in multiple formats for:
 * - **Automation**: API integration and programmatic access
 * - **Threat Intelligence**: STIX, MISP, OpenIOC formats
 * - **SIEM Integration**: ElasticSearch, Splunk formats
 * - **Detection Rules**: YARA, Sigma rule generation
 * - **Data Exchange**: Standardized format sharing
 * 
 * **Supported Formats**:
 * - **STANDARD**: Paramite native format (most comprehensive)
 * - **STIX 2.1**: OASIS CTI standard for threat intelligence
 * - **MISP**: Malware Information Sharing Platform format
 * - **OpenIOC**: Mandiant Indicator of Compromise format
 * - **YARA**: Detection rule format
 * - **Sigma**: Generic SIEM detection rule format
 * - **MINIMAL**: Summary and IOCs only
 * 
 * **Usage Example**:
 * @code
 * JsonReporterConfig config;
 * config.format = JsonFormat::STIX_2_1;
 * config.pretty_print = true;
 * config.include_stix_relationships = true;
 * 
 * JsonReporter reporter(config);
 * 
 * // Generate STIX bundle
 * auto report_path = reporter.GenerateReport(analysis_result);
 * 
 * // Or get as string for API response
 * std::string json = reporter.GenerateJsonString(analysis_result);
 * 
 * // Generate IOCs only
 * std::string iocs_json = reporter.GenerateIOCsJson(analysis_result);
 * @endcode
 */
class JsonReporter {
public:
    /**
     * @brief Construct JSON reporter with configuration
     * @param config Reporter configuration
     */
    explicit JsonReporter(const JsonReporterConfig& config = JsonReporterConfig{});
    
    ~JsonReporter();

    /**
     * @brief Generate JSON report and save to file
     * 
     * @param result Complete analysis result
     * @return Path to generated JSON file
     */
    std::filesystem::path GenerateReport(const core::AnalysisResult& result);

    /**
     * @brief Generate JSON string without saving to file
     * 
     * @param result Analysis result
     * @return JSON string
     */
    std::string GenerateJsonString(const core::AnalysisResult& result);

    /**
     * @brief Generate IOCs-only JSON
     * 
     * @param result Analysis result
     * @return JSON string with IOCs only
     */
    std::string GenerateIOCsJson(const core::AnalysisResult& result);

    /**
     * @brief Generate summary JSON (minimal output)
     * 
     * @param result Analysis result
     * @return JSON string with summary only
     */
    std::string GenerateSummaryJson(const core::AnalysisResult& result);

    /**
     * @brief Generate STIX 2.1 bundle
     * 
     * @param result Analysis result
     * @return STIX 2.1 JSON bundle
     */
    std::string GenerateSTIXBundle(const core::AnalysisResult& result);

    /**
     * @brief Generate MISP event JSON
     * 
     * @param result Analysis result
     * @return MISP event JSON
     */
    std::string GenerateMISPEvent(const core::AnalysisResult& result);

    /**
     * @brief Generate OpenIOC format
     * 
     * @param result Analysis result
     * @return OpenIOC XML/JSON
     */
    std::string GenerateOpenIOC(const core::AnalysisResult& result);

    /**
     * @brief Generate YARA rule from IOCs
     * 
     * @param result Analysis result
     * @return YARA rule string
     */
    std::string GenerateYARARule(const core::AnalysisResult& result);

    /**
     * @brief Generate Sigma detection rule
     * 
     * @param result Analysis result
     * @return Sigma rule YAML string
     */
    std::string GenerateSigmaRule(const core::AnalysisResult& result);

    /**
     * @brief Validate JSON against schema
     * 
     * @param json_string JSON to validate
     * @return true if valid
     */
    bool ValidateJson(const std::string& json_string);

    /**
     * @brief Get JSON schema for format
     * 
     * @param format Format to get schema for
     * @return JSON schema string
     */
    std::string GetSchema(JsonFormat format = JsonFormat::STANDARD);

    /**
     * @brief Convert between JSON formats
     * 
     * @param json_string Input JSON
     * @param from Source format
     * @param to Target format
     * @return Converted JSON
     */
    std::string ConvertFormat(const std::string& json_string, 
                             JsonFormat from, 
                             JsonFormat to);

    /**
     * @brief Merge multiple JSON reports
     * 
     * @param json_reports Vector of JSON report strings
     * @return Merged JSON report
     */
    std::string MergeReports(const std::vector<std::string>& json_reports);

    /**
     * @brief Get current configuration
     * @return Reference to config
     */
    const JsonReporterConfig& GetConfig() const { return config_; }

    /**
     * @brief Update reporter configuration
     * @param config New configuration
     */
    void UpdateConfig(const JsonReporterConfig& config);

private:
    JsonReporterConfig config_;  ///< Configuration

    // JSON Generation Methods (internal)
    std::string GenerateJsonRoot(const core::AnalysisResult& result);
    std::string GenerateMetadata(const core::AnalysisResult& result);
    std::string GenerateSampleInfo(const core::AnalysisResult& result);
    std::string GenerateThreatAssessment(const core::AnalysisResult& result);
    std::string GenerateStaticAnalysis(const core::AnalysisResult& result);
    std::string GenerateDynamicAnalysis(const core::AnalysisResult& result);
    std::string GenerateBehaviorAnalysis(const core::AnalysisResult& result);
    std::string GenerateNetworkAnalysis(const core::AnalysisResult& result);
    std::string GenerateFileOperations(const core::AnalysisResult& result);
    std::string GenerateProcessTree(const core::AnalysisResult& result);
    std::string GenerateSyscalls(const core::AnalysisResult& result);
    std::string GenerateIOCs(const core::AnalysisResult& result);
    std::string GenerateTimeline(const core::AnalysisResult& result);
    std::string GenerateArtifacts(const core::AnalysisResult& result);
    
    // Format-Specific Methods
    std::string ConvertToSTIX(const core::AnalysisResult& result);
    std::string CreateSTIXIndicator(const std::string& ioc, const std::string& type);
    std::string CreateSTIXMalware(const core::AnalysisResult& result);
    std::string CreateSTIXRelationship(const std::string& source_id,
                                       const std::string& target_id,
                                       const std::string& relationship_type);
    std::string ConvertToMISP(const core::AnalysisResult& result);
    std::string CreateMISPAttribute(const std::string& type,
                                    const std::string& value,
                                    const std::string& category);
    std::string ConvertToOpenIOC(const core::AnalysisResult& result);
    std::string CreateOpenIOCIndicator(const std::string& ioc,
                                       const std::string& type);
    
    // Helper Methods
    std::string EscapeJson(const std::string& text);
    std::string FormatTimestamp(const std::chrono::system_clock::time_point& time);
    std::string PrettyPrintJson(const std::string& json);
    std::string MinifyJson(const std::string& json);
    std::string GenerateUUID();
    std::string GenerateFilename(const core::AnalysisResult& result);
    bool SaveJson(const std::string& json_content,
                 const std::filesystem::path& output_path);
    std::vector<std::string> FilterIOCsByConfidence(
        const std::vector<std::string>& iocs,
        int min_confidence);
    std::vector<std::string> DeduplicateIOCs(
        const std::vector<std::string>& iocs);
    bool ValidateSyntax(const std::string& json);
    std::string GetSchemaVersionString(SchemaVersion version);
    
    template<typename T>
    std::string CreateJsonArray(const std::vector<T>& items);
    
    std::string CreateJsonObject(const std::map<std::string, std::string>& data);
    std::string CreateSTIXPattern(const std::string& type, const std::string& value);
    std::string ConvertToMISPType(const std::string& type);
    std::string ConvertToMISPCategory(const std::string& type);
    std::string ConvertToOpenIOCSearch(const std::string& type);
    std::string ConvertToOpenIOCType(const std::string& type);
};

/**
 * @namespace schemas
 * @brief JSON Schema definitions for various formats
 */
namespace schemas {

/// Paramite native JSON schema (v2.0)
inline const char* PARAMITE_SCHEMA_V2 = R"({
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "Paramite Malware Analysis Report",
  "version": "2.0",
  "type": "object",
  "required": ["metadata", "sample", "analysis"],
  "properties": {
    "metadata": {
      "type": "object",
      "properties": {
        "version": {"type": "string"},
        "generated_at": {"type": "string", "format": "date-time"},
        "analysis_id": {"type": "string"},
        "engine_version": {"type": "string"}
      }
    },
    "sample": {
      "type": "object",
      "properties": {
        "hash_md5": {"type": "string"},
        "hash_sha1": {"type": "string"},
        "hash_sha256": {"type": "string"},
        "file_size": {"type": "integer"},
        "file_type": {"type": "string"},
        "file_name": {"type": "string"}
      }
    },
    "analysis": {
      "type": "object",
      "properties": {
        "threat_score": {"type": "integer", "minimum": 0, "maximum": 100},
        "threat_level": {"type": "string"},
        "verdict": {"type": "string"},
        "static_analysis": {"type": "object"},
        "dynamic_analysis": {"type": "object"},
        "behavior_analysis": {"type": "object"},
        "network_analysis": {"type": "object"},
        "iocs": {"type": "array"}
      }
    }
  }
})";

/// STIX 2.1 schema reference URL
inline const char* STIX_2_1_SCHEMA_URL = "https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html";

/// MISP format reference URL
inline const char* MISP_FORMAT_URL = "https://www.misp-project.org/datamodels/";

/// OpenIOC schema reference URL
inline const char* OPENIOC_SCHEMA_URL = "http://www.openioc.org/";

} // namespace schemas

/**
 * @class JsonBuilder
 * @brief Fluent API for building JSON documents
 * 
 * **Usage Example**:
 * @code
 * JsonBuilder builder;
 * std::string json = builder
 *     .StartObject()
 *     .AddString("name", "malware.exe")
 *     .AddInt("threat_score", 85)
 *     .AddBool("is_malicious", true)
 *     .StartArray("iocs")
 *         .AddString("", "192.168.1.1")
 *         .AddString("", "evil.com")
 *     .EndArray()
 *     .EndObject()
 *     .Build();
 * @endcode
 */
class JsonBuilder {
public:
    JsonBuilder& StartObject();
    JsonBuilder& EndObject();
    JsonBuilder& StartArray(const std::string& key);
    JsonBuilder& EndArray();
    JsonBuilder& AddString(const std::string& key, const std::string& value);
    JsonBuilder& AddInt(const std::string& key, int value);
    JsonBuilder& AddBool(const std::string& key, bool value);
    JsonBuilder& AddNull(const std::string& key);
    JsonBuilder& AddTimestamp(const std::string& key, 
                             const std::chrono::system_clock::time_point& time);
    std::string Build() const;
    void Reset();

private:
    std::string json_;                    ///< JSON being built
    std::vector<bool> is_object_stack_;   ///< Stack: true=object, false=array
    bool needs_comma_{false};             ///< Comma needed before next item
    
    void AddCommaIfNeeded();
};

} // namespace reporters
} // namespace paramite