/**
 * @file analysis_engine.hpp
 * @brief Core orchestration engine for comprehensive malware analysis workflows
 *
 * Coordinates all analysis components (static, dynamic, behavioral) and manages
 * the complete analysis lifecycle from sample intake through report generation.
 * Provides both synchronous and asynchronous analysis capabilities with support
 * for batch processing and concurrent analyses.
 *
 * @date 2025
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <filesystem>
#include <optional>
#include <future>
#include <functional>
#include <mutex>
#include <chrono>

#include "sample_manager.hpp"
#include "sandbox_engine.hpp"

#include "paramite/analyzers/static_analyzer.hpp"
#include "paramite/analyzers/behavior_analyzer.hpp"
#include "paramite/analyzers/ioc_extractor.hpp"
#include "paramite/parsers/strace_parser.hpp"
#include "paramite/parsers/wine_parser.hpp"

namespace paramite {

namespace core {

/**
 * @enum AnalysisPhase
 * @brief Sequential phases of the malware analysis pipeline
 *
 * Tracks progress through the analysis workflow. Each phase represents
 * a major step in the analysis process.
 */
enum class AnalysisPhase {
    INITIALIZATION,       ///< Engine initialization and setup
    SAMPLE_INTAKE,        ///< Sample loading and validation
    STATIC_ANALYSIS,      ///< Pre-execution analysis (PE/ELF parsing, strings, entropy)
    SANDBOX_SETUP,        ///< Docker container preparation
    DYNAMIC_EXECUTION,    ///< Malware execution in sandbox
    BEHAVIOR_ANALYSIS,    ///< Behavioral pattern matching and scoring
    IOC_EXTRACTION,       ///< Indicator of Compromise extraction
    REPORT_GENERATION,    ///< HTML/JSON report creation
    CLEANUP,              ///< Artifact cleanup and finalization
    COMPLETED,            ///< Analysis successfully completed
    FAILED                ///< Analysis failed (check error_message)
};

/**
 * @enum AnalysisPriority
 * @brief Priority levels for analysis queue management
 *
 * Used when multiple analyses are queued to determine execution order.
 * Higher priority analyses are processed first.
 */
enum class AnalysisPriority {
    LOW,        ///< Background analysis, no urgency
    NORMAL,     ///< Standard priority
    HIGH,       ///< Expedited analysis
    CRITICAL    ///< Emergency analysis, highest priority
};

/**
 * @struct AnalysisStatus
 * @brief Real-time status information for active analysis
 *
 * Provides progress tracking and error reporting for long-running analyses.
 * Can be polled asynchronously to monitor analysis progress.
 */
struct AnalysisStatus {
    std::string analysis_id;                              ///< Unique analysis identifier (UUID)
    AnalysisPhase current_phase;                          ///< Current pipeline phase
    float progress_percentage{0.0f};                      ///< Overall progress (0.0-100.0)
    std::string status_message;                           ///< Human-readable status
    std::chrono::system_clock::time_point start_time;    ///< Analysis start time
    std::optional<std::chrono::system_clock::time_point> end_time;  ///< Completion time (if finished)
    bool is_complete{false};                              ///< Analysis finished (success or failure)
    bool has_error{false};                                ///< Error occurred during analysis
    std::string error_message;                            ///< Error details (if has_error = true)
};

/**
 * @struct AnalysisConfig
 * @brief Configuration parameters for malware analysis
 *
 * Controls which analysis phases to execute, monitoring options,
 * resource limits, and output formats. Provides fine-grained control
 * over the analysis pipeline.
 *
 * **Common Configurations**:
 * - Quick scan: static_only, no sandbox
 * - Full analysis: all phases enabled, extended timeout
 * - IOC extraction: minimal analysis, focus on indicators
 */
struct AnalysisConfig {
    // Sample Information
    std::filesystem::path sample_path;           ///< Path to malware sample file
    std::string sample_name;                     ///< Optional custom name
    AnalysisPriority priority{AnalysisPriority::NORMAL};  ///< Queue priority

    // Analysis Phase Selection
    bool perform_static_analysis{true};          ///< Enable static analysis (always recommended)
    bool perform_dynamic_analysis{true};         ///< Execute in sandbox
    bool perform_behavior_analysis{true};        ///< Behavioral pattern matching
    bool extract_iocs{true};                     ///< Extract indicators of compromise

    // Execution Settings
    std::chrono::seconds execution_timeout{300};      ///< Sandbox runtime limit (default: 5 min)
    std::chrono::seconds analysis_timeout{600};       ///< Total analysis timeout (default: 10 min)
    bool enable_network{true};                        ///< Allow network in sandbox (isolated)
    bool enable_internet{false};                      ///< Allow internet access (dangerous!)

    // Resource Limits (prevents resource exhaustion)
    std::size_t max_memory_mb{2048};             ///< Maximum RAM for sandbox (MB)
    int max_cpu_cores{2};                        ///< CPU cores allocated to sandbox
    std::size_t max_disk_mb{1024};               ///< Disk space limit (MB)

    // Monitoring Options
    bool monitor_syscalls{true};                 ///< Enable strace syscall monitoring
    bool monitor_network{true};                  ///< Capture network traffic (tcpdump)
    bool monitor_filesystem{true};               ///< Monitor file operations (inotify)
    bool monitor_processes{true};                ///< Track process creation/termination
    bool capture_screenshots{false};             ///< Take periodic screenshots (Windows malware)

    // Output Configuration
    bool generate_json_report{true};             ///< Generate JSON report
    bool generate_html_report{true};             ///< Generate HTML report
    bool generate_timeline{true};                ///< Create behavioral timeline
    bool export_iocs{true};                      ///< Export IOCs to separate file
    std::filesystem::path output_directory{"./reports"};  ///< Report output directory

    // Advanced Options
    std::map<std::string, std::string> custom_parameters;  ///< Custom key-value parameters
    std::vector<std::string> tags;                         ///< Tags for organization/filtering
};

/**
 * @struct AnalysisResult
 * @brief Comprehensive results of malware analysis
 *
 * Contains all analysis outputs including static analysis, behavioral
 * findings, extracted IOCs, monitoring data, threat scoring, and
 * MITRE ATT&CK mappings. This is the primary output of the analysis engine.
 *
 * **Key Components**:
 * - Static analysis: File metadata, strings, entropy, PE/ELF info
 * - Behavioral analysis: Pattern matches, syscalls, network activity
 * - IOCs: Network, file, process indicators
 * - Threat scoring: Numerical score and classification
 * - Reports: Paths to generated HTML/JSON reports
 */
struct AnalysisResult {
    // Identifiers
    std::string analysis_id;                     ///< Unique analysis ID
    std::string sample_hash;                     ///< SHA-256 of analyzed sample

    // Status
    AnalysisStatus status;                       ///< Current analysis status

    // Component Results
    std::optional<SampleMetadata> sample_metadata;                     ///< Sample metadata
    std::optional<analyzers::StaticAnalysisReport> static_report;      ///< Static analysis results
    std::optional<analyzers::BehaviorAnalysisReport> behavior_report;  ///< Behavioral findings
    std::optional<analyzers::IOCCollection> iocs;                      ///< Extracted IOCs

    // Execution Data
    std::vector<std::string> syscall_logs;       ///< System call traces
    std::vector<std::string> network_logs;       ///< Network packet captures
    std::vector<std::string> file_changes;       ///< File system modifications
    std::vector<std::string> process_events;     ///< Process creation/termination

    // Summary Intelligence
    std::string executive_summary;               ///< High-level summary for stakeholders
    int overall_threat_score{0};                 ///< Aggregate threat score (0-1000)
    std::string threat_level;                    ///< Classification (Safe, Low, Medium, High, Critical)
    std::vector<std::string> key_findings;       ///< Top N most significant findings
    std::vector<std::string> classifications;    ///< Malware classifications (trojan, ransomware, etc.)
    std::vector<std::string> recommendations;    ///< Security recommendations

    // Sandbox Execution Results
    bool sandbox_executed{false};                ///< Sandbox was run
    bool sandbox_timeout{false};                 ///< Execution timed out
    bool sandbox_crashed{false};                 ///< Sample crashed
    int sandbox_exit_code{0};                    ///< Process exit code
    int64_t sandbox_duration_ms{0};              ///< Execution time in milliseconds
    std::vector<std::string> sandbox_artifacts;  ///< Collected artifacts (PCAPs, logs)

    // Artifact Paths
    std::filesystem::path strace_log;            ///< Path to strace output
    std::filesystem::path wine_log;              ///< Path to Wine debug log
    std::filesystem::path network_pcap;          ///< Path to PCAP file
    std::filesystem::path file_changes_log;      ///< Path to file change log

    // Sample Information (convenience accessors)
    struct SampleInfo {
        std::string file_name;
        std::filesystem::path file_path;
        std::size_t file_size{0};
        std::string file_type;
        std::string md5;
        std::string sha1;
        std::string sha256;
    } sample_info;

    // Threat Assessment
    int threat_score{0};                         ///< Normalized threat score (0-100)
    std::string threat_description;              ///< Textual threat description

    /**
     * @struct MitreTechnique
     * @brief MITRE ATT&CK technique mapping
     */
    struct MitreTechnique {
        std::string id;            ///< Technique ID (e.g., "T1055")
        std::string name;          ///< Technique name (e.g., "Process Injection")
        std::string tactic;        ///< Tactic name (e.g., "Defense Evasion")
    };
    std::vector<MitreTechnique> mitre_techniques;  ///< MITRE ATT&CK mappings

    // PE Information (if applicable)
    struct PEInfo {
        std::string architecture;
        std::string subsystem;
        std::chrono::system_clock::time_point compile_time;
        std::vector<std::string> sections;
    };

    // Static Analysis Summary (quick access)
    struct StaticAnalysisSummary {
        std::optional<PEInfo> pe_info;                  ///< PE-specific info
        std::vector<std::string> interesting_strings;   ///< Notable strings
        std::vector<std::string> imported_functions;    ///< Imported API calls
    } static_analysis;

    // Dynamic Analysis Summary
    struct DynamicAnalysisSummary {
        int exit_code{0};                          ///< Process exit code
        std::chrono::milliseconds execution_time{0};  ///< Runtime duration
    } dynamic_analysis;

    // Detected Behaviors
    struct DetectedBehavior {
        std::string name;           ///< Behavior name (e.g., "Process Injection")
        std::string description;    ///< Detailed description
        int confidence{0};          ///< Confidence score (0-100)
        std::string severity;       ///< Severity level
    };
    std::vector<DetectedBehavior> detected_behaviors;

    // Network Summary
    struct NetworkSummary {
        int total_connections{0};
        int dns_queries{0};
        int http_requests{0};
        int suspicious_connections{0};
    } network_summary;

    struct NetworkConnection {
        std::string protocol;       ///< TCP/UDP/ICMP
        std::string remote_address; ///< IP or domain
        int remote_port{0};
        bool is_suspicious{false};
    };
    std::vector<NetworkConnection> network_connections;

    // File Operations Summary
    struct FileSummary {
        int files_created{0};
        int files_modified{0};
        int files_deleted{0};
        int suspicious_operations{0};
    } file_summary;

    struct FileOperation {
        std::string operation;          ///< CREATE/MODIFY/DELETE
        std::filesystem::path path;
        bool success{false};
        bool is_suspicious{false};
    };
    std::vector<FileOperation> file_operations;

    parsers::SyscallSummary syscall_summary;     ///< System call statistics

    // Process Tree Data
    parsers::ProcessTree process_tree;           ///< Hierarchical process tree
    parsers::ProcessSummary process_summary;     ///< Process statistics

    // IOC Structure (flattened for rendering)
    struct IOC {
        std::string type;    ///< IOC type (ip, domain, file, process)
        std::string value;   ///< IOC value
        std::string source;  ///< Where IOC was found
    };
    std::vector<IOC> iocs_list;                  ///< All extracted IOCs

    // Artifacts and Reports
    std::string pcap_file;                                    ///< PCAP filename
    std::filesystem::path ioc_export_path;                    ///< IOC export file
    std::vector<std::filesystem::path> additional_artifacts;  ///< Other artifacts

    // Timing Breakdown
    std::chrono::milliseconds analysis_duration{0};           ///< Total analysis time
    std::map<std::string, std::chrono::milliseconds> phase_durations;  ///< Per-phase timing

    // Report Paths
    std::filesystem::path json_report_path;       ///< JSON report location
    std::filesystem::path html_report_path;       ///< HTML report location
    std::optional<std::filesystem::path> timeline_path;  ///< Timeline visualization

    // Timing Details
    std::chrono::system_clock::time_point start_time;
    std::chrono::system_clock::time_point end_time;
    std::chrono::milliseconds total_duration{0};
};

/// Progress callback function type for asynchronous analysis
using ProgressCallback = std::function<void(const AnalysisStatus&)>;

/**
 * @class AnalysisEngine
 * @brief Core orchestration engine for comprehensive malware analysis
 *
 * The AnalysisEngine coordinates all analysis components and manages the
 * complete analysis lifecycle. It provides:
 *
 * - **Multi-phase analysis pipeline**: Static → Dynamic → Behavioral → Reporting
 * - **Asynchronous execution**: Non-blocking analysis with progress callbacks
 * - **Batch processing**: Analyze multiple samples concurrently
 * - **Result caching**: Avoid re-analyzing known samples
 * - **Artifact management**: Automatic cleanup of temporary files
 * - **Error recovery**: Graceful handling of component failures
 *
 * **Analysis Workflow**:
 * 1. Sample intake and validation
 * 2. Hash calculation and deduplication check
 * 3. Static analysis (PE/ELF parsing, strings, entropy)
 * 4. Sandbox deployment (Docker container)
 * 5. Dynamic execution with monitoring
 * 6. Behavioral analysis and pattern matching
 * 7. IOC extraction
 * 8. Report generation (JSON/HTML)
 * 9. Cleanup and archival
 *
 * **Thread Safety**: Instance methods are thread-safe. Multiple threads can
 * call Analyze() or AnalyzeAsync() concurrently on the same instance.
 *
 * **Usage Example - Synchronous**:
 * @code
 * AnalysisEngine engine;
 * engine.Initialize();
 *
 * AnalysisConfig config;
 * config.sample_path = "/path/to/malware.exe";
 * config.perform_static_analysis = true;
 * config.perform_dynamic_analysis = true;
 * config.execution_timeout = std::chrono::seconds(300);
 *
 * auto result = engine.Analyze(config);
 *
 * std::cout << "Threat Score: " << result.overall_threat_score << std::endl;
 * std::cout << "Report: " << result.html_report_path << std::endl;
 * @endcode
 *
 * **Usage Example - Asynchronous**:
 * @code
 * auto future = engine.AnalyzeAsync(config, [](const AnalysisStatus& status) {
 *     std::cout << "Progress: " << status.progress_percentage << "%" << std::endl;
 * });
 *
 * // Do other work...
 *
 * auto result = future.get();  // Wait for completion
 * @endcode
 */
class AnalysisEngine {
public:
    /**
     * @struct Config
     * @brief Engine-level configuration
     */
    struct Config {
        // Directory Configuration
        std::filesystem::path samples_directory{"./samples"};       ///< Sample storage
        std::filesystem::path reports_directory{"./reports"};       ///< Report output
        std::filesystem::path temp_directory{"./temp"};             ///< Temporary files
        std::filesystem::path sandbox_directory{"./sandbox"};       ///< Sandbox workspace

        // Engine Settings
        int max_concurrent_analyses{1};       ///< Maximum parallel analyses
        bool auto_cleanup_artifacts{false};   ///< Delete temp files after analysis
        bool verbose_logging{true};           ///< Enable debug logging

        // Safety Features
        bool enable_sandbox_isolation{true};     ///< Enforce sandbox isolation
        bool require_vm_environment{false};      ///< Only run in VM (safety check)
        std::vector<std::string> blacklisted_samples;  ///< SHA-256 hashes to refuse
    };

    /**
     * @brief Construct engine with custom configuration
     * @param config Engine configuration
     */
    explicit AnalysisEngine(const Config& config);

    /**
     * @brief Construct engine with default configuration
     */
    explicit AnalysisEngine();

    ~AnalysisEngine();

    AnalysisEngine(const AnalysisEngine&) = delete;
    AnalysisEngine& operator=(const AnalysisEngine&) = delete;

    /**
     * @brief Perform synchronous malware analysis
     *
     * Executes complete analysis pipeline and blocks until finished.
     * This is the primary analysis method for single-sample processing.
     *
     * @param config Analysis configuration
     * @return Complete analysis results
     *
     * @throws std::runtime_error if engine not initialized
     * @throws std::runtime_error if sample file doesn't exist
     * @throws std::runtime_error if sample is blacklisted
     *
     * **Performance**: Typical runtime 30s-10min depending on configuration
     */
    AnalysisResult Analyze(const AnalysisConfig& config);

    /**
     * @brief Perform asynchronous malware analysis
     *
     * Starts analysis in background thread and returns immediately.
     * Progress can be monitored via optional callback function.
     *
     * @param config Analysis configuration
     * @param callback Optional progress callback (called on status updates)
     * @return Future that resolves to analysis result
     *
     * **Example with callback**:
     * @code
     * auto future = engine.AnalyzeAsync(config, [](const AnalysisStatus& s) {
     *     if (s.current_phase == AnalysisPhase::DYNAMIC_EXECUTION) {
     *         std::cout << "Executing in sandbox..." << std::endl;
     *     }
     * });
     * @endcode
     */
    std::future<AnalysisResult> AnalyzeAsync(
        const AnalysisConfig& config,
        ProgressCallback callback = nullptr
    );

    /**
     * @brief Analyze multiple samples in batch
     *
     * Processes multiple malware samples concurrently (up to max_concurrent_analyses).
     * Results are returned in the same order as input paths.
     *
     * @param sample_paths Vector of file paths to analyze
     * @param base_config Base configuration (applied to all samples)
     * @return Vector of analysis results (same order as inputs)
     *
     * **Use Case**: Processing sample sets from malware feeds or incident responses
     *
     * @note Failed analyses will have status.has_error = true
     */
    std::vector<AnalysisResult> AnalyzeBatch(
        const std::vector<std::filesystem::path>& sample_paths,
        const AnalysisConfig& base_config
    );

    /**
     * @brief Get status of active analysis by ID
     *
     * @param analysis_id Analysis identifier (from AnalysisResult.analysis_id)
     * @return Current status, or nullopt if ID not found
     */
    std::optional<AnalysisStatus> GetAnalysisStatus(const std::string& analysis_id) const;

    /**
     * @brief Cancel running analysis
     *
     * Attempts to gracefully stop analysis. Sandbox processes are terminated.
     *
     * @param analysis_id Analysis to cancel
     * @return true if cancelled successfully, false if not found/already complete
     */
    bool CancelAnalysis(const std::string& analysis_id);

    /**
     * @brief Get all currently running analyses
     * @return Vector of active analysis statuses
     */
    std::vector<AnalysisStatus> GetActiveAnalyses() const;

    /**
     * @brief Get historical analysis results
     *
     * @param limit Maximum number of results (default: 100)
     * @return Vector of recent analysis results
     */
    std::vector<AnalysisResult> GetAnalysisHistory(int limit = 100) const;

    /**
     * @brief Load previous analysis result from disk
     *
     * @param analysis_id Analysis ID to load
     * @return Loaded result, or nullopt if not found
     */
    std::optional<AnalysisResult> LoadAnalysisResult(const std::string& analysis_id);

    /**
     * @brief Delete analysis artifacts from disk
     *
     * Removes temporary files, logs, and PCAPs for specified analysis.
     * Reports are preserved.
     *
     * @param analysis_id Analysis to clean up
     */
    void CleanupArtifacts(const std::string& analysis_id);

    /**
     * @brief Initialize analysis engine
     *
     * Sets up directories, validates Docker, loads configuration.
     * Must be called before performing analyses.
     *
     * @return true if initialization successful
     */
    bool Initialize();

    /**
     * @brief Shutdown engine and cleanup resources
     *
     * Cancels active analyses, releases resources, and saves state.
     */
    void Shutdown();

    /**
     * @brief Check if sample was previously analyzed
     *
     * Searches analysis history for matching SHA-256 hash.
     * Can be used to avoid duplicate analyses.
     *
     * @param sample_hash SHA-256 hash of sample
     * @return Previous result if found, nullopt otherwise
     */
    std::optional<AnalysisResult> FindPreviousAnalysis(const std::string& sample_hash);

    /**
     * @brief Get current engine configuration
     * @return Reference to configuration structure
     */
    const Config& GetConfig() const { return config_; }

    /**
     * @brief Update engine configuration
     *
     * @param config New configuration
     * @note Changes take effect for new analyses only
     */
    void UpdateConfig(const Config& config);

private:
    Config config_;

    class Impl;
    std::unique_ptr<Impl> impl_;  ///< Pimpl idiom for implementation hiding

    // State Management
    std::map<std::string, AnalysisStatus> active_analyses_;
    std::vector<AnalysisResult> analysis_history_;
    mutable std::mutex state_mutex_;  ///< Protects shared state

    // Pipeline Methods (internal)
    AnalysisResult ExecuteAnalysisPipeline(const AnalysisConfig& config);
    void UpdateStatus(const std::string& analysis_id, AnalysisPhase phase,
                     float progress, const std::string& message);
    std::string GenerateAnalysisID();
    int CalculateOverallThreatScore(const AnalysisResult& result);
    std::string DetermineThreatLevel(int threat_score);
};

} // namespace core
} // namespace paramite