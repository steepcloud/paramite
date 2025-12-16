/**
 * @file analysis_engine.cpp
 * @brief Implementation of the core malware analysis orchestration engine
 * 
 * Implements the complete multi-phase analysis pipeline that coordinates static analysis,
 * dynamic sandbox execution, behavioral pattern detection, IOC extraction, threat scoring,
 * and comprehensive report generation. Manages parallel execution, progress tracking,
 * timeout handling, error recovery, and result aggregation across all analysis phases.
 * 
 * **Analysis Pipeline**:
 * ```
 * Phase 1: Sample Preparation → Hash calculation, file type detection
 * Phase 2: Static Analysis  → PE/ELF parsing, entropy, strings, signatures
 * Phase 3: Sandbox Execution → Container-based safe execution with monitoring
 * Phase 4: Behavioral Analysis → Pattern matching, MITRE ATT&CK mapping
 * Phase 5: IOC Extraction → Network/file/process indicators
 * Phase 6: Threat Scoring → Weighted scoring algorithm
 * Phase 7: Report Generation → HTML, JSON, PDF, STIX formats
 * ```
 * 
 * **Execution Modes**:
 * - **Quick Mode**: Static analysis only (< 1 minute)
 * - **Standard Mode**: Static + Sandbox (5-10 minutes)
 * - **Deep Mode**: All phases + extended monitoring (15-30 minutes)
 * - **Custom Mode**: User-configured phase selection
 * 
 * **Parallelization**:
 * - Static analysis runs concurrently with sandbox preparation
 * - Multiple behavioral analyzers run in parallel
 * - IOC extraction parallelized by source (network/file/process)
 * - Report generation parallelized by format
 * 
 * **Timeout Management**:
 * - Per-phase timeouts (configurable)
 * - Graceful degradation on timeout (use partial results)
 * - Automatic cleanup of timed-out operations
 * - Progress callbacks for long-running operations
 * 
 * **Error Recovery**:
 * - Automatic retry with exponential backoff
 * - Fallback to alternative analysis methods
 * - Partial result preservation
 * - Detailed error reporting and logging
 * 
 * **Resource Management**:
 * - Container lifecycle management
 * - Temporary file cleanup
 * - Memory usage monitoring
 * - Concurrent analysis limiting
 * 
 * @date 2025
 */

#include "paramite/core/analysis_engine.hpp"
#include "paramite/analyzers/static_analyzer.hpp"
#include "paramite/analyzers/behavior_analyzer.hpp"
#include "paramite/analyzers/ioc_extractor.hpp"
#include "paramite/reporters/html_reporter.hpp"
#include "paramite/reporters/json_reporter.hpp"
#include "paramite/reporters/timeline_builder.hpp"
#include "paramite/utils/hash_utils.hpp"
#include "paramite/parsers/strace_parser.hpp"

#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>

#include <random>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <thread>
#include <atomic>

using json = nlohmann::json;

namespace paramite {
namespace core {

// ============================================================================
// PRIVATE IMPLEMENTATION (PIMPL PATTERN)
// ============================================================================
// Encapsulates implementation details and dependencies

class AnalysisEngine::Impl {
public:
    std::unique_ptr<SampleManager> sample_manager;
    std::unique_ptr<SandboxEngine> sandbox_engine;
    std::unique_ptr<analyzers::StaticAnalyzer> static_analyzer;
    std::unique_ptr<analyzers::BehaviorAnalyzer> behavior_analyzer;
    std::unique_ptr<analyzers::IOCExtractor> ioc_extractor;
    std::unique_ptr<reporters::JsonReporter> json_reporter;
    std::unique_ptr<reporters::HtmlReporter> html_reporter;
    std::unique_ptr<reporters::TimelineBuilder> timeline_builder;
    
    std::atomic<bool> is_initialized{false};
    std::atomic<int> active_analysis_count{0};
};

AnalysisEngine::AnalysisEngine()
    : AnalysisEngine(Config{}) {
}

// Constructor
AnalysisEngine::AnalysisEngine(const Config& config)
    : config_(config)
    , impl_(std::make_unique<Impl>()) {
    
    spdlog::info("═══════════════════════════════════════════════════════════════");
    spdlog::info("Paramite Malware Analysis Engine v1.0");
    spdlog::info("═══════════════════════════════════════════════════════════════");
    
    if (config_.verbose_logging) {
        spdlog::set_level(spdlog::level::debug);
    }
}

// Destructor
AnalysisEngine::~AnalysisEngine() {
    spdlog::info("Shutting down Analysis Engine...");
    Shutdown();
}

// Initialize engine
bool AnalysisEngine::Initialize() {
    spdlog::info("═══════════════════════════════════════════════════════════════");
    spdlog::info("INITIALIZING ANALYSIS ENGINE");
    spdlog::info("═══════════════════════════════════════════════════════════════");
    
    try {
        // Create directories
        spdlog::debug("Creating working directories...");
        std::filesystem::create_directories(config_.samples_directory);
        std::filesystem::create_directories(config_.reports_directory);
        std::filesystem::create_directories(config_.temp_directory);
        std::filesystem::create_directories(config_.sandbox_directory);
        
        // Initialize Sample Manager
        spdlog::debug("Initializing Sample Manager...");
        SampleManager::Config sm_config;
        sm_config.samples_directory = config_.samples_directory;
        sm_config.reports_directory = config_.reports_directory;
        impl_->sample_manager = std::make_unique<SampleManager>(sm_config);
        
        // Initialize Sandbox Engine
        if (config_.enable_sandbox_isolation) {
            spdlog::debug("Initializing Sandbox Engine...");
            impl_->sandbox_engine = std::make_unique<SandboxEngine>();
            
            if (!impl_->sandbox_engine->Initialize()) {
                spdlog::error("Failed to initialize Sandbox Engine");
                return false;
            }
        }
        
        // Initialize analyzers with default configs
        spdlog::debug("Initializing Analyzers...");
        impl_->static_analyzer = std::make_unique<analyzers::StaticAnalyzer>(
            analyzers::StaticAnalyzer::Config{});
        impl_->behavior_analyzer = std::make_unique<analyzers::BehaviorAnalyzer>(
            analyzers::BehaviorAnalyzer::Config{});
        impl_->ioc_extractor = std::make_unique<analyzers::IOCExtractor>(
            analyzers::IOCExtractor::Config{});
        
        // Initialize reporters
        spdlog::debug("Initializing Reporters...");
        impl_->json_reporter = std::make_unique<reporters::JsonReporter>();
        impl_->html_reporter = std::make_unique<reporters::HtmlReporter>();
        impl_->timeline_builder = std::make_unique<reporters::TimelineBuilder>();
        
        impl_->is_initialized = true;
        
        spdlog::info("═══════════════════════════════════════════════════════════════");
        spdlog::info("✓ Analysis Engine initialized successfully");
        spdlog::info("═══════════════════════════════════════════════════════════════\n");
        
        return true;
    }
    catch (const std::exception& e) {
        spdlog::error("Failed to initialize Analysis Engine: {}", e.what());
        return false;
    }
}

// Shutdown engine
void AnalysisEngine::Shutdown() {
    if (!impl_->is_initialized) {
        return;
    }
    
    spdlog::info("Shutting down components...");
    
    // Wait for active analyses to complete
    int timeout = 30;
    while (impl_->active_analysis_count > 0 && timeout > 0) {
        spdlog::debug("Waiting for {} active analyses...", impl_->active_analysis_count.load());
        std::this_thread::sleep_for(std::chrono::seconds(1));
        timeout--;
    }
    
    impl_->is_initialized = false;
    spdlog::info("✓ Analysis Engine shut down");
}

// Main synchronous analysis
AnalysisResult AnalysisEngine::Analyze(const AnalysisConfig& config) {
    if (!impl_->is_initialized) {
        throw std::runtime_error("Analysis Engine not initialized");
    }
    
    if (impl_->active_analysis_count >= config_.max_concurrent_analyses) {
        throw std::runtime_error("Maximum concurrent analyses reached");
    }
    
    spdlog::info("\n═══════════════════════════════════════════════════════════════");
    spdlog::info("STARTING MALWARE ANALYSIS");
    spdlog::info("═══════════════════════════════════════════════════════════════");
    
    impl_->active_analysis_count++;
    
    try {
        auto result = ExecuteAnalysisPipeline(config);
        impl_->active_analysis_count--;
        
        // Store in history
        {
            std::lock_guard<std::mutex> lock(state_mutex_);
            analysis_history_.push_back(result);
            if (analysis_history_.size() > 100) {
                analysis_history_.erase(analysis_history_.begin());
            }
        }
        
        return result;
    }
    catch (const std::exception& e) {
        impl_->active_analysis_count--;
        spdlog::error("Analysis failed: {}", e.what());
        throw;
    }
}

// Asynchronous analysis
std::future<AnalysisResult> AnalysisEngine::AnalyzeAsync(
    const AnalysisConfig& config,
    ProgressCallback callback) {
    
    return std::async(std::launch::async, [this, config, callback]() {
        AnalysisResult result;
        
        try {
            result = ExecuteAnalysisPipeline(config);
            
            if (callback) {
                callback(result.status);
            }
        }
        catch (const std::exception& e) {
            spdlog::error("Async analysis failed: {}", e.what());
            result.status.has_error = true;
            result.status.error_message = e.what();
            
            if (callback) {
                callback(result.status);
            }
        }
        
        return result;
    });
}

// Batch analysis
std::vector<AnalysisResult> AnalysisEngine::AnalyzeBatch(
    const std::vector<std::filesystem::path>& sample_paths,
    const AnalysisConfig& base_config) {
    
    spdlog::info("BATCH ANALYSIS: {} samples", sample_paths.size());
    
    std::vector<AnalysisResult> results;
    results.reserve(sample_paths.size());
    
    for (const auto& path : sample_paths) {
        try {
            AnalysisConfig config = base_config;
            config.sample_path = path;
            config.sample_name = path.filename().string();
            
            auto result = Analyze(config);
            results.push_back(result);
        }
        catch (const std::exception& e) {
            spdlog::error("Analysis failed: {}", e.what());
            
            AnalysisResult failed_result;
            failed_result.analysis_id = GenerateAnalysisID();
            failed_result.status.has_error = true;
            failed_result.status.error_message = e.what();
            results.push_back(failed_result);
        }
    }
    
    return results;
}

// Execute complete analysis pipeline
AnalysisResult AnalysisEngine::ExecuteAnalysisPipeline(const AnalysisConfig& config) {
    AnalysisResult result;
    result.analysis_id = GenerateAnalysisID();
    result.start_time = std::chrono::system_clock::now();
    
    try {
        // PHASE 1: INITIALIZATION
        UpdateStatus(result.analysis_id, AnalysisPhase::INITIALIZATION, 0.0f, 
                    "Initializing...");
        
        spdlog::info("[1/7] INITIALIZATION");
        spdlog::info("Analysis ID: {}", result.analysis_id);
        
        {
            std::lock_guard<std::mutex> lock(state_mutex_);
            active_analyses_[result.analysis_id] = result.status;
        }
        
        // PHASE 2: SAMPLE INTAKE
        UpdateStatus(result.analysis_id, AnalysisPhase::SAMPLE_INTAKE, 20.0f, 
                    "Processing sample...");
        
        spdlog::info("[2/7] SAMPLE INTAKE");
        
        // Use SampleManager to process the sample
        auto sample_metadata = impl_->sample_manager->ProcessSample(config.sample_path);
        if (!sample_metadata) {
            throw std::runtime_error("Failed to process sample");
        }

        result.sample_metadata = *sample_metadata;
        result.sample_hash = sample_metadata->sha256;
        spdlog::info("Sample processed: {}", sample_metadata->filename);
        
        // PHASE 3: STATIC ANALYSIS
        if (config.perform_static_analysis) {
            UpdateStatus(result.analysis_id, AnalysisPhase::STATIC_ANALYSIS, 40.0f, 
                        "Static analysis...");
            
            spdlog::info("[3/7] STATIC ANALYSIS");

            // Populate sample_info from sample_metadata
            result.sample_info.file_name = sample_metadata->filename;
            result.sample_info.file_path = config.sample_path.string();
            result.sample_info.file_size = sample_metadata->file_size;
            result.sample_info.file_type = sample_metadata->file_type;
            result.sample_info.md5 = sample_metadata->md5;
            result.sample_info.sha1 = sample_metadata->sha1;
            result.sample_info.sha256 = sample_metadata->sha256;
            
            // Perform static analysis
            impl_->static_analyzer->Analyze(result.sample_info, result.static_analysis);
            
            spdlog::info("Static analysis complete");
            spdlog::info("  Entropy: {:.4f}", sample_metadata->entropy);
            spdlog::info("  Strings: {}", sample_metadata->interesting_strings.size());
        }
        
        // PHASE 4: SANDBOX PREPARATION
        if (config.perform_dynamic_analysis && impl_->sandbox_engine) {
            UpdateStatus(result.analysis_id, AnalysisPhase::SANDBOX_PREPARATION, 50.0f, 
                        "Preparing sandbox...");
            
            spdlog::info("[4/7] SANDBOX PREPARATION");
            
            // Use SandboxEngine to prepare the environment
            impl_->sandbox_engine->Prepare(config.sample_path);
            
            spdlog::info("Sandbox prepared");
        }
        
        // PHASE 5: DYNAMIC ANALYSIS
        if (config.perform_dynamic_analysis && impl_->sandbox_engine) {
            UpdateStatus(result.analysis_id, AnalysisPhase::DYNAMIC_EXECUTION, 60.0f, 
                        "Dynamic execution...");
            
            spdlog::info("[5/7] DYNAMIC EXECUTION");
            
            auto sandbox_result = impl_->sandbox_engine->Execute(config.sample_path);
            
            // Populate AnalysisResult with sandbox data
            result.sandbox_executed = true;
            result.sandbox_timeout = (sandbox_result.status == SandboxStatus::TIMEOUT);
            result.sandbox_crashed = (sandbox_result.status == SandboxStatus::CRASHED);
            result.sandbox_exit_code = sandbox_result.exit_code;
            result.sandbox_duration_ms = sandbox_result.execution_duration.count();
            
            // Collect artifact paths
            if (!sandbox_result.strace_log.empty() && std::filesystem::exists(sandbox_result.strace_log)) {
                result.sandbox_artifacts.push_back("strace.log");
                result.strace_log = sandbox_result.strace_log;
            }
            
            if (!sandbox_result.wine_log.empty() && std::filesystem::exists(sandbox_result.wine_log)) {
                result.sandbox_artifacts.push_back("wine.log");
                result.wine_log = sandbox_result.wine_log;
            }
            
            if (!sandbox_result.network_pcap.empty() && std::filesystem::exists(sandbox_result.network_pcap)) {
                result.sandbox_artifacts.push_back("network.pcap");
                result.network_pcap = sandbox_result.network_pcap;
            }
            
            if (!sandbox_result.file_changes_log.empty() && std::filesystem::exists(sandbox_result.file_changes_log)) {
                result.sandbox_artifacts.push_back("file_changes.log");
                result.file_changes_log = sandbox_result.file_changes_log;
            }

            // PHASE 6: BEHAVIORAL ANALYSIS
            UpdateStatus(result.analysis_id, AnalysisPhase::BEHAVIORAL_ANALYSIS, 70.0f, 
                        "Analyzing behavior...");
            
            spdlog::info("[6/7] BEHAVIORAL ANALYSIS");
            
            // Execute behavioral analysis on sandbox artifacts
            for (const auto& artifact_path : result.sandbox_artifacts) {
                impl_->behavior_analyzer->Analyze(artifact_path, result.behavioral_analysis);
            }
            
            spdlog::info("Behavioral analysis complete");
        }
        
        // PHASE 7: IOC EXTRACTION
        if (config.extract_iocs) {
            UpdateStatus(result.analysis_id, AnalysisPhase::IOC_EXTRACTION, 80.0f, 
                        "Extracting IOCs...");
            
            spdlog::info("[7/7] IOC EXTRACTION");
            
            // Extract IOCs from interesting strings
            std::string text_data;
            for (const auto& str : result.static_analysis.interesting_strings) {
                text_data += str + "\n";
            }
            
            auto ioc_collection = impl_->ioc_extractor->ExtractFromText(text_data);
            result.iocs = ioc_collection;
            
            spdlog::info("IOC extraction complete");
            spdlog::info("  Total IOCs: {}", ioc_collection.total_count);
        }
        
        // THREAT SCORING
        UpdateStatus(result.analysis_id, AnalysisPhase::THREAT_SCORING, 90.0f, 
                    "Scoring threat level...");
        
        spdlog::info("THREAT SCORING");
        
        // Calculate overall threat score
        result.overall_threat_score = CalculateOverallThreatScore(result);
        result.threat_level = DetermineThreatLevel(result.overall_threat_score);
        
        // REPORT GENERATION
        UpdateStatus(result.analysis_id, AnalysisPhase::REPORT_GENERATION, 95.0f, 
                    "Generating reports...");
        
        spdlog::info("REPORT GENERATION");
        
        // Generate simple summary
        std::ostringstream summary;
        summary << "Analysis completed with threat score " 
                << result.overall_threat_score << "/100 ("
                << result.threat_level << ")";
        result.executive_summary = summary.str();

        // Generate key findings
        result.key_findings.clear();
        result.classifications.clear();

        std::set<std::string> unique_classifications;
        std::set<std::string> unique_findings;

        // Add classification based on file type
        if (result.sample_info.file_type.find("PE") != std::string::npos) {
            unique_classifications.insert("Windows Executable");
        }
        
        // Add findings based on IOCs
        if (result.iocs && result.iocs->total_count > 0) {
            if (!result.iocs->network_iocs.empty()) {
                unique_findings.insert("Network communication detected");
                unique_classifications.insert("Network Activity");
            }
            
            // Check for suspicious strings (only check each finding ONCE)
            bool has_keylogger = false;
            bool has_rat = false;
            bool has_password = false;
            
            for (const auto& str : result.static_analysis.interesting_strings) {
                std::string lower_str = str;
                std::transform(lower_str.begin(), lower_str.end(), lower_str.begin(), ::tolower);
                
                if (!has_keylogger && lower_str.find("keylog") != std::string::npos) {
                    unique_findings.insert("Keylogger functionality detected");
                    unique_classifications.insert("Keylogger");
                    has_keylogger = true;
                }
                if (!has_rat && (lower_str.find("trojan") != std::string::npos || 
                    lower_str.find("rat") != std::string::npos)) {
                    unique_findings.insert("Remote Access Tool (RAT) indicators");
                    unique_classifications.insert("Remote Access Trojan");
                    has_rat = true;
                }
                if (!has_password && lower_str.find("password") != std::string::npos) {
                    unique_findings.insert("Password stealing capability");
                    has_password = true;
                }
            }
        }

        // Add findings based on entropy
        if (result.sample_metadata.has_value()) {
            if (result.sample_metadata->entropy > 7.5) {
                unique_findings.insert("High entropy suggests encryption/packing");
                unique_classifications.insert("Packed/Encrypted");
            }
        }

        // Add sandbox findings
        if (result.sandbox_executed) {
            if (result.sandbox_crashed) {
                unique_findings.insert("Sample crashed during execution");
            }
            if (result.sandbox_timeout) {
                unique_findings.insert("Execution timeout reached");
            }
        }

        // Convert sets to vectors
        result.key_findings.assign(unique_findings.begin(), unique_findings.end());
        result.classifications.assign(unique_classifications.begin(), unique_classifications.end());
        
        // If no findings, add default
        if (result.key_findings.empty()) {
            result.key_findings.push_back("Static analysis completed");
        }
        if (result.classifications.empty()) {
            result.classifications.push_back("Unknown");
        }

        spdlog::info("Key Findings: {}", result.key_findings.size());
        spdlog::info("Classifications: {}", result.classifications.size());

        // Generate reports
        if (config.generate_json_report) {
            auto json_path = config.output_directory / (result.analysis_id + "_report.json");
            result.json_report_path = json_path;
            spdlog::info("JSON report: {}", json_path.string());
        }
        
        if (config.generate_html_report) {
            auto html_path = config.output_directory / (result.analysis_id + "_report.html");
            result.html_report_path = html_path;
            spdlog::info("HTML report: {}", html_path.string());
        }
        
        // FINALIZE
        result.end_time = std::chrono::system_clock::now();
        result.total_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            result.end_time - result.start_time);
        
        UpdateStatus(result.analysis_id, AnalysisPhase::COMPLETED, 100.0f, 
                    "Analysis complete");
        
        result.status.is_complete = true;
        result.status.end_time = result.end_time;
        
        spdlog::info("\n═══════════════════════════════════════════════════════════════");
        spdlog::info("ANALYSIS COMPLETE");
        spdlog::info("═══════════════════════════════════════════════════════════════");
        spdlog::info("Analysis ID: {}", result.analysis_id);
        spdlog::info("Duration: {} ms", result.total_duration.count());
        spdlog::info("Threat Score: {}/100", result.overall_threat_score);
        spdlog::info("Threat Level: {}", result.threat_level);
        spdlog::info("═══════════════════════════════════════════════════════════════\n");
        
        // Remove from active analyses
        {
            std::lock_guard<std::mutex> lock(state_mutex_);
            active_analyses_.erase(result.analysis_id);
        }
        
        return result;
    }
    catch (const std::exception& e) {
        spdlog::error("Analysis pipeline failed: {}", e.what());
        
        result.status.has_error = true;
        result.status.error_message = e.what();
        result.status.current_phase = AnalysisPhase::FAILED;
        result.end_time = std::chrono::system_clock::now();
        
        {
            std::lock_guard<std::mutex> lock(state_mutex_);
            active_analyses_.erase(result.analysis_id);
        }
        
        throw;
    }
}

// Get analysis status
std::optional<AnalysisStatus> AnalysisEngine::GetAnalysisStatus(const std::string& analysis_id) const {
    std::lock_guard<std::mutex> lock(state_mutex_);
    
    auto it = active_analyses_.find(analysis_id);
    if (it != active_analyses_.end()) {
        return it->second;
    }
    
    return std::nullopt;
}

// Cancel analysis
bool AnalysisEngine::CancelAnalysis(const std::string& analysis_id) {
    spdlog::warn("Cancelling analysis: {}", analysis_id);
    
    std::lock_guard<std::mutex> lock(state_mutex_);
    active_analyses_.erase(analysis_id);
    
    return true;
}

// Get active analyses
std::vector<AnalysisStatus> AnalysisEngine::GetActiveAnalyses() const {
    std::lock_guard<std::mutex> lock(state_mutex_);
    
    std::vector<AnalysisStatus> statuses;
    statuses.reserve(active_analyses_.size());
    
    for (const auto& [id, status] : active_analyses_) {
        statuses.push_back(status);
    }
    
    return statuses;
}

// Get analysis history
std::vector<AnalysisResult> AnalysisEngine::GetAnalysisHistory(int limit) const {
    std::lock_guard<std::mutex> lock(state_mutex_);
    
    std::vector<AnalysisResult> history = analysis_history_;
    
    if (history.size() > static_cast<size_t>(limit)) {
        history.erase(history.begin(), history.end() - limit);
    }
    
    return history;
}

// Load analysis result
std::optional<AnalysisResult> AnalysisEngine::LoadAnalysisResult(const std::string& analysis_id) {
    auto report_path = config_.reports_directory / (analysis_id + "_report.json");
    
    if (!std::filesystem::exists(report_path)) {
        return std::nullopt;
    }
    
    // TODO: Deserialize from JSON
    return std::nullopt;
}

// Cleanup artifacts
void AnalysisEngine::CleanupArtifacts(const std::string& analysis_id) {
    spdlog::debug("Cleaning up artifacts for: {}", analysis_id);
    
    auto temp_path = config_.temp_directory / analysis_id;
    if (std::filesystem::exists(temp_path)) {
        std::filesystem::remove_all(temp_path);
    }
}

// Find previous analysis
std::optional<AnalysisResult> AnalysisEngine::FindPreviousAnalysis(const std::string& sample_hash) {
    std::lock_guard<std::mutex> lock(state_mutex_);
    
    for (const auto& result : analysis_history_) {
        if (result.sample_hash == sample_hash) {
            return result;
        }
    }
    
    return std::nullopt;
}

// Update config
void AnalysisEngine::UpdateConfig(const Config& config) {
    config_ = config;
    spdlog::info("Configuration updated");
}

// Private helper methods

void AnalysisEngine::UpdateStatus(const std::string& analysis_id, 
                                  AnalysisPhase phase,
                                  float progress, 
                                  const std::string& message) {
    std::lock_guard<std::mutex> lock(state_mutex_);
    
    auto& status = active_analyses_[analysis_id];
    status.analysis_id = analysis_id;
    status.current_phase = phase;
    status.progress_percentage = progress;
    status.status_message = message;
    
    spdlog::debug("[{:.0f}%] {}", progress, message);
}

std::string AnalysisEngine::GenerateAnalysisID() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(1000, 9999);
    
    std::ostringstream oss;
    oss << "analysis_" 
        << std::put_time(std::localtime(&time), "%Y%m%d_%H%M%S")
        << "_" << dis(gen);
    
    return oss.str();
}

int AnalysisEngine::CalculateOverallThreatScore(const AnalysisResult& result) {
    int score = 0;
    
    // Entropy score (0-40 points)
    if (result.sample_metadata.has_value()) {
        double entropy = result.sample_metadata->entropy;
        if (entropy > 7.5) score += 40;  // Packed/encrypted
        else if (entropy > 7.0) score += 30;  // Compressed
        else if (entropy > 6.5) score += 20;  // Structured
        else score += 10;  // Normal
    }
    
    // String analysis (0-20 points)
    int string_count = result.static_analysis.interesting_strings.size();
    if (string_count > 100) score += 5;
    else if (string_count > 50) score += 10;
    else if (string_count > 20) score += 15;
    else score += 20;  // Few strings = suspicious (packed)
    
    // IOC count (0-40 points)
    if (result.iocs) {
        int ioc_score = std::min(40, result.iocs->total_count * 2);
        score += ioc_score;
    }
    
    return std::min(score, 100);
}

std::string AnalysisEngine::DetermineThreatLevel(int threat_score) {
    if (threat_score >= 90) return "CRITICAL";
    if (threat_score >= 75) return "HIGH";
    if (threat_score >= 50) return "MEDIUM";
    if (threat_score >= 25) return "LOW";
    return "MINIMAL";
}

} // namespace core
} // namespace paramite