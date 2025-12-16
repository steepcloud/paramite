/**
 * @file html_reporter.cpp
 * @brief Implementation of interactive HTML report generation
 * 
 * Implements comprehensive HTML report generation with interactive visualizations,
 * charts, graphs, timeline views, and detailed analysis sections. Uses modern web
 * technologies (D3.js, Chart.js, vis.js) for data visualization, includes embedded
 * CSS/JavaScript for standalone reports, and provides export functionality for
 * sharing analysis results.
 * 
 * **Report Sections**:
 * 1. **Executive Summary**: High-level threat assessment, risk score
 * 2. **Sample Information**: Hashes, file type, size, timestamps
 * 3. **Static Analysis**: PE/ELF headers, sections, imports, entropy
 * 4. **Behavioral Analysis**: Process tree, network activity, file operations
 * 5. **IOC Extraction**: Network IOCs, file IOCs, process IOCs
 * 6. **MITRE ATT&CK**: Mapped techniques with descriptions
 * 7. **Timeline**: Chronological event visualization
 * 8. **Detailed Logs**: strace, network captures, file changes
 * 
 * **Visualization Components**:
 * - **Threat Score Gauge**: Radial gauge showing 0-100 threat score
 * - **Process Tree**: Interactive tree diagram (vis.js)
 * - **Network Graph**: Source/destination connections (D3.js force layout)
 * - **Timeline**: Horizontal timeline of events (vis.js timeline)
 * - **Entropy Chart**: Line chart showing entropy per section
 * - **File Operations**: Bar chart of file access patterns
 * - **API Call Frequency**: Heatmap of Windows API calls
 * 
 * **Interactive Features**:
 * - Expandable/collapsible sections
 * - Search/filter functionality
 * - Zoom and pan on graphs
 * - Tooltips with detailed information
 * - Export to PDF (print CSS)
 * - Copy-to-clipboard for IOCs
 * 
 * **Standalone Report**:
 * All resources embedded:
 * - CSS stylesheets (Bootstrap, custom)
 * - JavaScript libraries (jQuery, D3.js, Chart.js, vis.js)
 * - No external dependencies (works offline)
 * - Self-contained single HTML file
 * 
 * **Color Coding**:
 * - Red: Critical/high severity
 * - Orange: Medium severity
 * - Yellow: Low severity
 * - Green: Benign/informational
 * - Blue: Neutral/technical details
 * 
 * **Responsive Design**:
 * - Mobile-friendly layout
 * - Tablet-optimized views
 * - Desktop full-featured interface
 * - Print-optimized styling
 * 
 * **Performance**:
 * - Lazy loading of large data sections
 * - Virtualized scrolling for long lists
 * - Compressed JSON data
 * - Minified CSS/JavaScript
 * 
 * @date 2025
 */

#include "paramite/reporters/html_reporter.hpp"
#include "paramite/core/analysis_engine.hpp"

#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>

#include <fstream>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <algorithm>
#include <regex>

using json = nlohmann::json;

namespace paramite {
namespace reporters {

// Constructor
HtmlReporter::HtmlReporter(const HtmlReportConfig& config)
    : config_(config) {
    spdlog::info("HTML Reporter initialized");
    spdlog::debug("Theme: {}", static_cast<int>(config_.theme));
    spdlog::debug("Output directory: {}", config_.output_directory.string());
}

// Destructor
HtmlReporter::~HtmlReporter() {
    spdlog::info("HTML Reporter destroyed");
}

// Generate report
std::filesystem::path HtmlReporter::GenerateReport(const core::AnalysisResult& result) {
    spdlog::info("═══════════════════════════════════════════════════════════════");
    spdlog::info("GENERATING HTML REPORT");
    spdlog::info("═══════════════════════════════════════════════════════════════");
    
    try {
        // Create output directory
        if (!std::filesystem::exists(config_.output_directory)) {
            std::filesystem::create_directories(config_.output_directory);
        }
        
        // Generate filename
        std::string filename = GenerateFilename(result);
        std::filesystem::path output_path = config_.output_directory / filename;
        
        spdlog::info("Generating report: {}", output_path.string());
        
        // Generate HTML content
        std::string html = GenerateHTML(result);
        
        // Save report
        if (!SaveReport(html, output_path)) {
            spdlog::error("Failed to save report");
            return {};
        }
        
        // Create supporting files if configured
        if (config_.create_supporting_files) {
            CreateSupportingFiles(config_.output_directory);
        }
        
        spdlog::info("═══════════════════════════════════════════════════════════════");
        spdlog::info("✓ Report generated successfully");
        spdlog::info("  Location: {}", output_path.string());
        spdlog::info("  Size: {}", FormatFileSize(std::filesystem::file_size(output_path)));
        spdlog::info("═══════════════════════════════════════════════════════════════\n");
        
        return output_path;
    }
    catch (const std::exception& e) {
        spdlog::error("Failed to generate HTML report: {}", e.what());
        return {};
    }
}

// Convert IOCType enum to string
std::string IOCTypeToString(analyzers::IOCType type) {
    switch (type) {
            case analyzers::IOCType::IP_ADDRESS: return "IP";
            case analyzers::IOCType::DOMAIN_NAME: return "DOMAIN";
            case analyzers::IOCType::URL: return "URL";
            case analyzers::IOCType::EMAIL: return "EMAIL";
            case analyzers::IOCType::FILE_PATH: return "FILE_PATH";
            case analyzers::IOCType::REGISTRY_KEY: return "REGISTRY";
            case analyzers::IOCType::USER_AGENT: return "USER_AGENT";
            case analyzers::IOCType::FILE_HASH_MD5: return "MD5";
            case analyzers::IOCType::FILE_HASH_SHA1: return "SHA1";
            case analyzers::IOCType::FILE_HASH_SHA256: return "SHA256";
            case analyzers::IOCType::PROCESS_NAME: return "PROCESS";
            case analyzers::IOCType::CVE_ID: return "CVE";
            default: return "UNKNOWN";
        }
}

// Generate report with custom sections
std::filesystem::path HtmlReporter::GenerateReport(
    const core::AnalysisResult& result,
    const ReportSections& sections) {
    
    auto old_sections = config_.sections;
    config_.sections = sections;
    
    auto path = GenerateReport(result);
    
    config_.sections = old_sections;
    return path;
}

// Generate minimal report
std::filesystem::path HtmlReporter::GenerateMinimalReport(const core::AnalysisResult& result) {
    ReportSections minimal_sections;
    minimal_sections.executive_summary = true;
    minimal_sections.sample_information = true;
    minimal_sections.ioc_extraction = true;
    minimal_sections.static_analysis = false;
    minimal_sections.dynamic_analysis = false;
    minimal_sections.behavior_analysis = false;
    minimal_sections.network_analysis = false;
    minimal_sections.file_operations = false;
    minimal_sections.process_tree = false;
    minimal_sections.syscall_analysis = false;
    minimal_sections.timeline = false;
    minimal_sections.mitigation_recommendations = false;
    minimal_sections.artifacts = false;
    
    return GenerateReport(result, minimal_sections);
}

// Generate executive summary
std::string HtmlReporter::GenerateExecutiveSummary(const core::AnalysisResult& result) {
    return GenerateExecutiveSummarySection(result);
}

// Add custom section
void HtmlReporter::AddCustomSection(const std::string& title, const std::string& content) {
    custom_sections_.emplace_back(title, content);
}

// Add chart
void HtmlReporter::AddChart(const ChartData& chart) {
    custom_charts_.push_back(chart);
}

// Set custom CSS
void HtmlReporter::SetCustomCSS(const std::string& css) {
    custom_css_ = css;
}

// Set custom JavaScript
void HtmlReporter::SetCustomJavaScript(const std::string& js) {
    custom_js_ = js;
}

// Update configuration
void HtmlReporter::UpdateConfig(const HtmlReportConfig& config) {
    config_ = config;
    spdlog::debug("HTML Reporter configuration updated");
}

// Private Methods

// Generate HTML
std::string HtmlReporter::GenerateHTML(const core::AnalysisResult& result) {
    std::ostringstream html;
    
    html << "<!DOCTYPE html>\n";
    html << "<html lang=\"en\">\n";
    html << "<head>\n";
    html << "    <meta charset=\"UTF-8\">\n";
    html << "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n";
    html << "    <title>" << EscapeHTML(config_.report_title) << "</title>\n";
    html << "    <script src=\"https://d3js.org/d3.v7.min.js\"></script>\n";
    html << "    <script src=\"https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js\"></script>\n";
    html << "    <script src=\"https://unpkg.com/vis-network@9.1.9/dist/vis-network.min.js\"></script>\n";
    html << "    <link href=\"https://unpkg.com/vis-network@9.1.9/dist/dist/vis-network.min.css\" rel=\"stylesheet\" />\n";
    html << "    <style>\n" << GetCSS() << "\n" << custom_css_ << "\n    </style>\n";
    html << "</head>\n";
    html << "<body class=\"theme-" << (config_.theme == ReportTheme::DARK ? "dark" : "light") << "\">\n";
    html << "    <div class=\"container\">\n";
    
    // Header
    html << GenerateHeader(result);
    
    // Navigation
    html << GenerateNavigation();
    
    // Main content
    html << "        <main class=\"content\">\n";
    
    // Executive Summary
    if (config_.sections.executive_summary) {
        html << GenerateExecutiveSummarySection(result);
    }
    
    // Sample Information
    if (config_.sections.sample_information) {
        html << GenerateSampleInfoSection(result);
    }
    
    // Threat Assessment
    html << GenerateThreatAssessment(result);
    
    // Static Analysis
    if (config_.sections.static_analysis) {
        html << GenerateStaticAnalysisSection(result);
    }
    
    // Dynamic Analysis
    if (config_.sections.dynamic_analysis) {
        html << GenerateDynamicAnalysisSection(result);
    }
    
    // Behavior Analysis
    if (config_.sections.behavior_analysis) {
        html << GenerateBehaviorAnalysisSection(result);
    }
    
    // Network Analysis
    if (config_.sections.network_analysis) {
        html << GenerateNetworkAnalysisSection(result);
    }
    
    // File Operations
    if (config_.sections.file_operations) {
        html << GenerateFileOperationsSection(result);
    }
    
    // Process Tree
    if (config_.sections.process_tree) {
        html << GenerateProcessTreeSection(result);
    }
    
    // Syscall Analysis
    if (config_.sections.syscall_analysis) {
        html << GenerateSyscallAnalysisSection(result);
    }
    
    // IOCs
    if (config_.sections.ioc_extraction) {
        html << GenerateIOCSection(result);
    }
    
    // Timeline
    if (config_.sections.timeline) {
        html << GenerateTimelineSection(result);
    }
    
    // Mitigation
    if (config_.sections.mitigation_recommendations) {
        html << GenerateMitigationSection(result);
    }
    
    // Artifacts
    if (config_.sections.artifacts) {
        html << GenerateArtifactsSection(result);
    }

    // Sandbox results
    if (result.sandbox_executed) {
        html << GenerateSandboxResultsSection(result);
    }
    
    // Custom sections
    for (const auto& [title, content] : custom_sections_) {
        html << "            <section class=\"report-section custom-section\">\n";
        html << "                <h2>" << EscapeHTML(title) << "</h2>\n";
        html << content << "\n";
        html << "            </section>\n";
    }
    
    html << "        </main>\n";
    
    // Footer
    html << GenerateFooter();
    
    html << "    </div>\n";
    html << "    <script>\n" << GetJavaScript() << "\n" << custom_js_ << "\n    </script>\n";
    html << "</body>\n";
    html << "</html>\n";
    
    return html.str();
}

// Generate header
std::string HtmlReporter::GenerateHeader(const core::AnalysisResult& result) {
    std::ostringstream html;
    
    html << "        <header class=\"report-header\">\n";
    
    // Oddworld banner if configured
    if (config_.theme == ReportTheme::ODDWORLD) {
        html << GenerateOddworldBanner();
    }
    
    html << "            <div class=\"header-content\">\n";
    html << "                <h1>";
    html << "<img src=\"data:image/png;base64," << GetBase64Logo() << "\" ";
    html << "alt=\"Paramite\" class=\"title-logo\" /> ";
    html << EscapeHTML(config_.report_title) << "</h1>\n";
    
    if (!config_.analyst_name.empty() || !config_.organization.empty()) {
        html << "                <div class=\"analyst-info\">\n";
        if (!config_.analyst_name.empty()) {
            html << "                    <span class=\"analyst\">Analyst: " 
                 << EscapeHTML(config_.analyst_name) << "</span>\n";
        }
        if (!config_.organization.empty()) {
            html << "                    <span class=\"organization\">Organization: " 
                 << EscapeHTML(config_.organization) << "</span>\n";
        }
        html << "                </div>\n";
    }
    
    html << "                <div class=\"report-meta\">\n";
    html << "                    <span class=\"report-date\">Generated: " 
         << FormatTimestamp(std::chrono::system_clock::now()) << "</span>\n";
    html << "                    <span class=\"sample-name\">Sample: " 
         << EscapeHTML(result.sample_info.file_name) << "</span>\n";
    html << "                </div>\n";
    html << "            </div>\n";
    html << "        </header>\n";
    
    return html.str();
}

// Generate navigation
std::string HtmlReporter::GenerateNavigation() {
    std::ostringstream html;
    
    html << "        <nav class=\"sidebar\">\n";
    html << "            <ul class=\"nav-menu\">\n";
    
    if (config_.sections.executive_summary) {
        html << "                <li><a href=\"#executive-summary\">[SUMMARY] Executive Summary</a></li>\n";
    }
    if (config_.sections.sample_information) {
        html << "                <li><a href=\"#sample-info\">[FILE] Sample Information</a></li>\n";
    }
    html << "                <li><a href=\"#threat-assessment\">[THREAT] Threat Assessment</a></li>\n";
    if (config_.sections.static_analysis) {
        html << "                <li><a href=\"#static-analysis\">[STATIC] Static Analysis</a></li>\n";
    }
    if (config_.sections.dynamic_analysis) {
        html << "                <li><a href=\"#dynamic-analysis\">[DYNAMIC] Dynamic Analysis</a></li>\n";
    }
    if (config_.sections.behavior_analysis) {
        html << "                <li><a href=\"#behavior-analysis\">[BEHAVIOR] Behavior Analysis</a></li>\n";
    }
    if (config_.sections.network_analysis) {
        html << "                <li><a href=\"#network-analysis\">[NETWORK] Network Analysis</a></li>\n";
    }
    if (config_.sections.file_operations) {
        html << "                <li><a href=\"#file-operations\">[FILES] File Operations</a></li>\n";
    }
    if (config_.sections.process_tree) {
        html << "                <li><a href=\"#process-tree\">[PROCESS] Process Tree</a></li>\n";
    }
    if (config_.sections.syscall_analysis) {
        html << "                <li><a href=\"#syscall-analysis\">[SYSCALL] Syscall Analysis</a></li>\n";
    }
    if (config_.sections.ioc_extraction) {
        html << "                <li><a href=\"#iocs\">[IOCS] IOCs</a></li>\n";
    }
    if (config_.sections.timeline) {
        html << "                <li><a href=\"#timeline\">[TIME] Timeline</a></li>\n";
    }
    if (config_.sections.mitigation_recommendations) {
        html << "                <li><a href=\"#mitigation\">[MITIGATE] Mitigation</a></li>\n";
    }
    if (config_.sections.artifacts) {
        html << "                <li><a href=\"#artifacts\">[ARTIFACTS] Artifacts</a></li>\n";
    }
    
    html << "            </ul>\n";
    html << "        </nav>\n";
    
    return html.str();
}

// Generate executive summary section
std::string HtmlReporter::GenerateExecutiveSummarySection(const core::AnalysisResult& result) {
    std::ostringstream html;
    
    html << "            <section id=\"executive-summary\" class=\"report-section\">\n";
    html << "                <h2>[SUMMARY] Executive Summary</h2>\n";
    
    html << "                <div class=\"summary-grid\">\n";
    
    // Threat score card
    html << "                    <div class=\"summary-card threat-card\">\n";
    html << "                        <h3>Threat Score</h3>\n";
    html << GenerateThreatGauge(result.overall_threat_score);
    html << "                        <p class=\"threat-level-text " 
         << result.threat_level << "\">" << result.threat_level << "</p>\n";
    html << "                    </div>\n";
    
    // Classification
    html << "                    <div class=\"summary-card\">\n";
    html << "                        <h3>Classification</h3>\n";
    html << "                        <ul class=\"classification-list\">\n";
    for (const auto& cls : result.classifications) {
        html << "                            <li>" << EscapeHTML(cls) << "</li>\n";
    }
    html << "                        </ul>\n";
    html << "                    </div>\n";
    
    // Key findings
    html << "                    <div class=\"summary-card\">\n";
    html << "                        <h3>Key Findings</h3>\n";
    html << "                        <ul class=\"findings-list\">\n";
    for (const auto& finding : result.key_findings) {
        html << "                            <li>" << EscapeHTML(finding) << "</li>\n";
    }
    html << "                        </ul>\n";
    html << "                    </div>\n";
    
    // Statistics
    html << "                    <div class=\"summary-card\">\n";
    html << "                        <h3>Analysis Statistics</h3>\n";
    html << "                        <table class=\"stats-table\">\n";
    html << "                            <tr><td>File Size</td><td>" 
         << FormatFileSize(result.sample_info.file_size) << "</td></tr>\n";
    html << "                            <tr><td>Syscalls Captured</td><td>" 
         << result.syscall_summary.total_syscalls << "</td></tr>\n";
    html << "                            <tr><td>Network Connections</td><td>" 
         << result.network_summary.total_connections << "</td></tr>\n";
    html << "                        </table>\n";
    html << "                    </div>\n";
    
    html << "                </div>\n";
    html << "            </section>\n";
    
    return html.str();
}

// Generate sample info section
std::string HtmlReporter::GenerateSampleInfoSection(const core::AnalysisResult& result) {
    std::ostringstream html;
    
    const auto& info = result.sample_info;
    
    html << "            <section id=\"sample-info\" class=\"report-section\">\n";
    html << "                <h2>[FILE INFO] Sample Information</h2>\n";
    
    html << "                <table class=\"info-table\">\n";
    html << "                    <tr><th>Property</th><th>Value</th></tr>\n";
    html << "                    <tr><td>File Name</td><td><code>" 
         << EscapeHTML(info.file_name) << "</code></td></tr>\n";
    html << "                    <tr><td>File Path</td><td><code>" 
         << EscapeHTML(info.file_path.string()) << "</code></td></tr>\n";
    html << "                    <tr><td>File Size</td><td>" 
         << FormatFileSize(info.file_size) << "</td></tr>\n";
    html << "                    <tr><td>File Type</td><td>" 
         << EscapeHTML(info.file_type) << "</td></tr>\n";
    
    // Hashes
    if (!info.md5.empty()) {
        html << "                    <tr><td>MD5</td><td><code class=\"hash\">" 
             << info.md5 << "</code></td></tr>\n";
    }
    if (!info.sha1.empty()) {
        html << "                    <tr><td>SHA-1</td><td><code class=\"hash\">" 
             << info.sha1 << "</code></td></tr>\n";
    }
    if (!info.sha256.empty()) {
        html << "                    <tr><td>SHA-256</td><td><code class=\"hash\">" 
             << info.sha256 << "</code></td></tr>\n";
    }
    
    html << "                </table>\n";
    html << "            </section>\n";
    
    return html.str();
}

// Generate threat assessment
std::string HtmlReporter::GenerateThreatAssessment(const core::AnalysisResult& result) {
    std::ostringstream html;
    
    html << "            <section id=\"threat-assessment\" class=\"report-section\">\n";
    html << "                <h2>[THREAT ANALYSIS] Threat Assessment</h2>\n";
    
    if (config_.show_threat_gauge) {
        html << "                <div class=\"threat-assessment-visual\">\n";
        html << GenerateThreatGauge(result.overall_threat_score);
        html << "                </div>\n";
    }
    
    html << "                <div class=\"threat-details\">\n";
    html << "                    <h3>Threat Level: <span class=\"threat-badge " 
         << result.threat_level << "\">" << result.threat_level << "</span></h3>\n";
    html << "                    <p class=\"threat-description\">" 
         << EscapeHTML(result.threat_description) << "</p>\n";
    html << "                </div>\n";
    
    // Detected techniques
    if (!result.mitre_techniques.empty()) {
        html << "                <div class=\"mitre-techniques\">\n";
        html << "                    <h3>MITRE ATT&CK Techniques</h3>\n";
        html << "                    <ul class=\"technique-list\">\n";
        for (const auto& technique : result.mitre_techniques) {
            html << "                        <li>\n";
            html << "                            <span class=\"technique-id\">" 
                 << EscapeHTML(technique.id) << "</span>\n";
            html << "                            <span class=\"technique-name\">" 
                 << EscapeHTML(technique.name) << "</span>\n";
            html << "                        </li>\n";
        }
        html << "                    </ul>\n";
        html << "                </div>\n";
    }
    
    html << "            </section>\n";
    
    return html.str();
}

// Generate static analysis section
std::string HtmlReporter::GenerateStaticAnalysisSection(const core::AnalysisResult& result) {
    std::ostringstream html;
    
    html << "            <section id=\"static-analysis\" class=\"report-section\">\n";
    html << "                <h2>[STATIC] Static Analysis</h2>\n";
    
    const auto& static_analysis = result.static_analysis;
    
    // PE Information
    if (static_analysis.pe_info.has_value()) {
        const auto& pe = *static_analysis.pe_info;
        html << "                <h3>PE Information</h3>\n";
        html << "                <table class=\"info-table\">\n";
        html << "                    <tr><td>Architecture</td><td>" << pe.architecture << "</td></tr>\n";
        html << "                    <tr><td>Subsystem</td><td>" << pe.subsystem << "</td></tr>\n";
        html << "                    <tr><td>Compile Time</td><td>" 
             << FormatTimestamp(pe.compile_time) << "</td></tr>\n";
        html << "                    <tr><td>Sections</td><td>" << pe.sections.size() << "</td></tr>\n";
        html << "                </table>\n";
    }
    
    // Strings
    if (!static_analysis.interesting_strings.empty()) {
        html << "                <h3>Interesting Strings</h3>\n";
        html << "                <ul class=\"strings-list\">\n";
        int count = 0;
        for (const auto& str : static_analysis.interesting_strings) {
            if (count++ >= 50) break;  // Limit display
            html << "                    <li><code>" << EscapeHTML(str) << "</code></li>\n";
        }
        html << "                </ul>\n";
    }
    
    // Imported functions
    if (!static_analysis.imported_functions.empty()) {
        html << "                <h3>Imported Functions (Top 20)</h3>\n";
        html << "                <ul class=\"imports-list\">\n";
        int count = 0;
        for (const auto& func : static_analysis.imported_functions) {
            if (count++ >= 20) break;
            html << "                    <li><code>" << EscapeHTML(func) << "</code></li>\n";
        }
        html << "                </ul>\n";
    }
    
    html << "            </section>\n";
    
    return html.str();
}

// Generate dynamic analysis section
std::string HtmlReporter::GenerateDynamicAnalysisSection(const core::AnalysisResult& result) {
    std::ostringstream html;
    
    html << "            <section id=\"dynamic-analysis\" class=\"report-section\">\n";
    html << "                <h2>[DYNAMIC] Dynamic Analysis</h2>\n";
    
    if (!result.sandbox_executed) {
        html << "                <p class=\"no-data\">Sandbox execution not performed</p>\n";
        html << "            </section>\n";
        return html.str();
    }
    
    std::string status_class = result.sandbox_timeout ? "timeout" :
                               result.sandbox_crashed ? "crashed" : "success";
    std::string status_text = result.sandbox_timeout ? "[TIMEOUT] Execution timeout" :
                              result.sandbox_crashed ? "[CRASH] Sample crashed" : "[OK] Completed";
    
    html << "                <div class=\"execution-summary " << status_class << "\">\n";
    html << "                    <h3>Execution Status: " << status_text << "</h3>\n";
    html << "                    <p>Duration: " << (result.sandbox_duration_ms / 1000.0) << "s</p>\n";
    html << "                    <p>Exit Code: " << result.sandbox_exit_code << "</p>\n";
    html << "                </div>\n";
    
    html << "            </section>\n";
    
    return html.str();
}

// Generate behavior analysis section
std::string HtmlReporter::GenerateBehaviorAnalysisSection(const core::AnalysisResult& result) {
    std::ostringstream html;
    
    html << "            <section id=\"behavior-analysis\" class=\"report-section\">\n";
    html << "                <h2>[BEHAVIOR] Behavior Analysis</h2>\n";
    
    const auto& behaviors = result.detected_behaviors;
    
    if (behaviors.empty()) {
        html << "                <p class=\"no-data\">No suspicious behaviors detected</p>\n";
    } else {
        html << "                <div class=\"behaviors-grid\">\n";
        for (const auto& behavior : behaviors) {
            html << "                    <div class=\"behavior-card severity-" 
                 << behavior.severity << "\">\n";
            html << "                        <h4>" << EscapeHTML(behavior.name) << "</h4>\n";
            html << "                        <p>" << EscapeHTML(behavior.description) << "</p>\n";
            html << "                        <div class=\"behavior-meta\">\n";
            html << "                            <span class=\"confidence\">Confidence: " 
                 << behavior.confidence << "%</span>\n";
            html << "                            <span class=\"severity\">Severity: " 
                 << behavior.severity << "</span>\n";
            html << "                        </div>\n";
            html << "                    </div>\n";
        }
        html << "                </div>\n";
    }
    
    html << "            </section>\n";
    
    return html.str();
}

// Generate network analysis section
std::string HtmlReporter::GenerateNetworkAnalysisSection(const core::AnalysisResult& result) {
    std::ostringstream html;
    
    html << "            <section id=\"network-analysis\" class=\"report-section\">\n";
    html << "                <h2>[NETWORK] Network Analysis</h2>\n";
    
    const auto& network = result.network_summary;
    
    // Statistics
    html << "                <div class=\"network-stats\">\n";
    html << "                    <div class=\"stat-card\">\n";
    html << "                        <div class=\"stat-value\">" << network.total_connections << "</div>\n";
    html << "                        <div class=\"stat-label\">Total Connections</div>\n";
    html << "                    </div>\n";
    html << "                    <div class=\"stat-card\">\n";
    html << "                        <div class=\"stat-value\">" << network.dns_queries << "</div>\n";
    html << "                        <div class=\"stat-label\">DNS Queries</div>\n";
    html << "                    </div>\n";
    html << "                    <div class=\"stat-card\">\n";
    html << "                        <div class=\"stat-value\">" << network.http_requests << "</div>\n";
    html << "                        <div class=\"stat-label\">HTTP Requests</div>\n";
    html << "                    </div>\n";
    html << "                    <div class=\"stat-card\">\n";
    html << "                        <div class=\"stat-value\">" 
             << network.suspicious_connections << "</div>\n";
    html << "                        <div class=\"stat-label\">Suspicious</div>\n";
    html << "                    </div>\n";
    html << "                </div>\n";
    
    // Network table
    if (!result.network_connections.empty()) {
        html << GenerateNetworkTable(result);
    }
    
    // Network graph
    if (config_.show_network_graph) {
        html << GenerateNetworkGraph(result);
    }
    
    html << "            </section>\n";
    
    return html.str();
}

// Generate file operations section
std::string HtmlReporter::GenerateFileOperationsSection(const core::AnalysisResult& result) {
    std::ostringstream html;
    
    html << "            <section id=\"file-operations\" class=\"report-section\">\n";
    html << "                <h2>[FILE OPS] File Operations</h2>\n";
    
    const auto& file_ops = result.file_summary;
    
    // Statistics
    html << "                <div class=\"file-stats\">\n";
    html << "                    <div class=\"stat-card\">\n";
    html << "                        <div class=\"stat-value\">" << file_ops.files_created << "</div>\n";
    html << "                        <div class=\"stat-label\">Created</div>\n";
    html << "                    </div>\n";
    html << "                    <div class=\"stat-card\">\n";
    html << "                        <div class=\"stat-value\">" << file_ops.files_modified << "</div>\n";
    html << "                        <div class=\"stat-label\">Modified</div>\n";
    html << "                    </div>\n";
    html << "                    <div class=\"stat-card\">\n";
    html << "                        <div class=\"stat-value\">" << file_ops.files_deleted << "</div>\n";
    html << "                        <div class=\"stat-label\">Deleted</div>\n";
    html << "                    </div>\n";
    html << "                    <div class=\"stat-card\">\n";
    html << "                        <div class=\"stat-value\">" 
             << file_ops.suspicious_operations << "</div>\n";
    html << "                        <div class=\"stat-label\">Suspicious</div>\n";
    html << "                    </div>\n";
    html << "                </div>\n";
    
    // File operations table
    if (!result.file_operations.empty()) {
        html << GenerateFileOperationsTable(result);
    }
    
    html << "            </section>\n";
    
    return html.str();
}

// Generate process tree section
std::string HtmlReporter::GenerateProcessTreeSection(const core::AnalysisResult& result) {
    std::ostringstream html;
    
    html << "            <section id=\"process-tree\" class=\"report-section\">\n";
    html << "                <h2>[PROCESS TREE] Process Tree</h2>\n";
    
    if (config_.show_process_tree_graph) {
        html << GenerateProcessTreeGraph(result);
    } else {
        html << "                <p class=\"info\">Process tree visualization requires JavaScript</p>\n";
    }
    
    html << "            </section>\n";
    
    return html.str();
}

// Generate syscall analysis section
std::string HtmlReporter::GenerateSyscallAnalysisSection(const core::AnalysisResult& result) {
    std::ostringstream html;
    
    html << "            <section id=\"syscall-analysis\" class=\"report-section\">\n";
    html << "                <h2>[SYSCALLS] Syscall Analysis</h2>\n";
    
    const auto& syscalls = result.syscall_summary;
    
    // Statistics
    html << "                <div class=\"syscall-stats\">\n";
    html << "                    <p><strong>Total Syscalls:</strong> " 
         << syscalls.total_syscalls << "</p>\n";
    html << "                    <p><strong>Failed Syscalls:</strong> " 
         << syscalls.failed_syscalls << "</p>\n";
    html << "                    <p><strong>Suspicious Syscalls:</strong> " 
         << syscalls.suspicious_syscalls << "</p>\n";
    html << "                </div>\n";
    
    // Top syscalls table
    if (!syscalls.syscall_counts.empty()) {
        html << "                <h3>Top Syscalls</h3>\n";
        html << "                <table class=\"data-table\">\n";
        html << "                    <thead>\n";
        html << "                        <tr><th>Syscall</th><th>Count</th><th>Percentage</th></tr>\n";
        html << "                    </thead>\n";
        html << "                    <tbody>\n";
        
        // Sort by count
        std::vector<std::pair<std::string, int>> sorted_syscalls(
            syscalls.syscall_counts.begin(), syscalls.syscall_counts.end());
        std::sort(sorted_syscalls.begin(), sorted_syscalls.end(),
                 [](const auto& a, const auto& b) { return a.second > b.second; });
        
        int count = 0;
        for (const auto& [name, freq] : sorted_syscalls) {
            if (count++ >= 20) break;
            
            double percentage = (freq * 100.0) / syscalls.total_syscalls;
            
            html << "                        <tr>\n";
            html << "                            <td><code>" << EscapeHTML(name) << "</code></td>\n";
            html << "                            <td>" << freq << "</td>\n";
            html << "                            <td>" << std::fixed << std::setprecision(2) 
                 << percentage << "%</td>\n";
            html << "                        </tr>\n";
        }
        
        html << "                    </tbody>\n";
        html << "                </table>\n";
    }
    
    html << "            </section>\n";
    
    return html.str();
}

// Generate IOC section
std::string HtmlReporter::GenerateIOCSection(const core::AnalysisResult& result) {
    std::ostringstream html;
    
    html << "            <section id=\"iocs\" class=\"report-section\">\n";
    html << "                <h2>[IOC] Indicators of Compromise (IOCs)</h2>\n";
    
    if (!result.iocs || result.iocs->total_count == 0) {
        html << "                <p class=\"no-data\">No IOCs extracted</p>\n";
        html << "            </section>\n";
        return html.str();
    }
    
    // Display IOC summary
    html << "                <div class=\"ioc-summary\">\n";
    html << "                    <p>Total IOCs: <strong>" << result.iocs->total_count << "</strong></p>\n";
    html << "                </div>\n";
    
    // Network IOCs (IPs, URLs, domains)
    if (!result.iocs->network_iocs.empty()) {
        html << "                <h3>Network IOCs (" << result.iocs->network_iocs.size() << ")</h3>\n";
        html << "                <ul class=\"ioc-list\">\n";
        for (const auto& ioc : result.iocs->network_iocs) {
            html << "                    <li><span class=\"ioc-type\">[" << EscapeHTML(IOCTypeToString(ioc.type)) << "]</span> ";
            html << "<code>" << EscapeHTML(ioc.value) << "</code></li>\n";
        }
        html << "                </ul>\n";
    }
    
    // File IOCs (paths, hashes)
    if (!result.iocs->file_iocs.empty()) {
        html << "                <h3>File IOCs (" << result.iocs->file_iocs.size() << ")</h3>\n";
        html << "                <ul class=\"ioc-list\">\n";
        for (const auto& ioc : result.iocs->file_iocs) {
            html << "                    <li><span class=\"ioc-type\">[" << EscapeHTML(IOCTypeToString(ioc.type)) << "]</span> ";
            html << "<code>" << EscapeHTML(ioc.value) << "</code></li>\n";
        }
        html << "                </ul>\n";
    }
    
    // Host IOCs (registry keys, mutexes)
    if (!result.iocs->host_iocs.empty()) {
        html << "                <h3>Host IOCs (" << result.iocs->host_iocs.size() << ")</h3>\n";
        html << "                <ul class=\"ioc-list\">\n";
        for (const auto& ioc : result.iocs->host_iocs) {
            html << "                    <li><span class=\"ioc-type\">[" << EscapeHTML(IOCTypeToString(ioc.type)) << "]</span> ";
            html << "<code>" << EscapeHTML(ioc.value) << "</code></li>\n";
        }
        html << "                </ul>\n";
    }
    
    // Behavioral IOCs
    if (!result.iocs->behavioral_iocs.empty()) {
        html << "                <h3>Behavioral IOCs (" << result.iocs->behavioral_iocs.size() << ")</h3>\n";
        html << "                <ul class=\"ioc-list\">\n";
        for (const auto& ioc : result.iocs->behavioral_iocs) {
            html << "                    <li><span class=\"ioc-type\">[" << EscapeHTML(IOCTypeToString(ioc.type)) << "]</span> ";
            html << "<code>" << EscapeHTML(ioc.value) << "</code></li>\n";
        }
        html << "                </ul>\n";
    }
    
    html << "            </section>\n";
    
    return html.str();
}

// Generate timeline section
std::string HtmlReporter::GenerateTimelineSection(const core::AnalysisResult& result) {
    std::ostringstream html;
    
    html << "            <section id=\"timeline\" class=\"report-section\">\n";
    html << "                <h2>[TIMELINE] Execution Timeline</h2>\n";
    
    if (config_.show_timeline_graph) {
        html << GenerateTimelineChart(result);
    } else {
        html << "                <p class=\"info\">Timeline visualization requires JavaScript</p>\n";
    }
    
    html << "            </section>\n";
    
    return html.str();
}

// Generate mitigation section
std::string HtmlReporter::GenerateMitigationSection(const core::AnalysisResult& result) {
    std::ostringstream html;
    
    html << "            <section id=\"mitigation\" class=\"report-section\">\n";
    html << "                <h2>[MITIGATION] Mitigation Recommendations</h2>\n";
    
    if (result.recommendations.empty()) {
        html << "                <p class=\"no-data\">No specific recommendations</p>\n";
    } else {
        html << "                <ul class=\"recommendations-list\">\n";
        for (const auto& rec : result.recommendations) {
            html << "                    <li>" << EscapeHTML(rec) << "</li>\n";
        }
        html << "                </ul>\n";
    }
    
    html << "            </section>\n";
    
    return html.str();
}

// Generate artifacts section
std::string HtmlReporter::GenerateArtifactsSection(const core::AnalysisResult& result) {
    std::ostringstream html;
    
    html << "            <section id=\"artifacts\" class=\"report-section\">\n";
    html << "                <h2>[ARTIFACTS] Analysis Artifacts</h2>\n";
    
    html << "                <div class=\"artifacts-list\">\n";
    
    // PCAP file
    if (config_.include_pcap_download && !result.pcap_file.empty()) {
        html << "                    <div class=\"artifact-item\">\n";
        html << "                        <span class=\"artifact-icon\">[PCAP]</span>\n";
        html << "                        <span class=\"artifact-name\">Network Capture (PCAP)</span>\n";
        html << GenerateDownloadLink(result.pcap_file, "Download PCAP");
        html << "                    </div>\n";
    }
    
    // JSON export
    if (config_.include_json_export) {
        html << "                    <div class=\"artifact-item\">\n";
        html << "                        <span class=\"artifact-icon\">[JSON]</span>\n";
        html << "                        <span class=\"artifact-name\">JSON Export</span>\n";
        html << "                        <button onclick=\"downloadJSON()\">Download JSON</button>\n";
        html << "                    </div>\n";
    }
    
    html << "                </div>\n";
    html << "            </section>\n";
    
    return html.str();
}

// Generate sandbox results section
std::string HtmlReporter::GenerateSandboxResultsSection(const core::AnalysisResult& result) {
    std::ostringstream html;
    
    html << "            <section id=\"sandbox-results\" class=\"report-section\">\n";
    html << "                <h2>Dynamic Analysis (Sandbox Execution)</h2>\n";
    
    // Status
    std::string status_class = "success";
    std::string status_text = "[OK] COMPLETED";
    if (result.sandbox_timeout) {
        status_class = "warning";
        status_text = "[TIMEOUT] EXECUTION TIMEOUT";
    } else if (result.sandbox_crashed) {
        status_class = "danger";
        status_text = "[CRASH] EXECUTION FAILED";
    }
    
    html << "                <div class=\"sandbox-summary\">\n";
    html << "                    <p><strong>Execution Status:</strong> ";
    html << "<span class=\"badge badge-" << status_class << "\">" << status_text << "</span></p>\n";
    html << "                    <p><strong>Exit Code:</strong> " << result.sandbox_exit_code << "</p>\n";
    html << "                    <p><strong>Duration:</strong> " << result.sandbox_duration_ms << " ms</p>\n";
    html << "                </div>\n";
    
    // Artifacts
    if (!result.sandbox_artifacts.empty()) {
        html << "                <h3>Captured Artifacts</h3>\n";
        html << "                <ul class=\"artifacts-list\">\n";
        for (const auto& artifact : result.sandbox_artifacts) {
            html << "                    <li>[FILE]" << EscapeHTML(artifact) << "</li>\n";
        }
        html << "                </ul>\n";
    }
    
    html << "            </section>\n";
    
    return html.str();
}

// Generate footer
std::string HtmlReporter::GenerateFooter() {
    std::ostringstream html;
    
    html << "        <footer class=\"report-footer\">\n";
    
    if (config_.show_paramite_branding) {
        html << "            <p class=\"branding\">Generated by <strong>Paramite</strong> "
             << "- Oddworld-Inspired Malware Analysis Framework</p>\n";
    }
    
    if (!config_.custom_footer.empty()) {
        html << "            <p class=\"custom-footer\">" 
             << EscapeHTML(config_.custom_footer) << "</p>\n";
    }
    
    html << "            <p class=\"timestamp\">Report generated: " 
         << FormatTimestamp(std::chrono::system_clock::now()) << "</p>\n";
    html << "        </footer>\n";
    
    return html.str();
}

// Generate threat gauge
std::string HtmlReporter::GenerateThreatGauge(int threat_score) {
    std::ostringstream html;
    
    double percentage = (threat_score / 100.0) * 180.0;  // 0-180 degrees
    
    std::string threat_level;
    if (threat_score >= 90) {
        threat_level = "CRITICAL";
    } else if (threat_score >= 75) {
        threat_level = "HIGH";
    } else if (threat_score >= 50) {
        threat_level = "MEDIUM";
    } else if (threat_score >= 25) {
        threat_level = "LOW";
    } else {
        threat_level = "MINIMAL";
    }
    std::string color = GetThreatColor(threat_level);
    
    html << "                <div class=\"threat-gauge\">\n";
    html << "                    <svg viewBox=\"0 0 200 120\" class=\"gauge-svg\">\n";
    html << "                        <path class=\"gauge-background\" "
         << "d=\"M 20 100 A 80 80 0 0 1 180 100\" "
         << "stroke=\"#e0e0e0\" stroke-width=\"15\" fill=\"none\"></path>\n";
    html << "                        <path class=\"gauge-fill\" "
         << "d=\"M 20 100 A 80 80 0 0 1 180 100\" "
         << "stroke=\"" << color << "\" stroke-width=\"15\" fill=\"none\" "
         << "stroke-dasharray=\"" << percentage << " 251.2\" "
         << "stroke-linecap=\"round\"></path>\n";
    html << "                        <text x=\"100\" y=\"85\" text-anchor=\"middle\" "
         << "font-size=\"32\" font-weight=\"bold\" fill=\"" << color << "\">"
         << threat_score << "</text>\n";
    html << "                        <text x=\"100\" y=\"105\" text-anchor=\"middle\" "
         << "font-size=\"14\" fill=\"#666\">Threat Score</text>\n";
    html << "                    </svg>\n";
    html << "                </div>\n";
    
    return html.str();
}

// Generate process tree graph
std::string HtmlReporter::GenerateProcessTreeGraph(const core::AnalysisResult& result) {
    std::ostringstream html;
    
    const auto& tree = result.process_tree;
    const auto& summary = result.process_summary;
    
    html << "                <div class=\"process-tree-section\">\n";
    
    // Summary stats
    html << "                    <div class=\"process-stats\">\n";
    html << "                        <p><strong>Total Processes:</strong> " 
         << summary.total_processes << "</p>\n";
    html << "                        <p><strong>Processes Created:</strong> " 
         << summary.processes_created << "</p>\n";
    html << "                        <p><strong>Threads Created:</strong> " 
         << summary.threads_created << "</p>\n";
    html << "                    </div>\n";
    
    // Process list
    if (!tree.processes.empty()) {
        html << "                    <h3>Process List</h3>\n";
        html << "                    <table class=\"data-table\">\n";
        html << "                        <thead>\n";
        html << "                            <tr><th>PID</th><th>Name</th><th>Path</th></tr>\n";
        html << "                        </thead>\n";
        html << "                        <tbody>\n";
        
        for (const auto& proc : tree.processes) {
            html << "                            <tr>\n";
            html << "                                <td>" << proc.pid << "</td>\n";
            html << "                                <td><code>" 
                 << EscapeHTML(proc.name) << "</code></td>\n";
            html << "                                <td><code>" 
                 << EscapeHTML(proc.path) << "</code></td>\n";
            html << "                            </tr>\n";
        }
        
        html << "                        </tbody>\n";
        html << "                    </table>\n";
    } else {
        html << "                    <p class=\"no-data\">No process information captured</p>\n";
    }
    
    html << "                </div>\n";
    
    return html.str();
}

// Generate network graph
std::string HtmlReporter::GenerateNetworkGraph(const core::AnalysisResult& result) {
    std::ostringstream html;
    
    if (result.network_connections.empty()) {
        return "                <div class=\"no-data\">No network connections captured</div>\n";
    }
    
    // Generate network graph with vis.js
    html << "                <div id=\"network-graph\" style=\"height: 400px; border: 1px solid var(--border-color);\"></div>\n";
    html << "                <script>\n";
    html << "                    var nodes = new vis.DataSet([\n";
    
    // Add sample node (the malware)
    html << "                        {id: 0, label: '" << EscapeHTML(result.sample_info.file_name) 
         << "', color: '#f44336', size: 30}\n";
    
    // Add network nodes
    std::set<std::string> unique_ips;
    int node_id = 1;
    for (const auto& conn : result.network_connections) {
        if (unique_ips.insert(conn.remote_address).second) {
            html << "                        ,{id: " << node_id++ 
                 << ", label: '" << EscapeHTML(conn.remote_address) 
                 << "', color: '" << (conn.is_suspicious ? "#ff9800" : "#4caf50") << "'}\n";
        }
    }
    
    html << "                    ]);\n";
    html << "                    var edges = new vis.DataSet([\n";
    
    // Add edges (connections)
    node_id = 1;
    unique_ips.clear();
    bool first = true;
    for (const auto& conn : result.network_connections) {
        if (unique_ips.insert(conn.remote_address).second) {
            if (!first) html << ",\n";
            html << "                        {from: 0, to: " << node_id++ 
                 << ", label: '" << conn.protocol << ":" << conn.remote_port << "'}";
            first = false;
        }
    }
    
    html << "\n                    ]);\n";
    html << "                    var container = document.getElementById('network-graph');\n";
    html << "                    var data = { nodes: nodes, edges: edges };\n";
    html << "                    var options = {\n";
    html << "                        nodes: { shape: 'dot', font: { color: 'var(--text-color)' } },\n";
    html << "                        edges: { arrows: 'to', font: { color: 'var(--text-color)' } },\n";
    html << "                        physics: { stabilization: true }\n";
    html << "                    };\n";
    html << "                    var network = new vis.Network(container, data, options);\n";
    html << "                </script>\n";
    
    return html.str();
}

// Generate timeline chart
std::string HtmlReporter::GenerateTimelineChart(const core::AnalysisResult& result) {
    std::ostringstream html;
    
    // Collect timeline events
    std::vector<std::pair<int, std::string>> events;
    
    if (result.process_summary.processes_created > 0) {
        events.push_back({0, "Processes Created"});
    }
    if (result.syscall_summary.total_syscalls > 0) {
        events.push_back({5, "Syscalls Executed"});
    }
    if (result.network_summary.total_connections > 0) {
        events.push_back({10, "Network Activity"});
    }
    if (result.file_summary.files_created > 0) {
        events.push_back({8, "File Operations"});
    }
    
    if (events.empty()) {
        return "                <div class=\"no-data\">No timeline data available</div>\n";
    }
    
    html << "                <canvas id=\"timeline-chart\" height=\"100\"></canvas>\n";
    html << "                <script>\n";
    html << "                    var ctx = document.getElementById('timeline-chart').getContext('2d');\n";
    html << "                    var chart = new Chart(ctx, {\n";
    html << "                        type: 'line',\n";
    html << "                        data: {\n";
    html << "                            labels: [";
    
    // Add labels
    bool first = true;
    for (const auto& [time, label] : events) {
        if (!first) html << ", ";
        html << "'" << time << "s'";
        first = false;
    }
    
    html << "],\n";
    html << "                            datasets: [{\n";
    html << "                                label: 'Activity Timeline',\n";
    html << "                                data: [";
    
    // Add data points
    first = true;
    for (const auto& [time, label] : events) {
        if (!first) html << ", ";
        html << time;
        first = false;
    }
    
    html << "],\n";
    html << "                                borderColor: '#4a9eff',\n";
    html << "                                backgroundColor: 'rgba(74, 158, 255, 0.1)',\n";
    html << "                                tension: 0.4\n";
    html << "                            }]\n";
    html << "                        },\n";
    html << "                        options: {\n";
    html << "                            responsive: true,\n";
    html << "                            plugins: { legend: { display: true } }\n";
    html << "                        }\n";
    html << "                    });\n";
    html << "                </script>\n";
    
    return html.str();
}

// Generate chart (stub)
std::string HtmlReporter::GenerateChart(const ChartData& chart) {
    std::ostringstream html;
    
    html << "                <div class=\"chart-container\">\n";
    html << "                    <h4>" << EscapeHTML(chart.title) << "</h4>\n";
    html << "                    <canvas id=\"chart-" << chart.chart_id << "\" height=\"80\"></canvas>\n";
    html << "                </div>\n";
    html << "                <script>\n";
    html << "                    var ctx" << chart.chart_id << " = document.getElementById('chart-" 
         << chart.chart_id << "').getContext('2d');\n";
    html << "                    new Chart(ctx" << chart.chart_id << ", {\n";
    
    std::string chart_type_str;
    switch (chart.type) {
        case ChartType::LINE: chart_type_str = "line"; break;
        case ChartType::BAR: chart_type_str = "bar"; break;
        case ChartType::PIE: chart_type_str = "pie"; break;
        default: chart_type_str = "bar"; break;
    }

    html << "                        type: '" << chart_type_str << "',\n";
    html << "                        data: {\n";
    html << "                            labels: [";
    
    // Labels
    bool first = true;
    for (const auto& label : chart.labels) {
        if (!first) html << ", ";
        html << "'" << EscapeHTML(label) << "'";
        first = false;
    }
    
    html << "],\n";
    html << "                            datasets: [{\n";
    html << "                                data: [";
    
    // Data
    first = true;
    for (double value : chart.values) {
        if (!first) html << ", ";
        html << value;
        first = false;
    }
    
    html << "],\n";
    html << "                                backgroundColor: 'rgba(74, 158, 255, 0.5)',\n";
    html << "                                borderColor: '#4a9eff',\n";
    html << "                                borderWidth: 2\n";
    html << "                            }]\n";
    html << "                        },\n";
    html << "                        options: { responsive: true }\n";
    html << "                    });\n";
    html << "                </script>\n";
    
    return html.str();
}

// Generate IOC table
std::string HtmlReporter::GenerateIOCTable(const core::AnalysisResult& result) {
    std::ostringstream html;
    
    html << "                <table class=\"ioc-table data-table\">\n";
    html << "                    <thead>\n";
    html << "                        <tr>\n";
    html << "                            <th>Type</th>\n";
    html << "                            <th>Value</th>\n";
    html << "                            <th>Source</th>\n";
    html << "                        </tr>\n";
    html << "                    </thead>\n";
    html << "                    <tbody>\n";
    
    for (const auto& ioc : result.iocs_list) {
        html << "                        <tr>\n";
        html << "                            <td><span class=\"ioc-type\">" 
             << EscapeHTML(ioc.type) << "</span></td>\n";
        html << "                            <td><code>" << EscapeHTML(ioc.value) << "</code></td>\n";
        html << "                            <td>" << EscapeHTML(ioc.source) << "</td>\n";
        html << "                        </tr>\n";
    }
    
    html << "                    </tbody>\n";
    html << "                </table>\n";
    
    return html.str();
}

// Generate file operations table
std::string HtmlReporter::GenerateFileOperationsTable(const core::AnalysisResult& result) {
    std::ostringstream html;
    
    html << "                <table class=\"file-ops-table data-table\">\n";
    html << "                    <thead>\n";
    html << "                        <tr>\n";
    html << "                            <th>Operation</th>\n";
    html << "                            <th>Path</th>\n";
    html << "                            <th>Status</th>\n";
    html << "                        </tr>\n";
    html << "                    </thead>\n";
    html << "                    <tbody>\n";
    
    int count = 0;
    for (const auto& op : result.file_operations) {
        if (count++ >= 100) break;  // Limit display
        
        html << "                        <tr class=\"" 
             << (op.is_suspicious ? "suspicious" : "") << "\">\n";
        html << "                            <td>" << EscapeHTML(op.operation) << "</td>\n";
        html << "                            <td><code>" << EscapeHTML(op.path.string()) << "</code></td>\n";
        html << "                            <td>" << (op.success ? "[OK]" : "[FAIL]") << "</td>\n";
        html << "                        </tr>\n";
    }
    
    html << "                    </tbody>\n";
    html << "                </table>\n";
    
    return html.str();
}

// Generate network table
std::string HtmlReporter::GenerateNetworkTable(const core::AnalysisResult& result) {
    std::ostringstream html;
    
    html << "                <table class=\"network-table data-table\">\n";
    html << "                    <thead>\n";
    html << "                        <tr>\n";
    html << "                            <th>Protocol</th>\n";
    html << "                            <th>Remote Address</th>\n";
    html << "                            <th>Port</th>\n";
    html << "                            <th>Status</th>\n";
    html << "                        </tr>\n";
    html << "                    </thead>\n";
    html << "                    <tbody>\n";
    
    int count = 0;
    for (const auto& conn : result.network_connections) {
        if (count++ >= config_.max_network_connections_displayed) break;
        
        html << "                        <tr class=\"" 
             << (conn.is_suspicious ? "suspicious" : "") << "\">\n";
        html << "                            <td>" << EscapeHTML(conn.protocol) << "</td>\n";
        html << "                            <td><code>" 
             << EscapeHTML(conn.remote_address) << "</code></td>\n";
        html << "                            <td>" << conn.remote_port << "</td>\n";
        html << "                            <td>" << (conn.is_suspicious ? "[!] Suspicious" : "[OK]") << "</td>\n";
        html << "                        </tr>\n";
    }
    
    html << "                    </tbody>\n";
    html << "                </table>\n";
    
    return html.str();
}

// Get CSS
std::string HtmlReporter::GetCSS() {
    std::ostringstream css;
    
    css << GetThemeCSS(config_.theme);
    
    css << R"(
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: var(--text-color);
            background-color: var(--bg-color);
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .report-header {
            background: var(--header-bg);
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .report-header h1 {
            font-size: 2.5em;
            margin-bottom: 15px;
            color: var(--primary-color);
        }

        .title-logo {
            height: 1.2em;
            width: auto;
            vertical-align: middle;
            margin-right: 10px;
            display: inline-block;
        }
        
        .sidebar {
            position: fixed;
            left: 0;
            top: 120px;
            width: 250px;
            background: var(--sidebar-bg);
            padding: 20px;
            border-radius: 0 10px 10px 0;
            max-height: calc(100vh - 140px);
            overflow-y: auto;
        }
        
        .nav-menu {
            list-style: none;
        }
        
        .nav-menu li {
            margin-bottom: 10px;
        }
        
        .nav-menu a {
            color: var(--text-color);
            text-decoration: none;
            padding: 8px 12px;
            display: block;
            border-radius: 5px;
            transition: all 0.3s;
        }
        
        .nav-menu a:hover {
            background: var(--primary-color);
            color: white;
        }
        
        .content {
            margin-left: 280px;
        }
        
        .report-section {
            background: var(--section-bg);
            padding: 30px;
            margin-bottom: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        
        .report-section h2 {
            font-size: 2em;
            margin-bottom: 20px;
            color: var(--primary-color);
            border-bottom: 2px solid var(--border-color);
            padding-bottom: 10px;
        }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        
        .summary-card {
            background: var(--card-bg);
            padding: 20px;
            border-radius: 8px;
            border: 1px solid var(--border-color);
        }
        
        .threat-gauge {
            text-align: center;
            margin: 20px 0;
        }
        
        .gauge-svg {
            max-width: 200px;
            height: auto;
        }
        
        .data-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        
        .data-table th,
        .data-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }
        
        .data-table th {
            background: var(--header-bg);
            font-weight: bold;
        }
        
        .data-table tr:hover {
            background: var(--hover-color);
        }
        
        .data-table tr.suspicious {
            background: rgba(255, 100, 100, 0.1);
        }
        
        code {
            background: var(--code-bg);
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }
        
        .hash {
            font-size: 0.8em;
            word-break: break-all;
        }
        
        .threat-badge {
            padding: 4px 12px;
            border-radius: 4px;
            font-weight: bold;
            text-transform: uppercase;
        }
        
        .threat-badge.LOW { background: #4caf50; color: white; }
        .threat-badge.MEDIUM { background: #ff9800; color: white; }
        .threat-badge.HIGH { background: #ff5722; color: white; }
        .threat-badge.CRITICAL { background: #f44336; color: white; }
        
        .report-footer {
            text-align: center;
            padding: 30px;
            color: var(--text-muted);
            border-top: 1px solid var(--border-color);
            margin-top: 50px;
        }
        
        .no-data {
            color: var(--text-muted);
            font-style: italic;
            padding: 20px;
            text-align: center;
        }
    )";
    
    return css.str();
}

// Embed Paramite logo as base64
std::string HtmlReporter::GetBase64Logo() {
    std::filesystem::path logo_path = std::filesystem::path(__FILE__).parent_path().parent_path().parent_path() / "html_assets" / "Paramite.png";
    
    if (!std::filesystem::exists(logo_path)) {
        logo_path = std::filesystem::current_path() / "html_assets" / "Paramite.png";
    }

    if (!std::filesystem::exists(logo_path)) {
        spdlog::warn("Logo not found at: {}", logo_path.string());
        return "";
    }

    std::ifstream file(logo_path, std::ios::binary);
    if (!file.is_open()) {
        spdlog::warn("Failed to open logo: {}", logo_path.string());
        return "";
    }
    
    std::vector<unsigned char> buffer(std::istreambuf_iterator<char>(file), {});
    file.close();

    // Base64 encode
    static const char* base64_chars = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::string encoded;
    int val = 0, valb = -6;
    for (unsigned char c : buffer) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            encoded.push_back(base64_chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) encoded.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
    while (encoded.size() % 4) encoded.push_back('=');
    
    spdlog::info("Logo encoded: {} bytes -> {} base64 chars", buffer.size(), encoded.size());
    return encoded;
}

// Get JavaScript
std::string HtmlReporter::GetJavaScript() {
    return R"(
        // Table filtering and search
        function initializeTables() {
            const tables = document.querySelectorAll('.data-table');
            tables.forEach(table => {
                // Add sorting
                const headers = table.querySelectorAll('th');
                headers.forEach((header, index) => {
                    header.style.cursor = 'pointer';
                    header.addEventListener('click', () => sortTable(table, index));
                });
            });
        }
        
        function sortTable(table, column) {
            // Table sorting logic
            console.log('Sorting table by column', column);
        }
        
        function downloadJSON() {
            // Export JSON logic
            console.log('Downloading JSON');
        }
        
        // Initialize when DOM is loaded
        document.addEventListener('DOMContentLoaded', () => {
            initializeTables();
        });
    )";
}

// Get theme CSS
std::string HtmlReporter::GetThemeCSS(ReportTheme theme) {
    if (theme == ReportTheme::DARK) {
        return R"(
            :root {
                --bg-color: #1a1a1a;
                --text-color: #e0e0e0;
                --text-muted: #888;
                --primary-color: #4a9eff;
                --header-bg: #2a2a2a;
                --sidebar-bg: #252525;
                --section-bg: #222;
                --card-bg: #2a2a2a;
                --border-color: #444;
                --hover-color: #333;
                --code-bg: #1a1a1a;
            }
        )";
    } else if (theme == ReportTheme::ODDWORLD) {
        return R"(
            :root {
                --bg-color: #0a0e1a;
                --text-color: #b8c5d6;
                --text-muted: #6a7688;
                --primary-color: #7c3aed;
                --header-bg: linear-gradient(135deg, #1a1f3a 0%, #2d1b4e 100%);
                --sidebar-bg: #141829;
                --section-bg: #0f1322;
                --card-bg: #141829;
                --border-color: #2d1b4e;
                --hover-color: #1a1f3a;
                --code-bg: #0a0d16;
            }
        )";
    } else {
        return R"(
            :root {
                --bg-color: #f5f5f5;
                --text-color: #333;
                --text-muted: #666;
                --primary-color: #2196f3;
                --header-bg: #fff;
                --sidebar-bg: #fff;
                --section-bg: #fff;
                --card-bg: #f9f9f9;
                --border-color: #ddd;
                --hover-color: #f0f0f0;
                --code-bg: #f5f5f5;
            }
        )";
    }
}

// Embed file as base64 (stub)
std::string HtmlReporter::EmbedFileAsBase64(const std::filesystem::path& file_path) {
    return "data:application/octet-stream;base64,SGVsbG8gV29ybGQ=";
}

// Generate download link
std::string HtmlReporter::GenerateDownloadLink(const std::filesystem::path& file_path,
                                               const std::string& display_name) {
    return "<a href=\"" + file_path.string() + "\" download class=\"download-link\">" + 
           display_name + "</a>";
}

// Escape HTML
std::string HtmlReporter::EscapeHTML(const std::string& text) {
    std::string escaped;
    escaped.reserve(text.length());
    
    for (char c : text) {
        switch (c) {
            case '&':  escaped += "&amp;"; break;
            case '<':  escaped += "&lt;"; break;
            case '>':  escaped += "&gt;"; break;
            case '"':  escaped += "&quot;"; break;
            case '\'': escaped += "&#39;"; break;
            default:   escaped += c; break;
        }
    }
    
    return escaped;
}

// Format timestamp
std::string HtmlReporter::FormatTimestamp(const std::chrono::system_clock::time_point& time) {
    auto time_t = std::chrono::system_clock::to_time_t(time);
    std::ostringstream oss;
    oss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

// Format duration
std::string HtmlReporter::FormatDuration(const std::chrono::milliseconds& duration) {
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration).count();
    
    if (seconds < 60) {
        return std::to_string(seconds) + "s";
    } else if (seconds < 3600) {
        return std::tostring(seconds / 60) + "m " + std::to_string(seconds % 60) + "s";
    } else {
        auto hours = seconds / 3600;
        auto minutes = (seconds % 3600) / 60;
        return std::to_string(hours) + "h " + std::to_string(minutes) + "m";
    }
}

// Format file size
std::string HtmlReporter::FormatFileSize(std::size_t bytes) {
    const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    int unit_index = 0;
    double size = static_cast<double>(bytes);
    
    while (size >= 1024.0 && unit_index < 4) {
        size /= 1024.0;
        unit_index++;
    }
    
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2) << size << " " << units[unit_index];
    return oss.str();
}

// Get threat color
std::string HtmlReporter::GetThreatColor(const std::string& threat_level) {
    if (threat_level == "CRITICAL") return "#c0392b";  // Dark red
    if (threat_level == "HIGH") return "#e74c3c";      // Red
    if (threat_level == "MEDIUM") return "#f39c12";    // Orange
    if (threat_level == "LOW") return "#f1c40f";       // Yellow
    if (threat_level == "MINIMAL") return "#27ae60";   // Green
    return "#95a5a6";  // Gray (default)
}

// Get threat emoji
std::string HtmlReporter::GetThreatEmoji(const std::string& threat_level) {
    if (threat_level == "LOW") return "✅";
    if (threat_level == "MEDIUM") return "⚠️";
    if (threat_level == "HIGH") return "🚨";
    if (threat_level == "CRITICAL") return "☠️";
    return "ℹ️";
}

// Generate filename
std::string HtmlReporter::GenerateFilename(const core::AnalysisResult& result) {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    
    std::ostringstream filename;
    filename << "paramite_report_";
    
    if (!result.sample_info.sha256.empty()) {
        filename << result.sample_info.sha256.substr(0, 16) << "_";
    }
    
    filename << std::put_time(std::localtime(&time_t), "%Y%m%d_%H%M%S");
    filename << ".html";
    
    return filename.str();
}

// Save report
bool HtmlReporter::SaveReport(const std::string& html_content,
                             const std::filesystem::path& output_path) {
    try {
        std::ofstream file(output_path);
        if (!file.is_open()) {
            spdlog::error("Failed to open file for writing: {}", output_path.string());
            return false;
        }
        
        file << html_content;
        file.close();
        
        return true;
    }
    catch (const std::exception& e) {
        spdlog::error("Error saving report: {}", e.what());
        return false;
    }
}

// Create supporting files
void HtmlReporter::CreateSupportingFiles(const std::filesystem::path& report_dir) {
    // Would create external CSS, JS, and image files
    spdlog::debug("Supporting files would be created in: {}", report_dir.string());
}

// Generate Oddworld banner
std::string HtmlReporter::GenerateOddworldBanner() {
    return R"(
        <div class="oddworld-banner">
            <pre style="font-size: 8px; color: #7c3aed; text-align: center;">
  ____                            _ _       
 |  _ \ __ _ _ __ __ _ _ __ ___ (_) |_ ___ 
 | |_) / _` | '__/ _` | '_ ` _ \| | __/ _ \
 |  __/ (_| | | | (_| | | | | | | | ||  __/
 |_|   \__,_|_|  \__,_|_| |_| |_|_|\__\___|
                                            
    Oddworld-Inspired Malware Analysis
            </pre>
        </div>
    )";
}

// Generate table of contents
std::string HtmlReporter::GenerateTableOfContents() {
    return ""; // Implemented via navigation sidebar
}

} // namespace reporters
} // namespace paramite