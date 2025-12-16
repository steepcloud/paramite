/**
 * @file html_reporter.hpp
 * @brief Interactive HTML report generation for malware analysis results
 * 
 * Provides comprehensive HTML report generation with interactive visualizations,
 * charts, graphs, and analyst-friendly interfaces. Supports multiple themes,
 * embedded artifacts, and customizable sections for professional presentation
 * of malware analysis findings.
 * 
 * @date 2025
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <filesystem>
#include <memory>
#include <optional>

namespace paramite {

// Forward declarations
namespace core {
    struct AnalysisResult;
}

namespace reporters {

/**
 * @enum ReportTheme
 * @brief Visual themes for HTML reports
 */
enum class ReportTheme {
    LIGHT,      ///< Light mode (standard)
    DARK,       ///< Dark mode (easier on eyes)
    ODDWORLD    ///< Custom Paramite-themed (Oddworld aesthetic)
};

/**
 * @struct ReportSections
 * @brief Controls which sections to include in report
 * 
 * Allows fine-grained control over report content for
 * different audiences (executive, technical, security team).
 */
struct ReportSections {
    bool executive_summary{true};           ///< High-level overview
    bool sample_information{true};          ///< File metadata
    bool static_analysis{true};             ///< Static analysis results
    bool dynamic_analysis{true};            ///< Sandbox execution
    bool behavior_analysis{true};           ///< Behavioral patterns
    bool network_analysis{true};            ///< Network activity
    bool file_operations{true};             ///< File system changes
    bool process_tree{true};                ///< Process execution tree
    bool syscall_analysis{true};            ///< System call analysis
    bool ioc_extraction{true};              ///< Indicators of Compromise
    bool timeline{true};                    ///< Event timeline
    bool mitigation_recommendations{true};  ///< Security recommendations
    bool artifacts{true};                   ///< Downloadable artifacts
};

/**
 * @struct HtmlReportConfig
 * @brief Configuration for HTML report generation
 */
struct HtmlReportConfig {
    // Appearance
    ReportTheme theme{ReportTheme::DARK};                     ///< Visual theme
    std::string report_title{"Paramite Malware Analysis Report"};  ///< Report title
    std::string analyst_name;              ///< Analyst name
    std::string organization;              ///< Organization name
    bool include_logo{true};               ///< Include Paramite logo
    std::filesystem::path custom_logo_path;  ///< Custom logo path
    
    // Sections
    ReportSections sections;  ///< Section visibility control
    
    // Content Options
    bool embed_artifacts{true};       ///< Embed vs link to artifacts
    bool include_raw_logs{false};     ///< Include full strace/tcpdump logs
    bool include_screenshots{true};   ///< Include screenshots
    bool include_pcap_download{true}; ///< Provide PCAP download
    bool include_json_export{true};   ///< Provide JSON export
    
    // Interactivity
    bool enable_javascript{true};  ///< Enable JavaScript features
    bool enable_charts{true};      ///< Enable Chart.js visualizations
    bool enable_graphs{true};      ///< Enable D3.js/vis.js graphs
    bool enable_filtering{true};   ///< Enable table filtering
    bool enable_search{true};      ///< Enable search functionality
    
    // Visualization
    bool show_process_tree_graph{true};  ///< Process tree visualization
    bool show_network_graph{true};       ///< Network graph visualization
    bool show_timeline_graph{true};      ///< Timeline visualization
    bool show_threat_gauge{true};        ///< Threat score gauge
    
    // Size Limits
    std::size_t max_report_size_mb{50};         ///< Maximum report size
    std::size_t max_embedded_file_size_mb{5};   ///< Max embedded file size
    int max_syscalls_displayed{1000};           ///< Max syscalls in table
    int max_network_connections_displayed{500}; ///< Max network connections
    
    // Output
    std::filesystem::path output_directory{"./reports"};  ///< Output directory
    std::string filename_pattern{"{hash}_{timestamp}.html"};  ///< Filename pattern
    bool create_supporting_files{true};  ///< Create separate CSS/JS files
    
    // Branding
    bool show_paramite_branding{true};  ///< Show Paramite branding
    std::string custom_footer;          ///< Custom footer HTML
};

/**
 * @enum ChartType
 * @brief Supported chart/graph visualization types
 */
enum class ChartType {
    PIE,             ///< Pie chart
    BAR,             ///< Bar chart
    LINE,            ///< Line chart
    AREA,            ///< Area chart
    SCATTER,         ///< Scatter plot
    TIMELINE,        ///< Timeline visualization
    TREE,            ///< Tree diagram
    NETWORK_GRAPH,   ///< Network graph
    HEATMAP          ///< Heat map
};

/**
 * @struct ChartData
 * @brief Data structure for chart generation
 */
struct ChartData {
    ChartType type;                        ///< Chart type
    std::string title;                     ///< Chart title
    std::string chart_id;                  ///< HTML element ID
    std::vector<std::string> labels;       ///< Data labels
    std::vector<double> values;            ///< Data values
    std::string color_scheme;              ///< Color scheme
    std::map<std::string, double> data;    ///< Key-value data
    std::vector<std::pair<std::string, std::vector<double>>> series;  ///< Multi-series data
    std::string x_axis_label;              ///< X-axis label
    std::string y_axis_label;              ///< Y-axis label
};

/**
 * @class HtmlReporter
 * @brief Professional HTML report generator for malware analysis
 * 
 * Generates comprehensive, interactive HTML reports with:
 * - **Professional Presentation**: Clean, analyst-friendly interface
 * - **Interactive Visualizations**: Charts, graphs, trees using D3.js, Chart.js, vis.js
 * - **Multiple Themes**: Light, Dark, and custom Oddworld theme
 * - **Embedded Artifacts**: PCAP files, logs, screenshots
 * - **Responsive Design**: Works on desktop and mobile
 * - **Search & Filter**: Interactive data tables with filtering
 * - **Customizable Sections**: Control content for different audiences
 * - **Export Options**: JSON, IOC lists, artifacts
 * 
 * **Report Structure**:
 * 1. Executive Summary - High-level findings
 * 2. Threat Assessment - Score, classification, MITRE ATT&CK
 * 3. Sample Information - Hashes, file type, metadata
 * 4. Static Analysis - PE/ELF analysis, strings, entropy
 * 5. Dynamic Analysis - Sandbox execution results
 * 6. Behavior Analysis - Detected behaviors and patterns
 * 7. Network Analysis - Connections, DNS, HTTP, C2
 * 8. File Operations - File changes, encryption indicators
 * 9. Process Tree - Hierarchical process execution
 * 10. System Calls - Syscall analysis and patterns
 * 11. IOCs - Extracted indicators
 * 12. Timeline - Chronological event timeline
 * 13. Recommendations - Mitigation steps
 * 14. Artifacts - Downloadable evidence
 * 
 * **Usage Example**:
 * @code
 * HtmlReportConfig config;
 * config.theme = ReportTheme::DARK;
 * config.analyst_name = "John Doe";
 * config.organization = "Security Team";
 * config.enable_charts = true;
 * 
 * HtmlReporter reporter(config);
 * 
 * // Generate full report
 * auto report_path = reporter.GenerateReport(analysis_result);
 * std::cout << "Report generated: " << report_path << std::endl;
 * 
 * // Or generate minimal report for executives
 * auto exec_report = reporter.GenerateMinimalReport(analysis_result);
 * @endcode
 */
class HtmlReporter {
public:
    /**
     * @brief Construct HTML reporter with configuration
     * @param config Report configuration
     */
    explicit HtmlReporter(const HtmlReportConfig& config = HtmlReportConfig{});
    
    ~HtmlReporter();

    /**
     * @brief Generate complete HTML report from analysis result
     * 
     * @param result Complete analysis result
     * @return Path to generated HTML file
     * 
     * @throws std::runtime_error if report generation fails
     */
    std::filesystem::path GenerateReport(const core::AnalysisResult& result);

    /**
     * @brief Generate report with custom section selection
     * 
     * @param result Analysis result
     * @param sections Sections to include
     * @return Path to generated HTML file
     */
    std::filesystem::path GenerateReport(
        const core::AnalysisResult& result,
        const ReportSections& sections
    );

    /**
     * @brief Generate minimal report (executive summary only)
     * 
     * Lightweight report for executives showing only high-level findings.
     * 
     * @param result Analysis result
     * @return Path to generated HTML file
     */
    std::filesystem::path GenerateMinimalReport(const core::AnalysisResult& result);

    /**
     * @brief Generate executive summary section HTML
     * 
     * @param result Analysis result
     * @return HTML string for executive summary
     */
    std::string GenerateExecutiveSummary(const core::AnalysisResult& result);

    /**
     * @brief Add custom section to report
     * 
     * @param title Section title
     * @param content Section HTML content
     */
    void AddCustomSection(const std::string& title, const std::string& content);

    /**
     * @brief Add custom chart to report
     * 
     * @param chart Chart data and configuration
     */
    void AddChart(const ChartData& chart);

    /**
     * @brief Get base64-encoded Paramite logo
     * @return Base64 image data URL
     */
    std::string GetBase64Logo();

    /**
     * @brief Set custom CSS styles
     * @param css Custom CSS string
     */
    void SetCustomCSS(const std::string& css);

    /**
     * @brief Set custom JavaScript code
     * @param js Custom JavaScript string
     */
    void SetCustomJavaScript(const std::string& js);

    /**
     * @brief Get current configuration
     * @return Reference to config
     */
    const HtmlReportConfig& GetConfig() const { return config_; }

    /**
     * @brief Update reporter configuration
     * @param config New configuration
     */
    void UpdateConfig(const HtmlReportConfig& config);

private:
    HtmlReportConfig config_;                                            ///< Configuration
    std::vector<std::pair<std::string, std::string>> custom_sections_;  ///< Custom sections
    std::vector<ChartData> custom_charts_;                              ///< Custom charts
    std::string custom_css_;                                            ///< Custom CSS
    std::string custom_js_;                                             ///< Custom JavaScript

    // HTML Generation Methods (internal)
    std::string GenerateHTML(const core::AnalysisResult& result);
    std::string GenerateSandboxResults(const core::AnalysisResult& result);
    std::string GenerateSandboxResultsSection(const core::AnalysisResult& result);
    std::string GenerateHeader(const core::AnalysisResult& result);
    std::string GenerateNavigation();
    std::string GenerateExecutiveSummarySection(const core::AnalysisResult& result);
    std::string GenerateSampleInfoSection(const core::AnalysisResult& result);
    std::string GenerateThreatAssessment(const core::AnalysisResult& result);
    std::string GenerateStaticAnalysisSection(const core::AnalysisResult& result);
    std::string GenerateDynamicAnalysisSection(const core::AnalysisResult& result);
    std::string GenerateBehaviorAnalysisSection(const core::AnalysisResult& result);
    std::string GenerateNetworkAnalysisSection(const core::AnalysisResult& result);
    std::string GenerateFileOperationsSection(const core::AnalysisResult& result);
    std::string GenerateProcessTreeSection(const core::AnalysisResult& result);
    std::string GenerateSyscallAnalysisSection(const core::AnalysisResult& result);
    std::string GenerateIOCSection(const core::AnalysisResult& result);
    std::string GenerateTimelineSection(const core::AnalysisResult& result);
    std::string GenerateMitigationSection(const core::AnalysisResult& result);
    std::string GenerateArtifactsSection(const core::AnalysisResult& result);
    std::string GenerateFooter();
    
    // Visualization Methods
    std::string GenerateThreatGauge(int threat_score);
    std::string GenerateProcessTreeGraph(const core::AnalysisResult& result);
    std::string GenerateNetworkGraph(const core::AnalysisResult& result);
    std::string GenerateTimelineChart(const core::AnalysisResult& result);
    std::string GenerateChart(const ChartData& chart);
    std::string GenerateIOCTable(const core::AnalysisResult& result);
    std::string GenerateFileOperationsTable(const core::AnalysisResult& result);
    std::string GenerateNetworkTable(const core::AnalysisResult& result);
    
    // Asset Methods
    std::string GetCSS();
    std::string GetJavaScript();
    std::string GetThemeCSS(ReportTheme theme);
    std::string EmbedFileAsBase64(const std::filesystem::path& file_path);
    std::string GenerateDownloadLink(const std::filesystem::path& file_path,
                                     const std::string& display_name);
    
    // Helper Methods
    std::string EscapeHTML(const std::string& text);
    std::string FormatTimestamp(const std::chrono::system_clock::time_point& time);
    std::string FormatDuration(const std::chrono::milliseconds& duration);
    std::string FormatFileSize(std::size_t bytes);
    std::string GetThreatColor(const std::string& threat_level);
    std::string GetThreatEmoji(const std::string& threat_level);
    std::string GenerateFilename(const core::AnalysisResult& result);
    bool SaveReport(const std::string& html_content,
                   const std::filesystem::path& output_path);
    void CreateSupportingFiles(const std::filesystem::path& report_dir);
    std::string GenerateOddworldBanner();
    std::string GenerateTableOfContents();
};

/**
 * @namespace templates
 * @brief HTML template snippets for report generation
 */
namespace templates {

/// Basic HTML5 document template
inline const char* HTML_TEMPLATE = R"(
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{TITLE}</title>
    <style>{CSS}</style>
</head>
<body class="{THEME}">
    <div class="container">
        <header>{HEADER}</header>
        <nav>{NAVIGATION}</nav>
        <main>{CONTENT}</main>
        <footer>{FOOTER}</footer>
    </div>
    <script>{JAVASCRIPT}</script>
</body>
</html>
)";

/// Threat gauge visualization template
inline const char* THREAT_GAUGE_TEMPLATE = R"(
<div class="threat-gauge">
    <div class="gauge-container">
        <svg viewBox="0 0 200 120">
            <path class="gauge-background" d="M 20 100 A 80 80 0 0 1 180 100"></path>
            <path class="gauge-fill" d="M 20 100 A 80 80 0 0 1 180 100" 
                  stroke-dasharray="{SCORE_PERCENT} 100"></path>
        </svg>
        <div class="gauge-value">{THREAT_SCORE}</div>
        <div class="gauge-label">{THREAT_LEVEL}</div>
    </div>
</div>
)";

/// IOC table template
inline const char* IOC_TABLE_TEMPLATE = R"(
<table class="ioc-table" id="ioc-table">
    <thead>
        <tr>
            <th>Type</th>
            <th>Value</th>
            <th>Context</th>
            <th>Confidence</th>
        </tr>
    </thead>
    <tbody>
        {IOC_ROWS}
    </tbody>
</table>
)";

/// Process tree node template
inline const char* PROCESS_TREE_NODE = R"(
<div class="process-node {SUSPICIOUS_CLASS}" data-pid="{PID}">
    <div class="process-icon">{ICON}</div>
    <div class="process-info">
        <div class="process-name">{NAME}</div>
        <div class="process-pid">PID: {PID}</div>
        <div class="process-cmdline">{CMDLINE}</div>
    </div>
</div>
)";

} // namespace templates

} // namespace reporters
} // namespace paramite