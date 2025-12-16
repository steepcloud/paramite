/**
 * @file timeline_builder.hpp
 * @brief Chronological event timeline generation and attack chain visualization
 * 
 * Provides comprehensive timeline construction from all monitoring sources with
 * attack phase identification, event correlation, MITRE ATT&CK mapping, and
 * interactive visualization. Enables analysts to understand malware behavior
 * chronologically and identify attack patterns.
 * 
 * @date 2025
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <set>
#include <chrono>
#include <optional>
#include <functional>
#include <memory>

namespace paramite {

// Forward declarations
namespace core {
    struct AnalysisResult;
}

namespace monitors {
    struct FileEvent;
    struct NetworkConnection;
    struct ProcessCreationEvent;
    struct SyscallEvent;
}

namespace reporters {

/**
 * @enum TimelineEventType
 * @brief Types of timeline events
 */
enum class TimelineEventType {
    PROCESS_START,         ///< Process creation
    PROCESS_END,           ///< Process termination
    FILE_CREATE,           ///< File creation
    FILE_DELETE,           ///< File deletion
    FILE_MODIFY,           ///< File modification
    FILE_READ,             ///< File read
    NETWORK_CONNECT,       ///< Network connection
    NETWORK_SEND,          ///< Data transmission
    NETWORK_RECEIVE,       ///< Data reception
    DNS_QUERY,             ///< DNS resolution
    HTTP_REQUEST,          ///< HTTP request
    SYSCALL,               ///< System call
    MEMORY_ALLOCATE,       ///< Memory allocation
    MEMORY_PROTECT,        ///< Memory protection change
    INJECTION,             ///< Process/DLL injection
    PRIVILEGE_ESCALATION,  ///< Privilege escalation
    ANTI_DEBUG,            ///< Anti-debugging technique
    ENCRYPTION,            ///< Encryption operation
    EXFILTRATION,          ///< Data exfiltration
    CUSTOM                 ///< Custom event type
};

/**
 * @enum EventSeverity
 * @brief Event severity/importance level
 */
enum class EventSeverity {
    INFO,      ///< Informational (normal behavior)
    LOW,       ///< Low severity (minor concern)
    MEDIUM,    ///< Medium severity (notable)
    HIGH,      ///< High severity (suspicious)
    CRITICAL   ///< Critical severity (malicious)
};

/**
 * @enum TimelineTrack
 * @brief Timeline visualization tracks/lanes
 */
enum class TimelineTrack {
    PROCESS,   ///< Process events track
    FILE,      ///< File operations track
    NETWORK,   ///< Network activity track
    SYSCALL,   ///< System calls track
    MEMORY,    ///< Memory operations track
    SECURITY,  ///< Security events track
    ALL        ///< All tracks combined
};

/**
 * @struct TimelineEvent
 * @brief Single event on the timeline
 */
struct TimelineEvent {
    // Identification
    std::string id;              ///< Unique event ID
    TimelineEventType type;      ///< Event type
    TimelineTrack track;         ///< Timeline track/lane
    EventSeverity severity;      ///< Severity level
    
    // Timing
    std::chrono::system_clock::time_point timestamp;  ///< When event occurred
    std::chrono::microseconds duration{0};            ///< Event duration
    
    // Content
    std::string title;                         ///< Short title
    std::string description;                   ///< Detailed description
    std::map<std::string, std::string> details;  ///< Additional details
    
    // Context
    int pid{0};                            ///< Process ID
    std::string process_name;              ///< Process name
    std::optional<std::string> parent_process;  ///< Parent process
    
    // Relationships
    std::vector<std::string> related_event_ids;     ///< Related events
    std::optional<std::string> caused_by_event_id;  ///< Causal relationship
    
    // Analysis
    bool is_suspicious{false};                  ///< Flagged as suspicious
    std::string suspicion_reason;               ///< Why suspicious
    std::vector<std::string> tags;              ///< Classification tags
    std::vector<std::string> mitre_techniques;  ///< MITRE ATT&CK technique IDs
    
    // Visualization
    std::string color;   ///< Display color
    std::string icon;    ///< Display icon
};

/**
 * @struct TimelinePhase
 * @brief Attack phase/stage (mapped to MITRE ATT&CK tactics)
 */
struct TimelinePhase {
    std::string name;          ///< Phase name
    std::string description;   ///< Phase description
    std::chrono::system_clock::time_point start_time;  ///< Phase start
    std::chrono::system_clock::time_point end_time;    ///< Phase end
    std::vector<std::string> event_ids;  ///< Events in this phase
    std::string mitre_tactic;  ///< MITRE ATT&CK tactic (e.g., "Initial Access")
    std::string color;         ///< Display color
};

/**
 * @struct TimelineMarker
 * @brief Important milestone marker on timeline
 */
struct TimelineMarker {
    std::string label;                               ///< Marker label
    std::chrono::system_clock::time_point timestamp; ///< When marker occurs
    std::string description;                         ///< Description
    EventSeverity severity;                          ///< Importance
    std::string color;                               ///< Display color
};

/**
 * @struct TimelineConfig
 * @brief Configuration for timeline building
 */
struct TimelineConfig {
    // Track Selection
    std::set<TimelineTrack> enabled_tracks{
        TimelineTrack::PROCESS,
        TimelineTrack::FILE,
        TimelineTrack::NETWORK,
        TimelineTrack::SYSCALL
    };  ///< Tracks to include
    
    // Filtering
    EventSeverity min_severity{EventSeverity::INFO};  ///< Minimum severity
    bool show_successful_operations{true};     ///< Include successful operations
    bool show_failed_operations{true};         ///< Include failed operations
    bool show_only_suspicious{false};          ///< Only show suspicious events
    std::set<std::string> excluded_processes;  ///< Processes to exclude
    
    // Time Range
    std::optional<std::chrono::system_clock::time_point> start_time;  ///< Range start
    std::optional<std::chrono::system_clock::time_point> end_time;    ///< Range end
    
    // Grouping
    bool group_by_process{true};               ///< Group events by process
    bool group_by_phase{true};                 ///< Group by attack phase
    std::chrono::milliseconds event_grouping_threshold{100};  ///< Group within threshold
    
    // Analysis
    bool correlate_events{true};         ///< Correlate related events
    bool detect_attack_chains{true};     ///< Detect attack sequences
    bool identify_phases{true};          ///< Identify attack phases
    
    // Visualization
    bool color_by_severity{true};        ///< Color by severity
    bool color_by_track{false};          ///< Color by track
    bool show_event_duration{true};      ///< Show event duration bars
    bool show_relationships{true};       ///< Show event relationships
    
    // Output Format
    enum class OutputFormat {
        HTML,    ///< Interactive HTML (vis.js)
        JSON,    ///< JSON data export
        SVG,     ///< Static SVG image
        ASCII,   ///< Text-based timeline
        CSV      ///< CSV export
    };
    OutputFormat format{OutputFormat::HTML};  ///< Output format
    
    // Limits
    int max_events{10000};                 ///< Maximum events to display
    int max_events_per_second{100};        ///< Sampling rate
    
    // Labels
    bool show_timestamps{true};            ///< Show timestamps
    bool show_process_names{true};         ///< Show process names
    bool use_relative_time{false};         ///< Relative vs absolute time
};

/**
 * @struct TimelineStatistics
 * @brief Aggregate timeline statistics
 */
struct TimelineStatistics {
    int total_events{0};                                  ///< Total events
    std::map<TimelineEventType, int> event_type_counts;   ///< Count by type
    std::map<TimelineTrack, int> track_counts;            ///< Count by track
    std::map<EventSeverity, int> severity_counts;         ///< Count by severity
    
    std::chrono::system_clock::time_point first_event_time;  ///< First event time
    std::chrono::system_clock::time_point last_event_time;   ///< Last event time
    std::chrono::milliseconds total_duration{0};             ///< Total duration
    
    int suspicious_events{0};                  ///< Suspicious event count
    int attack_phases{0};                      ///< Detected attack phases
    std::vector<std::string> detected_techniques;  ///< MITRE ATT&CK techniques
    
    // Peak Activity
    std::vector<std::pair<std::chrono::system_clock::time_point, int>> peak_activity;  ///< Busiest moments
};

/**
 * @class TimelineBuilder
 * @brief Chronological timeline generator with attack pattern detection
 * 
 * Comprehensive timeline construction that:
 * - **Aggregates** events from all monitoring sources
 * - **Correlates** related events (parent-child, cause-effect)
 * - **Identifies** attack phases (Initial Access, Execution, C2, Exfiltration)
 * - **Maps** to MITRE ATT&CK tactics and techniques
 * - **Visualizes** interactive timelines with vis.js
 * - **Exports** to multiple formats (HTML, JSON, SVG, ASCII, CSV)
 * 
 * **Attack Phase Detection**:
 * - Initial Access (first execution)
 * - Execution (process creation)
 * - Persistence (startup modifications)
 * - Privilege Escalation (setuid, exploit)
 * - Defense Evasion (anti-debug, packing)
 * - Discovery (enumeration, recon)
 * - Command and Control (C2 communication)
 * - Exfiltration (data transfer)
 * - Impact (encryption, destruction)
 * 
 * **Usage Example**:
 * @code
 * TimelineConfig config;
 * config.enabled_tracks = {TimelineTrack::PROCESS, TimelineTrack::NETWORK};
 * config.correlate_events = true;
 * config.identify_phases = true;
 * config.format = TimelineConfig::OutputFormat::HTML;
 * 
 * TimelineBuilder timeline(config);
 * 
 * // Build from analysis result
 * timeline.Build(analysis_result);
 * 
 * // Get statistics
 * auto stats = timeline.GetStatistics();
 * std::cout << "Total events: " << stats.total_events << std::endl;
 * std::cout << "Attack phases: " << stats.attack_phases << std::endl;
 * 
 * // Generate interactive HTML
 * std::string html = timeline.GenerateHTML();
 * 
 * // Get suspicious events
 * auto suspicious = timeline.GetSuspiciousEvents();
 * 
 * // Get attack phases
 * auto phases = timeline.GetPhases();
 * for (const auto& phase : phases) {
 *     std::cout << "Phase: " << phase.name 
 *               << " (" << phase.mitre_tactic << ")" << std::endl;
 * }
 * @endcode
 */
class TimelineBuilder {
public:
    /**
     * @brief Construct timeline builder with configuration
     * @param config Timeline configuration
     */
    explicit TimelineBuilder(const TimelineConfig& config = TimelineConfig{});
    
    ~TimelineBuilder();

    /**
     * @brief Build timeline from complete analysis result
     * 
     * @param result Analysis result with all monitoring data
     * @return true if timeline built successfully
     */
    bool Build(const core::AnalysisResult& result);

    /**
     * @brief Add file event to timeline
     * @param event File operation event
     */
    void AddFileEvent(const monitors::FileEvent& event);

    /**
     * @brief Add network event to timeline
     * @param event Network connection event
     */
    void AddNetworkEvent(const monitors::NetworkConnection& event);

    /**
     * @brief Add process event to timeline
     * @param event Process creation/termination event
     */
    void AddProcessEvent(const monitors::ProcessCreationEvent& event);

    /**
     * @brief Add syscall event to timeline
     * @param event System call event
     */
    void AddSyscallEvent(const monitors::SyscallEvent& event);

    /**
     * @brief Add custom timeline event
     * @param event Custom event
     */
    void AddEvent(const TimelineEvent& event);

    /**
     * @brief Add timeline marker
     * @param marker Milestone marker
     */
    void AddMarker(const TimelineMarker& marker);

    /**
     * @brief Get all timeline events (chronologically sorted)
     * @return Vector of all events
     */
    std::vector<TimelineEvent> GetEvents() const;

    /**
     * @brief Get events in specific time range
     * @param start Range start time
     * @param end Range end time
     * @return Filtered events
     */
    std::vector<TimelineEvent> GetEvents(
        const std::chrono::system_clock::time_point& start,
        const std::chrono::system_clock::time_point& end) const;

    /**
     * @brief Get events by timeline track
     * @param track Track to filter
     * @return Filtered events
     */
    std::vector<TimelineEvent> GetEventsByTrack(TimelineTrack track) const;

    /**
     * @brief Get events by minimum severity
     * @param min_severity Minimum severity level
     * @return Filtered events
     */
    std::vector<TimelineEvent> GetEventsBySeverity(EventSeverity min_severity) const;

    /**
     * @brief Get only suspicious events
     * @return Flagged events
     */
    std::vector<TimelineEvent> GetSuspiciousEvents() const;

    /**
     * @brief Get detected attack phases
     * @return Vector of identified phases
     */
    std::vector<TimelinePhase> GetPhases() const;

    /**
     * @brief Get timeline markers
     * @return Vector of markers
     */
    std::vector<TimelineMarker> GetMarkers() const;

    /**
     * @brief Get timeline statistics
     * @return TimelineStatistics structure
     */
    TimelineStatistics GetStatistics() const;

    /**
     * @brief Generate interactive HTML timeline (vis.js)
     * @return HTML string
     */
    std::string GenerateHTML() const;

    /**
     * @brief Export timeline as JSON
     * @return JSON string
     */
    std::string ExportJSON() const;

    /**
     * @brief Export timeline as SVG image
     * @return SVG string
     */
    std::string ExportSVG() const;

    /**
     * @brief Export timeline as ASCII text
     * @return ASCII timeline string
     */
    std::string ExportASCII() const;

    /**
     * @brief Export timeline as CSV
     * @return CSV string
     */
    std::string ExportCSV() const;

    /**
     * @brief Get current configuration
     * @return Reference to config
     */
    const TimelineConfig& GetConfig() const { return config_; }

    /**
     * @brief Update timeline configuration
     * @param config New configuration
     */
    void UpdateConfig(const TimelineConfig& config);

    /**
     * @brief Clear all timeline data
     */
    void Clear();

private:
    TimelineConfig config_;                    ///< Configuration
    std::vector<TimelineEvent> events_;        ///< Timeline events
    std::vector<TimelinePhase> phases_;        ///< Attack phases
    std::vector<TimelineMarker> markers_;      ///< Milestone markers
    mutable TimelineStatistics statistics_;    ///< Statistics
    
    // Internal methods
    void SortEvents();
    void FilterEvents();
    void CorrelateEvents();
    void IdentifyPhases();
    void DetectAttackChains();
    std::vector<std::vector<TimelineEvent>> GroupEvents();
    void CalculateRelationships();
    void MapMitreTechniques();
    TimelineEvent ConvertFileEvent(const monitors::FileEvent& event);
    TimelineEvent ConvertNetworkEvent(const monitors::NetworkConnection& event);
    TimelineEvent ConvertProcessEvent(const monitors::ProcessCreationEvent& event);
    TimelineEvent ConvertSyscallEvent(const monitors::SyscallEvent& event);
    std::string GenerateVisJsTimeline() const;
    std::string GenerateTrackHTML(TimelineTrack track) const;
    std::string GenerateEventCardHTML(const TimelineEvent& event) const;
    std::string GeneratePhaseHTML(const TimelinePhase& phase) const;
    std::string GenerateMarkerHTML(const TimelineMarker& marker) const;
    std::string GenerateAsciiTimeline() const;
    std::string GetEventTypeColor(TimelineEventType type) const;
    std::string GetSeverityColor(EventSeverity severity) const;
    std::string GetTrackColor(TimelineTrack track) const;
    std::string GetEventIcon(TimelineEventType type) const;
    std::string FormatTimestamp(const std::chrono::system_clock::time_point& time) const;
    std::string FormatRelativeTime(const std::chrono::system_clock::time_point& time) const;
    std::chrono::milliseconds GetTimeDiff(
        const std::chrono::system_clock::time_point& t1,
        const std::chrono::system_clock::time_point& t2) const;
    void UpdateStatistics();
    std::string GenerateEventId();
    std::string EventTypeToString(TimelineEventType type) const;
    std::string TrackToString(TimelineTrack track) const;
    std::string SeverityToString(EventSeverity severity) const;
};

/**
 * @namespace templates
 * @brief HTML/ASCII templates for timeline visualization
 */
namespace templates {

/// Interactive HTML timeline template (vis.js)
inline const char* TIMELINE_HTML_TEMPLATE = R"(
<!DOCTYPE html>
<html>
<head>
    <title>Paramite Timeline</title>
    <script src="https://unpkg.com/vis-timeline@latest/standalone/umd/vis-timeline-graph2d.min.js"></script>
    <link href="https://unpkg.com/vis-timeline@latest/styles/vis-timeline-graph2d.min.css" rel="stylesheet" type="text/css" />
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background: #1a1a1a;
            color: #e0e0e0;
        }
        #timeline {
            height: 600px;
            border: 1px solid #333;
        }
        .timeline-header {
            margin-bottom: 20px;
        }
        .phase-indicator {
            padding: 10px;
            margin: 10px 0;
            border-left: 4px solid;
            background: rgba(255,255,255,0.05);
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 10px;
            margin-bottom: 20px;
        }
        .stat-card {
            background: rgba(255,255,255,0.05);
            padding: 15px;
            border-radius: 5px;
        }
    </style>
</head>
<body>
    <div class="timeline-header">
        <h1>🕐 Malware Execution Timeline</h1>
        <div class="stats-grid">
            {STATS}
        </div>
    </div>
    <div class="phases">
        {PHASES}
    </div>
    <div id="timeline"></div>
    <script>
        {TIMELINE_DATA}
        var container = document.getElementById('timeline');
        var options = {
            stack: true,
            verticalScroll: true,
            zoomKey: 'ctrlKey',
            orientation: 'top'
        };
        var timeline = new vis.Timeline(container, items, groups, options);
    </script>
</body>
</html>
)";

/// ASCII timeline template
inline const char* ASCII_TIMELINE_TEMPLATE = R"(
═══════════════════════════════════════════════════════════════
                  MALWARE EXECUTION TIMELINE
═══════════════════════════════════════════════════════════════

Timeline: {START_TIME} → {END_TIME}
Duration: {DURATION}
Total Events: {TOTAL_EVENTS}

{TIMELINE_BODY}

═══════════════════════════════════════════════════════════════
Legend:
  [P] Process   [F] File   [N] Network   [S] Syscall   [M] Memory
  ⚠️  Suspicious   🔴 Critical   🟡 High   🔵 Medium   ⚪ Low
═══════════════════════════════════════════════════════════════
)";

} // namespace templates

} // namespace reporters
} // namespace paramite