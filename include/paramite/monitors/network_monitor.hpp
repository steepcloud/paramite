/**
 * @file network_monitor.hpp
 * @brief Real-time network traffic monitoring and analysis for malware behavior detection
 * 
 * Provides comprehensive packet capture and analysis capabilities including protocol
 * parsing (DNS, HTTP, TCP, UDP), C2 detection, beaconing analysis, data exfiltration
 * detection, and GeoIP lookups. Integrates with tcpdump/libpcap for low-level capture.
 * 
 * @date 2025
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <set>
#include <chrono>
#include <functional>
#include <optional>
#include <cstdint>
#include <mutex>

namespace paramite {
namespace monitors {

/**
 * @enum Protocol
 * @brief Supported network protocols for monitoring and analysis
 */
enum class Protocol {
    TCP,      ///< Transmission Control Protocol
    UDP,      ///< User Datagram Protocol
    ICMP,     ///< Internet Control Message Protocol
    HTTP,     ///< Hypertext Transfer Protocol
    HTTPS,    ///< HTTP Secure (TLS/SSL)
    DNS,      ///< Domain Name System
    FTP,      ///< File Transfer Protocol
    SMTP,     ///< Simple Mail Transfer Protocol
    SSH,      ///< Secure Shell
    SMB,      ///< Server Message Block
    RDP,      ///< Remote Desktop Protocol
    IRC,      ///< Internet Relay Chat (common for botnets)
    UNKNOWN   ///< Unrecognized protocol
};

/**
 * @enum ConnectionState
 * @brief TCP connection states
 */
enum class ConnectionState {
    SYN_SENT,      ///< SYN sent, waiting for SYN-ACK
    SYN_RECEIVED,  ///< SYN received, sent SYN-ACK
    ESTABLISHED,   ///< Connection established
    FIN_WAIT,      ///< Sent FIN, waiting for ACK
    CLOSE_WAIT,    ///< Received FIN, waiting to close
    CLOSING,       ///< Both sides closing
    TIME_WAIT,     ///< Waiting for network to clear
    CLOSED,        ///< Connection closed
    LISTEN         ///< Listening for connections
};

/**
 * @enum TrafficDirection
 * @brief Direction of network traffic relative to monitored system
 */
enum class TrafficDirection {
    INBOUND,        ///< Incoming traffic
    OUTBOUND,       ///< Outgoing traffic
    BIDIRECTIONAL   ///< Both directions
};

/**
 * @struct DNSQuery
 * @brief DNS query and response information
 * 
 * Captures DNS resolution attempts which are critical for detecting
 * malware C2 communication and DGA (Domain Generation Algorithm) domains.
 */
struct DNSQuery {
    std::string query_name;                          ///< Domain being queried
    std::string query_type;                          ///< Record type (A, AAAA, MX, TXT, etc.)
    std::vector<std::string> responses;              ///< IP addresses or responses
    std::chrono::system_clock::time_point timestamp; ///< Query time
    int response_code{0};                            ///< DNS response code (0 = success)
    std::chrono::milliseconds response_time{0};      ///< Time to receive response
    bool is_suspicious{false};                       ///< Flagged as suspicious
    std::string suspicion_reason;                    ///< Why flagged
};

/**
 * @struct HTTPRequest
 * @brief HTTP request and response information
 * 
 * Captures HTTP traffic details for analyzing C2 communication patterns,
 * user agent strings, and potential data exfiltration via HTTP.
 */
struct HTTPRequest {
    std::string method;                          ///< HTTP method (GET, POST, PUT, etc.)
    std::string url;                             ///< Full URL
    std::string host;                            ///< Host header
    std::string path;                            ///< Request path
    std::string user_agent;                      ///< User-Agent header (often spoofed by malware)
    std::map<std::string, std::string> headers;  ///< All HTTP headers
    std::string body;                            ///< Request/response body
    int status_code{0};                          ///< HTTP status code
    std::size_t request_size{0};                 ///< Request size in bytes
    std::size_t response_size{0};                ///< Response size in bytes
    std::chrono::system_clock::time_point timestamp;
    std::chrono::milliseconds response_time{0};
    bool is_suspicious{false};
    std::string suspicion_reason;
};

/**
 * @struct NetworkConnection
 * @brief Complete information about a network connection
 * 
 * Represents a single network connection with full context including
 * endpoints, process information, traffic statistics, and threat assessment.
 */
struct NetworkConnection {
    // Connection Details
    Protocol protocol;               ///< Protocol type
    std::string local_address;       ///< Local IP address
    uint16_t local_port{0};         ///< Local port number
    std::string remote_address;      ///< Remote IP address
    uint16_t remote_port{0};        ///< Remote port number
    ConnectionState state;           ///< Connection state (TCP)
    TrafficDirection direction;      ///< Traffic direction
    
    // Process Information
    int pid{0};                  ///< Process ID that created connection
    std::string process_name;    ///< Process name
    std::string process_path;    ///< Process executable path
    
    // Timing
    std::chrono::system_clock::time_point start_time;  ///< Connection start
    std::chrono::system_clock::time_point end_time;    ///< Connection end
    std::chrono::milliseconds duration{0};             ///< Connection duration
    
    // Traffic Statistics
    std::size_t bytes_sent{0};       ///< Bytes transmitted
    std::size_t bytes_received{0};   ///< Bytes received
    int packets_sent{0};             ///< Packets sent
    int packets_received{0};         ///< Packets received
    
    // Geolocation (if GeoIP enabled)
    std::optional<std::string> remote_country;       ///< Country code
    std::optional<std::string> remote_asn;           ///< Autonomous System Number
    std::optional<std::string> remote_organization;  ///< ISP/Organization
    
    // DNS Resolution
    std::optional<std::string> remote_hostname;  ///< Reverse DNS result
    
    // Threat Analysis
    bool is_suspicious{false};       ///< Flagged as suspicious
    std::string suspicion_reason;    ///< Reason for suspicion
    int suspicion_score{0};          ///< Suspicion score (0-100)
    std::vector<std::string> iocs;   ///< Extracted IOCs
};

/**
 * @struct PacketCapture
 * @brief Raw packet capture information
 * 
 * Low-level packet data for detailed analysis and forensics.
 */
struct PacketCapture {
    std::chrono::system_clock::time_point timestamp;  ///< Capture time
    Protocol protocol;                                ///< Protocol
    std::string src_address;                          ///< Source IP
    uint16_t src_port{0};                            ///< Source port
    std::string dst_address;                          ///< Destination IP
    uint16_t dst_port{0};                            ///< Destination port
    std::size_t length{0};                           ///< Packet length
    std::vector<uint8_t> payload;                    ///< Raw payload bytes
    std::string payload_hex;                         ///< Hex representation
    std::string payload_ascii;                       ///< ASCII representation
    bool is_suspicious{false};                       ///< Flagged
    std::string suspicion_reason;                    ///< Reason
};

/**
 * @struct NetworkStatistics
 * @brief Aggregate network traffic statistics
 * 
 * Summary statistics for traffic analysis and reporting.
 */
struct NetworkStatistics {
    // Connection Counts
    int total_connections{0};    ///< Total connections observed
    int tcp_connections{0};      ///< TCP connections
    int udp_connections{0};      ///< UDP connections
    int http_requests{0};        ///< HTTP requests
    int https_requests{0};       ///< HTTPS requests
    int dns_queries{0};          ///< DNS queries
    
    // Traffic Volume
    std::size_t total_bytes_sent{0};        ///< Total bytes sent
    std::size_t total_bytes_received{0};    ///< Total bytes received
    std::size_t total_packets_sent{0};      ///< Total packets sent
    std::size_t total_packets_received{0};  ///< Total packets received
    
    // Unique Endpoints
    std::set<std::string> unique_remote_ips;      ///< Unique destination IPs
    std::set<std::string> unique_remote_domains;  ///< Unique domains contacted
    std::set<uint16_t> unique_remote_ports;       ///< Unique ports contacted
    
    // Suspicious Activity
    int suspicious_connections{0};      ///< Suspicious connection count
    int c2_indicators{0};               ///< C2 indicators detected
    int exfiltration_indicators{0};     ///< Exfiltration indicators
    
    // Top Destinations
    std::vector<std::pair<std::string, int>> top_remote_ips;  ///< Most contacted IPs
    std::vector<std::pair<std::string, int>> top_domains;     ///< Most contacted domains
    std::vector<std::pair<uint16_t, int>> top_ports;          ///< Most used ports
    
    // Protocol Distribution
    std::map<Protocol, int> protocol_distribution;  ///< Connections by protocol
    
    // Geolocation Summary
    std::map<std::string, int> countries_contacted;  ///< Countries communicated with
};

/**
 * @struct NetworkMonitorConfig
 * @brief Configuration for network traffic monitoring
 */
struct NetworkMonitorConfig {
    // Capture Settings
    std::string capture_interface{"any"};   ///< Network interface to monitor
    bool capture_all_traffic{true};         ///< Capture all network traffic
    bool capture_loopback{false};           ///< Include loopback traffic
    std::size_t max_packet_size{65535};    ///< Maximum packet size to capture
    
    // Filters
    std::vector<std::string> excluded_ips;      ///< IPs to exclude from monitoring
    std::vector<std::string> excluded_domains;  ///< Domains to exclude
    std::vector<uint16_t> excluded_ports;       ///< Ports to exclude
    bool exclude_local_traffic{true};           ///< Exclude 127.0.0.1, 192.168.x.x
    
    // Protocol Capture Toggles
    bool capture_dns{true};     ///< Capture DNS queries
    bool capture_http{true};    ///< Capture HTTP traffic
    bool capture_https{true};   ///< Capture HTTPS (encrypted, metadata only)
    bool capture_smtp{true};    ///< Capture SMTP (email)
    bool capture_ftp{true};     ///< Capture FTP
    bool capture_ssh{true};     ///< Capture SSH
    bool capture_raw_packets{true};  ///< Capture raw packets
    
    // Protocol Analysis
    bool parse_http_headers{true};      ///< Parse HTTP headers
    bool parse_dns_queries{true};       ///< Parse DNS queries
    bool extract_http_bodies{true};     ///< Extract HTTP body content
    std::size_t max_http_body_size{1024 * 1024};  ///< Max HTTP body size (1MB)
    
    // Detection Features
    bool detect_c2_communication{true};  ///< Detect C2 patterns
    bool detect_exfiltration{true};      ///< Detect data exfiltration
    bool detect_port_scanning{true};     ///< Detect port scans
    bool detect_beaconing{true};         ///< Detect periodic beacons
    std::vector<std::string> known_malicious_ips;      ///< Known bad IPs
    std::vector<std::string> known_malicious_domains;  ///< Known bad domains
    
    // GeoIP Lookup
    bool enable_geolocation{true};  ///< Enable GeoIP lookups
    std::string geoip_database_path{"/usr/share/GeoIP/GeoLite2-City.mmdb"};  ///< GeoIP DB path
    
    // Performance
    int max_packets_per_second{10000};      ///< Rate limit
    std::size_t max_buffered_packets{100000};  ///< Buffer size
    bool enable_rate_limiting{true};        ///< Enable rate limiting
    
    // Output
    bool save_pcap{true};                      ///< Save PCAP file
    std::string pcap_file{"network_capture.pcap"};  ///< PCAP output filename
    bool verbose_logging{false};               ///< Enable verbose logging
};

/// Callback function types for network events
using NetworkEventCallback = std::function<void(const NetworkConnection&)>;
using DNSEventCallback = std::function<void(const DNSQuery&)>;
using HTTPEventCallback = std::function<void(const HTTPRequest&)>;

/**
 * @class NetworkMonitor
 * @brief Real-time network traffic capture and behavioral analysis
 * 
 * Comprehensive network monitoring solution for malware analysis that:
 * - **Captures** all network traffic at packet level (libpcap/tcpdump)
 * - **Parses** protocols (DNS, HTTP, HTTPS, TCP, UDP, ICMP)
 * - **Detects** C2 communication patterns and beaconing
 * - **Identifies** data exfiltration attempts
 * - **Extracts** network IOCs (IPs, domains, URLs)
 * - **Performs** GeoIP lookups for threat intelligence
 * - **Analyzes** timing patterns for periodic callbacks
 * 
 * **Detection Capabilities**:
 * - C2 beaconing (regular intervals)
 * - Data exfiltration (large outbound transfers)
 * - Port scanning (rapid connection attempts)
 * - DGA domains (algorithmically generated)
 * - Suspicious user agents
 * - Known malicious IPs/domains
 * 
 * **Thread Safety**: NOT thread-safe. Use from single thread.
 * 
 * **Usage Example**:
 * @code
 * NetworkMonitorConfig config;
 * config.capture_interface = "eth0";
 * config.detect_c2_communication = true;
 * config.detect_beaconing = true;
 * config.save_pcap = true;
 * 
 * NetworkMonitor monitor(config);
 * 
 * // Register real-time callbacks
 * monitor.RegisterConnectionCallback([](const NetworkConnection& conn) {
 *     if (conn.is_suspicious) {
 *         std::cout << "Suspicious connection to " << conn.remote_address 
 *                   << ":" << conn.remote_port << std::endl;
 *     }
 * });
 * 
 * // Start monitoring
 * monitor.Start();
 * 
 * // ... execute malware ...
 * 
 * // Stop and analyze
 * monitor.Stop();
 * 
 * auto connections = monitor.GetConnections();
 * auto dns_queries = monitor.GetDNSQueries();
 * auto stats = monitor.GetStatistics();
 * 
 * // Detect specific behaviors
 * auto [c2_score, c2_desc] = monitor.DetectC2Communication();
 * auto [beacon_score, beacon_desc] = monitor.DetectBeaconing();
 * 
 * if (c2_score > 75) {
 *     std::cout << "C2 detected: " << c2_desc << std::endl;
 * }
 * 
 * // Get PCAP for detailed analysis
 * std::string pcap_path = monitor.GetPCAPPath();
 * @endcode
 */
class NetworkMonitor {
public:
    /**
     * @brief Construct network monitor with configuration
     * @param config Monitoring configuration
     */
    explicit NetworkMonitor(const NetworkMonitorConfig& config = NetworkMonitorConfig{});
    
    ~NetworkMonitor();

    NetworkMonitor(const NetworkMonitor&) = delete;
    NetworkMonitor& operator=(const NetworkMonitor&) = delete;

    /**
     * @brief Start network traffic capture and monitoring
     * 
     * Initializes packet capture (libpcap), starts capture thread,
     * and begins protocol parsing.
     * 
     * @return true if monitoring started successfully
     * 
     * @throws std::runtime_error if packet capture initialization fails
     * @note Requires root/admin privileges for raw packet capture
     */
    bool Start();

    /**
     * @brief Stop network monitoring and finalize PCAP
     */
    void Stop();

    /**
     * @brief Check if monitoring is currently active
     * @return true if monitoring
     */
    bool IsMonitoring() const { return is_monitoring_; }

    /**
     * @brief Register callback for connection events
     * @param callback Function to call for each connection
     */
    void RegisterConnectionCallback(NetworkEventCallback callback);
    
    /**
     * @brief Register callback for DNS query events
     * @param callback Function to call for each DNS query
     */
    void RegisterDNSCallback(DNSEventCallback callback);
    
    /**
     * @brief Register callback for HTTP request events
     * @param callback Function to call for each HTTP request
     */
    void RegisterHTTPCallback(HTTPEventCallback callback);

    /**
     * @brief Get all captured network connections
     * @return Vector of all connections
     */
    std::vector<NetworkConnection> GetConnections() const;

    /**
     * @brief Get connections filtered by protocol
     * @param proto Protocol to filter
     * @return Filtered connections
     */
    std::vector<NetworkConnection> GetConnectionsByProtocol(Protocol proto) const;

    /**
     * @brief Get only suspicious connections
     * @return Flagged connections
     */
    std::vector<NetworkConnection> GetSuspiciousConnections() const;

    /**
     * @brief Get all DNS queries
     * @return Vector of DNS queries
     */
    std::vector<DNSQuery> GetDNSQueries() const;

    /**
     * @brief Get all HTTP requests
     * @return Vector of HTTP requests
     */
    std::vector<HTTPRequest> GetHTTPRequests() const;

    /**
     * @brief Get raw captured packets
     * @return Vector of packet captures
     */
    std::vector<PacketCapture> GetPackets() const;

    /**
     * @brief Get aggregate network statistics
     * @return NetworkStatistics structure
     */
    NetworkStatistics GetStatistics() const;

    /**
     * @brief Get list of contacted IP addresses
     * @return Vector of unique IPs
     */
    std::vector<std::string> GetContactedIPs() const;

    /**
     * @brief Get list of contacted domains (from DNS)
     * @return Vector of unique domains
     */
    std::vector<std::string> GetContactedDomains() const;

    /**
     * @brief Detect C2 (Command and Control) communication patterns
     * 
     * Analyzes traffic for C2 indicators:
     * - Connections to known malicious IPs/domains
     * - Suspicious user agents
     * - Regular beaconing patterns
     * - Unusual ports
     * 
     * @return Pair of (confidence score 0-100, description)
     */
    std::pair<int, std::string> DetectC2Communication() const;

    /**
     * @brief Detect beaconing behavior (periodic callbacks)
     * 
     * Analyzes connection timing for regular intervals indicating
     * automated C2 check-ins.
     * 
     * @return Pair of (confidence score, description)
     */
    std::pair<int, std::string> DetectBeaconing() const;

    /**
     * @brief Detect data exfiltration patterns
     * 
     * Looks for:
     * - Large outbound data transfers
     * - Compression/encryption before transfer
     * - Unusual protocols (DNS tunneling, ICMP exfil)
     * 
     * @return Pair of (confidence score, description)
     */
    std::pair<int, std::string> DetectExfiltration() const;

    /**
     * @brief Detect port scanning activity
     * 
     * @return Pair of (confidence score, description)
     */
    std::pair<int, std::string> DetectPortScanning() const;

    /**
     * @brief Detect DGA (Domain Generation Algorithm) domains
     * 
     * Identifies domains with high entropy, unusual TLDs,
     * or algorithmic patterns.
     * 
     * @return Vector of suspected DGA domains
     */
    std::vector<std::string> DetectDGADomains() const;

    /**
     * @brief Extract network IOCs from captured traffic
     * 
     * @return Vector of IOCs (IPs, domains, URLs)
     */
    std::vector<std::string> ExtractIOCs() const;

    /**
     * @brief Export monitoring data to JSON
     * @return JSON string
     */
    std::string ExportToJSON() const;

    /**
     * @brief Get path to saved PCAP file
     * @return PCAP file path
     */
    std::string GetPCAPPath() const;

    /**
     * @brief Get current configuration
     * @return Reference to config
     */
    const NetworkMonitorConfig& GetConfig() const { return config_; }

    /**
     * @brief Clear all captured data
     */
    void ClearData();

private:
    NetworkMonitorConfig config_;           ///< Configuration
    bool is_monitoring_{false};             ///< Monitoring active flag
    std::vector<NetworkConnection> connections_;  ///< Captured connections
    std::vector<DNSQuery> dns_queries_;     ///< DNS queries
    std::vector<HTTPRequest> http_requests_; ///< HTTP requests
    std::vector<PacketCapture> packets_;    ///< Raw packets
    mutable std::mutex data_mutex_;         ///< Thread synchronization
    std::vector<NetworkEventCallback> connection_callbacks_;  ///< Connection callbacks
    std::vector<DNSEventCallback> dns_callbacks_;            ///< DNS callbacks
    std::vector<HTTPEventCallback> http_callbacks_;          ///< HTTP callbacks
    mutable NetworkStatistics statistics_;  ///< Statistics
    void* pcap_handle_{nullptr};           ///< libpcap handle (pcap_t*)
    std::string pcap_file_path_;           ///< PCAP output path

    // Internal methods
    bool InitializeCapture();
    void CaptureLoop();
    void ProcessPacket(const uint8_t* packet, std::size_t length);
    void ParseEthernetFrame(const uint8_t* data, std::size_t length);
    void ParseIPPacket(const uint8_t* data, std::size_t length);
    void ParseTCPSegment(const uint8_t* data, std::size_t length,
                        const std::string& src_ip, const std::string& dst_ip);
    void ParseUDPDatagram(const uint8_t* data, std::size_t length,
                         const std::string& src_ip, const std::string& dst_ip);
    void ParseDNS(const uint8_t* data, std::size_t length);
    void ParseHTTP(const uint8_t* data, std::size_t length,
                  const std::string& src_ip, uint16_t src_port,
                  const std::string& dst_ip, uint16_t dst_port);
    void AnalyzeConnection(NetworkConnection& conn);
    bool IsMaliciousIP(const std::string& ip) const;
    bool IsMaliciousDomain(const std::string& domain) const;
    bool IsDGADomain(const std::string& domain) const;
    std::optional<std::string> LookupCountry(const std::string& ip);
    std::optional<std::string> ReverseDNSLookup(const std::string& ip);
    int CalculateSuspicionScore(const NetworkConnection& conn) const;
    bool DetectBeaconPattern(const std::vector<std::chrono::system_clock::time_point>& times) const;
    void UpdateStatistics(const NetworkConnection& conn);
    void NotifyConnectionCallbacks(const NetworkConnection& conn);
    void NotifyDNSCallbacks(const DNSQuery& query);
    void NotifyHTTPCallbacks(const HTTPRequest& req);
    std::string ProtocolToString(Protocol proto) const;
    std::string GetProcessName(int pid) const;
    void LogEvent(const std::string& event);
};

} // namespace monitors
} // namespace paramite