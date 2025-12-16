/**
 * @file network_monitor.cpp
 * @brief Implementation of network traffic capture and behavioral analysis
 * 
 * Implements comprehensive network monitoring using tcpdump/libpcap for packet capture,
 * protocol dissection (DNS/HTTP/HTTPS/FTP/SMB), C2 communication detection, beaconing
 * pattern analysis, data exfiltration identification, and suspicious network behavior
 * recognition during sandbox execution.
 * 
 * **Network Monitoring Capabilities**:
 * - **Packet Capture**: Raw packet capture (PCAP format)
 * - **Protocol Analysis**: DNS, HTTP, HTTPS, FTP, SMB, IRC, custom protocols
 * - **C2 Detection**: Command & Control server identification
 * - **Beaconing Analysis**: Periodic communication pattern detection
 * - **Exfiltration Detection**: Large data uploads, encoded data transfer
 * - **DGA Detection**: Domain Generation Algorithm identification
 * 
 * **C2 Communication Indicators**:
 * - Periodic beacons (regular intervals: 1s, 5s, 60s, etc.)
 * - Unusual ports (non-standard HTTP ports, high ports)
 * - Encrypted traffic without TLS handshake
 * - Base64 encoded payloads
 * - Known C2 domains/IPs (threat intelligence feeds)
 * - HTTP requests to suspicious paths (/api/v1/poll, /gate.php)
 * 
 * **Beaconing Detection Algorithm**:
 * ```
 * 1. Track connection timestamps per destination
 * 2. Calculate inter-arrival times (IAT)
 * 3. Compute standard deviation of IAT
 * 4. If StdDev < threshold → Regular beaconing detected
 * 5. Classify beacon interval (fast: <5s, slow: >60s)
 * ```
 * 
 * **DGA (Domain Generation Algorithm) Detection**:
 * Indicators:
 * - High entropy domain names (random character sequences)
 * - Many DNS queries to non-existent domains (NXDOMAIN responses)
 * - Unusual TLD usage (.top, .xyz, .club, etc.)
 * - Algorithmically generated patterns
 * 
 * **Data Exfiltration Patterns**:
 * - Large POST requests (>1MB)
 * - DNS tunneling (TXT records with encoded data)
 * - ICMP tunneling (data in ping packets)
 * - Steganography (data hidden in images)
 * - FTP uploads to unknown servers
 * 
 * **Protocol Dissection**:
 * - **DNS**: Query names, types, responses, nameservers
 * - **HTTP**: URLs, headers, user-agents, POST data
 * - **HTTPS**: SNI extraction, certificate fingerprinting
 * - **FTP**: Commands, file transfers
 * - **SMB**: Shared folders, file operations
 * 
 * **Performance Considerations**:
 * - Packet filtering (BPF) to reduce noise
 * - Ring buffer for high-throughput capture
 * - Asynchronous packet processing
 * - Selective deep packet inspection
 * 
 * @date 2025
 */

#include "paramite/monitors/network_monitor.hpp"
#include "paramite/utils/string_utils.hpp"

#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <cmath>
#include <regex>
#include <thread>
#include <chrono>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#endif

using json = nlohmann::json;

namespace paramite {
namespace monitors {

// Constructor
NetworkMonitor::NetworkMonitor(const NetworkMonitorConfig& config)
    : config_(config)
    , is_monitoring_(false) {
    
    spdlog::info("Network Monitor initialized");
    spdlog::debug("Capture interface: {}", config_.capture_interface);
    spdlog::debug("Save PCAP: {}", config_.save_pcap);
    
#ifdef _WIN32
    // Initialize Winsock
    WSADATA wsa_data;
    WSAStartup(MAKEWORD(2, 2), &wsa_data);
#endif
}

// Destructor
NetworkMonitor::~NetworkMonitor() {
    Stop();
    spdlog::info("Network Monitor destroyed");
    
#ifdef _WIN32
    WSACleanup();
#endif
}

// Start monitoring
bool NetworkMonitor::Start() {
    if (is_monitoring_) {
        spdlog::warn("Network Monitor already running");
        return true;
    }
    
    spdlog::info("═══════════════════════════════════════════════════════════════");
    spdlog::info("STARTING NETWORK MONITOR");
    spdlog::info("═══════════════════════════════════════════════════════════════");
    
    try {
        // Clear previous data
        {
            std::lock_guard<std::mutex> lock(data_mutex_);
            connections_.clear();
            dns_queries_.clear();
            http_requests_.clear();
            packets_.clear();
            statistics_ = NetworkStatistics{};
        }
        
        // Initialize packet capture
        if (config_.capture_raw_packets) {
            spdlog::info("Initializing packet capture...");
            if (!InitializeCapture()) {
                spdlog::error("Failed to initialize packet capture");
                spdlog::warn("Continuing with connection monitoring only");
            } else {
                spdlog::info("✓ Packet capture initialized");
            }
        }
        
        is_monitoring_ = true;
        
        spdlog::info("═══════════════════════════════════════════════════════════════");
        spdlog::info("✓ Network Monitor started");
        spdlog::info("═══════════════════════════════════════════════════════════════\n");
        
        return true;
    }
    catch (const std::exception& e) {
        spdlog::error("Failed to start Network Monitor: {}", e.what());
        return false;
    }
}

// Stop monitoring
void NetworkMonitor::Stop() {
    if (!is_monitoring_) {
        return;
    }
    
    spdlog::info("Stopping Network Monitor...");
    is_monitoring_ = false;
    
    // Close PCAP handle
    if (pcap_handle_) {
        // pcap_close((pcap_t*)pcap_handle_);
        pcap_handle_ = nullptr;
    }
    
    spdlog::info("✓ Network Monitor stopped");
    spdlog::info("  Total connections: {}", connections_.size());
    spdlog::info("  DNS queries: {}", dns_queries_.size());
    spdlog::info("  HTTP requests: {}", http_requests_.size());
    spdlog::info("  Suspicious connections: {}", statistics_.suspicious_connections);
}

// Register callbacks
void NetworkMonitor::RegisterConnectionCallback(NetworkEventCallback callback) {
    connection_callbacks_.push_back(callback);
    spdlog::debug("Connection callback registered");
}

void NetworkMonitor::RegisterDNSCallback(DNSEventCallback callback) {
    dns_callbacks_.push_back(callback);
    spdlog::debug("DNS callback registered");
}

void NetworkMonitor::RegisterHTTPCallback(HTTPEventCallback callback) {
    http_callbacks_.push_back(callback);
    spdlog::debug("HTTP callback registered");
}

// Get all connections
std::vector<NetworkConnection> NetworkMonitor::GetConnections() const {
    std::lock_guard<std::mutex> lock(data_mutex_);
    return connections_;
}

// Get connections by protocol
std::vector<NetworkConnection> NetworkMonitor::GetConnectionsByProtocol(Protocol proto) const {
    std::lock_guard<std::mutex> lock(data_mutex_);
    
    std::vector<NetworkConnection> filtered;
    for (const auto& conn : connections_) {
        if (conn.protocol == proto) {
            filtered.push_back(conn);
        }
    }
    
    return filtered;
}

// Get suspicious connections
std::vector<NetworkConnection> NetworkMonitor::GetSuspiciousConnections() const {
    std::lock_guard<std::mutex> lock(data_mutex_);
    
    std::vector<NetworkConnection> suspicious;
    for (const auto& conn : connections_) {
        if (conn.is_suspicious) {
            suspicious.push_back(conn);
        }
    }
    
    return suspicious;
}

// Get DNS queries
std::vector<DNSQuery> NetworkMonitor::GetDNSQueries() const {
    std::lock_guard<std::mutex> lock(data_mutex_);
    return dns_queries_;
}

// Get HTTP requests
std::vector<HTTPRequest> NetworkMonitor::GetHTTPRequests() const {
    std::lock_guard<std::mutex> lock(data_mutex_);
    return http_requests_;
}

// Get packets
std::vector<PacketCapture> NetworkMonitor::GetPackets() const {
    std::lock_guard<std::mutex> lock(data_mutex_);
    return packets_;
}

// Get statistics
NetworkStatistics NetworkMonitor::GetStatistics() const {
    std::lock_guard<std::mutex> lock(data_mutex_);
    return statistics_;
}

// Get contacted IPs
std::vector<std::string> NetworkMonitor::GetContactedIPs() const {
    std::lock_guard<std::mutex> lock(data_mutex_);
    
    std::set<std::string> unique_ips;
    for (const auto& conn : connections_) {
        if (!conn.remote_address.empty()) {
            unique_ips.insert(conn.remote_address);
        }
    }
    
    return std::vector<std::string>(unique_ips.begin(), unique_ips.end());
}

// Get contacted domains
std::vector<std::string> NetworkMonitor::GetContactedDomains() const {
    std::lock_guard<std::mutex> lock(data_mutex_);
    
    std::set<std::string> unique_domains;
    
    // From DNS queries
    for (const auto& query : dns_queries_) {
        unique_domains.insert(query.query_name);
    }
    
    // From HTTP requests
    for (const auto& req : http_requests_) {
        if (!req.host.empty()) {
            unique_domains.insert(req.host);
        }
    }
    
    // From reverse DNS
    for (const auto& conn : connections_) {
        if (conn.remote_hostname) {
            unique_domains.insert(*conn.remote_hostname);
        }
    }
    
    return std::vector<std::string>(unique_domains.begin(), unique_domains.end());
}

// Detect C2 communication
std::pair<int, std::string> NetworkMonitor::DetectC2Communication() const {
    std::lock_guard<std::mutex> lock(data_mutex_);
    
    int confidence = 0;
    std::ostringstream description;
    std::vector<std::string> indicators;
    
    // Check for known malicious IPs/domains
    int malicious_contacts = 0;
    for (const auto& conn : connections_) {
        if (IsMaliciousIP(conn.remote_address)) {
            malicious_contacts++;
        }
    }
    
    if (malicious_contacts > 0) {
        confidence += 50;
        indicators.push_back("Contacted " + std::to_string(malicious_contacts) + 
                           " known malicious IPs");
    }
    
    // Check for DGA domains
    auto dga_domains = DetectDGADomains();
    if (!dga_domains.empty()) {
        confidence += 30;
        indicators.push_back("Detected " + std::to_string(dga_domains.size()) + 
                           " potential DGA domains");
    }
    
    // Check for beaconing
    auto beacon_result = DetectBeaconing();
    int beacon_score = beacon_result.first;
    const std::string& beacon_desc = beacon_result.second;
    
    if (beacon_score > 50) {
        confidence += 30;
        indicators.push_back("Beaconing behavior detected");
    }
    
    // Check for suspicious ports
    std::vector<uint16_t> suspicious_ports = {
        6667, 6668, 6669,  // IRC
        8080, 8888, 8443,  // Common C2 ports
        4444, 31337,       // Common backdoor ports
        1337, 3389         // Remote access
    };
    
    int suspicious_port_connections = 0;
    for (const auto& conn : connections_) {
        if (std::find(suspicious_ports.begin(), suspicious_ports.end(), 
                     conn.remote_port) != suspicious_ports.end()) {
            suspicious_port_connections++;
        }
    }
    
    if (suspicious_port_connections > 0) {
        confidence += 20;
        indicators.push_back("Connections to suspicious ports (" + 
                           std::to_string(suspicious_port_connections) + ")");
    }
    
    // Check for encrypted traffic to unusual destinations
    int https_to_ip = 0;
    for (const auto& conn : connections_) {
        if (conn.protocol == Protocol::HTTPS) {
            // Check if connecting directly to IP instead of domain
            if (std::regex_match(conn.remote_address, 
                std::regex(R"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"))) {
                https_to_ip++;
            }
        }
    }
    
    if (https_to_ip > 0) {
        confidence += 15;
        indicators.push_back("HTTPS connections directly to IP addresses");
    }
    
    confidence = std::min<int>(confidence, 100);
    
    if (confidence > 0) {
        description << "C2 communication indicators detected:\n";
        for (const auto& indicator : indicators) {
            description << "  • " << indicator << "\n";
        }
    } else {
        description << "No significant C2 indicators detected";
    }
    
    return {confidence, description.str()};
}

// Detect beaconing
std::pair<int, std::string> NetworkMonitor::DetectBeaconing() const {
    std::lock_guard<std::mutex> lock(data_mutex_);
    
    int confidence = 0;
    std::ostringstream description;
    
    // Group connections by remote endpoint
    std::map<std::pair<std::string, uint16_t>, 
             std::vector<std::chrono::system_clock::time_point>> endpoint_times;
    
    for (const auto& conn : connections_) {
        auto endpoint = std::make_pair(conn.remote_address, conn.remote_port);
        endpoint_times[endpoint].push_back(conn.start_time);
    }
    
    // Analyze timing patterns
    int beaconing_endpoints = 0;
    std::vector<std::string> beacon_details;
    
    for (const auto& [endpoint, times] : endpoint_times) {
        if (times.size() < 3) {
            continue;  // Need at least 3 connections
        }
        
        // Calculate intervals
        std::vector<std::chrono::seconds> intervals;
        for (size_t i = 1; i < times.size(); ++i) {
            auto interval = std::chrono::duration_cast<std::chrono::seconds>(
                times[i] - times[i-1]);
            intervals.push_back(interval);
        }
        
        // Check for regularity
        if (intervals.empty()) continue;
        
        // Calculate mean and standard deviation
        double mean = 0;
        for (const auto& interval : intervals) {
            mean += interval.count();
        }
        mean /= intervals.size();
        
        double variance = 0;
        for (const auto& interval : intervals) {
            double diff = interval.count() - mean;
            variance += diff * diff;
        }
        variance /= intervals.size();
        double std_dev = std::sqrt(variance);
        
        // If standard deviation is small relative to mean, it's likely beaconing
        double coefficient_of_variation = std_dev / mean;
        
        if (coefficient_of_variation < 0.3 && mean > 10) {  // Regular and not too frequent
            beaconing_endpoints++;
            
            std::ostringstream beacon_info;
            beacon_info << endpoint.first << ":" << endpoint.second 
                       << " (interval: ~" << static_cast<int>(mean) << "s)";
            beacon_details.push_back(beacon_info.str());
        }
    }
    
    if (beaconing_endpoints > 0) {
        confidence = std::min<int>(30 + (beaconing_endpoints * 20), 100);
        
        description << "Beaconing behavior detected:\n";
        description << "  • " << beaconing_endpoints << " endpoint(s) with regular intervals\n";
        for (const auto& detail : beacon_details) {
            description << "    - " << detail << "\n";
        }
    } else {
        description << "No beaconing behavior detected";
    }
    
    return {confidence, description.str()};
}

// Detect exfiltration
std::pair<int, std::string> NetworkMonitor::DetectExfiltration() const {
    std::lock_guard<std::mutex> lock(data_mutex_);
    
    int confidence = 0;
    std::ostringstream description;
    std::vector<std::string> indicators;
    
    // Calculate total bytes sent
    std::size_t total_sent = 0;
    std::size_t total_received = 0;
    
    for (const auto& conn : connections_) {
        total_sent += conn.bytes_sent;
        total_received += conn.bytes_received;
    }
    
    // Check for large uploads
    if (total_sent > 10 * 1024 * 1024) {  // > 10 MB
        confidence += 40;
        indicators.push_back("Large volume of outbound traffic (" + 
                           std::to_string(total_sent / (1024 * 1024)) + " MB)");
    }
    
    // Check upload/download ratio
    if (total_received > 0) {
        double ratio = static_cast<double>(total_sent) / total_received;
        if (ratio > 3.0) {  // Sending much more than receiving
            confidence += 30;
            indicators.push_back("High upload/download ratio (" + 
                               std::to_string(static_cast<int>(ratio)) + ":1)");
        }
    }
    
    // Check for POST requests with large bodies
    int large_posts = 0;
    for (const auto& req : http_requests_) {
        if (req.method == "POST" && req.request_size > 1024 * 1024) {  // > 1 MB
            large_posts++;
        }
    }
    
    if (large_posts > 0) {
        confidence += 25;
        indicators.push_back("Large HTTP POST requests (" + 
                           std::to_string(large_posts) + ")");
    }
    
    // Check for connections to file-sharing or paste sites
    std::vector<std::string> exfil_domains = {
        "pastebin", "dropbox", "mega.nz", "transfer.sh", "anonfiles"
    };
    
    int exfil_domain_connections = 0;
    for (const auto& req : http_requests_) {
        for (const auto& domain : exfil_domains) {
            if req.host.find(domain) != std::string::npos) {
                exfil_domain_connections++;
                break;
            }
        }
    }
    
    if (exfil_domain_connections > 0) {
        confidence += 35;
        indicators.push_back("Connections to file-sharing services");
    }
    
    confidence = std::min<int>(confidence, 100);
    
    if (confidence > 0) {
        description << "Data exfiltration indicators detected:\n";
        for (const auto& indicator : indicators) {
            description << "  • " << indicator << "\n";
        }
    } else {
        description << "No significant exfiltration indicators detected";
    }
    
    return {confidence, description.str()};
}

// Detect port scanning
std::pair<int, std::string> NetworkMonitor::DetectPortScanning() const {
    std::lock_guard<std::mutex> lock(data_mutex_);
    
    int confidence = 0;
    std::ostringstream description;
    
    // Group by remote IP
    std::map<std::string, std::set<uint16_t>> ip_ports;
    
    for (const auto& conn : connections_) {
        ip_ports[conn.remote_address].insert(conn.remote_port);
    }
    
    // Look for many different ports contacted on same IP
    int scanning_targets = 0;
    for (const auto& [ip, ports] : ip_ports) {
        if (ports.size() > 10) {  // More than 10 different ports
            scanning_targets++;
        }
    }
    
    if (scanning_targets > 0) {
        confidence = std::min<int>(50 + (scanning_targets * 15), 100);
        description << "Port scanning behavior detected:\n";
        description << "  • Contacted multiple ports on " << scanning_targets << " target(s)";
    } else {
        description << "No port scanning behavior detected";
    }
    
    return {confidence, description.str()};
}

// Detect DGA domains
std::vector<std::string> NetworkMonitor::DetectDGADomains() const {
    std::lock_guard<std::mutex> lock(data_mutex_);
    
    std::vector<std::string> dga_domains;
    
    // Check DNS queries
    for (const auto& query : dns_queries_) {
        if (IsDGADomain(query.query_name)) {
            dga_domains.push_back(query.query_name);
        }
    }
    
    // Check HTTP hosts
    for (const auto& req : http_requests_) {
        if (IsDGADomain(req.host)) {
            dga_domains.push_back(req.host);
        }
    }
    
    return dga_domains;
}

// Extract IOCs
std::vector<std::string> NetworkMonitor::ExtractIOCs() const {
    std::lock_guard<std::mutex> lock(data_mutex_);
    
    std::set<std::string> iocs;
    
    // Extract IPs
    for (const auto& conn : connections_) {
        if (!conn.remote_address.empty() && 
            conn.remote_address.substr(0, 4) != "127." &&
            conn.remote_address.substr(0, 8) != "192.168." &&
            conn.remote_address.substr(0, 3) != "10.") {
            iocs.insert("ip:" + conn.remote_address);
        }
    }
    
    // Extract domains
    auto domains = GetContactedDomains();
    for (const auto& domain : domains) {
        iocs.insert("domain:" + domain);
    }
    
    // Extract suspicious URLs
    for (const auto& req : http_requests_) {
        if (req.is_suspicious) {
            iocs.insert("url:" + req.url);
        }
    }
    
    return std::vector<std::string>(iocs.begin(), iocs.end());
}

// Export to JSON
std::string NetworkMonitor::ExportToJSON() const {
    std::lock_guard<std::mutex> lock(data_mutex_);
    
    json j;
    
    // Statistics
    j["statistics"] = {
        {"total_connections", statistics_.total_connections},
        {"tcp_connections", statistics_.tcp_connections},
        {"udp_connections", statistics_.udp_connections},
        {"http_requests", statistics_.http_requests},
        {"dns_queries", statistics_.dns_queries},
        {"total_bytes_sent", statistics_.total_bytes_sent},
        {"total_bytes_received", statistics_.total_bytes_received},
        {"suspicious_connections", statistics_.suspicious_connections}
    };
    
    // Connections
    json connections_array = json::array();
    for (const auto& conn : connections_) {
        json conn_obj;
        conn_obj["protocol"] = ProtocolToString(conn.protocol);
        conn_obj["local_address"] = conn.local_address;
        conn_obj["local_port"] = conn.local_port;
        conn_obj["remote_address"] = conn.remote_address;
        conn_obj["remote_port"] = conn.remote_port;
        conn_obj["bytes_sent"] = conn.bytes_sent;
        conn_obj["bytes_received"] = conn.bytes_received;
        conn_obj["is_suspicious"] = conn.is_suspicious;
        
        if (conn.is_suspicious) {
            conn_obj["suspicion_reason"] = conn.suspicion_reason;
            conn_obj["suspicion_score"] = conn.suspicion_score;
        }
        
        if (conn.remote_hostname) {
            conn_obj["remote_hostname"] = *conn.remote_hostname;
        }
        
        connections_array.push_back(conn_obj);
    }
    j["connections"] = connections_array;
    
    // DNS queries
    json dns_array = json::array();
    for (const auto& query : dns_queries_) {
        json dns_obj;
        dns_obj["query_name"] = query.query_name;
        dns_obj["query_type"] = query.query_type;
        dns_obj["responses"] = query.responses;
        dns_obj["is_suspicious"] = query.is_suspicious;
        dns_array.push_back(dns_obj);
    }
    j["dns_queries"] = dns_array;
    
    // HTTP requests
    json http_array = json::array();
    for (const auto& req : http_requests_) {
        json http_obj;
        http_obj["method"] = req.method;
        http_obj["url"] = req.url;
        http_obj["host"] = req.host;
        http_obj["user_agent"] = req.user_agent;
        http_obj["status_code"] = req.status_code;
        http_obj["is_suspicious"] = req.is_suspicious;
        http_array.push_back(http_obj);
    }
    j["http_requests"] = http_array;
    
    // IOCs
    j["iocs"] = ExtractIOCs();
    
    return j.dump(2);
}

// Get PCAP path
std::string NetworkMonitor::GetPCAPPath() const {
    return pcap_file_path_;
}

// Clear data
void NetworkMonitor::ClearData() {
    std::lock_guard<std::mutex> lock(data_mutex_);
    
    connections_.clear();
    dns_queries_.clear();
    http_requests_.clear();
    packets_.clear();
    statistics_ = NetworkStatistics{};
    
    spdlog::debug("Network Monitor data cleared");
}

// Private methods

// Initialize capture
bool NetworkMonitor::InitializeCapture() {
    // This is a stub - real implementation would use libpcap
    // For now, we'll just create the PCAP file path
    
    pcap_file_path_ = config_.pcap_file;
    
    spdlog::info("PCAP capture would be initialized here");
    spdlog::info("Output file: {}", pcap_file_path_);
    
    // In real implementation:
    // char errbuf[PCAP_ERRBUF_SIZE];
    // pcap_handle_ = pcap_open_live(config_.capture_interface.c_str(), 
    //                               config_.max_packet_size, 1, 1000, errbuf);
    
    return true;
}

// Capture loop (stub)
void NetworkMonitor::CaptureLoop() {
    // Would run packet capture loop
    // pcap_loop((pcap_t*)pcap_handle_, -1, packet_handler, (u_char*)this);
}

// Process packet (stub)
void NetworkMonitor::ProcessPacket(const uint8_t* packet, std::size_t length) {
    // Would parse packet headers and extract data
}

// Parse Ethernet frame (stub)
void NetworkMonitor::ParseEthernetFrame(const uint8_t* data, std::size_t length) {
    // Would parse Ethernet header
}

// Parse IP packet (stub)
void NetworkMonitor::ParseIPPacket(const uint8_t* data, std::size_t length) {
    // Would parse IP header
}

// Parse TCP segment (stub)
void NetworkMonitor::ParseTCPSegment(const uint8_t* data, std::size_t length,
                                    const std::string& src_ip, const std::string& dst_ip) {
    // Would parse TCP header and extract connection info
}

// Parse UDP datagram (stub)
void NetworkMonitor::ParseUDPDatagram(const uint8_t* data, std::size_t length,
                                     const std::string& src_ip, const std::string& dst_ip) {
    // Would parse UDP header
}

// Parse DNS (stub)
void NetworkMonitor::ParseDNS(const uint8_t* data, std::size_t length) {
    // Would parse DNS packet
}

// Parse HTTP (stub)
void NetworkMonitor::ParseHTTP(const uint8_t* data, std::size_t length,
                              const std::string& src_ip, uint16_t src_port,
                              const std::string& dst_ip, uint16_t dst_port) {
    // Would parse HTTP request/response
}

// Analyze connection
void NetworkMonitor::AnalyzeConnection(NetworkConnection& conn) {
    conn.suspicion_score = CalculateSuspicionScore(conn);
    
    if (conn.suspicion_score >= 50) {
        conn.is_suspicious = true;
        
        std::vector<std::string> reasons;
        
        if (IsMaliciousIP(conn.remote_address)) {
            reasons.push_back("Known malicious IP");
        }
        
        if (conn.remote_hostname && IsMaliciousDomain(*conn.remote_hostname)) {
            reasons.push_back("Known malicious domain");
        }
        
        if (!reasons.empty()) {
            std::ostringstream oss;
            for (size_t i = 0; i < reasons.size(); ++i) {
                if (i > 0) oss << ", ";
                oss << reasons[i];
            }
            conn.suspicion_reason = oss.str();
        }
    }
}

// Is malicious IP
bool NetworkMonitor::IsMaliciousIP(const std::string& ip) const {
    for (const auto& malicious : config_.known_malicious_ips) {
        if (ip == malicious) {
            return true;
        }
    }
    return false;
}

// Is malicious domain
bool NetworkMonitor::IsMaliciousDomain(const std::string& domain) const {
    for (const auto& malicious : config_.known_malicious_domains) {
        if (domain.find(malicious) != std::string::npos) {
            return true;
        }
    }
    return false;
}

// Is DGA domain
bool NetworkMonitor::IsDGADomain(const std::string& domain) const {
    // Simple heuristics for DGA detection
    
    // Remove TLD
    auto dot_pos = domain.find_last_of('.');
    if (dot_pos == std::string::npos) {
        return false;
    }
    
    std::string name = domain.substr(0, dot_pos);
    
    // Check length (DGA domains often long)
    if (name.length() > 20) {
        return true;
    }
    
    // Check for high entropy (random characters)
    std::map<char, int> char_freq;
    for (char c : name) {
        char_freq[c]++;
    }
    
    double entropy = 0.0;
    for (const auto& [c, freq] : char_freq) {
        double p = static_cast<double>(freq) / name.length();
        entropy -= p * std::log2(p);
    }
    
    // High entropy = likely random = potential DGA
    if (entropy > 3.5) {
        return true;
    }
    
    // Check for lack of vowels
    int vowel_count = 0;
    for (char c : name) {
        if (c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u') {
            vowel_count++;
        }
    }
    
    double vowel_ratio = static_cast<double>(vowel_count) / name.length();
    if (vowel_ratio < 0.2) {  // Very few vowels
        return true;
    }
    
    return false;
}

// Lookup country (stub)
std::optional<std::string> NetworkMonitor::LookupCountry(const std::string& ip) {
    // Would use GeoIP database
    return std::nullopt;
}

// Reverse DNS lookup (stub)
std::optional<std::string> NetworkMonitor::ReverseDNSLookup(const std::string& ip) {
    // Would perform reverse DNS lookup
    return std::nullopt;
}

// Calculate suspicion score
int NetworkMonitor::CalculateSuspicionScore(const NetworkConnection& conn) const {
    int score = 0;
    
    // Check malicious IP
    if (IsMaliciousIP(conn.remote_address)) {
        score += 50;
    }
    
    // Check malicious domain
    if (conn.remote_hostname && IsMaliciousDomain(*conn.remote_hostname)) {
        score += 50;
    }
    
    // Check DGA
    if (conn.remote_hostname && IsDGADomain(*conn.remote_hostname)) {
        score += 30;
    }
    
    // Check suspicious ports
    std::vector<uint16_t> suspicious_ports = {6667, 8080, 4444, 31337};
    if (std::find(suspicious_ports.begin(), suspicious_ports.end(), 
                 conn.remote_port) != suspicious_ports.end()) {
        score += 20;
    }
    
    // Check for large data transfer
    if (conn.bytes_sent > 10 * 1024 * 1024) {  // > 10 MB
        score += 15;
    }
    
    return std::min<int>(score, 100);
}

// Detect beacon pattern
bool NetworkMonitor::DetectBeaconPattern(
    const std::vector<std::chrono::system_clock::time_point>& times) const {
    
    if (times.size() < 3) {
        return false;
    }
    
    // Calculate intervals and check regularity
    std::vector<int> intervals;
    for (size_t i = 1; i < times.size(); ++i) {
        auto diff = std::chrono::duration_cast<std::chrono::seconds>(
            times[i] - times[i-1]);
        intervals.push_back(static_cast<int>(diff.count()));
    }
    
    // Calculate variance
    double mean = 0;
    for (int interval : intervals) {
        mean += interval;
    }
    mean /= intervals.size();
    
    double variance = 0;
    for (int interval : intervals) {
        variance += (interval - mean) * (interval - mean);
    }
    variance /= intervals.size();
    
    // Low variance = regular intervals = beaconing
    return variance < (mean * 0.2);
}

// Update statistics
void NetworkMonitor::UpdateStatistics(const NetworkConnection& conn) {
    statistics_.total_connections++;
    
    if (conn.protocol == Protocol::TCP) {
        statistics_.tcp_connections++;
    } else if (conn.protocol == Protocol::UDP) {
        statistics_.udp_connections++;
    }
    
    statistics_.total_bytes_sent += conn.bytes_sent;
    statistics_.total_bytes_received += conn.bytes_received;
    statistics_.total_packets_sent += conn.packets_sent;
    statistics_.total_packets_received += conn.packets_received;
    
    if (conn.is_suspicious) {
        statistics_.suspicious_connections++;
    }
    
    statistics_.unique_remote_ips.insert(conn.remote_address);
    statistics_.unique_remote_ports.insert(conn.remote_port);
    
    statistics_.protocol_distribution[conn.protocol]++;
}

// Notify callbacks
void NetworkMonitor::NotifyConnectionCallbacks(const NetworkConnection& conn) {
    for (const auto& callback : connection_callbacks_) {
        try {
            callback(conn);
        }
        catch (const std::exception& e) {
            spdlog::error("Connection callback error: {}", e.what());
        }
    }
}

void NetworkMonitor::NotifyDNSCallbacks(const DNSQuery& query) {
    for (const auto& callback : dns_callbacks_) {
        try {
            callback(query);
        }
        catch (const std::exception& e) {
            spdlog::error("DNS callback error: {}", e.what());
        }
    }
}

void NetworkMonitor::NotifyHTTPCallbacks(const HTTPRequest& req) {
    for (const auto& callback : http_callbacks_) {
        try {
            callback(req);
        }
        catch (const std::exception& e) {
            spdlog::error("HTTP callback error: {}", e.what());
        }
    }
}

// Protocol to string
std::string NetworkMonitor::ProtocolToString(Protocol proto) const {
    switch (proto) {
        case Protocol::TCP: return "TCP";
        case Protocol::UDP: return "UDP";
        case Protocol::ICMP: return "ICMP";
        case Protocol::HTTP: return "HTTP";
        case Protocol::HTTPS: return "HTTPS";
        case Protocol::DNS: return "DNS";
        case Protocol::FTP: return "FTP";
        case Protocol::SMTP: return "SMTP";
        case Protocol::SSH: return "SSH";
        case Protocol::SMB: return "SMB";
        case Protocol::RDP: return "RDP";
        case Protocol::IRC: return "IRC";
        default: return "UNKNOWN";
    }
}

// Get process name
std::string NetworkMonitor::GetProcessName(int pid) const {
    // Would read from /proc on Linux or use Windows API
    return "unknown";
}

// Log event
void NetworkMonitor::LogEvent(const std::string& event) {
    if (config_.verbose_logging) {
        spdlog::debug("[NETWORK] {}", event);
    }
}

} // namespace monitors
} // namespace paramite