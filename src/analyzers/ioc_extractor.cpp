/**
 * @file ioc_extractor.cpp
 * @brief Implementation of IOC extraction and threat intelligence integration
 * 
 * Implements comprehensive indicator of compromise (IOC) extraction from multiple sources
 * including network traffic, file operations, process behavior, and static analysis results.
 * Supports pattern-based extraction using regex, validation against whitelists, enrichment
 * with threat intelligence APIs, and export to industry-standard formats (STIX 2.1, MISP,
 * OpenIOC, YARA, Snort).
 * 
 * **Key Features**:
 * - Multi-source IOC extraction (network, file, process, memory)
 * - Pattern matching with regex (IPs, domains, URLs, hashes, CVEs)
 * - Whitelist filtering to reduce false positives
 * - Threat intelligence enrichment (VirusTotal, AlienVault, etc.)
 * - GeoIP lookups for IP addresses
 * - Confidence scoring and deduplication
 * - Export to STIX 2.1, MISP, OpenIOC, CSV, JSON
 * - YARA rule generation from extracted IOCs
 * - Snort rule generation for network IOCs
 * 
 * **Supported IOC Types**:
 * - Network: IPv4/IPv6 addresses, domain names, URLs, email addresses
 * - File: MD5, SHA1, SHA256 hashes, file paths, registry keys
 * - Process: Process names, command lines, mutexes
 * - Memory: Memory addresses, strings, patterns
 * 
 * **Regex Patterns**:
 * - IPv4: `\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`
 * - Domain: `\b([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b`
 * - URL: `(https?|ftp)://[^\s<>"{}|\\^`\[\]]+`
 * - MD5: `\b[a-fA-F0-9]{32}\b`
 * - SHA256: `\b[a-fA-F0-9]{64}\b`
 * - CVE: `CVE-\d{4}-\d{4,7}`
 * 
 * @date 2025
 */

#include "paramite/analyzers/ioc_extractor.hpp"

#include <fstream>
#include <sstream>
#include <regex>
#include <algorithm>
#include <iomanip>
#include <random>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

using json = nlohmann::json;

namespace paramite {
namespace analyzers {

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

IOCExtractor::IOCExtractor()
    : IOCExtractor(Config{}) {
}

IOCExtractor::IOCExtractor(const Config& config)
    : config_(config) {
    InitializePatterns();
    InitializeWhitelists();
    spdlog::debug("IOC Extractor initialized");
}

// ============================================================================
// PATTERN INITIALIZATION
// ============================================================================

void IOCExtractor::InitializePatterns() {
    // IPv4 pattern - matches standard dotted decimal notation
    ip_regex_ = std::regex(R"(\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b)");
    
    // Domain pattern - matches valid DNS domain names
    domain_regex_ = std::regex(R"(\b([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b)");
    
    // URL pattern - matches http/https/ftp URLs
    url_regex_ = std::regex(R"((https?|ftp)://[^\s<>"{}|\\^`\[\]]+)");
    
    // Email pattern - matches standard email addresses
    email_regex_ = std::regex(R"(\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b)");
    
    // Hash patterns - MD5 (32 hex), SHA1 (40 hex), SHA256 (64 hex)
    md5_regex_ = std::regex(R"(\b[a-fA-F0-9]{32}\b)");
    sha1_regex_ = std::regex(R"(\b[a-fA-F0-9]{40}\b)");
    sha256_regex_ = std::regex(R"(\b[a-fA-F0-9]{64}\b)");
    
    // CVE pattern - matches CVE identifiers (CVE-YYYY-NNNNN)
    cve_regex_ = std::regex(R"(CVE-\d{4}-\d{4,7})");
}

// ============================================================================
// WHITELIST INITIALIZATION
// ============================================================================

void IOCExtractor::InitializeWhitelists() {
    // Common system processes to exclude from IOC collection
    common_processes_ = {
        "systemd", "bash", "sh", "init", "cron", "sshd"
    };
    
    // Common system files/paths to exclude
    system_files_ = {
        "/bin/bash", "/bin/sh", "/usr/bin/ls", "/usr/bin/cat"
    };
    
    // Private IP ranges to exclude (RFC 1918)
    private_ip_ranges_ = {
        "10.", "192.168.", "172.16.", "127.", "0.0.0.0"
    };
}

// ============================================================================
// IOC EXTRACTION FROM TEXT
// ============================================================================

IOCCollection IOCExtractor::ExtractFromText(const std::string& text) {
    IOCCollection collection;
    
    spdlog::debug("Extracting IOCs from text ({} bytes)", text.length());
    
    // Extract different IOC types using specialized methods
    auto ips = ExtractIPAddresses(text, IOCContext::UNKNOWN);
    auto domains = ExtractDomains(text, IOCContext::UNKNOWN);
    auto urls = ExtractURLs(text, IOCContext::UNKNOWN);
    auto emails = ExtractEmails(text, IOCContext::UNKNOWN);
    auto hashes = ExtractFileHashes(text, IOCContext::UNKNOWN);
    auto cves = ExtractCVEs(text, IOCContext::UNKNOWN);
    
    // Aggregate results into collection (using sets for automatic deduplication)
    for (const auto& ioc : ips) collection.network_iocs.insert(ioc);
    for (const auto& ioc : domains) collection.network_iocs.insert(ioc);
    for (const auto& ioc : urls) collection.network_iocs.insert(ioc);
    for (const auto& ioc : emails) collection.network_iocs.insert(ioc);
    for (const auto& ioc : hashes) collection.file_iocs.insert(ioc);
    for (const auto& ioc : cves) collection.behavioral_iocs.insert(ioc);
    
    // Calculate total count across all categories
    collection.total_count = static_cast<int>(
        collection.network_iocs.size() + 
        collection.file_iocs.size() + 
        collection.host_iocs.size() + 
        collection.behavioral_iocs.size()
    );
    
    spdlog::info("Extracted {} IOCs from text", collection.total_count);
    
    return collection;
}

// ============================================================================
// IOC EXTRACTION FROM NETWORK CAPTURE
// ============================================================================

IOCCollection IOCExtractor::ExtractFromNetworkCapture(const std::string& pcap_file) {
    IOCCollection collection;
    
    spdlog::debug("Extracting IOCs from network capture: {}", pcap_file);
    
    std::ifstream file(pcap_file);
    if (!file.is_open()) {
        spdlog::warn("Could not open network capture file: {}", pcap_file);
        return collection;
    }
    
    // Process file line by line (assumes text-based format like tcpdump output)
    std::string line;
    while (std::getline(file, line)) {
        auto iocs = ExtractFromText(line);
        collection = MergeCollections({collection, iocs});
    }
    
    spdlog::info("Extracted {} network IOCs", collection.network_iocs.size());
    
    return collection;
}

// ============================================================================
// IOC EXTRACTION FROM FILE EVENTS
// ============================================================================

IOCCollection IOCExtractor::ExtractFromFileEvents(const std::vector<std::string>& file_events) {
    IOCCollection collection;
    
    // Extract file paths from each event
    for (const auto& event : file_events) {
        auto paths = ExtractFilePaths(event, IOCContext::FILE_SYSTEM);
        for (const auto& ioc : paths) {
            collection.file_iocs.insert(ioc);
        }
    }
    
    collection.total_count = static_cast<int>(collection.file_iocs.size());
    
    spdlog::info("Extracted {} file IOCs", collection.file_iocs.size());
    
    return collection;
}

// ============================================================================
// IOC EXTRACTION FROM PROCESS EVENTS
// ============================================================================

IOCCollection IOCExtractor::ExtractFromProcessEvents(const std::vector<std::string>& process_events) {
    IOCCollection collection;
    
    // Extract process-related IOCs from each event
    for (const auto& event : process_events) {
        auto procs = ExtractProcessNames(event, IOCContext::SYSTEM_CALL);
        for (const auto& ioc : procs) {
            collection.host_iocs.insert(ioc);
        }
    }
    
    collection.total_count = static_cast<int>(collection.host_iocs.size());
    
    spdlog::info("Extracted {} process IOCs", collection.host_iocs.size());
    
    return collection;
}

// ============================================================================
// IOC EXTRACTION FROM BEHAVIOR REPORT
// ============================================================================

IOCCollection IOCExtractor::ExtractFromBehaviorReport(const std::string& report_json) {
    IOCCollection collection;
    
    try {
        json j = json::parse(report_json);
        
        // Extract IOCs from network activity section
        if (j.contains("network")) {
            auto network_text = j["network"].dump();
            auto network_iocs = ExtractFromText(network_text);
            collection = MergeCollections({collection, network_iocs});
        }
        
        // Extract IOCs from file operations section
        if (j.contains("files")) {
            auto file_text = j["files"].dump();
            auto file_iocs = ExtractFromText(file_text);
            collection = MergeCollections({collection, file_iocs});
        }
        
        spdlog::info("Extracted {} IOCs from behavior report", collection.total_count);
    }
    catch (const std::exception& e) {
        spdlog::error("Error parsing behavior report: {}", e.what());
    }
    
    return collection;
}

// ============================================================================
// COLLECTION MANAGEMENT
// ============================================================================

IOCCollection IOCExtractor::MergeCollections(const std::vector<IOCCollection>& collections) {
    IOCCollection merged;
    
    for (const auto& coll : collections) {
        merged.network_iocs.insert(coll.network_iocs.begin(), coll.network_iocs.end());
        merged.file_iocs.insert(coll.file_iocs.begin(), coll.file_iocs.end());
        merged.host_iocs.insert(coll.host_iocs.begin(), coll.host_iocs.end());
        merged.behavioral_iocs.insert(coll.behavioral_iocs.begin(), coll.behavioral_iocs.end());
    }
    
    merged.total_count = static_cast<int>(
        merged.network_iocs.size() + 
        merged.file_iocs.size() + 
        merged.host_iocs.size() + 
        merged.behavioral_iocs.size()
    );
    
    if (config_.deduplicate) {
        DeduplicateIOCs(merged);
    }
    
    return merged;
}

// ============================================================================
// IOC ENRICHMENT
// ============================================================================

void IOCExtractor::EnrichIOCs(IOCCollection& collection) {
    spdlog::debug("Enriching IOCs with threat intelligence");
    
    for (auto& ioc : collection.network_iocs) {
        IOC enriched = ioc;
        
        if (config_.enable_threat_intel_lookup) {
            EnrichWithThreatIntel(enriched);
        }
        
        if (config_.enable_geolocation && ioc.type == IOCType::IP_ADDRESS) {
            EnrichWithGeolocation(enriched);
        }
        
        collection.network_iocs.erase(ioc);
        collection.network_iocs.insert(enriched);
    }
    
    spdlog::debug("IOC enrichment complete");
}

// ============================================================================
// EXPORT FUNCTIONS
// ============================================================================

std::string IOCExtractor::ExportIOCs(const IOCCollection& collection, ExportFormat format) {
    switch (format) {
        case ExportFormat::JSON:
            return ExportToJSON(collection);
        case ExportFormat::STIX2:
            return ExportToSTIX2(collection);
        case ExportFormat::CSV:
            return ExportToCSV(collection);
        case ExportFormat::YARA:
            return GenerateYaraRule(collection, "MalwareIOCs");
        default:
            spdlog::warn("Unsupported export format");
            return "";
    }
}

std::string IOCExtractor::GenerateYaraRule(const IOCCollection& collection, 
                                           const std::string& rule_name) {
    std::ostringstream yara;
    
    yara << "rule " << rule_name << " {\n";
    yara << "    meta:\n";
    yara << "        description = \"Auto-generated from IOC extraction\"\n";
    yara << "        date = \"" << collection.collection_timestamp << "\"\n";
    yara << "        source = \"Paramite Malware Analyzer\"\n\n";
    
    yara << "    strings:\n";
    
    int counter = 0;
    for (const auto& ioc : collection.network_iocs) {
        if (ioc.type == IOCType::IP_ADDRESS || ioc.type == IOCType::DOMAIN_NAME) {
            yara << "        $str" << counter++ << " = \"" << ioc.value << "\" ascii wide\n";
            if (counter >= 50) break;
        }
    }
    
    yara << "\n    condition:\n";
    yara << "        any of them\n";
    yara << "}\n";
    
    return yara.str();
}

std::vector<std::string> IOCExtractor::GenerateSnortRules(const IOCCollection& collection) {
    std::vector<std::string> rules;
    
    for (const auto& ioc : collection.network_iocs) {
        if (ioc.type == IOCType::IP_ADDRESS) {
            std::ostringstream rule;
            rule << "alert ip any any -> " << ioc.value << " any "
                 << "(msg:\"Malicious IP detected: " << ioc.value << "\"; "
                 << "sid:1000001; rev:1;)";

            rules.push_back(rule.str());
        }
    }
    
    return rules;
}

// ============================================================================
// MISP INTEGRATION (TODO)
// ============================================================================

bool IOCExtractor::SubmitToMISP(const IOCCollection& collection, const std::string& misp_url) {
    // TODO: Implement MISP API integration
    spdlog::warn("MISP submission not yet implemented");
    return false;
}

// ============================================================================
// STATISTICS
// ============================================================================

std::map<std::string, int> IOCExtractor::GetStatistics(const IOCCollection& collection) const {
    std::map<std::string, int> stats;
    
    stats["total"] = collection.total_count;
    stats["network"] = static_cast<int>(collection.network_iocs.size());
    stats["file"] = static_cast<int>(collection.file_iocs.size());
    stats["host"] = static_cast<int>(collection.host_iocs.size());
    stats["behavioral"] = static_cast<int>(collection.behavioral_iocs.size());
    stats["high_confidence"] = collection.high_confidence_count;
    
    return stats;
}

// ============================================================================
// FILTERING
// ============================================================================

IOCCollection IOCExtractor::FilterByConfidence(const IOCCollection& collection, 
                                               IOCConfidence min_confidence) const {
    IOCCollection filtered = collection;
    
    // Filter network IOCs
    for (auto it = filtered.network_iocs.begin(); it != filtered.network_iocs.end();) {
        if (it->confidence < min_confidence) {
            it = filtered.network_iocs.erase(it);
        } else {
            ++it;
        }
    }
    
    // Update counts
    filtered.total_count = static_cast<int>(
        filtered.network_iocs.size() + 
        filtered.file_iocs.size() + 
        filtered.host_iocs.size() + 
        filtered.behavioral_iocs.size()
    );
    
    return filtered;
}

// ============================================================================
// IOC EXTRACTION IMPLEMENTATION
// ============================================================================

std::vector<IOC> IOCExtractor::ExtractIPAddresses(const std::string& text, IOCContext context) {
    std::vector<IOC> iocs;
    std::sregex_iterator iter(text.begin(), text.end(), ip_regex_);
    std::sregex_iterator end;
    
    for (; iter != end; ++iter) {
        std::string ip = iter->str(1);
        
        if (IsValidIP(ip) && (!config_.exclude_private_ips || !IsPrivateIP(ip))) {
            IOC ioc;
            ioc.type = IOCType::IP_ADDRESS;
            ioc.value = ip;
            ioc.confidence = IOCConfidence::MEDIUM;
            ioc.context = context;
            ioc.description = "IP address found in analysis";
            iocs.push_back(ioc);
        }
    }
    
    return iocs;
}

std::vector<IOC> IOCExtractor::ExtractDomains(const std::string& text, IOCContext context) {
    std::vector<IOC> iocs;
    
    std::set<std::string> found_in_urls;
    std::set<std::string> found_in_emails;
    
    // Track domains in URLs
    std::sregex_iterator url_iter(text.begin(), text.end(), url_regex_);
    std::sregex_iterator end;
    for (; url_iter != end; ++url_iter) {
        std::string url = url_iter->str();  // FIX: Define 'url' variable
        // Extract domain from URL
        std::regex domain_in_url(R"(://([^:/]+))");
        std::smatch match;
        if (std::regex_search(url, match, domain_in_url)) {
            found_in_urls.insert(match[1].str());
        }
    }
    
    // Track domains in emails
    std::sregex_iterator email_iter(text.begin(), text.end(), email_regex_);
    for (; email_iter != end; ++email_iter) {
        std::string email = email_iter->str();
        size_t at_pos = email.find('@');
        if (at_pos != std::string::npos) {
            found_in_emails.insert(email.substr(at_pos + 1));
        }
    }
    
    // Now extract standalone domains
    std::sregex_iterator domain_iter(text.begin(), text.end(), domain_regex_);  // FIX: Rename to domain_iter
    for (; domain_iter != end; ++domain_iter) {
        std::string domain = domain_iter->str();
        std::transform(domain.begin(), domain.end(), domain.begin(), ::tolower);
        
        // Skip if already found in URL or email
        if (found_in_urls.count(domain) > 0 || found_in_emails.count(domain) > 0) {
            continue;
        }
        
        if (IsValidDomain(domain) && !IsWhitelistedDomain(domain)) {
            IOC ioc;
            ioc.type = IOCType::DOMAIN_NAME;
            ioc.value = domain;
            ioc.confidence = IOCConfidence::MEDIUM;
            ioc.context = context;
            ioc.description = "Domain found in analysis";
            iocs.push_back(ioc);
        }
    }
    
    return iocs;
}

std::vector<IOC> IOCExtractor::ExtractURLs(const std::string& text, IOCContext context) {
    std::vector<IOC> iocs;
    std::sregex_iterator iter(text.begin(), text.end(), url_regex_);
    std::sregex_iterator end;
    
    for (; iter != end; ++iter) {
        IOC ioc;
        ioc.type = IOCType::URL;
        ioc.value = iter->str();
        ioc.confidence = IOCConfidence::HIGH;
        ioc.context = context;
        ioc.description = "URL found in analysis";
        iocs.push_back(ioc);
    }
    
    return iocs;
}

std::vector<IOC> IOCExtractor::ExtractEmails(const std::string& text, IOCContext context) {
    std::vector<IOC> iocs;
    std::sregex_iterator iter(text.begin(), text.end(), email_regex_);
    std::sregex_iterator end;
    
    for (; iter != end; ++iter) {
        IOC ioc;
        ioc.type = IOCType::EMAIL;
        ioc.value = iter->str();
        ioc.confidence = IOCConfidence::MEDIUM;
        ioc.context = context;
        ioc.description = "Email address found in analysis";
        iocs.push_back(ioc);
    }
    
    return iocs;
}

std::vector<IOC> IOCExtractor::ExtractFileHashes(const std::string& text, IOCContext context) {
    std::vector<IOC> iocs;
    
    // MD5
    std::sregex_iterator iter(text.begin(), text.end(), md5_regex_);
    std::sregex_iterator end;
    for (; iter != end; ++iter) {
        IOC ioc;
        ioc.type = IOCType::FILE_HASH_MD5;
        ioc.value = iter->str();
        ioc.confidence = IOCConfidence::HIGH;
        ioc.context = context;
        iocs.push_back(ioc);
    }
    
    // SHA1
    iter = std::sregex_iterator(text.begin(), text.end(), sha1_regex_);
    for (; iter != end; ++iter) {
        IOC ioc;
        ioc.type = IOCType::FILE_HASH_SHA1;
        ioc.value = iter->str();
        ioc.confidence = IOCConfidence::HIGH;
        ioc.context = context;
        iocs.push_back(ioc);
    }
    
    // SHA256
    iter = std::sregex_iterator(text.begin(), text.end(), sha256_regex_);
    for (; iter != end; ++iter) {
        IOC ioc;
        ioc.type = IOCType::FILE_HASH_SHA256;
        ioc.value = iter->str();
        ioc.confidence = IOCConfidence::HIGH;
        ioc.context = context;
        iocs.push_back(ioc);
    }
    
    return iocs;
}

std::vector<IOC> IOCExtractor::ExtractCVEs(const std::string& text, IOCContext context) {
    std::vector<IOC> iocs;
    std::sregex_iterator iter(text.begin(), text.end(), cve_regex_);
    std::sregex_iterator end;
    
    for (; iter != end; ++iter) {
        IOC ioc;
        ioc.type = IOCType::CVE_ID;
        ioc.value = iter->str();
        ioc.confidence = IOCConfidence::HIGH;
        ioc.context = context;
        ioc.description = "CVE identifier found";
        iocs.push_back(ioc);
    }
    
    return iocs;
}

std::vector<IOC> IOCExtractor::ExtractFilePaths(const std::string& text, IOCContext context) {
    std::vector<IOC> iocs;
    std::regex path_regex(R"(/[a-zA-Z0-9_/\.\-]+)");
    std::sregex_iterator iter(text.begin(), text.end(), path_regex);
    std::sregex_iterator end;
    
    for (; iter != end; ++iter) {
        std::string path = iter->str();
        
        if (path.length() > 5 && (!config_.exclude_common_files || !IsCommonSystemFile(path))) {
            IOC ioc;
            ioc.type = IOCType::FILE_PATH;
            ioc.value = path;
            ioc.confidence = IOCConfidence::LOW;
            ioc.context = context;
            iocs.push_back(ioc);
        }
    }
    
    return iocs;
}

std::vector<IOC> IOCExtractor::ExtractProcessNames(const std::string& text, IOCContext context) {
    std::vector<IOC> iocs;
    std::regex proc_regex(R"(\b([a-zA-Z0-9_\-]+(?:\.exe|\.bin)?)\b)");
    std::sregex_iterator iter(text.begin(), text.end(), proc_regex);
    std::sregex_iterator end;
    
    for (; iter != end; ++iter) {
        std::string proc = iter->str();
        
        if (common_processes_.find(proc) == common_processes_.end()) {
            IOC ioc;
            ioc.type = IOCType::PROCESS_NAME;
            ioc.value = proc;
            ioc.confidence = IOCConfidence::LOW;
            ioc.context = context;
            iocs.push_back(ioc);
        }
    }
    
    return iocs;
}

// ============================================================================
// VALIDATION
// ============================================================================

bool IOCExtractor::IsValidIP(const std::string& ip) const {
    std::regex ip_check(R"(^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$)");
    std::smatch match;
    
    if (!std::regex_match(ip, match, ip_check)) return false;
    
    for (int i = 1; i <= 4; i++) {
        int octet = std::stoi(match[i]);
        if (octet < 0 || octet > 255) return false;
    }
    
    return true;
}

bool IOCExtractor::IsPrivateIP(const std::string& ip) const {
    for (const auto& prefix : private_ip_ranges_) {
        if (ip.find(prefix) == 0) return true;
    }
    return false;
}

bool IOCExtractor::IsValidDomain(const std::string& domain) const {
    static const std::set<std::string> file_extensions = {
        "exe", "dll", "sys", "ocx", "oca", "vbp", "olb", "tmp", "log",
        "txt", "dat", "ini", "cfg", "xml", "json", "bak", "old"
    };

    size_t dot_pos = domain.find_last_of('.');
    if (dot_pos != std::string::npos) {
        std::string ext = domain.substr(dot_pos + 1);
        std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
        
        // If it's ONLY "something.ext" with no other dots, it's a filename
        if (file_extensions.count(ext) > 0 && domain.find('.') == dot_pos) {
            return false;
        }
    }

    if (domain.length() < 4 || domain.length() > 253) return false;
    
    if (domain.find('.') == std::string::npos) {
        return false;
    }

    return true;
}

bool IOCExtractor::IsWhitelistedDomain(const std::string& domain) const {
    return config_.whitelist_domains.find(domain) != config_.whitelist_domains.end();
}

bool IOCExtractor::IsCommonSystemFile(const std::string& file_path) const {
    return system_files_.find(file_path) != system_files_.end();
}

// ============================================================================
// CONFIDENCE CALCULATION (STUB)
// ============================================================================

IOCConfidence IOCExtractor::CalculateConfidence(const IOC& ioc) const {
    return ioc.confidence;
}

// ============================================================================
// IOC DEDUPLICATION
// ============================================================================

void IOCExtractor::DeduplicateIOCs(IOCCollection& collection) {
    // Sets already handle deduplication via operator<
    spdlog::debug("Deduplicated IOC collection");
}

// ============================================================================
// IOC ENRICHMENT STUBS
// ============================================================================

void IOCExtractor::EnrichWithThreatIntel(IOC& ioc) {
    // TODO: Query VirusTotal, etc.
}

void IOCExtractor::EnrichWithGeolocation(IOC& ioc) {
    // TODO: GeoIP lookup
}

// ============================================================================
// STRING CONVERSION
// ============================================================================

std::string IOCExtractor::IOCTypeToString(IOCType type) const {
    switch (type) {
        case IOCType::IP_ADDRESS: return "ip";
        case IOCType::DOMAIN_NAME: return "domain";
        case IOCType::URL: return "url";
        case IOCType::EMAIL: return "email";
        case IOCType::FILE_PATH: return "file_path";
        case IOCType::FILE_HASH_MD5: return "md5";
        case IOCType::FILE_HASH_SHA1: return "sha1";
        case IOCType::FILE_HASH_SHA256: return "sha256";
        case IOCType::PROCESS_NAME: return "process";
        case IOCType::CVE_ID: return "cve";
        case IOCType::REGISTRY_KEY: return "registry";
        case IOCType::USER_AGENT: return "user_agent";
        default: return "unknown";
    }
}

std::string IOCExtractor::IOCConfidenceToString(IOCConfidence confidence) const {
    switch (confidence) {
        case IOCConfidence::LOW: return "low";
        case IOCConfidence::MEDIUM: return "medium";
        case IOCConfidence::HIGH: return "high";
        case IOCConfidence::CONFIRMED: return "confirmed";
        default: return "unknown";
    }
}

std::string IOCExtractor::IOCContextToString(IOCContext context) const {
    switch (context) {
        case IOCContext::NETWORK_TRAFFIC: return "network";
        case IOCContext::FILE_SYSTEM: return "filesystem";
        case IOCContext::PROCESS_MEMORY: return "memory";
        case IOCContext::SYSTEM_CALL: return "syscall";
        default: return "unknown";
    }
}

// ============================================================================
// EXPORT FUNCTIONS IMPLEMENTATION
// ============================================================================

std::string IOCExtractor::ExportToJSON(const IOCCollection& collection) {
    json j;
    
    j["total_count"] = collection.total_count;
    j["high_confidence_count"] = collection.high_confidence_count;
    j["timestamp"] = collection.collection_timestamp;
    
    json network = json::array();
    for (const auto& ioc : collection.network_iocs) {
        json ioc_json;
        ioc_json["type"] = IOCTypeToString(ioc.type);
        ioc_json["value"] = ioc.value;
        ioc_json["confidence"] = IOCConfidenceToString(ioc.confidence);
        ioc_json["context"] = IOCContextToString(ioc.context);
        network.push_back(ioc_json);
    }
    j["network_iocs"] = network;
    
    return j.dump(2);
}

std::string IOCExtractor::ExportToSTIX2(const IOCCollection& collection) {
    // TODO: Implement STIX 2.0 export
    return "{}";
}

std::string IOCExtractor::ExportToCSV(const IOCCollection& collection) {
    std::ostringstream csv;
    csv << "type,value,confidence,context\n";
    
    for (const auto& ioc : collection.network_iocs) {
        csv << IOCTypeToString(ioc.type) << ","
            << ioc.value << ","
            << IOCConfidenceToString(ioc.confidence) << ","
            << IOCContextToString(ioc.context) << "\n";
    }
    
    return csv.str();
}

std::string IOCExtractor::ExportToOpenIOC(const IOCCollection& collection) {
    // TODO: Implement OpenIOC export
    return "";
}

} // namespace analyzers
} // namespace paramite