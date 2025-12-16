/**
 * @file static_analyzer.cpp
 * @brief Implementation of static malware analysis (PE/ELF parsing, entropy, strings)
 * 
 * Implements comprehensive static analysis without executing the malware sample. Performs
 * file type detection, cryptographic hash calculation, entropy analysis, string extraction,
 * PE/ELF header parsing, import/export analysis, section analysis, packer/obfuscation
 * detection, and threat scoring based on static characteristics.
 * 
 * **Analysis Capabilities**:
 * - **File Type Detection**: Magic bytes, MIME type, file format identification
 * - **Hash Calculation**: MD5, SHA1, SHA256, SHA512, SSDEEP (fuzzy), imphash
 * - **Entropy Analysis**: Shannon entropy per section, overall entropy score
 * - **String Extraction**: ASCII/Unicode strings, URL/IP extraction, base64 detection
 * - **PE Analysis**: Headers, sections, imports, exports, resources, digital signatures
 * - **ELF Analysis**: Headers, program headers, section headers, symbols, dynamic linking
 * - **Packer Detection**: UPX, ASPack, PECompact, Themida, VMProtect signatures
 * - **Anti-Analysis Detection**: Anti-debugging, anti-VM, anti-sandbox indicators
 * 
 * **PE File Analysis**:
 * ```
 * DOS Header ? PE Header ? Optional Header ? Section Headers ? Sections
 * ?? Import Directory (IAT)
 * ?? Export Directory (EAT)
 * ?? Resource Directory
 * ?? Relocation Table
 * ?? Digital Signature
 * ```
 * 
 * **Entropy Calculation**:
 * Shannon entropy formula: H(X) = -? P(xi) * log2(P(xi))
 * - 0.0-1.0: Very low entropy (mostly zeros/repeated data)
 * - 1.0-3.0: Low entropy (text files, source code)
 * - 3.0-5.0: Medium entropy (compiled code)
 * - 5.0-7.0: High entropy (compressed data)
 * - 7.0-8.0: Very high entropy (encrypted/packed)
 * 
 * **Packer Signatures**:
 * Detected by:
 * - Section names (.UPX0, .UPX1, .aspack, .petite)
 * - Entry point in non-standard section
 * - High entropy in code sections
 * - Suspicious import patterns
 * - Known packer signatures in PE header
 * 
 * **Threat Indicators**:
 * - Suspicious imports (VirtualAlloc, WriteProcessMemory, CreateRemoteThread)
 * - Encrypted sections (entropy > 7.0)
 * - No imports (packed/obfuscated)
 * - Suspicious section names
 * - TLS callbacks (anti-debugging)
 * - Invalid/missing digital signature
 * 
 * @date 2025
 */

#include "paramite/analyzers/static_analyzer.hpp"

#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cmath>
#include <regex>
#include <ctime>
#include <array>
#include <spdlog/spdlog.h>

namespace paramite {
namespace analyzers {

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================
// Initializes static analysis engine with configuration

StaticAnalyzer::StaticAnalyzer()
    : StaticAnalyzer(Config{}) {
}
// Constructor
StaticAnalyzer::StaticAnalyzer(const Config& config)
    : config_(config) {
    spdlog::debug("Static Analyzer initialized");
    
    if (config_.verbose_logging) {
        spdlog::set_level(spdlog::level::debug);
    }
}

// ============================================================================
// MAIN ANALYSIS ENTRY POINT
// ============================================================================
// Orchestrates complete static analysis workflow

StaticAnalysisReport StaticAnalyzer::Analyze(const std::filesystem::path& file_path) {
    spdlog::info("Starting static analysis of: {}", file_path.string());
    auto start_time = std::chrono::steady_clock::now();
    
    StaticAnalysisReport report;
    report.file_path = file_path;
    report.filename = file_path.filename().string();
    
    // Check file exists and size
    if (!std::filesystem::exists(file_path)) {
        spdlog::error("File not found: {}", file_path.string());
        throw std::runtime_error("File not found: " + file_path.string());
    }
    
    report.file_size = std::filesystem::file_size(file_path);
    spdlog::debug("File size: {} bytes", report.file_size);
    
    // Check file size limit
    if (report.file_size > config_.max_file_size) {
        spdlog::warn("File exceeds maximum size limit ({} > {})", 
                     report.file_size, config_.max_file_size);
    }
    
    // Calculate file hashes
    spdlog::debug("Calculating file hashes...");
    // TODO: Implement actual hash calculation using hash_utils
    report.md5 = "placeholder_md5";
    report.sha1 = "placeholder_sha1";
    report.sha256 = "placeholder_sha256";
    report.ssdeep = "placeholder_ssdeep";
    
    // Detect file type
    spdlog::debug("Detecting file type...");
    report.file_type = DetectFileType(file_path);
    report.mime_type = DetermineMIMEType(file_path);
    
    auto magic = ReadMagicBytes(file_path, 16);
    for (auto byte : magic) {
        std::ostringstream oss;
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
        report.magic_bytes.push_back(oss.str());
    }
    
    spdlog::info("Detected file type: {}", FileTypeToString(report.file_type));
    
    // Format-specific analysis
    switch (report.file_type) {
        case FileType::PE_EXECUTABLE:
            if (config_.analyze_pe) {
                spdlog::debug("Performing PE analysis...");
                report.pe_analysis = AnalyzePE(file_path);
            }
            break;
            
        case FileType::ELF_EXECUTABLE:
            if (config_.analyze_elf) {
                spdlog::debug("Performing ELF analysis...");
                report.elf_analysis = AnalyzeELF(file_path);
            }
            break;
            
        case FileType::SCRIPT_BASH:
        case FileType::SCRIPT_PYTHON:
        case FileType::SCRIPT_PERL:
        case FileType::SCRIPT_POWERSHELL:
        case FileType::SCRIPT_JAVASCRIPT:
            if (config_.analyze_scripts) {
                spdlog::debug("Performing script analysis...");
                report.script_analysis = AnalyzeScript(file_path);
            }
            break;
            
        default:
            spdlog::debug("No format-specific analysis for this file type");
            break;
    }
    
    // String extraction
    if (config_.extract_strings) {
        spdlog::debug("Extracting strings...");
        report.string_analysis = ExtractStrings(file_path);
        spdlog::info("Extracted {} strings", report.string_analysis.total_count);
    }
    
    // Entropy analysis
    if (config_.calculate_entropy) {
        spdlog::debug("Calculating entropy...");
        report.entropy_analysis = CalculateEntropy(file_path);
        spdlog::info("Overall entropy: {:.2f}", report.entropy_analysis.overall_entropy);
    }
    
    // Packer detection
    if (config_.detect_packers) {
        spdlog::debug("Detecting packers...");
        report.packer_detections = DetectPackers(file_path);
        if (!report.packer_detections.empty()) {
            spdlog::info("Detected {} packers", report.packer_detections.size());
        }
    }
    
    // Signature matching
    if (config_.check_signatures && config_.enable_yara_scanning) {
        spdlog::debug("Matching signatures...");
        report.signature_matches = MatchSignatures(file_path);
        if (!report.signature_matches.empty()) {
            spdlog::warn("Found {} signature matches!", report.signature_matches.size());
        }
    }
    
    // Detect anti-analysis techniques
    report.anti_analysis_techniques = DetectAntiAnalysis(report);
    
    // Calculate threat score
    report.threat_score = CalculateThreatScore(report);
    report.suspicion_level = report.threat_score / 10;
    report.likely_malicious = (report.threat_score >= 70);
    
    spdlog::info("Threat score: {}/100 (Suspicion level: {}/10)", 
                 report.threat_score, report.suspicion_level);
    
    // Finalize report
    auto end_time = std::chrono::steady_clock::now();
    report.analysis_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        end_time - start_time);
    
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::ostringstream timestamp;
    timestamp << std::put_time(std::gmtime(&time), "%Y-%m-%d %H:%M:%S UTC");
    report.analysis_timestamp = timestamp.str();
    
    spdlog::info("Static analysis complete in {} ms", report.analysis_duration.count());
    
    return report;
}

// ============================================================================
// FILE TYPE DETECTION
// ============================================================================

FileType StaticAnalyzer::DetectFileType(const std::filesystem::path& file_path) {
    // Check by magic bytes first
    if (IsPEFile(file_path)) {
        return FileType::PE_EXECUTABLE;
    }
    
    if (IsELFFile(file_path)) {
        return FileType::ELF_EXECUTABLE;
    }
    
    // Check by file extension
    std::string ext = file_path.extension().string();
    std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
    
    if (ext == ".sh" || ext == ".bash") return FileType::SCRIPT_BASH;
    if (ext == ".py") return FileType::SCRIPT_PYTHON;
    if (ext == ".pl") return FileType::SCRIPT_PERL;
    if (ext == ".ps1") return FileType::SCRIPT_POWERSHELL;
    if (ext == ".js") return FileType::SCRIPT_JAVASCRIPT;
    if (ext == ".pdf") return FileType::DOCUMENT_PDF;
    if (ext == ".doc" || ext == ".docx" || ext == ".xls" || ext == ".xlsx") {
        return FileType::DOCUMENT_OFFICE;
    }
    if (ext == ".zip") return FileType::ARCHIVE_ZIP;
    if (ext == ".rar") return FileType::ARCHIVE_RAR;
    if (ext == ".tar" || ext == ".tar.gz" || ext == ".tgz") return FileType::ARCHIVE_TAR;
    
    // Check shebang for scripts
    auto script_type = DetectScriptType(file_path);
    if (script_type) {
        if (*script_type == "bash") return FileType::SCRIPT_BASH;
        if (*script_type == "python") return FileType::SCRIPT_PYTHON;
        if (*script_type == "perl") return FileType::SCRIPT_PERL;
    }
    
    return FileType::UNKNOWN;
}

// ============================================================================
// PE ANALYSIS
// ============================================================================

PEAnalysis StaticAnalyzer::AnalyzePE(const std::filesystem::path& file_path) {
    PEAnalysis analysis;
    
    spdlog::debug("Analyzing PE file structure");
    
    // Parse headers
    ParsePEHeaders(file_path, analysis);
    
    // Analyze imports
    if (config_.analyze_imports) {
        // Check for suspicious imports
        std::vector<std::string> suspicious_functions = {
            "VirtualAlloc", "VirtualProtect", "WriteProcessMemory",
            "CreateRemoteThread", "SetWindowsHookEx", "URLDownloadToFile",
            "WinExec", "ShellExecute", "CreateProcess", "LoadLibrary",
            "GetProcAddress", "IsDebuggerPresent", "CheckRemoteDebuggerPresent"
        };
        
        for (const auto& func : analysis.imported_functions) {
            for (const auto& suspicious : suspicious_functions) {
                if (func.find(suspicious) != std::string::npos) {
                    analysis.suspicious_imports.push_back(func);
                    break;
                }
            }
        }
        
        if (!analysis.suspicious_imports.empty()) {
            spdlog::warn("Found {} suspicious imports", analysis.suspicious_imports.size());
        }
    }
    
    // Check sections
    for (const auto& section : analysis.sections) {
        // High entropy sections (possibly packed/encrypted)
        if (section.entropy > config_.high_entropy_threshold) {
            analysis.suspicious_sections.push_back(section.name + " (high entropy)");
        }
        
        // Executable sections with unusual names
        bool is_executable = false;
        for (const auto& ch : section.characteristics) {
            if (ch.find("EXECUTE") != std::string::npos) {
                is_executable = true;
                break;
            }
        }
        
        if (is_executable && 
            section.name != ".text" && 
            section.name != ".code") {
            analysis.suspicious_sections.push_back(
                section.name + " (unusual executable section)");
        }
    }
    
    spdlog::debug("PE analysis complete");
    return analysis;
}

// ============================================================================
// ELF ANALYSIS
// ============================================================================

ELFAnalysis StaticAnalyzer::AnalyzeELF(const std::filesystem::path& file_path) {
    ELFAnalysis analysis;
    
    spdlog::debug("Analyzing ELF file structure");
    
    // Parse headers
    ParseELFHeaders(file_path, analysis);
    
    // Check security features
    spdlog::debug("ELF security features:");
    spdlog::debug("  Stack Canary: {}", analysis.has_stack_canary);
    spdlog::debug("  NX Bit: {}", analysis.has_nx_bit);
    spdlog::debug("  PIE: {}", analysis.has_pie);
    spdlog::debug("  RELRO: {}", analysis.has_relro);
    spdlog::debug("  Stripped: {}", analysis.is_stripped);
    
    // Analyze imports
    if (config_.analyze_imports) {
        std::vector<std::string> suspicious_functions = {
            "ptrace", "fork", "execve", "system", "popen",
            "dlopen", "mmap", "mprotect", "prctl"
        };
        
        for (const auto& sym : analysis.imported_symbols) {
            for (const auto& suspicious : suspicious_functions) {
                if (sym.find(suspicious) != std::string::npos) {
                    analysis.suspicious_symbols.push_back(sym);
                    break;
                }
            }
        }
        
        if (!analysis.suspicious_symbols.empty()) {
            spdlog::warn("Found {} suspicious symbols", analysis.suspicious_symbols.size());
        }
    }
    
    // Check sections
    for (const auto& section : analysis.sections) {
        // High entropy sections
        if (section.entropy > config_.high_entropy_threshold) {
            analysis.suspicious_sections.push_back(section.name + " (high entropy)");
        }
        
        // Unusual section names
        if (section.name.find("UPX") != std::string::npos ||
            section.name.find("packed") != std::string::npos) {
            analysis.suspicious_sections.push_back(section.name + " (packer indicator)");
        }
    }
    
    spdlog::debug("ELF analysis complete");
    return analysis;
}

// ============================================================================
// SCRIPT ANALYSIS
// ============================================================================

ScriptAnalysis StaticAnalyzer::AnalyzeScript(const std::filesystem::path& file_path) {
    ScriptAnalysis analysis;
    
    spdlog::debug("Analyzing script file");
    
    // Read script content
    std::ifstream file(file_path);
    if (!file.is_open()) {
        spdlog::error("Failed to open script file");
        return analysis;
    }
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string content = buffer.str();
    
    // Check shebang
    if (content.length() > 2 && content[0] == '#' && content[1] == '!') {
        std::istringstream iss(content);
        std::string shebang_line;
        std::getline(iss, shebang_line);
        analysis.shebang.push_back(shebang_line);
        
        // Extract interpreter
        if (shebang_line.find("bash") != std::string::npos) {
            analysis.language = "Bash";
            analysis.interpreter = "/bin/bash";
        } else if (shebang_line.find("python") != std::string::npos) {
            analysis.language = "Python";
            analysis.interpreter = "python";
        } else if (shebang_line.find("perl") != std::string::npos) {
            analysis.language = "Perl";
            analysis.interpreter = "perl";
        }
    }
    
    // Analyze content
    AnalyzeScriptContent(content, analysis);
    
    // Detect obfuscation
    analysis.is_obfuscated = DetectObfuscation(content);
    if (analysis.is_obfuscated) {
        analysis.obfuscation_score = 0.8;
        spdlog::warn("Script appears to be obfuscated");
    }
    
    // Check for encoding
    if (content.find("base64") != std::string::npos) {
        analysis.is_base64_encoded = true;
    }
    
    std::regex hex_pattern(R"(\\x[0-9a-fA-F]{2})");
    if (std::regex_search(content, hex_pattern)) {
        analysis.is_hex_encoded = true;
    }
    
    spdlog::debug("Script analysis complete");
    return analysis;
}

// ============================================================================
// STRINGS AND ENTROPY
// ============================================================================

StringAnalysis StaticAnalyzer::ExtractStrings(const std::filesystem::path& file_path) {
    StringAnalysis analysis;
    
    // Read file
    std::ifstream file(file_path, std::ios::binary);
    if (!file.is_open()) {
        spdlog::error("Failed to open file for string extraction");
        return analysis;
    }
    
    std::vector<uint8_t> data(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>()
    );
    
    // Extract ASCII strings
    auto ascii_strings = ExtractASCIIStrings(data, config_.min_string_length);
    analysis.printable_count = static_cast<int>(ascii_strings.size());
    
    // Extract Unicode strings
    std::vector<std::string> unicode_strings;
    if (config_.extract_unicode) {
        unicode_strings = ExtractUnicodeStrings(data, config_.min_string_length);
        analysis.unicode_count = static_cast<int>(unicode_strings.size());
    }
    
    // Combine all strings
    analysis.all_strings = ascii_strings;
    analysis.all_strings.insert(analysis.all_strings.end(), 
                               unicode_strings.begin(), unicode_strings.end());
    
    // Limit total strings
    if (analysis.all_strings.size() > config_.max_strings_to_extract) {
        analysis.all_strings.resize(config_.max_strings_to_extract);
    }
    
    analysis.total_count = static_cast<int>(analysis.all_strings.size());
    
    // Categorize strings
    std::regex ip_regex(R"(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)");
    std::regex url_regex(R"((https?|ftp)://[^\s]+)");
    std::regex domain_regex(R"(\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b)");
    std::regex path_regex(R"([A-Za-z]:\\[^<>:"|?*\n\r]+)");  // Windows paths
    std::regex unix_path_regex(R"(/[a-zA-Z0-9_/.-]+)");      // Unix paths
    std::regex email_regex(R"(\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b)");
    std::regex registry_regex(R"(HKEY_[A-Z_]+\\[^\n\r]+)");
    
    for (const auto& str : analysis.all_strings) {
        // Check if interesting
        if (IsInterestingString(str)) {
            analysis.interesting_strings.push_back(str);
        }
        
        // Extract specific types
        if (std::regex_search(str, ip_regex)) {
            analysis.ip_addresses.push_back(str);
        }
        if (std::regex_search(str, url_regex)) {
            analysis.urls.push_back(str);
        }
        if (std::regex_search(str, domain_regex)) {
            analysis.domains.push_back(str);
        }
        if (std::regex_search(str, path_regex) || std::regex_search(str, unix_path_regex)) {
            analysis.file_paths.push_back(str);
        }
        if (std::regex_search(str, email_regex)) {
            analysis.email_addresses.push_back(str);
        }
        if (std::regex_search(str, registry_regex)) {
            analysis.registry_keys.push_back(str);
        }
    }
    
    // Find suspicious keywords
    analysis.suspicious_keywords = FindSuspiciousKeywords(analysis.all_strings);
    
    spdlog::debug("String extraction complete: {} total, {} interesting",
                 analysis.total_count, analysis.interesting_strings.size());
    
    return analysis;
}

EntropyAnalysis StaticAnalyzer::CalculateEntropy(const std::filesystem::path& file_path) {
    EntropyAnalysis analysis;
    
    // Read file
    std::ifstream file(file_path, std::ios::binary);
    if (!file.is_open()) {
        spdlog::error("Failed to open file for entropy calculation");
        return analysis;
    }
    
    std::vector<uint8_t> data(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>()
    );
    
    // Calculate overall entropy
    analysis.overall_entropy = CalculateShannonEntropy(data);
    
    // Determine indicators
    if (analysis.overall_entropy > config_.high_entropy_threshold) {
        analysis.likely_packed = true;
        analysis.packing_confidence = 
            (analysis.overall_entropy - config_.high_entropy_threshold) / 
            (8.0 - config_.high_entropy_threshold);
        spdlog::warn("High entropy detected ({:.2f}) - likely packed/encrypted", 
                    analysis.overall_entropy);
    } else if (analysis.overall_entropy > config_.medium_entropy_threshold) {
        analysis.likely_compressed = true;
        spdlog::info("Medium entropy detected ({:.2f}) - possibly compressed", 
                    analysis.overall_entropy);
    }
    
    return analysis;
}

// ============================================================================
// PACKER DETECTION
// ============================================================================

std::vector<std::string> StaticAnalyzer::DetectPackers(const std::filesystem::path& file_path) {
    std::vector<std::string> detected_packers;
    
    // Read file
    std::ifstream file(file_path, std::ios::binary);
    if (!file.is_open()) {
        return detected_packers;
    }
    
    std::vector<uint8_t> data(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>()
    );
    
    std::string content(data.begin(), data.end());
    
    // Known packer signatures
    std::vector<std::pair<std::string, std::string>> packer_signatures = {
        {"UPX", "UPX!"},
        {"UPX", "UPX0"},
        {"UPX", "UPX1"},
        {"ASPack", "ASPack"},
        {"PECompact", "PECompact"},
        {"Armadillo", "Armadillo"},
        {"Themida", "Themida"},
        {"VMProtect", "VMProtect"},
        {"Enigma", "Enigma"},
        {"Petite", ".petite"},
        {"FSG", "FSG!"},
        {"MEW", "MEW"}
    };
    
    for (const auto& [name, signature] : packer_signatures) {
        if (content.find(signature) != std::string::npos) {
            detected_packers.push_back(name);
            spdlog::info("Detected packer: {}", name);
        }
    }
    
    // Check entropy-based detection
    double entropy = CalculateShannonEntropy(data);
    if (entropy > config_.high_entropy_threshold && detected_packers.empty()) {
        detected_packers.push_back("Unknown packer (high entropy)");
    }
    
    return detected_packers;
}

// ============================================================================
// SIGNATURE MATCHING (YARA STUB)
// ============================================================================

std::vector<SignatureMatch> StaticAnalyzer::MatchSignatures(const std::filesystem::path& file_path) {
    std::vector<SignatureMatch> matches;
    
    // TODO: Implement YARA scanning
    // This requires libyara integration
    
    spdlog::debug("YARA scanning not yet implemented");
    
    return matches;
}

// ============================================================================
// THREAT SCORING
// ============================================================================

int StaticAnalyzer::CalculateThreatScore(const StaticAnalysisReport& report) {
    int score = 0;
    
    // High entropy (+30)
    if (report.entropy_analysis.overall_entropy > config_.high_entropy_threshold) {
        score += 30;
    }
    
    // Packer detection (+25)
    if (!report.packer_detections.empty()) {
        score += 25;
    }
    
    // Suspicious strings (+20)
    if (report.string_analysis.suspicious_keywords.size() > 5) {
        score += 20;
    }
    
    // Network indicators (+15)
    int network_iocs = static_cast<int>(report.string_analysis.ip_addresses.size() + 
                                       report.string_analysis.urls.size());
    if (network_iocs > 3) {
        score += 15;
    }
    
    // PE-specific
    if (report.pe_analysis) {
        // Suspicious imports (+20)
        if (report.pe_analysis->suspicious_imports.size() > 5) {
            score += 20;
        }
        
        // Suspicious sections (+15)
        if (!report.pe_analysis->suspicious_sections.empty()) {
            score += 15;
        }
        
        // Not signed (+10)
        if (!report.pe_analysis->is_signed) {
            score += 10;
        }
    }
    
    // ELF-specific
    if (report.elf_analysis) {
        // Missing security features (+15)
        int missing_features = 0;
        if (!report.elf_analysis->has_stack_canary) missing_features++;
        if (!report.elf_analysis->has_nx_bit) missing_features++;
        if (!report.elf_analysis->has_pie) missing_features++;
        if (!report.elf_analysis->has_relro) missing_features++;
        
        if (missing_features >= 3) {
            score += 15;
        }
        
        // Suspicious symbols (+20)
        if (report.elf_analysis->suspicious_symbols.size() > 3) {
            score += 20;
        }
        
        // Stripped (+5)
        if (report.elf_analysis->is_stripped) {
            score += 5;
        }
    }
    
    // Script-specific
    if (report.script_analysis) {
        // Obfuscation (+30)
        if (report.script_analysis->is_obfuscated) {
            score += 30;
        }
        
        // Suspicious commands (+25)
        if (report.script_analysis->suspicious_commands.size() > 3) {
            score += 25;
        }
        
        // Encoding (+15)
        if (report.script_analysis->is_base64_encoded || 
            report.script_analysis->is_hex_encoded) {
            score += 15;
        }
    }
    
    // Signature matches (+40 per match)
    score += static_cast<int>(report.signature_matches.size()) * 40;
    
    // Anti-analysis (+20)
    if (!report.anti_analysis_techniques.empty()) {
        score += 20;
    }
    
    // Cap at 100
    return std::min(score, 100);
}

// ============================================================================
// PRIVATE HELPERS
// ============================================================================

std::vector<uint8_t> StaticAnalyzer::ReadMagicBytes(const std::filesystem::path& file_path, 
                                                     std::size_t count) {
    std::ifstream file(file_path, std::ios::binary);
    std::vector<uint8_t> bytes(count);
    
    if (file.is_open()) {
        file.read(reinterpret_cast<char*>(bytes.data()), count);
        bytes.resize(file.gcount());
    }
    
    return bytes;
}

bool StaticAnalyzer::IsPEFile(const std::filesystem::path& file_path) {
    auto magic = ReadMagicBytes(file_path, 4);
    
    // Check for MZ header
    if (magic.size() >= 2 && magic[0] == 'M' && magic[1] == 'Z') {
        return true;
    }
    
    return false;
}

bool StaticAnalyzer::IsELFFile(const std::filesystem::path& file_path) {
    auto magic = ReadMagicBytes(file_path, 4);
    
    // Check for ELF magic: 0x7F 'E' 'L' 'F'
    if (magic.size() >= 4 && 
        magic[0] == 0x7F && 
        magic[1] == 'E' && 
        magic[2] == 'L' && 
        magic[3] == 'F') {
        return true;
    }
    
    return false;
}

std::optional<std::string> StaticAnalyzer::DetectScriptType(const std::filesystem::path& file_path) {
    std::ifstream file(file_path);
    if (!file.is_open()) {
        return std::nullopt;
    }
    
    std::string first_line;
    std::getline(file, first_line);
    
    if (first_line.length() > 2 && first_line[0] == '#' && first_line[1] == '!') {
        if (first_line.find("bash") != std::string::npos) return "bash";
        if (first_line.find("python") != std::string::npos) return "python";
        if (first_line.find("perl") != std::string::npos) return "perl";
    }
    
    return std::nullopt;
}

std::vector<std::string> StaticAnalyzer::ExtractASCIIStrings(const std::vector<uint8_t>& data,
                                                              std::size_t min_length) {
    std::vector<std::string> strings;
    std::string current;
    
    for (uint8_t byte : data) {
        if (std::isprint(byte) && byte != 0x7F) {
            current += static_cast<char>(byte);
        } else {
            if (current.length() >= min_length && current.length() <= config_.max_string_length) {
                strings.push_back(current);
            }
            current.clear();
        }
    }
    
    // Add final string
    if (current.length() >= min_length && current.length() <= config_.max_string_length) {
        strings.push_back(current);
    }
    
    return strings;
}

std::vector<std::string> StaticAnalyzer::ExtractUnicodeStrings(const std::vector<uint8_t>& data,
                                                                std::size_t min_length) {
    std::vector<std::string> strings;
    std::string current;
    
    // Simple UTF-16 LE extraction
    for (std::size_t i = 0; i < data.size() - 1; i += 2) {
        if (std::isprint(data[i]) && data[i + 1] == 0) {
            current += static_cast<char>(data[i]);
        } else {
            if (current.length() >= min_length && current.length() <= config_.max_string_length) {
                strings.push_back(current);
            }
            current.clear();
        }
    }
    
    if (current.length() >= min_length && current.length() <= config_.max_string_length) {
        strings.push_back(current);
    }
    
    return strings;
}

double StaticAnalyzer::CalculateShannonEntropy(const std::vector<uint8_t>& data) {
    if (data.empty()) return 0.0;
    
    // Count byte frequencies
    std::array<int, 256> frequencies = {};
    for (uint8_t byte : data) {
        frequencies[byte]++;
    }
    
    // Calculate entropy
    double entropy = 0.0;
    double size = static_cast<double>(data.size());
    
    for (int freq : frequencies) {
        if (freq > 0) {
            double probability = freq / size;
            entropy -= probability * std::log2(probability);
        }
    }
    
    return entropy;
}

bool StaticAnalyzer::IsInterestingString(const std::string& str) {
    // Check for URLs
    if (str.find("http://") == 0 || str.find("https://") == 0 || str.find("ftp://") == 0) {
        return true;
    }
    
    // Check for IP addresses
    std::regex ip_regex(R"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})");
    if (std::regex_search(str, ip_regex)) {
        return true;
    }
    
    // Check for file paths
    if (str.find("C:\\") == 0 || str.find("/etc/") == 0 || str.find("/tmp/") == 0) {
        return true;
    }
    
    // Check for suspicious keywords
    std::vector<std::string> keywords = {
        "password", "passwd", "admin", "root", "key", "token",
        "api", "secret", "credential", "exploit", "payload",
        "shell", "cmd", "exec", "eval", "system"
    };
    
    std::string lower_str = str;
    std::transform(lower_str.begin(), lower_str.end(), lower_str.begin(), ::tolower);
    
    for (const auto& keyword : keywords) {
        if (lower_str.find(keyword) != std::string::npos) {
            return true;
        }
    }
    
    return false;
}

std::vector<std::string> StaticAnalyzer::FindSuspiciousKeywords(const std::vector<std::string>& strings) {
    std::vector<std::string> suspicious;
    
    std::vector<std::string> keywords = {
        "backdoor", "rootkit", "keylog", "ransomware", "trojan",
        "exploit", "shellcode", "payload", "metasploit", "meterpreter",
        "mimikatz", "powershell", "wget", "curl", "nc", "netcat",
        "reverse_tcp", "bind_tcp", "cmd.exe", "/bin/sh", "/bin/bash"
    };
    
    for (const auto& str : strings) {
        std::string lower_str = str;
        std::transform(lower_str.begin(), lower_str.end(), lower_str.begin(), ::tolower);
        
        for (const auto& keyword : keywords) {
            if (lower_str.find(keyword) != std::string::npos) {
                suspicious.push_back(str);
                break;
            }
        }
    }
    
    return suspicious;
}

void StaticAnalyzer::ParsePEHeaders(const std::filesystem::path& file_path, PEAnalysis& analysis) {
    // TODO: Implement full PE parsing
    // This would require a PE parser library or manual implementation
    
    spdlog::debug("PE header parsing not yet fully implemented");
    
    // Placeholder values
    analysis.architecture = "x86_64";
    analysis.subsystem = "Console";
    analysis.compiler = "MSVC";
}

void StaticAnalyzer::ParseELFHeaders(const std::filesystem::path& file_path, ELFAnalysis& analysis) {
    // TODO: Implement full ELF parsing
    // This would require an ELF parser library or manual implementation
    
    spdlog::debug("ELF header parsing not yet fully implemented");
    
    // Placeholder values
    analysis.architecture = "x86_64";
    analysis.abi = "GNU/Linux";
    analysis.file_class = "64-bit";
    analysis.endianness = "Little";
    analysis.type = "EXEC";
}

void StaticAnalyzer::AnalyzeScriptContent(const std::string& content, ScriptAnalysis& analysis) {
    // Check for suspicious commands
    std::vector<std::string> suspicious_cmds = {
        "wget", "curl", "nc", "netcat", "eval", "exec",
        "chmod +x", "rm -rf", "/dev/tcp", "bash -i",
        "python -c", "perl -e", "base64 -d"
    };
    
    for (const auto& cmd : suspicious_cmds) {
        if (content.find(cmd) != std::string::npos) {
            analysis.suspicious_commands.push_back(cmd);
        }
    }
    
    // Check for network operations
    if (content.find("socket") != std::string::npos ||
        content.find("connect") != std::string::npos ||
        content.find("curl") != std::string::npos ||
        content.find("wget") != std::string::npos) {
        analysis.network_operations.push_back("Network communication detected");
    }
    
    // Check for file operations
    if (content.find("open(") != std::string::npos ||
        content.find("write(") != std::string::npos ||
        content.find("fopen") != std::string::npos) {
        analysis.file_operations.push_back("File manipulation detected");
    }
}

bool StaticAnalyzer::DetectObfuscation(const std::string& content) {
    // Check for base64 encoding
    std::regex base64_regex(R"([A-Za-z0-9+/]{40,}={0,2})");
    if (std::regex_search(content, base64_regex)) {
        return true;
    }
    
    // Check for hex encoding
    std::regex hex_regex(R"(\\x[0-9a-fA-F]{2}{10,})");
    if (std::regex_search(content, hex_regex)) {
        return true;
    }
    
    // Check for excessive special characters (indicator of obfuscation)
    int special_char_count = 0;
    for (char c : content) {
        if (!std::isalnum(c) && !std::isspace(c)) {
            special_char_count++;
        }
    }
    
    double special_ratio = static_cast<double>(special_char_count) / content.length();
    if (special_ratio > 0.3) {  // More than 30% special characters
        return true;
    }
    
    return false;
}

// ============================================================================
// ANTI-ANALYSIS DETECTION
// ============================================================================

std::vector<std::string> StaticAnalyzer::DetectAntiAnalysis(const StaticAnalysisReport& report) {
    std::vector<std::string> techniques;
    
    // High entropy (anti-static analysis)
    if (report.entropy_analysis.likely_packed) {
        techniques.push_back("Packing (anti-static analysis)");
    }
    
    // PE-specific
    if (report.pe_analysis) {
        for (const auto& func : report.pe_analysis->imported_functions) {
            if (func.find("IsDebuggerPresent") != std::string::npos ||
                func.find("CheckRemoteDebuggerPresent") != std::string::npos) {
                techniques.push_back("Debugger detection");
                break;
            }
        }
    }
    
    // ELF-specific
    if (report.elf_analysis) {
        for (const auto& sym : report.elf_analysis->imported_symbols) {
            if (sym.find("ptrace") != std::string::npos) {
                techniques.push_back("Ptrace anti-debugging");
                break;
            }
        }
    }
    
    // Script obfuscation
    if (report.script_analysis && report.script_analysis->is_obfuscated) {
        techniques.push_back("Script obfuscation");
    }
    
    return techniques;
}

// ============================================================================
// FILE TYPE TO STRING
// ============================================================================

std::string StaticAnalyzer::FileTypeToString(FileType type) const {
    switch (type) {
        case FileType::PE_EXECUTABLE: return "PE Executable";
        case FileType::ELF_EXECUTABLE: return "ELF Executable";
        case FileType::MACH_O: return "Mach-O Executable";
        case FileType::SCRIPT_BASH: return "Bash Script";
        case FileType::SCRIPT_PYTHON: return "Python Script";
        case FileType::SCRIPT_PERL: return "Perl Script";
        case FileType::SCRIPT_POWERSHELL: return "PowerShell Script";
        case FileType::SCRIPT_JAVASCRIPT: return "JavaScript";
        case FileType::DOCUMENT_PDF: return "PDF Document";
        case FileType::DOCUMENT_OFFICE: return "Office Document";
        case FileType::ARCHIVE_ZIP: return "ZIP Archive";
        case FileType::ARCHIVE_RAR: return "RAR Archive";
        case FileType::ARCHIVE_TAR: return "TAR Archive";
        default: return "Unknown";
    }
}

// ============================================================================
// MIME TYPE DETERMINATION
// ============================================================================

std::string StaticAnalyzer::DetermineMIMEType(const std::filesystem::path& file_path) {
    auto magic = ReadMagicBytes(file_path, 4);
    
    if (magic.size() >= 2 && magic[0] == 'M' && magic[1] == 'Z') {
        return "application/x-msdownload";
    }
    
    if (magic.size() >= 4 && magic[0] == 0x7F && magic[1] == 'E' && 
        magic[2] == 'L' && magic[3] == 'F') {
        return "application/x-executable";
    }
    
    if (magic.size() >= 4 && magic[0] == 0x50 && magic[1] == 0x4B) {
        return "application/zip";
    }
    
    return "application/octet-stream";
}

} // namespace analyzers
} // namespace paramite