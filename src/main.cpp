/**
 * @file main.cpp
 * @brief Paramite Malware Analysis Engine - Command-line interface
 * 
 * Entry point for the Paramite malware analyzer. Provides CLI interface for
 * static and dynamic malware analysis with support for Docker sandbox execution,
 * comprehensive reporting (HTML/JSON), and automated threat scoring.
 * 
 * @author Paramite Development Team
 * @date 2025
 */

#include <CLI/CLI.hpp>
#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>

#include "paramite/core/analysis_engine.hpp"
#include "paramite/reporters/html_reporter.hpp"
#include "paramite/reporters/json_reporter.hpp"

#include <iostream>
#include <fstream>
#include <iomanip>
#include <chrono>
#include <ctime>

using json = nlohmann::json;

/*******************************************************************************
 * UI and Display Functions
 ******************************************************************************/


void PrintBanner() {
    std::cout << R"(
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   ██████╗  █████╗ ██████╗  █████╗ ███╗   ███╗██╗████████╗███████╗
║   ██╔══██╗██╔══██╗██╔══██╗██╔══██╗████╗ ████║██║╚══██╔══╝██╔════╝
║   ██████╔╝███████║██████╔╝███████║██╔████╔██║██║   ██║   █████╗  
║   ██╔═══╝ ██╔══██║██╔══██╗██╔══██║██║╚██╔╝██║██║   ██║   ██╔══╝  
║   ██║     ██║  ██║██║  ██║██║  ██║██║ ╚═╝ ██║██║   ██║   ███████╗
║   ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝   ╚═╝   ╚══════╝
║                                                               ║
║              Oddworld-Themed Malware Behavior Analyzer        ║
║                              v1.0.0                           ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
)" << std::endl;
}


std::string FormatFileSize(std::size_t bytes) {
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


void PrintConsoleSummary(const paramite::core::AnalysisResult& result) {
    if (!result.sample_metadata.has_value()) {
        std::cout << "[ERROR] No sample metadata available\n";
        return;
    }
    
    auto& metadata = result.sample_metadata.value();
    
    std::cout << "\n";
    std::cout << "╔═══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                     ANALYSIS SUMMARY                          ║\n";
    std::cout << "╚═══════════════════════════════════════════════════════════════╝\n";
    
    // Display filename (truncate if too long)
    std::string filename = metadata.filename;
    if (filename.length() > 50) {
        filename = filename.substr(0, 47) + "...";
    }
    std::cout << "║  Sample: " << filename << std::string(53 - filename.length(), ' ') << "║\n";
    
    // Display SHA-256 hash (truncated for readability)
    std::cout << "║  SHA-256: " << metadata.sha256.substr(0, 50) << "...║\n";
    
    // Display file type
    std::string file_type = metadata.file_type;
    if (file_type.length() > 50) {
        file_type = file_type.substr(0, 47) + "...";
    }
    std::cout << "║  Type: " << file_type << std::string(56 - file_type.length(), ' ') << "║\n";
    
    // Display file size
    std::string size_str = FormatFileSize(metadata.file_size);
    std::cout << "║  Size: " << size_str << std::string(56 - size_str.length(), ' ') << "║\n";
    
    // Display entropy with automatic classification
    std::cout << "║  Entropy: " << std::fixed << std::setprecision(4) << metadata.entropy << " / 8.0";
    std::string entropy_status = metadata.entropy > 7.5 ? "[CRITICAL] Packed/Encrypted" :
                                 metadata.entropy > 7.0 ? "[HIGH] Compressed" :
                                 metadata.entropy > 6.0 ? "[MEDIUM] Structured" : "[NORMAL] Plain";
    std::cout << std::string(41 - entropy_status.length(), ' ') << "║\n";
    std::cout << "║           " << entropy_status << std::string(52 - entropy_status.length(), ' ') << "║\n";
    
    // Display strings count
    std::string strings_count = std::to_string(metadata.interesting_strings.size());
    std::cout << "║  Strings: " << strings_count << std::string(53 - strings_count.length(), ' ') << "║\n";
    
    // Display sandbox execution status
    if (result.sandbox_executed) {
        std::string sandbox_status = result.sandbox_timeout ? "[TIMEOUT]" :
                                    result.sandbox_crashed ? "[CRASHED]" : "[COMPLETED]";
        std::cout << "║  Sandbox: " << sandbox_status << std::string(53 - sandbox_status.length(), ' ') << "║\n";
    }
    
    std::cout << "╚═══════════════════════════════════════════════════════════════╝\n";
    
    // Next steps guidance
    std::cout << "\n";
    std::cout << "[+] Analysis complete! Reports generated.\n";
    if (!result.sandbox_executed) {
        std::cout << "[i] Next step: Deploy to sandbox for behavioral analysis\n";
    }
}

/*******************************************************************************
 * Main Application Entry Point
 ******************************************************************************/

int main(int argc, char** argv) {
    PrintBanner();

    // Configure CLI parser
    CLI::App app{"Paramite Malware Analyzer"};
    app.footer("\nOddworld Industries - Making malware analysis fun since 2025!");
    
    std::string sample_path;
    std::string output_dir = "./reports";
    bool verbose = false;
    bool json_only = false;
    
    app.add_option("sample", sample_path, "Path to malware sample to analyze")
        ->required()
        ->check(CLI::ExistingFile);
    
    app.add_option("-o,--output", output_dir, "Output directory for reports")
        ->default_val("./reports");
    
    app.add_flag("-v,--verbose", verbose, "Enable verbose logging");
    app.add_flag("--json-only", json_only, "Generate JSON report only (no HTML)");
    
    bool enable_sandbox = false;
    int sandbox_timeout = 300;

    app.add_flag("--sandbox", enable_sandbox, 
                 "Execute sample in isolated Docker sandbox (RUNS MALWARE!)");
    app.add_option("--timeout", sandbox_timeout, "Sandbox execution timeout in seconds")
        ->default_val(300);

    CLI11_PARSE(app, argc, argv);

    // Configure logging level and format
    if (verbose) {
        spdlog::set_level(spdlog::level::debug);
        spdlog::debug("[DEBUG] Verbose logging enabled");
    } else {
        spdlog::set_level(spdlog::level::info);
    }
    spdlog::set_pattern("[%H:%M:%S] [%^%l%$] %v");

    try {
        // Ensure output directory exists
        std::filesystem::create_directories(output_dir);
        
        // Initialize Analysis Engine
        spdlog::info("[INIT] Initializing Paramite Analysis Engine...");
        
        paramite::core::AnalysisEngine engine;
        if (!engine.Initialize()) {
            spdlog::error("[ERROR] Failed to initialize analysis engine");
            return 1;
        }

        // Configure analysis pipeline
        paramite::core::AnalysisConfig config;
        config.sample_path = sample_path;
        config.output_directory = output_dir;
        config.perform_static_analysis = true;
        config.perform_dynamic_analysis = enable_sandbox;
        config.perform_behavior_analysis = enable_sandbox;
        config.extract_iocs = true;
        config.execution_timeout = std::chrono::seconds(sandbox_timeout);
        config.monitor_syscalls = enable_sandbox;
        config.monitor_network = enable_sandbox;
        config.monitor_filesystem = enable_sandbox;
        config.monitor_processes = enable_sandbox;
        config.generate_json_report = true;
        config.generate_html_report = !json_only;

        // Execute analysis pipeline
        spdlog::info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        spdlog::info("[START] Processing sample: {}", sample_path);
        
        auto result = engine.Analyze(config);
        
        if (!result.status.is_complete) {
            spdlog::error("[FAIL] Analysis failed");
            if (result.status.has_error) {
                spdlog::error("[ERROR] {}", result.status.error_message);
            }
            return 1;
        }

        spdlog::info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        spdlog::info("[DONE] Analysis complete!");

        // Generate reports
        if (!result.sample_metadata.has_value()) {
            spdlog::error("[ERROR] No sample metadata - cannot generate reports");
            return 1;
        }
        
        auto report_base = std::filesystem::path(output_dir) / result.sample_metadata->sha256;
        
        // JSON Report Generation
        if (config.generate_json_report) {
            paramite::reporters::JsonReporter json_reporter;
            auto json_path = json_reporter.GenerateReport(result);
            if (!json_path.empty()) {
                spdlog::info("[REPORT] JSON report saved: {}", json_path.string());
            } else {
                spdlog::warn("[WARN] Failed to generate JSON report");
            }
        }
        
        // HTML Report Generation
        if (config.generate_html_report) {
            paramite::reporters::HtmlReporter html_reporter;
            auto html_path = html_reporter.GenerateReport(result);
            if (!html_path.empty()) {
                spdlog::info("[REPORT] HTML report saved: {}", html_path.string());
            } else {
                spdlog::warn("[WARN] Failed to generate HTML report");
            }
        }

        // Display console summary
        PrintConsoleSummary(result);

        // Sandbox execution summary (if applicable)
        if (result.sandbox_executed) {
            std::cout << "\n";
            spdlog::info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            spdlog::info("[SANDBOX] Dynamic Analysis Results");
            spdlog::info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            
            std::string status_str = result.sandbox_timeout ? "[TIMEOUT] Execution timeout reached" :
                                    result.sandbox_crashed ? "[CRASH] Sample crashed" :
                                    "[OK] Completed successfully";
            
            spdlog::info("Status: {}", status_str);
            spdlog::info("Exit code: {}", result.sandbox_exit_code);
            spdlog::info("Duration: {} ms", result.sandbox_duration_ms);
            
            // Display collected artifacts
            for (const auto& artifact : result.sandbox_artifacts) {
                spdlog::info("[ARTIFACT] {}", artifact);
            }
            
            spdlog::info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        }

        return 0;

    } catch (const CLI::ParseError& e) {
        return app.exit(e);
    } catch (const std::filesystem::filesystem_error& e) {
        spdlog::error("[ERROR] Filesystem error: {}", e.what());
        return 1;
    } catch (const std::exception& e) {
        spdlog::error("[ERROR] Fatal error: {}", e.what());
        return 1;
    } catch (...) {
        spdlog::error("[ERROR] Unknown error occurred");
        return 1;
    }
}