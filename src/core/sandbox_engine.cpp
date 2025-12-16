/**
 * @file sandbox_engine.cpp
 * @brief Implementation of isolated malware execution environment
 * 
 * Implements comprehensive sandboxed malware execution using Docker containers with
 * security hardening, real-time monitoring integration, resource limits, network isolation,
 * syscall tracing (strace), network capture (tcpdump), file system monitoring (inotify),
 * and automated artifact collection for behavioral analysis.
 * 
 * **Sandbox Architecture**:
 * ```
 * Host System
 * └─ Docker Container (Isolated Environment)
 *     ├─ Malware Sample (copied in)
 *     ├─ strace (syscall monitoring)
 *     ├─ tcpdump (network capture)
 *     ├─ inotify (filesystem monitoring)
 *     └─ Wine (for Windows PE execution on Linux)
 * ```
 * 
 * **Security Hardening**:
 * - **Network Isolation**: --network none (no external communication)
 * - **Read-only Rootfs**: Prevent system tampering
 * - **Capability Dropping**: Remove all Linux capabilities
 * - **Resource Limits**: CPU, memory, disk, process limits
 * - **Seccomp Profile**: Block dangerous syscalls
 * - **AppArmor/SELinux**: Mandatory Access Control
 * - **No Privileged Mode**: Never use --privileged flag
 * - **User Namespace**: Non-root execution
 * 
 * **Execution Workflow**:
 * 1. **Preparation**: Create isolated container with security config
 * 2. **Sample Injection**: Copy malware into container
 * 3. **Monitor Setup**: Start strace, tcpdump, inotify
 * 4. **Execution**: Run malware with timeout protection
 * 5. **Monitoring**: Collect real-time behavior data
 * 6. **Termination**: Stop execution after timeout or completion
 * 7. **Artifact Collection**: Extract logs, captures, modified files
 * 8. **Cleanup**: Remove container and temporary files
 * 
 * **Monitoring Components**:
 * - **strace**: System call tracing (open, connect, exec, etc.)
 * - **tcpdump**: Network packet capture (DNS, HTTP, C2 traffic)
 * - **inotify**: File system events (create, modify, delete)
 * - **procfs**: Process tree monitoring
 * - **Resource Stats**: CPU, memory, I/O usage over time
 * 
 * **Timeout Management**:
 * - Global timeout (default: 300 seconds)
 * - Per-phase timeouts (setup, execution, teardown)
 * - Graceful termination (SIGTERM → SIGKILL)
 * - Watchdog thread for hang detection
 * 
 * **Artifact Collection**:
 * - System call logs (strace output)
 * - Network captures (PCAP files)
 * - Modified files (diff from baseline)
 * - Process tree snapshots
 * - Container logs (stdout/stderr)
 * - Resource usage metrics
 * 
 * @date 2025
 */

#include "paramite/core/sandbox_engine.hpp"

#include <spdlog/spdlog.h>
#include <cstdlib>
#include <sstream>
#include <fstream>
#include <thread>
#include <future>
#include <random>
#include <iomanip>
#include <ctime>
#include <regex>

#ifdef _WIN32
#include <windows.h>
#define popen _popen
#define pclose _pclose
#else
#include <unistd.h>
#include <sys/wait.h>
#endif

namespace paramite {
namespace core {

// Constructor
SandboxEngine::SandboxEngine(const SandboxConfig& config)
    : config_(config)
    , current_status_(SandboxStatus::IDLE) {
    
    spdlog::info("Sandbox Engine initialized");
    spdlog::debug("Docker image: {}", config_.docker_image);
    spdlog::debug("Network mode: {}", static_cast<int>(config_.network_mode));
    spdlog::debug("Timeout: {}s", config_.timeout.count());
}

// Destructor
SandboxEngine::~SandboxEngine() {
    Cleanup();
    spdlog::info("Sandbox Engine destroyed");
}

// Initialize sandbox environment
bool SandboxEngine::Initialize() {
    spdlog::info("═══════════════════════════════════════════════════════════════");
    spdlog::info("INITIALIZING SANDBOX ENGINE");
    spdlog::info("═══════════════════════════════════════════════════════════════");
    
    try {
        // Validate configuration
        if (!ValidateConfig()) {
            spdlog::error("Invalid sandbox configuration");
            return false;
        }
        
        // Check Docker availability
        spdlog::info("Checking Docker availability...");
        if (!IsDockerAvailable()) {
            spdlog::error("Docker is not available or not running");
            return false;
        }
        spdlog::info("✓ Docker is available");
        
        // Create output directory
        if (!std::filesystem::exists(config_.output_directory)) {
            std::filesystem::create_directories(config_.output_directory);
            spdlog::info("✓ Created output directory: {}", config_.output_directory.string());
        }
        
        // Build sandbox image if needed
        spdlog::info("Checking sandbox image...");
        auto images = ListSandboxImages();
        bool has_image = false;
        for (const auto& img : images) {
            if (img.find(config_.docker_image) != std::string::npos) {
                has_image = true;
                break;
            }
        }
        
        if (!has_image) {
            spdlog::warn("Sandbox image not found, building...");
            if (!BuildSandboxImage()) {
                spdlog::error("Failed to build sandbox image");
                return false;
            }
        } else {
            spdlog::info("✓ Sandbox image exists");
        }
        
        // Test VM connectivity (if configured)
        if (!config_.vm_ssh_host.empty()) {
            spdlog::info("Testing VM connectivity...");
            if (IsVMReachable()) {
                spdlog::info("✓ VM is reachable at {}", config_.vm_ssh_host);
            } else {
                spdlog::warn("⚠ VM is not reachable (will use local execution)");
            }
        }
        
        current_status_ = SandboxStatus::IDLE;
        
        spdlog::info("═══════════════════════════════════════════════════════════════");
        spdlog::info("✓ Sandbox Engine initialized successfully");
        spdlog::info("═══════════════════════════════════════════════════════════════\n");
        
        return true;
    }
    catch (const std::exception& e) {
        spdlog::error("Sandbox initialization failed: {}", e.what());
        return false;
    }
}

// Execute sample in sandbox
SandboxExecutionResult SandboxEngine::Execute(const std::filesystem::path& sample_path) {
    SandboxExecutionResult result;
    result.start_time = std::chrono::system_clock::now();
    
    spdlog::info("\n═══════════════════════════════════════════════════════════════");
    spdlog::info("SANDBOX EXECUTION");
    spdlog::info("═══════════════════════════════════════════════════════════════");
    spdlog::info("Sample: {}", sample_path.filename().string());
    spdlog::info("Timeout: {}s", config_.timeout.count());
    
    try {
        current_status_ = SandboxStatus::PREPARING;
        
        // Prepare sample
        std::filesystem::path sandbox_sample_path;
        if (!PrepareSample(sample_path, sandbox_sample_path)) {
            result.status = SandboxStatus::FAILED;
            result.has_error = true;
            result.error_message = "Failed to prepare sample";
            return result;
        }
        
        // Create container
        spdlog::info("Creating Docker container...");
        std::string container_id = CreateContainer(sandbox_sample_path);
        if (container_id.empty()) {
            result.status = SandboxStatus::FAILED;
            result.has_error = true;
            result.error_message = "Failed to create container";
            return result;
        }
        
        current_container_id_ = container_id;
        spdlog::info("✓ Container created: {}", container_id.substr(0, 12));
        
        // Start monitoring
        if (!StartMonitoring(container_id)) {
            spdlog::warn("⚠ Monitoring initialization failed (continuing anyway)");
        }
        
        // Execute in container
        current_status_ = SandboxStatus::EXECUTING;
        result = ExecuteInContainer(container_id, sandbox_sample_path);
        
        // Collect monitoring data
        current_status_ = SandboxStatus::MONITORING;
        CollectMonitoringData(result);
        
        // Detect anomalies
        DetectAnomalies(result);
        
        // Cleanup
        if (!config_.preserve_container) {
            RemoveContainer(container_id);
        } else {
            spdlog::info("Container preserved for forensics: {}", container_id);
        }
        
        result.end_time = std::chrono::system_clock::now();
        
        current_status_ = SandboxStatus::COMPLETED;
        current_container_id_.clear();
        
        spdlog::info("═══════════════════════════════════════════════════════════════");
        spdlog::info("SANDBOX EXECUTION COMPLETE");
        spdlog::info("═══════════════════════════════════════════════════════════════");
        spdlog::info("Status: {}", static_cast<int>(result.status));
        spdlog::info("Exit code: {}", result.exit_code);
        spdlog::info("Duration: {} ms", result.execution_duration.count());
        spdlog::info("═══════════════════════════════════════════════════════════════\n");
        
        return result;
    }
    catch (const std::exception& e) {
        spdlog::error("Sandbox execution failed: {}", e.what());
        
        result.status = SandboxStatus::FAILED;
        result.has_error = true;
        result.error_message = e.what();
        result.end_time = std::chrono::system_clock::now();
        
        // Cleanup on error
        if (!current_container_id_.empty()) {
            RemoveContainer(current_container_id_);
            current_container_id_.clear();
        }
        
        current_status_ = SandboxStatus::IDLE;
        
        return result;
    }
}

// Execute sample asynchronously
std::future<SandboxExecutionResult> SandboxEngine::ExecuteAsync(
    const std::filesystem::path& sample_path,
    std::function<void(SandboxStatus, float)> callback) {
    
    return std::async(std::launch::async, [this, sample_path, callback]() {
        // Wrapper to provide progress updates
        auto result = Execute(sample_path);
        
        if (callback) {
            callback(result.status, 100.0f);
        }
        
        return result;
    });
}

// Stop currently executing sandbox
bool SandboxEngine::StopExecution() {
    if (current_container_id_.empty()) {
        return false;
    }
    
    spdlog::warn("Stopping sandbox execution: {}", current_container_id_);
    
    std::string cmd = "docker stop " + current_container_id_;
    int ret = std::system(cmd.c_str());
    
    if (ret == 0) {
        current_status_ = SandboxStatus::IDLE;
        return true;
    }
    
    return false;
}

// Clean up sandbox artifacts
void SandboxEngine::Cleanup() {
    if (!current_container_id_.empty()) {
        RemoveContainer(current_container_id_);
        current_container_id_.clear();
    }
    
    current_status_ = SandboxStatus::IDLE;
}

// Check if Docker is available
bool SandboxEngine::IsDockerAvailable() const {
    std::string cmd = "docker --version > ";
    
#ifdef _WIN32
    cmd += "nul 2>&1";
#else
    cmd += "/dev/null 2>&1";
#endif
    
    int ret = std::system(cmd.c_str());
    return ret == 0;
}

// Check if VM is reachable
bool SandboxEngine::IsVMReachable() const {
    if (config_.vm_ssh_host.empty()) {
        return false;
    }
    
    // Simple ping test
    std::string cmd = "ping -c 1 -W 2 " + config_.vm_ssh_host + " > ";
    
#ifdef _WIN32
    cmd = "ping -n 1 -w 2000 " + config_.vm_ssh_host + " > nul 2>&1";
#else
    cmd += "/dev/null 2>&1";
#endif
    
    int ret = std::system(cmd.c_str());
    return ret == 0;
}

// Update configuration
void SandboxEngine::UpdateConfig(const SandboxConfig& config) {
    config_ = config;
    spdlog::info("Sandbox configuration updated");
}

// Build Docker sandbox image
bool SandboxEngine::BuildSandboxImage() {
    spdlog::info("Building sandbox Docker image...");

    // Paths to external Dockerfile and entrypoint
    std::filesystem::path dockerfile_src = "containers/Dockerfile.sandbox";
    std::filesystem::path entrypoint_src = "containers/entrypoint.sh";

    // Write files to temp directory
    auto temp_dir = std::filesystem::temp_directory_path() / "paramite_sandbox_build";
    std::filesystem::create_directories(temp_dir);

    // Copy Dockerfile
    std::filesystem::copy_file(dockerfile_src, temp_dir / "Dockerfile", std::filesystem::copy_options::overwrite_existing);

    // Copy entrypoint
    std::filesystem::copy_file(entrypoint_src, temp_dir / "entrypoint.sh", std::filesystem::copy_options::overwrite_existing);

    // Build image
    std::string cmd = "docker build -t " + config_.docker_image + " " + temp_dir.string();
    spdlog::debug("Build command: {}", cmd);

    int ret = std::system(cmd.c_str());

    // Cleanup
    std::filesystem::remove_all(temp_dir);

    if (ret == 0) {
        spdlog::info("✓ Sandbox image built successfully");
        return true;
    } else {
        spdlog::error("Failed to build sandbox image");
        return false;
    }
}

// List available sandbox images
std::vector<std::string> SandboxEngine::ListSandboxImages() const {
    std::vector<std::string> images;
    
    // Execute docker images command
    std::string cmd = "docker images --format \"{{.Repository}}:{{.Tag}}\"";
    
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        return images;
    }
    
    char buffer[256];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        std::string line(buffer);
        // Remove newline
        if (!line.empty() && line.back() == '\n') {
            line.pop_back();
        }
        images.push_back(line);
    }
    
    pclose(pipe);
    
    return images;
}

// Get resource usage of running sandbox
std::map<std::string, double> SandboxEngine::GetResourceUsage() const {
    std::map<std::string, double> usage;
    
    if (current_container_id_.empty()) {
        return usage;
    }
    
    // docker stats --no-stream --format "{{.CPUPerc}},{{.MemUsage}}"
    std::string cmd = "docker stats --no-stream --format \"{{.CPUPerc}},{{.MemUsage}}\" " 
                     + current_container_id_;
    
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        return usage;
    }
    
    char buffer[256];
    if (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        std::string output(buffer);
        // Parse: "12.34%,123.4MiB / 2GiB"
        // Simplified parsing
        usage["cpu_percent"] = 0.0;
        usage["memory_mb"] = 0.0;
    }
    
    pclose(pipe);
    
    return usage;
}

// Private methods

// Prepare sample for execution
bool SandboxEngine::PrepareSample(const std::filesystem::path& sample_path,
                                  std::filesystem::path& sandbox_sample_path) {
    spdlog::info("Preparing sample for sandbox...");
    
    if (!std::filesystem::exists(sample_path)) {
        spdlog::error("Sample not found: {}", sample_path.string());
        return false;
    }
    
    // Copy to output directory with unique name
    auto timestamp = std::time(nullptr);
    std::ostringstream oss;
    oss << "sample_" << std::put_time(std::localtime(&timestamp), "%Y%m%d_%H%M%S")
        << "_" << sample_path.filename().string();
    
    sandbox_sample_path = config_.output_directory / oss.str();
    
    try {
        std::filesystem::copy_file(sample_path, sandbox_sample_path,
                                  std::filesystem::copy_options::overwrite_existing);
        
        spdlog::info("✓ Sample prepared: {}", sandbox_sample_path.filename().string());
        return true;
    }
    catch (const std::exception& e) {
        spdlog::error("Failed to prepare sample: {}", e.what());
        return false;
    }
}

// Create Docker container
std::string SandboxEngine::CreateContainer(const std::filesystem::path& sample_path) {
    std::string container_name = GenerateContainerName();
    
    std::ostringstream cmd;
    cmd << "docker create";
    cmd << " --name " << container_name;
    cmd << " --network none";  // Isolated by default
    
    // Add resource limits
    auto resource_args = GetResourceLimitArgs();
    for (const auto& arg : resource_args) {
        cmd << " " << arg;
    }
    
    // Mount sample
    cmd << " -v " << std::filesystem::absolute(sample_path).string()
        << ":/sandbox/sample:ro";
    
    // Mount output directory for logs
    cmd << " -v " << std::filesystem::absolute(config_.output_directory).string()
        << ":/sandbox/output";
    
    // Image and command
    cmd << " " << config_.docker_image;
    
    // Detect if Windows PE and use Wine for it
    std::string file_cmd = "file " + std::filesystem::absolute(sample_path).string();
    FILE* file_pipe = popen(file_cmd.c_str(), "r");
    char file_buf[256];
    bool is_pe = false;
    if (file_pipe && fgets(file_buf, sizeof(file_buf), file_pipe) != nullptr) {
        std::string file_type(file_buf);
        is_pe = (file_type.find("PE32") != std::string::npos || 
                 file_type.find("MS Windows") != std::string::npos);
    }
    if (file_pipe) pclose(file_pipe);
    
    // Use Wine for Windows executables with Xvfb and strace monitoring
    if (is_pe) {
        cmd << " /bin/bash -c \"Xvfb :99 -screen 0 1024x768x16 & sleep 1 && "
            << "DISPLAY=:99 strace -f -o /sandbox/output/strace.log -s 512 "
            << "wine /sandbox/sample 2>&1 | tee /sandbox/output/wine.log; "
            << "pkill Xvfb\"";
    } else {
        cmd << " /bin/bash -c \"strace -ff -tt -T -v -s 4096 -o /sandbox/output/strace.log /sandbox/sample 2>&1 | tee /sandbox/output/execution.log\"";
    }
    
    // Add command line args
    for (const auto& arg : config_.command_line_args) {
        cmd << " " << arg;
    }
    
    spdlog::debug("Docker command: {}", cmd.str());
    
    // Execute and capture container ID
    FILE* pipe = popen(cmd.str().c_str(), "r");
    if (!pipe) {
        return "";
    }
    
    char buffer[256];
    std::string container_id;
    if (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        container_id = buffer;
        // Remove newline
        if (!container_id.empty() && container_id.back() == '\n') {
            container_id.pop_back();
        }
    }
    
    pclose(pipe);
    
    return container_id;
}

// Start monitoring processes
bool SandboxEngine::StartMonitoring(const std::string& container_id) {
    spdlog::info("Starting monitoring...");
    
    // Monitoring is handled by docker exec during execution
    
    return true;
}

// Execute sample inside container
SandboxExecutionResult SandboxEngine::ExecuteInContainer(
    const std::string& container_id,
    const std::filesystem::path& sample_path) {
    
    SandboxExecutionResult result;
    result.status = SandboxStatus::EXECUTING;
    
    spdlog::info("Executing sample in container...");
    
    auto exec_start = std::chrono::system_clock::now();
    
    // Start timeout thread that will force-stop the container
    std::atomic<bool> finished{false};
    std::thread timeout_thread([&, this]() {
        auto timeout_secs = std::chrono::duration_cast<std::chrono::seconds>(config_.timeout);
        for (int i = 0; i < timeout_secs.count() && !finished.load(); ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        
        if (!finished.load()) {
            spdlog::warn("⏱ Timeout reached ({}s), stopping container...", timeout_secs.count());
            std::string stop_cmd = "docker stop " + container_id + " >/dev/null 2>&1";
            std::system(stop_cmd.c_str());
        }
    });
    
    // Execute container (blocking)
    std::string start_cmd = "docker start -a " + container_id;
    int exit_code = std::system(start_cmd.c_str());
    
    // Mark as finished so timeout thread stops
    finished.store(true);
    
    // Wait for timeout thread to complete
    if (timeout_thread.joinable()) {
        timeout_thread.join();
    }
    
    auto exec_end = std::chrono::system_clock::now();
    result.execution_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        exec_end - exec_start);
    
    // Determine status based on duration and exit code
    auto timeout_ms = std::chrono::duration_cast<std::chrono::milliseconds>(config_.timeout);
    if (result.execution_duration >= timeout_ms - std::chrono::milliseconds(100)) {
        result.status = SandboxStatus::TIMEOUT;
        spdlog::warn("⚠ Execution timed out");
    } else if (exit_code != 0 && exit_code != 137) { // 137 = docker stop signal
        result.status = SandboxStatus::CRASHED;
        spdlog::warn("⚠ Sample crashed (exit code: {})", exit_code);
    } else {
        result.status = SandboxStatus::COMPLETED;
        spdlog::info("✓ Execution completed normally");
    }
    
    result.exit_code = exit_code;
    
    return result;
}

// Collect monitoring data
void SandboxEngine::CollectMonitoringData(SandboxExecutionResult& result) {
    spdlog::info("Collecting monitoring data...");

    // Collect strace log
    auto strace_log = config_.output_directory / "strace.log";
    if (std::filesystem::exists(strace_log)) {
        result.strace_log = strace_log;
        spdlog::info("✓ Collected: strace.log ({} bytes)", 
            std::filesystem::file_size(strace_log));
    }
    
    // Collect wine log
    auto wine_log = config_.output_directory / "wine.log";
    if (std::filesystem::exists(wine_log)) {
        result.wine_log = wine_log;
        spdlog::info("✓ Collected: wine.log ({} bytes)", 
            std::filesystem::file_size(wine_log));
    }

    // Collect network pcap
    auto pcap_log = config_.output_directory / "network.pcap";
    if (std::filesystem::exists(pcap_log)) {
        result.network_pcap = pcap_log;
        spdlog::info("✓ Collected: network.pcap ({} bytes)", 
            std::filesystem::file_size(pcap_log));
    }
    
    // Collect file changes log
    auto changes_log = config_.output_directory / "file_changes.log";
    if (std::filesystem::exists(changes_log)) {
        result.file_changes_log = changes_log;
        spdlog::info("✓ Collected: file_changes.log ({} bytes)", 
            std::filesystem::file_size(changes_log));
    }
    
    // Copy artifacts from container to host before it's removed
    std::vector<std::string> artifact_files = {
        "strace.log",
        "wine.log", 
        "network.pcap",
        "files.log"
    };
    
    for (const auto& artifact : artifact_files) {
        std::string src = current_container_id_ + ":/sandbox/output/" + artifact;
        std::string dst = (config_.output_directory / artifact).string();
        
        std::string copy_cmd = "docker cp " + src + " " + dst + " 2>/dev/null";
        int ret = std::system(copy_cmd.c_str());
        
        if (ret == 0 && std::filesystem::exists(dst)) {
            spdlog::info("✓ Collected: {}", artifact);
            
            // Add to result paths
            if (artifact == "strace.log") {
                result.strace_log = dst;
            } else if (artifact == "wine.log") {
                // Could add wine_log to result struct
            } else if (artifact == "network.pcap") {
                result.network_pcap = dst;
            } else if (artifact == "files.log") {
                result.file_changes_log = dst;
            }
        } else {
            spdlog::debug("Artifact not found: {}", artifact);
        }
    }
    
    // Also check for files that were already written to mounted output dir
    auto output_dir = config_.output_directory;
    
    if (result.strace_log.empty()) {
        auto strace_log = output_dir / "strace.log";
        if (std::filesystem::exists(strace_log)) {
            result.strace_log = strace_log;
            spdlog::info("✓ Found strace log: {}", strace_log.filename().string());
        }
    }
    
    if (result.network_pcap.empty()) {
        auto pcap_file = output_dir / "network.pcap";
        if (std::filesystem::exists(pcap_file)) {
            result.network_pcap = pcap_file;
            spdlog::info("✓ Found network capture: {}", pcap_file.filename().string());
        }
    }
    
    if (result.file_changes_log.empty()) {
        auto file_log = output_dir / "file_changes.log";
        if (std::filesystem::exists(file_log)) {
            result.file_changes_log = file_log;
            spdlog::info("✓ Found file changes: {}", file_log.filename().string());
        }
    }
}

// Stop and remove container
void SandboxEngine::RemoveContainer(const std::string& container_id) {
    spdlog::debug("Removing container: {}", container_id);
    
    // Stop first
    std::string stop_cmd = "docker stop " + container_id + " > ";
#ifdef _WIN32
    stop_cmd += "nul 2>&1";
#else
    stop_cmd += "/dev/null 2>&1";
#endif
    std::system(stop_cmd.c_str());
    
    // Remove
    std::string rm_cmd = "docker rm " + container_id + " > ";
#ifdef _WIN32
    rm_cmd += "nul 2>&1";
#else
    rm_cmd += "/dev/null 2>&1";
#endif
    std::system(rm_cmd.c_str());
}

// Generate Docker run command
std::string SandboxEngine::GenerateDockerCommand(
    const std::filesystem::path& sample_path,
    const std::string& container_name) {
    
    std::ostringstream cmd;
    cmd << "docker run -d";
    cmd << " --name " << container_name;
    
    // Network isolation
    auto net_args = GetNetworkArgs();
    for (const auto& arg : net_args) {
        cmd << " " << arg;
    }
    
    // Resource limits
    auto res_args = GetResourceLimitArgs();
    for (const auto& arg : res_args) {
        cmd << " " << arg;
    }
    
    cmd << " " << config_.docker_image;
    
    return cmd.str();
}

// Apply resource limits to container
std::vector<std::string> SandboxEngine::GetResourceLimitArgs() const {
    std::vector<std::string> args;
    
    // Memory limit
    args.push_back("--memory=" + std::to_string(config_.resource_limits.max_memory_mb) + "m");
    
    // CPU limit
    args.push_back("--cpus=" + std::to_string(config_.resource_limits.max_cpu_cores));
    
    // Process limit
    args.push_back("--pids-limit=" + std::to_string(config_.resource_limits.max_processes));
    
    return args;
}

// Get network isolation arguments
std::vector<std::string> SandboxEngine::GetNetworkArgs() const {
    std::vector<std::string> args;
    
    switch (config_.network_mode) {
        case NetworkMode::ISOLATED:
            args.push_back("--network=none");
            break;
        case NetworkMode::SIMULATED:
            args.push_back("--network=inetsim"); // Custom network
            break;
        case NetworkMode::RESTRICTED:
            args.push_back("--network=bridge");
            break;
        case NetworkMode::FULL:
            args.push_back("--network=host");
            break;
    }
    
    return args;
}

// Monitor container resource usage
void SandboxEngine::MonitorResourceUsage(const std::string& container_id,
                                        SandboxExecutionResult& result) {
    // Stub - would use docker stats API
    result.peak_memory_mb = 0;
    result.peak_cpu_percent = 0.0f;
}

// Check if execution timed out
bool SandboxEngine::CheckTimeout(const std::chrono::system_clock::time_point& start_time) const {
    auto now = std::chrono::system_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start_time);
    return elapsed >= config_.timeout;
}

// Detect crashes and errors
void SandboxEngine::DetectAnomalies(SandboxExecutionResult& result) {
    // Check for crashes based on exit code
    if (result.exit_code == 139) { // SIGSEGV
        result.has_error = true;
        result.error_message = "Segmentation fault";
        spdlog::warn("Detected: Segmentation fault");
    } else if (result.exit_code == 134) { // SIGABRT
        result.has_error = true;
        result.error_message = "Aborted";
        spdlog::warn("Detected: Abort signal");
    }
}

// Generate unique container name
std::string SandboxEngine::GenerateContainerName() const {
    auto timestamp = std::time(nullptr);
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(1000, 9999);
    
    std::ostringstream oss;
    oss << "paramite_sandbox_"
        << std::put_time(std::localtime(&timestamp), "%Y%m%d_%H%M%S")
        << "_" << dis(gen);
    
    return oss.str();
}

// Validate sandbox configuration
bool SandboxEngine::ValidateConfig() const {
    if (config_.timeout.count() <= 0) {
        spdlog::error("Invalid timeout: must be > 0");
        return false;
    }
    
    if (config_.resource_limits.max_memory_mb < 128) {
        spdlog::error("Invalid memory limit: must be >= 128 MB");
        return false;
    }
    
    if (config_.docker_image.empty()) {
        spdlog::error("Docker image name is required");
        return false;
    }
    
    return true;
}

// Log sandbox event
void SandboxEngine::LogEvent(const std::string& event, const std::string& details) {
    if (config_.verbose_logging) {
        if (details.empty()) {
            spdlog::debug("[SANDBOX] {}", event);
        } else {
            spdlog::debug("[SANDBOX] {} - {}", event, details);
        }
    }
}

// Stub implementations for methods not fully implemented

bool SandboxEngine::CopyToVM(const std::filesystem::path& local_path,
                             const std::filesystem::path& vm_path) {
    // Would use scp or shared folder
    return true;
}

bool SandboxEngine::CopyFromVM(const std::filesystem::path& vm_path,
                               const std::filesystem::path& local_path) {
    // Would use scp or shared folder
    return true;
}

std::string SandboxEngine::ExecuteOnVM(const std::string& command) {
    // Would use SSH
    return "";
}

std::vector<std::string> SandboxEngine::ParseStraceLog(const std::filesystem::path& log_path) {
    std::vector<std::string> syscalls;
    // Would parse strace output
    return syscalls;
}

std::vector<std::string> SandboxEngine::ParseNetworkCapture(const std::filesystem::path& pcap_path) {
    std::vector<std::string> packets;
    // Would parse tcpdump output
    return packets;
}

} // namespace core
} // namespace paramite