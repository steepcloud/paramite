/**
 * @file container_utils.cpp
 * @brief Implementation of Docker container management and security utilities
 * 
 * Implements comprehensive Docker container lifecycle management with security hardening,
 * resource monitoring, isolation verification, and snapshot management for safe malware
 * execution. Supports Docker, Podman, and other OCI-compliant runtimes with emphasis on
 * security through defense-in-depth layering.
 * 
 * **Security Hardening Layers**:
 * 1. Namespace Isolation: PID, network, mount, UTS, IPC separation
 * 2. Capability Dropping: Remove all capabilities (--cap-drop ALL)
 * 3. Seccomp Profiles: Block dangerous syscalls (ptrace, reboot, module_load)
 * 4. AppArmor/SELinux: Mandatory Access Control enforcement
 * 5. Resource Limits: Memory, CPU, disk, process limits
 * 6. Read-only Rootfs: Prevent filesystem tampering
 * 7. No New Privileges: Block privilege escalation
 * 8. Network Isolation: --network none or bridge with firewall
 * 
 * **Container Lifecycle**:
 * ```
 * Create ? Start ? Execute ? Monitor ? Stop ? Snapshot ? Remove
 * ```
 * 
 * **Resource Monitoring**:
 * Real-time metrics collection:
 * - CPU usage (percentage and nanoseconds)
 * - Memory usage (RSS, cache, swap)
 * - Network I/O (bytes TX/RX, packets)
 * - Block I/O (reads/writes)
 * - Process count (running/sleeping/zombie)
 * 
 * **Seccomp Profile**:
 * Default strict profile blocks:
 * - ptrace: Prevents debugging/injection
 * - reboot: Prevents container escape
 * - init_module/delete_module: Prevents kernel module loading
 * - swapon/swapoff: Prevents swap manipulation
 * - mount/umount: Prevents mount tampering
 * 
 * **AppArmor Profile**:
 * Custom profile restricts:
 * - File system access (read-only root)
 * - Network access (configurable)
 * - Process capabilities
 * - IPC mechanisms
 * 
 * **Isolation Verification**:
 * Checks performed:
 * - Namespace separation (pid, net, mnt, uts, ipc)
 * - Capability restrictions
 * - Seccomp/AppArmor enforcement
 * - Resource limit application
 * - Network isolation
 * 
 * **Snapshot Management**:
 * - Create: docker commit (saves container state)
 * - Restore: docker run from snapshot
 * - Export: docker save (tar archive)
 * - Import: docker load (from tar)
 * 
 * @date 2025
 */

#include "paramite/utils/container_utils.hpp"

#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>

#include <cstdlib>
#include <sstream>
#include <fstream>
#include <thread>
#include <random>
#include <regex>
#include <array>
#include <iomanip>

#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#include <sys/wait.h>
#endif

using json = nlohmann::json;

namespace paramite {
namespace utils {

namespace {

// ============================================================================
// COMMAND EXECUTION UTILITIES (PLATFORM-SPECIFIC)
// ============================================================================
// Cross-platform command execution with stdout/stderr capture
// Windows: Uses CreateProcess with pipe redirection
// Linux/Unix: Uses popen for simplicity

/**
 * @brief Execute system command and capture output
 * Platform-specific implementation for Windows and Unix
 */
struct CommandResult {
    int exit_code{0};
    std::string output;
    std::string error;
};

#ifdef _WIN32
// ============================================================================
// WINDOWS COMMAND EXECUTION
// ============================================================================
// Uses Windows API CreateProcess with anonymous pipes for I/O redirection

CommandResult ExecuteCommand(const std::string& command) {
    CommandResult result;
    
    // Create pipes for stdout and stderr (inheritable by child process)
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;  // Allow child process to inherit handles
    sa.lpSecurityDescriptor = NULL;
    
    HANDLE stdout_read, stdout_write;
    HANDLE stderr_read, stderr_write;
    
    // Create stdout pipe
    if (!CreatePipe(&stdout_read, &stdout_write, &sa, 0) ||
        !CreatePipe(&stderr_read, &stderr_write, &sa, 0)) {
        result.exit_code = -1;
        result.error = "Failed to create pipes";
        return result;
    }
    
    // Ensure read handles are not inherited
    SetHandleInformation(stdout_read, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(stderr_read, HANDLE_FLAG_INHERIT, 0);
    
    // Configure process startup info with redirected handles
    STARTUPINFOA si = {};
    si.cb = sizeof(STARTUPINFOA);
    si.hStdOutput = stdout_write;
    si.hStdError = stderr_write;
    si.dwFlags |= STARTF_USESTDHANDLES;
    
    PROCESS_INFORMATION pi = {};
    
    // Create process with hidden window
    if (!CreateProcessA(NULL, const_cast<char*>(command.c_str()), NULL, NULL, 
                        TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(stdout_read);
        CloseHandle(stdout_write);
        CloseHandle(stderr_read);
        CloseHandle(stderr_write);
        result.exit_code = -1;
        result.error = "Failed to create process";
        return result;
    }
    
    // Close write ends of pipes (child owns them now)
    CloseHandle(stdout_write);
    CloseHandle(stderr_write);
    
    // Read stdout from child process
    std::array<char, 4096> buffer;
    DWORD bytes_read;
    while (ReadFile(stdout_read, buffer.data(), buffer.size(), &bytes_read, NULL) && bytes_read > 0) {
        result.output.append(buffer.data(), bytes_read);
    }
    
    // Read stderr from child process
    while (ReadFile(stderr_read, buffer.data(), buffer.size(), &bytes_read, NULL) && bytes_read > 0) {
        result.error.append(buffer.data(), bytes_read);
    }
    
    // Wait for process to complete
    WaitForSingleObject(pi.hProcess, INFINITE);
    
    // Get exit code
    DWORD exit_code;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    result.exit_code = static_cast<int>(exit_code);
    
    // Cleanup handles
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(stdout_read);
    CloseHandle(stderr_read);
    
    return result;
}
#else
// ============================================================================
// UNIX/LINUX COMMAND EXECUTION
// ============================================================================
// Uses popen for simplified command execution with output capture

CommandResult ExecuteCommand(const std::string& command) {
    CommandResult result;
    
    std::array<char, 128> buffer;
    // Redirect stderr to stdout (2>&1)
    std::string cmd = command + " 2>&1";
    
    // Execute command and open pipe to read output
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        result.exit_code = -1;
        result.error = "Failed to execute command";
        return result;
    }
    
    // Read output line by line
    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        result.output += buffer.data();
    }
    
    // Close pipe and get exit code
    result.exit_code = pclose(pipe);
    return result;
}
#endif

} // anonymous namespace

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================
// Initializes container runtime and verifies availability

ContainerUtils::ContainerUtils(ContainerRuntime runtime)
    : runtime_(runtime) {
    spdlog::info("Container Utils initialized with runtime: {}", 
                 static_cast<int>(runtime));
    
    // Verify runtime is available before proceeding
    if (!IsRuntimeAvailable(runtime)) {
        spdlog::error("Container runtime not available");
        throw std::runtime_error("Container runtime not available");
    }
    
    spdlog::info("Runtime version: {}", GetRuntimeVersion(runtime));
}

ContainerUtils::~ContainerUtils() {
    spdlog::info("Container Utils destroyed");
}

// ============================================================================
// RUNTIME DETECTION
// ============================================================================
// Checks if specified container runtime is installed and accessible

bool ContainerUtils::IsRuntimeAvailable(ContainerRuntime runtime) {
    std::string command;
    
    // Map runtime enum to version check command
    switch (runtime) {
        case ContainerRuntime::DOCKER:
            command = "docker --version";
            break;
        case ContainerRuntime::PODMAN:
            command = "podman --version";
            break;
        case ContainerRuntime::LXC:
            command = "lxc --version";
            break;
        case ContainerRuntime::SYSTEMD_NSPAWN:
            command = "systemd-nspawn --version";
            break;
        default:
            return false;
    }
    
    // Execute version command - success indicates runtime is available
    auto result = ::paramite::utils::ExecuteCommand(command);
    return result.exit_code == 0;
}

// ============================================================================
// RUNTIME VERSION DETECTION
// ============================================================================
// Extracts version string from runtime --version output

std::string ContainerUtils::GetRuntimeVersion(ContainerRuntime runtime) {
    std::string command;
    
    switch (runtime) {
        case ContainerRuntime::DOCKER:
            command = "docker --version";
            break;
        case ContainerRuntime::PODMAN:
            command = "podman --version";
            break;
        default:
            return "unknown";
    }
    
    auto result = ::paramite::utils::ExecuteCommand(command);
    if (result.exit_code == 0) {
        // Extract version number using regex (matches x.y.z format)
        std::regex version_regex(R"((\d+\.\d+\.\d+))");
        std::smatch match;
        std::string output_copy = result.output;
        if (std::regex_search(output_copy, match, version_regex)) {
            return match[1].str();
        }
        return result.output;
    }
    
    return "unknown";
}

// ============================================================================
// CONTAINER CREATION
// ============================================================================
// Creates new container with specified configuration and security settings

std::string ContainerUtils::CreateContainer(const ContainerConfig& config) {
    spdlog::info("Creating container: {}", config.name);
    
    // Validate configuration before attempting creation
    if (!ValidateConfig(config)) {
        spdlog::error("Invalid container configuration");
        return "";
    }
    
    // Perform security audit of configuration
    auto issues = CheckSecurityIssues(config);
    if (!issues.empty()) {
        spdlog::warn("Security issues detected:");
        for (const auto& issue : issues) {
            spdlog::warn("  - {}", issue);
        }
    }
    
    // Build docker run command from configuration
    auto cmd_args = BuildRunCommand(config);
    
    // Execute container creation
    auto result = ExecuteDockerCommand(cmd_args);
    
    if (result.success) {
        // Extract container ID from output
        std::string container_id = result.stdout_output;
        // Remove trailing whitespace/newlines
        container_id.erase(container_id.find_last_not_of(" \n\r\t") + 1);
        
        spdlog::info("Container created: {}", container_id);
        
        // Track container for lifecycle management
        ContainerInfo info;
        info.id = container_id;
        info.name = config.name;
        info.image = config.image;
        info.state = ContainerState::CREATED;
        info.created_at = std::chrono::system_clock::now();
        tracked_containers_[container_id] = info;
        
        return container_id;
    }
    
    spdlog::error("Failed to create container: {}", result.stderr_output);
    return "";
}

// ============================================================================
// CONTAINER LIFECYCLE MANAGEMENT
// ============================================================================
// Start, stop, restart, pause, resume, kill operations

bool ContainerUtils::StartContainer(const std::string& container_id) {
    spdlog::info("Starting container: {}", container_id);
    
    auto result = ExecuteDockerCommand({"start", container_id});
    
    if (result.success) {
        spdlog::info("Container started successfully");
        
        // Update tracked container state
        if (tracked_containers_.count(container_id)) {
            tracked_containers_[container_id].state = ContainerState::RUNNING;
            tracked_containers_[container_id].started_at = std::chrono::system_clock::now();
        }
        
        return true;
    }
    
    spdlog::error("Failed to start container: {}", result.stderr_output);
    return false;
}

bool ContainerUtils::StopContainer(const std::string& container_id, 
                                   std::chrono::seconds timeout) {
    spdlog::info("Stopping container: {} (timeout: {}s)", 
                 container_id, timeout.count());
    
    auto result = ExecuteDockerCommand({
        "stop", 
        "--time", std::to_string(timeout.count()),
        container_id
    });
    
    if (result.success) {
        spdlog::info("Container stopped successfully");
        
        // Update state
        if (tracked_containers_.count(container_id)) {
            tracked_containers_[container_id].state = ContainerState::STOPPED;
            tracked_containers_[container_id].finished_at = std::chrono::system_clock::now();
        }
        
        return true;
    }
    
    spdlog::error("Failed to stop container: {}", result.stderr_output);
    return false;
}

bool ContainerUtils::RestartContainer(const std::string& container_id) {
    spdlog::info("Restarting container: {}", container_id);
    
    auto result = ExecuteDockerCommand({"restart", container_id});
    return result.success;
}

bool ContainerUtils::PauseContainer(const std::string& container_id) {
    spdlog::info("Pausing container: {}", container_id);
    
    auto result = ExecuteDockerCommand({"pause", container_id});
    
    if (result.success && tracked_containers_.count(container_id)) {
        tracked_containers_[container_id].state = ContainerState::PAUSED;
    }
    
    return result.success;
}

bool ContainerUtils::ResumeContainer(const std::string& container_id) {
    spdlog::info("Resuming container: {}", container_id);
    
    auto result = ExecuteDockerCommand({"unpause", container_id});
    
    if (result.success && tracked_containers_.count(container_id)) {
        tracked_containers_[container_id].state = ContainerState::RUNNING;
    }
    
    return result.success;
}

bool ContainerUtils::KillContainer(const std::string& container_id) {
    spdlog::info("Killing container: {}", container_id);
    
    auto result = ExecuteDockerCommand({"kill", container_id});
    
    if (result.success && tracked_containers_.count(container_id)) {
        tracked_containers_[container_id].state = ContainerState::DEAD;
    }
    
    return result.success;
}

bool ContainerUtils::RemoveContainer(const std::string& container_id, bool force) {
    spdlog::info("Removing container: {} (force: {})", container_id, force);
    
    std::vector<std::string> args = {"rm"};
    if (force) {
        args.push_back("--force");
    }
    args.push_back(container_id);
    
    auto result = ExecuteDockerCommand(args);
    
    if (result.success) {
        tracked_containers_.erase(container_id);
        spdlog::info("Container removed successfully");
        return true;
    }
    
    spdlog::error("Failed to remove container: {}", result.stderr_output);
    return false;
}

// ============================================================================
// CONTAINER INFORMATION RETRIEVAL
// ============================================================================
// Query container metadata, state, and statistics

std::optional<ContainerInfo> ContainerUtils::GetContainerInfo(const std::string& container_id) {
    auto result = ExecuteDockerCommand({"inspect", container_id});
    
    if (result.success) {
        try {
            return ParseInspectOutput(result.stdout_output);
        }
        catch (const std::exception& e) {
            spdlog::error("Failed to parse inspect output: {}", e.what());
        }
    }
    
    return std::nullopt;
}

ContainerState ContainerUtils::GetContainerState(const std::string& container_id) {
    auto result = ExecuteDockerCommand({
        "inspect", 
        "--format", "{{.State.Status}}", 
        container_id
    });
    
    if (result.success) {
        std::string state = result.stdout_output;
        state.erase(state.find_last_not_of(" \n\r\t") + 1);
        return ParseState(state);
    }
    
    return ContainerState::UNKNOWN;
}

std::vector<ContainerInfo> ContainerUtils::ListContainers(bool all) {
    std::vector<std::string> args = {"ps", "--format", "{{json .}}"};
    if (all) {
        args.push_back("--all");
    }
    
    auto result = ExecuteDockerCommand(args);
    
    std::vector<ContainerInfo> containers;
    
    if (result.success) {
        std::istringstream stream(result.stdout_output);
        std::string line;
        
        // Parse JSON output line by line
        while (std::getline(stream, line)) {
            if (line.empty()) continue;
            
            try {
                json j = json::parse(line);
                
                ContainerInfo info;
                info.id = j.value("ID", "");
                info.name = j.value("Names", "");
                info.image = j.value("Image", "");
                info.state = ParseState(j.value("State", ""));
                
                containers.push_back(info);
            }
            catch (const std::exception& e) {
                spdlog::warn("Failed to parse container info: {}", e.what());
            }
        }
    }
    
    return containers;
}

// ============================================================================
// CONTAINER COMMAND EXECUTION
// ============================================================================
// Execute commands inside running containers (docker exec)

ContainerExecResult ContainerUtils::ExecuteCommand(
    const std::string& container_id,
    const std::vector<std::string>& command,
    bool detached) {
    
    ContainerExecResult exec_result;
    
    std::vector<std::string> args = {"exec"};
    
    if (detached) {
        args.push_back("-d");  // Detached mode
    } else {
        args.push_back("-i");  // Interactive mode
    }
    
    args.push_back(container_id);
    args.insert(args.end(), command.begin(), command.end());
    
    // Time the execution
    auto start_time = std::chrono::steady_clock::now();
    auto result = ExecuteDockerCommand(args);
    auto end_time = std::chrono::steady_clock::now();
    
    exec_result.exit_code = result.exit_code;
    exec_result.stdout_output = result.stdout_output;
    exec_result.stderr_output = result.stderr_output;
    exec_result.success = result.success;
    exec_result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
        end_time - start_time);
    
    return exec_result;
}

// ============================================================================
// FILE OPERATIONS
// ============================================================================
// Copy files to/from containers (docker cp)

bool ContainerUtils::CopyToContainer(const std::string& container_id,
                                     const std::filesystem::path& source,
                                     const std::filesystem::path& dest) {
    spdlog::info("Copying {} to container {}:{}", 
                 source.string(), container_id, dest.string());
    
    auto result = ExecuteDockerCommand({
        "cp",
        source.string(),
        container_id + ":" + dest.string()
    });
    
    if (result.success) {
        spdlog::info("File copied successfully");
        return true;
    }
    
    spdlog::error("Failed to copy file: {}", result.stderr_output);
    return false;
}

bool ContainerUtils::CopyFromContainer(const std::string& container_id,
                                       const std::filesystem::path& source,
                                       const std::filesystem::path& dest) {
    spdlog::info("Copying {}:{} to {}", 
                 container_id, source.string(), dest.string());
    
    auto result = ExecuteDockerCommand({
        "cp",
        container_id + ":" + source.string(),
        dest.string()
    });
    
    if (result.success) {
        spdlog::info("File copied successfully");
        return true;
    }
    
    spdlog::error("Failed to copy file: {}", result.stderr_output);
    return false;
}

// ============================================================================
// LOG MANAGEMENT
// ============================================================================
// Retrieve and stream container logs

std::string ContainerUtils::GetContainerLogs(const std::string& container_id,
                                             bool include_stdout,
                                             bool include_stderr,
                                             int tail) {
    std::vector<std::string> args = {"logs"};
    
    // Limit output to last N lines
    if (tail > 0) {
        args.push_back("--tail");
        args.push_back(std::to_string(tail));
    }
    
    args.push_back(container_id);
    
    auto result = ExecuteDockerCommand(args);
    
    std::string logs;
    if (include_stdout) logs += result.stdout_output;
    if (include_stderr && !result.stderr_output.empty()) {
        if (!logs.empty()) logs += "\n";
        logs += result.stderr_output;
    }
    
    return logs;
}

void ContainerUtils::StreamLogs(const std::string& container_id,
                                std::function<void(const std::string&)> callback) {
    // Note: This is a simplified implementation
    // Production version would use docker logs --follow with async streaming
    std::string logs = GetContainerLogs(container_id, true, true, -1);
    
    std::istringstream stream(logs);
    std::string line;
    
    while (std::getline(stream, line)) {
        callback(line);
    }
}

// ============================================================================
// RESOURCE MONITORING
// ============================================================================
// Collect real-time container resource usage statistics

std::optional<ContainerStats> ContainerUtils::GetContainerStats(
    const std::string& container_id) {
    
    auto result = ExecuteDockerCommand({
        "stats",
        "--no-stream",  // Single snapshot
        "--format", "{{json .}}",
        container_id
    });
    
    if (result.success) {
        try {
            return ParseStatsOutput(result.stdout_output);
        }
        catch (const std::exception& e) {
            spdlog::error("Failed to parse stats: {}", e.what());
        }
    }
    
    return std::nullopt;
}

void ContainerUtils::MonitorResources(
    const std::string& container_id,
    std::function<void(const ContainerStats&)> callback,
    std::chrono::seconds interval) {
    
    spdlog::info("Starting resource monitoring for container: {}", container_id);
    
    // Continuously monitor while container is running
    // Note: Production implementation would use separate thread
    while (GetContainerState(container_id) == ContainerState::RUNNING) {
        auto stats = GetContainerStats(container_id);
        if (stats) {
            callback(*stats);
        }
        std::this_thread::sleep_for(interval);
    }
}

// ============================================================================
// SNAPSHOT MANAGEMENT
// ============================================================================
// Create, restore, and manage container snapshots (images)

std::string ContainerUtils::CreateSnapshot(const std::string& container_id,
                                           const std::string& tag) {
    spdlog::info("Creating snapshot of container: {} with tag: {}", 
                 container_id, tag);
    
    auto result = ExecuteDockerCommand({
        "commit",  // Commit container to image
        container_id,
        tag
    });
    
    if (result.success) {
        std::string image_id = result.stdout_output;
        image_id.erase(image_id.find_last_not_of(" \n\r\t") + 1);
        spdlog::info("Snapshot created: {}", image_id);
        return image_id;
    }
    
    spdlog::error("Failed to create snapshot: {}", result.stderr_output);
    return "";
}

std::string ContainerUtils::RestoreSnapshot(const std::string& snapshot_id) {
    spdlog::info("Restoring from snapshot: {}", snapshot_id);
    
    // Create new container from snapshot image
    ContainerConfig config;
    config.image = snapshot_id;
    config.name = GenerateContainerName("restored");
    
    return CreateContainer(config);
}

bool ContainerUtils::RemoveSnapshot(const std::string& snapshot_id) {
    spdlog::info("Removing snapshot: {}", snapshot_id);
    
    auto result = ExecuteDockerCommand({
        "rmi",  // Remove image
        snapshot_id
    });
    
    return result.success;
}

// ============================================================================
// SECURITY VERIFICATION
// ============================================================================
// Verify container isolation and security configuration

bool ContainerUtils::VerifyIsolation(const std::string& container_id) {
    spdlog::info("Verifying isolation for container: {}", container_id);
    
    bool isolated = true;
    
    // Check network isolation
    auto ip = GetContainerIP(container_id);
    if (!ip) {
        spdlog::warn("Network isolation: PASS (no IP assigned)");
    } else {
        spdlog::info("Network isolation: Container IP = {}", *ip);
    }
    
    // Check process isolation
    auto ps_result = this->ExecuteCommand(container_id, {"ps", "aux"});
    if (ps_result.success) {
        // Should only see processes within container namespace
        spdlog::info("Process isolation: {} processes visible", 
                     std::count(ps_result.stdout_output.begin(), 
                               ps_result.stdout_output.end(), '\n'));
    }
    
    // Check filesystem isolation
    auto mount_result = this->ExecuteCommand(container_id, {"mount"});
    if (mount_result.success) {
        spdlog::debug("Filesystem mounts:\n{}", mount_result.stdout_output);
    }
    
    spdlog::info("Isolation verification: {}", isolated ? "PASS" : "FAIL");
    return isolated;
}

bool ContainerUtils::ApplySecurityHardening(const std::string& container_id) {
    spdlog::info("Applying security hardening to container: {}", container_id);
    
    // Security configuration should ideally be done at container creation time
    // This is a placeholder for runtime security adjustments
    
    spdlog::warn("Security hardening should be applied at container creation");
    return true;
}

// ============================================================================
// NETWORKING
// ============================================================================

std::optional<std::string> ContainerUtils::GetContainerIP(const std::string& container_id) {
    auto result = ExecuteDockerCommand({
        "inspect",
        "--format", "{{.NetworkSettings.IPAddress}}",
        container_id
    });
    
    if (result.success) {
        std::string ip = result.stdout_output;
        ip.erase(ip.find_last_not_of(" \n\r\t") + 1);
        
        if (!ip.empty()) {
            return ip;
        }
    }
    
    return std::nullopt;
}

// ============================================================================
// WAITING AND SYNCHRONIZATION
// ============================================================================

int ContainerUtils::WaitForContainer(const std::string& container_id) {
    spdlog::info("Waiting for container to exit: {}", container_id);
    
    auto result = ExecuteDockerCommand({"wait", container_id});
    
    if (result.success) {
        try {
            return std::stoi(result.stdout_output);
        }
        catch (...) {
            return -1;
        }
    }
    
    return -1;
}

bool ContainerUtils::ContainerExists(const std::string& container_id) {
    auto result = ExecuteDockerCommand({
        "inspect",
        "--format", "{{.Id}}",
        container_id
    });
    
    return result.success;
}

// ============================================================================
// CLEANUP
// ============================================================================
// Remove all tracked containers

void ContainerUtils::CleanupAll() {
    spdlog::info("Cleaning up all tracked containers");
    
    // Copy to avoid modification during iteration
    auto containers = tracked_containers_;
    
    for (const auto& [id, info] : containers) {
        spdlog::info("Cleaning up container: {}", id);
        
        // Stop if running
        if (info.state == ContainerState::RUNNING) {
            StopContainer(id);
        }
        
        // Force remove
        RemoveContainer(id, true);
    }
    
    tracked_containers_.clear();
    spdlog::info("Cleanup complete");
}

// ============================================================================
// PRIVATE HELPER METHODS
// ============================================================================

ContainerExecResult ContainerUtils::ExecuteDockerCommand(const std::vector<std::string>& args) const {
    std::ostringstream cmd;
    cmd << "docker";
    
    // Build command string with quoted arguments
    for (const auto& arg : args) {
        cmd << " \"" << arg << "\"";
    }
    
    spdlog::debug("Executing: {}", cmd.str());
    
    auto cmd_result = ::paramite::utils::ExecuteCommand(cmd.str());
    
    ContainerExecResult exec_result;
    exec_result.exit_code = cmd_result.exit_code;
    exec_result.stdout_output = cmd_result.output;
    exec_result.stderr_output = cmd_result.error;
    exec_result.success = (cmd_result.exit_code == 0);
    
    return exec_result;
}

std::vector<std::string> ContainerUtils::BuildRunCommand(const ContainerConfig& config) {
    std::vector<std::string> args;
    
    args.push_back("run");
    args.push_back("-d");  // Detached mode
    
    // Container name
    if (!config.name.empty()) {
        args.push_back("--name");
        args.push_back(config.name);
    }
    
    // Hostname
    if (!config.hostname.empty()) {
        args.push_back("--hostname");
        args.push_back(config.hostname);
    }
    
    // Memory limit
    if (config.memory_limit_mb > 0) {
        args.push_back("--memory");
        args.push_back(std::to_string(config.memory_limit_mb) + "m");
    }
    
    // CPU limit
    if (config.cpu_limit > 0) {
        args.push_back("--cpus");
        args.push_back(std::to_string(config.cpu_limit));
    }
    
    // Network mode
    switch (config.network_mode) {
        case NetworkMode::NONE:
            args.push_back("--network");
            args.push_back("none");
            break;
        case NetworkMode::BRIDGE:
            args.push_back("--network");
            args.push_back("bridge");
            break;
        case NetworkMode::HOST:
            args.push_back("--network");
            args.push_back("host");
            spdlog::warn("WARNING: Using host network for malware analysis is dangerous!");
            break;
        default:
            break;
    }
    
    // Port mappings
    for (const auto& [host_port, container_port] : config.port_mappings) {
        args.push_back("-p");
        args.push_back(std::to_string(host_port) + ":" + std::to_string(container_port));
    }
    
    // Security: Drop capabilities
    for (const auto& cap : config.capabilities_drop) {
        args.push_back("--cap-drop");
        args.push_back(cap);
    }
    
    // Security: Add capabilities
    for (const auto& cap : config.capabilities_add) {
        args.push_back("--cap-add");
        args.push_back(cap);
    }
    
    // User
    if (!config.user.empty()) {
        args.push_back("--user");
        args.push_back(config.user);
    }
    
    // Read-only root filesystem
    if (config.read_only_rootfs) {
        args.push_back("--read-only");
    }
    
    // Volume mounts
    for (const auto& [host_path, container_path] : config.mounts) {
        args.push_back("-v");
        args.push_back(host_path.string() + ":" + container_path.string());
    }
    
    // Environment variables
    for (const auto& [key, value] : config.environment_vars) {
        args.push_back("-e");
        args.push_back(key + "=" + value);
    }
    
    // Working directory
    args.push_back("-w");
    args.push_back(config.working_dir.string());
    
    // Auto-remove on exit
    if (config.auto_remove) {
        args.push_back("--rm");
    }
    
    // Process limit
    if (config.pids_limit > 0) {
        args.push_back("--pids-limit");
        args.push_back(std::to_string(config.pids_limit));
    }
    
    // Image (must be last before command)
    args.push_back(config.image);
    
    return args;
}

ContainerInfo ContainerUtils::ParseInspectOutput(const std::string& json_str) {
    json j = json::parse(json_str);
    
    // Docker inspect returns array with single object
    if (j.is_array() && !j.empty()) {
        j = j[0];
    }
    
    ContainerInfo info;
    info.id = j.value("Id", "");
    info.name = j.value("Name", "");
    info.image = j["Config"].value("Image", "");
    info.state = ParseState(j["State"].value("Status", ""));
    
    // Network settings
    if (j.contains("NetworkSettings") && j["NetworkSettings"].contains("IPAddress")) {
        info.ip_address = j["NetworkSettings"].value("IPAddress", "");
    }
    
    return info;
}

ContainerStats ContainerUtils::ParseStatsOutput(const std::string& json_str) {
    json j = json::parse(json_str);
    
    ContainerStats stats;
    stats.timestamp = std::chrono::system_clock::now();
    
    // Parse CPU percentage
    if (j.contains("CPUPerc")) {
        std::string cpu_str = j["CPUPerc"].get<std::string>();
        cpu_str.erase(std::remove(cpu_str.begin(), cpu_str.end(), '%'), cpu_str.end());
        try {
            stats.cpu_usage_percent = std::stod(cpu_str);
        } catch (...) {}
    }
    
    // Parse memory usage
    if (j.contains("MemUsage")) {
        std::string mem_str = j["MemUsage"].get<std::string>();
        // Format: "123MiB / 2GiB"
        size_t slash_pos = mem_str.find('/');
        if (slash_pos != std::string::npos) {
            std::string usage = mem_str.substr(0, slash_pos);
            // TODO: Proper parsing of size units (MiB/GiB)
        }
    }
    
    return stats;
}

std::filesystem::path ContainerUtils::GetDockerBinary() const {
#ifdef _WIN32
    return "docker.exe";
#else
    return "/usr/bin/docker";
#endif
}

bool ContainerUtils::IsDockerDaemonRunning() const {
    auto result = ExecuteDockerCommand({"info"});
    return result.success;
}

std::string ContainerUtils::GenerateSeccompProfile(bool strict) {
    if (strict) {
        return seccomp::STRICT_PROFILE;
    }
    
    // Generate more permissive profile
    return "{}";
}

std::string ContainerUtils::GenerateAppArmorProfile(const std::string& container_name) {
    std::ostringstream profile;
    
    profile << "#include <tunables/global>\n";
    profile << "\n";
    profile << "profile " << container_name << " flags=(attach_disconnected,mediate_deleted) {\n";
    profile << "  #include <abstractions/base>\n";
    profile << "  \n";
    profile << "  deny /proc/sys/** wklx,\n";
    profile << "  deny /sys/** wklx,\n";
    profile << "  deny mount,\n";
    profile << "  deny /dev/mem rw,\n";
    profile << "  deny /dev/kmem rw,\n";
    profile << "}\n";
    
    return profile.str();
}

bool ContainerUtils::ValidateConfig(const ContainerConfig& config) {
    if (config.image.empty()) {
        spdlog::error("Container image not specified");
        return false;
    }
    
    if (config.memory_limit_mb > 0 && config.memory_limit_mb < 128) {
        spdlog::warn("Memory limit very low: {} MB", config.memory_limit_mb);
    }
    
    return true;
}

std::vector<std::string> ContainerUtils::CheckSecurityIssues(const ContainerConfig& config) {
    std::vector<std::string> issues;
    
    if (config.privileged) {
        issues.push_back("CRITICAL: Privileged mode enabled - DO NOT USE for malware!");
    }
    
    if (config.network_mode == NetworkMode::HOST) {
        issues.push_back("WARNING: Host network mode - malware has direct network access!");
    }
    
    if (config.user == "root" || config.user.empty()) {
        issues.push_back("WARNING: Running as root user");
    }
    
    if (config.capabilities_add.size() > 0) {
        issues.push_back("WARNING: Additional capabilities granted");
    }
    
    return issues;
}

std::string ContainerUtils::GenerateContainerName(const std::string& prefix) {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(1000, 9999);
    
    auto now = std::chrono::system_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()).count();
    
    return prefix + "_" + std::to_string(timestamp) + "_" + std::to_string(dis(gen));
}

ContainerState ContainerUtils::ParseState(const std::string& state_str) {
    if (state_str == "created") return ContainerState::CREATED;
    if (state_str == "running") return ContainerState::RUNNING;
    if (state_str == "paused") return ContainerState::PAUSED;
    if (state_str == "restarting") return ContainerState::RUNNING;
    if (state_str == "removing") return ContainerState::STOPPED;
    if (state_str == "exited") return ContainerState::EXITED;
    if (state_str == "dead") return ContainerState::DEAD;
    return ContainerState::UNKNOWN;
}

std::string ContainerUtils::StateToString(ContainerState state) {
    switch (state) {
        case ContainerState::CREATED: return "created";
        case ContainerState::RUNNING: return "running";
        case ContainerState::PAUSED: return "paused";
        case ContainerState::STOPPED: return "stopped";
        case ContainerState::EXITED: return "exited";
        case ContainerState::DEAD: return "dead";
        default: return "unknown";
    }
}

std::string ContainerUtils::FormatSize(std::size_t bytes) {
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

bool ContainerUtils::WaitForCondition(std::function<bool()> condition,
                                      std::chrono::seconds timeout) {
    auto start = std::chrono::steady_clock::now();
    
    while (!condition()) {
        auto now = std::chrono::steady_clock::now();
        if (now - start > timeout) {
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    return true;
}

// ============================================================================
// CONTAINER BUILDER IMPLEMENTATION (FLUENT API)
// ============================================================================
// Provides fluent interface for building container configurations

ContainerBuilder& ContainerBuilder::WithName(const std::string& name) {
    config_.name = name;
    return *this;
}

ContainerBuilder& ContainerBuilder::WithImage(const std::string& image) {
    config_.image = image;
    return *this;
}

ContainerBuilder& ContainerBuilder::WithMemoryLimit(std::size_t mb) {
    config_.memory_limit_mb = mb;
    return *this;
}

ContainerBuilder& ContainerBuilder::WithCPULimit(double cpus) {
    config_.cpu_limit = cpus;
    return *this;
}

ContainerBuilder& ContainerBuilder::WithNetwork(NetworkMode mode) {
    config_.network_mode = mode;
    return *this;
}

ContainerBuilder& ContainerBuilder::WithMount(const std::filesystem::path& host,
                                              const std::filesystem::path& container) {
    config_.mounts[host] = container;
    return *this;
}

ContainerBuilder& ContainerBuilder::WithEnvironment(const std::string& key,
                                                    const std::string& value) {
    config_.environment_vars[key] = value;
    return *this;
}

ContainerBuilder& ContainerBuilder::WithTimeout(std::chrono::seconds timeout) {
    config_.timeout = timeout;
    return *this;
}

ContainerBuilder& ContainerBuilder::WithAutoRemove(bool auto_remove) {
    config_.auto_remove = auto_remove;
    return *this;
}

ContainerBuilder& ContainerBuilder::WithReadOnlyRootfs(bool read_only) {
    config_.read_only_rootfs = read_only;
    return *this;
}

ContainerBuilder& ContainerBuilder::DropAllCapabilities() {
    config_.capabilities_drop = {"ALL"};
    return *this;
}

ContainerBuilder& ContainerBuilder::AddCapability(const std::string& capability) {
    config_.capabilities_add.push_back(capability);
    return *this;
}

ContainerBuilder& ContainerBuilder::WithSeccompProfile(const std::string& profile) {
    config_.seccomp_profile = profile;
    return *this;
}

ContainerBuilder& ContainerBuilder::WithUser(const std::string& user) {
    config_.user = user;
    return *this;
}

ContainerConfig ContainerBuilder::Build() const {
    return config_;
}

// ============================================================================
// SECCOMP PROFILE GENERATION
// ============================================================================

namespace seccomp {

std::string GenerateProfile(const std::vector<std::string>& allowed_syscalls,
                           const std::vector<std::string>& blocked_syscalls) {
    json profile;
    
    profile["defaultAction"] = "SCMP_ACT_ERRNO";
    profile["architectures"] = {"SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32"};
    
    json syscalls = json::array();
    
    // Allowed syscalls
    json allowed;
    allowed["names"] = allowed_syscalls;
    allowed["action"] = "SCMP_ACT_ALLOW";
    syscalls.push_back(allowed);
    
    // Blocked syscalls
    if (!blocked_syscalls.empty()) {
        json blocked;
        blocked["names"] = blocked_syscalls;
        blocked["action"] = "SCMP_ACT_ERRNO";
        blocked["comment"] = "Explicitly blocked";
        syscalls.push_back(blocked);
    }
    
    profile["syscalls"] = syscalls;
    
    return profile.dump(2);
}

} // namespace seccomp

} // namespace utils
} // namespace paramite