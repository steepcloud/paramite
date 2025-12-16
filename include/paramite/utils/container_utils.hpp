/**
 * @file container_utils.hpp
 * @brief Docker container management and security isolation utilities
 * 
 * Provides comprehensive container lifecycle management with security hardening,
 * resource monitoring, and isolation verification for safe malware execution.
 * Supports Docker, Podman, and other OCI-compliant container runtimes.
 * 
 * @date 2025
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <set>
#include <optional>
#include <filesystem>
#include <chrono>
#include <functional>

namespace paramite {
namespace utils {

/**
 * @enum ContainerRuntime
 * @brief Supported container runtime engines
 */
enum class ContainerRuntime {
    DOCKER,          ///< Docker Engine
    PODMAN,          ///< Podman (daemonless)
    LXC,             ///< Linux Containers
    SYSTEMD_NSPAWN   ///< systemd-nspawn
};

/**
 * @enum ContainerState
 * @brief Container lifecycle states
 */
enum class ContainerState {
    CREATED,   ///< Container created but not started
    RUNNING,   ///< Container is running
    PAUSED,    ///< Container paused
    STOPPED,   ///< Container stopped gracefully
    EXITED,    ///< Container exited
    DEAD,      ///< Container is dead
    UNKNOWN    ///< Unknown state
};

/**
 * @enum NetworkMode
 * @brief Container network isolation modes
 */
enum class NetworkMode {
    NONE,        ///< No network access (safest)
    BRIDGE,      ///< Bridge network (isolated)
    HOST,        ///< Host network (NOT recommended for malware!)
    CONTAINER,   ///< Share network with another container
    CUSTOM       ///< Custom network
};

/**
 * @struct ContainerConfig
 * @brief Complete container configuration
 */
struct ContainerConfig {
    // Basic Settings
    std::string name;                           ///< Container name
    std::string image{"kalilinux/kali-rolling"}; ///< Base image
    std::string hostname{"malware-sandbox"};    ///< Container hostname
    
    // Resource Limits
    std::size_t memory_limit_mb{2048};          ///< Memory limit (2GB)
    std::size_t memory_swap_limit_mb{4096};     ///< Swap limit (4GB)
    double cpu_limit{1.0};                      ///< CPU limit (1 core)
    std::size_t disk_limit_mb{10240};           ///< Disk limit (10GB)
    int pids_limit{100};                        ///< Process limit
    
    // Network Settings
    NetworkMode network_mode{NetworkMode::NONE};  ///< Network mode
    std::string network_name;                     ///< Network name
    std::vector<std::string> dns_servers;         ///< DNS servers
    std::map<int, int> port_mappings;             ///< Port mappings
    
    // Security Settings
    bool privileged{false};                       ///< Privileged mode (NEVER for malware!)
    bool read_only_rootfs{false};                 ///< Read-only root filesystem
    std::vector<std::string> capabilities_drop{"ALL"};  ///< Drop all capabilities
    std::vector<std::string> capabilities_add;    ///< Add specific capabilities
    std::optional<std::string> seccomp_profile;   ///< Seccomp profile path
    std::optional<std::string> apparmor_profile;  ///< AppArmor profile
    std::string user{"nobody"};                   ///< Run as user
    
    // Filesystem Settings
    std::map<std::filesystem::path, std::filesystem::path> mounts;  ///< Volume mounts
    std::vector<std::string> volumes;             ///< Volumes
    std::filesystem::path working_dir{"/tmp"};    ///< Working directory
    
    // Environment
    std::map<std::string, std::string> environment_vars;  ///< Environment variables
    
    // Lifecycle
    std::chrono::seconds timeout{300};     ///< Auto-stop timeout (5 min)
    bool auto_remove{true};                ///< Auto-remove on exit
    
    // Logging
    std::string log_driver{"json-file"};                  ///< Log driver
    std::map<std::string, std::string> log_options;       ///< Log options
};

/**
 * @struct ContainerInfo
 * @brief Container runtime information
 */
struct ContainerInfo {
    std::string id;          ///< Container ID
    std::string name;        ///< Container name
    std::string image;       ///< Image name
    ContainerState state;    ///< Current state
    
    // Timing
    std::chrono::system_clock::time_point created_at;   ///< Creation time
    std::chrono::system_clock::time_point started_at;   ///< Start time
    std::chrono::system_clock::time_point finished_at;  ///< Finish time
    
    // Network
    std::string ip_address;              ///< IP address
    std::map<int, int> port_mappings;    ///< Port mappings
    
    // Resource Usage
    std::size_t memory_usage_mb{0};   ///< Memory usage
    double cpu_usage_percent{0.0};    ///< CPU usage
    std::size_t disk_usage_mb{0};     ///< Disk usage
    int process_count{0};             ///< Process count
    
    // Exit Status
    int exit_code{0};         ///< Exit code
    std::string exit_reason;  ///< Exit reason
};

/**
 * @struct ContainerStats
 * @brief Real-time container resource statistics
 */
struct ContainerStats {
    // CPU
    double cpu_usage_percent{0.0};                ///< CPU utilization
    std::chrono::nanoseconds cpu_total_usage{0};  ///< Total CPU time
    std::chrono::nanoseconds cpu_system_usage{0}; ///< System CPU time
    
    // Memory
    std::size_t memory_usage_bytes{0};    ///< Memory usage
    std::size_t memory_limit_bytes{0};    ///< Memory limit
    std::size_t memory_cache_bytes{0};    ///< Cache memory
    double memory_usage_percent{0.0};     ///< Memory utilization
    
    // Network
    std::size_t network_rx_bytes{0};      ///< Received bytes
    std::size_t network_tx_bytes{0};      ///< Transmitted bytes
    std::size_t network_rx_packets{0};    ///< Received packets
    std::size_t network_tx_packets{0};    ///< Transmitted packets
    
    // Block I/O
    std::size_t block_read_bytes{0};      ///< Bytes read
    std::size_t block_write_bytes{0};     ///< Bytes written
    
    // Processes
    int process_count{0};  ///< Active processes
    
    // Timestamp
    std::chrono::system_clock::time_point timestamp;  ///< Stats timestamp
};

/**
 * @struct ContainerExecResult
 * @brief Result of command execution in container
 */
struct ContainerExecResult {
    int exit_code{0};              ///< Exit code
    std::string stdout_output;     ///< Standard output
    std::string stderr_output;     ///< Standard error
    std::chrono::milliseconds duration{0};  ///< Execution duration
    bool success{false};           ///< Success flag
};

/**
 * @class ContainerUtils
 * @brief Docker/container management and security utilities
 * 
 * Comprehensive container lifecycle management with:
 * - **Security Hardening**: Seccomp, AppArmor, capability dropping
 * - **Resource Limits**: Memory, CPU, disk, process limits
 * - **Network Isolation**: Complete network isolation or controlled access
 * - **Monitoring**: Real-time resource usage tracking
 * - **Snapshot/Restore**: Container state management
 * - **Isolation Verification**: Security checks
 * 
 * **Usage Example**:
 * @code
 * ContainerUtils utils(ContainerRuntime::DOCKER);
 * 
 * // Create secure container
 * ContainerConfig config;
 * config.name = "malware-sandbox";
 * config.memory_limit_mb = 2048;
 * config.network_mode = NetworkMode::NONE;
 * config.capabilities_drop = {"ALL"};
 * 
 * std::string container_id = utils.CreateContainer(config);
 * 
 * // Start and execute
 * utils.StartContainer(container_id);
 * auto result = utils.ExecuteCommand(container_id, {"/path/to/malware.exe"});
 * 
 * // Monitor resources
 * auto stats = utils.GetContainerStats(container_id);
 * 
 * // Cleanup
 * utils.StopContainer(container_id);
 * utils.RemoveContainer(container_id);
 * @endcode
 */
class ContainerUtils {
public:
    /**
     * @brief Construct container utilities for specific runtime
     * @param runtime Container runtime to use
     */
    explicit ContainerUtils(ContainerRuntime runtime = ContainerRuntime::DOCKER);
    
    ~ContainerUtils();

    /**
     * @brief Check if container runtime is available
     * @param runtime Runtime to check
     * @return true if available
     */
    static bool IsRuntimeAvailable(ContainerRuntime runtime = ContainerRuntime::DOCKER);

    /**
     * @brief Get runtime version string
     * @param runtime Runtime to query
     * @return Version string
     */
    static std::string GetRuntimeVersion(ContainerRuntime runtime = ContainerRuntime::DOCKER);

    /**
     * @brief Create container from configuration
     * @param config Container configuration
     * @return Container ID
     */
    std::string CreateContainer(const ContainerConfig& config);

    /**
     * @brief Start container
     * @param container_id Container ID
     * @return true if started successfully
     */
    bool StartContainer(const std::string& container_id);

    /**
     * @brief Stop container gracefully
     * @param container_id Container ID
     * @param timeout Stop timeout
     * @return true if stopped successfully
     */
    bool StopContainer(const std::string& container_id, 
                      std::chrono::seconds timeout = std::chrono::seconds(10));

    /**
     * @brief Restart container
     * @param container_id Container ID
     * @return true if restarted successfully
     */
    bool RestartContainer(const std::string& container_id);

    /**
     * @brief Pause container execution
     * @param container_id Container ID
     * @return true if paused successfully
     */
    bool PauseContainer(const std::string& container_id);

    /**
     * @brief Resume paused container
     * @param container_id Container ID
     * @return true if resumed successfully
     */
    bool ResumeContainer(const std::string& container_id);

    /**
     * @brief Kill container forcefully
     * @param container_id Container ID
     * @return true if killed successfully
     */
    bool KillContainer(const std::string& container_id);

    /**
     * @brief Remove container
     * @param container_id Container ID
     * @param force Force removal
     * @return true if removed successfully
     */
    bool RemoveContainer(const std::string& container_id, bool force = false);

    /**
     * @brief Get container information
     * @param container_id Container ID
     * @return Container info if found
     */
    std::optional<ContainerInfo> GetContainerInfo(const std::string& container_id);

    /**
     * @brief Get container state
     * @param container_id Container ID
     * @return Container state
     */
    ContainerState GetContainerState(const std::string& container_id);

    /**
     * @brief List containers
     * @param all Include stopped containers
     * @return Vector of container info
     */
    std::vector<ContainerInfo> ListContainers(bool all = false);

    /**
     * @brief Execute command in container
     * @param container_id Container ID
     * @param command Command to execute
     * @param detached Run detached
     * @return Execution result
     */
    ContainerExecResult ExecuteCommand(const std::string& container_id,
                                      const std::vector<std::string>& command,
                                      bool detached = false);

    /**
     * @brief Copy file to container
     * @param container_id Container ID
     * @param source Source path (host)
     * @param dest Destination path (container)
     * @return true if copied successfully
     */
    bool CopyToContainer(const std::string& container_id,
                        const std::filesystem::path& source,
                        const std::filesystem::path& dest);

    /**
     * @brief Copy file from container
     * @param container_id Container ID
     * @param source Source path (container)
     * @param dest Destination path (host)
     * @return true if copied successfully
     */
    bool CopyFromContainer(const std::string& container_id,
                          const std::filesystem::path& source,
                          const std::filesystem::path& dest);

    /**
     * @brief Get container logs
     * @param container_id Container ID
     * @param include_stdout Include stdout
     * @param include_stderr Include stderr
     * @param tail Number of lines (-1 for all)
     * @return Log output
     */
    std::string GetContainerLogs(const std::string& container_id,
                                bool include_stdout = true,
                                bool include_stderr = true,
                                int tail = -1);

    /**
     * @brief Stream container logs with callback
     * @param container_id Container ID
     * @param callback Log line callback
     */
    void StreamLogs(const std::string& container_id,
                   std::function<void(const std::string&)> callback);

    /**
     * @brief Get real-time container statistics
     * @param container_id Container ID
     * @return Container stats if available
     */
    std::optional<ContainerStats> GetContainerStats(const std::string& container_id);

    /**
     * @brief Monitor container resources continuously
     * @param container_id Container ID
     * @param callback Stats callback
     * @param interval Sampling interval
     */
    void MonitorResources(const std::string& container_id,
                         std::function<void(const ContainerStats&)> callback,
                         std::chrono::seconds interval = std::chrono::seconds(1));

    /**
     * @brief Create container snapshot
     * @param container_id Container ID
     * @param tag Snapshot tag
     * @return Snapshot ID
     */
    std::string CreateSnapshot(const std::string& container_id,
                              const std::string& tag);

    /**
     * @brief Restore container from snapshot
     * @param snapshot_id Snapshot ID
     * @return New container ID
     */
    std::string RestoreSnapshot(const std::string& snapshot_id);

    /**
     * @brief Remove snapshot
     * @param snapshot_id Snapshot ID
     * @return true if removed successfully
     */
    bool RemoveSnapshot(const std::string& snapshot_id);

    /**
     * @brief Verify container security isolation
     * @param container_id Container ID
     * @return true if properly isolated
     */
    bool VerifyIsolation(const std::string& container_id);

    /**
     * @brief Apply security hardening to container
     * @param container_id Container ID
     * @return true if hardening applied successfully
     */
    bool ApplySecurityHardening(const std::string& container_id);

    /**
     * @brief Get container IP address
     * @param container_id Container ID
     * @return IP address if found
     */
    std::optional<std::string> GetContainerIP(const std::string& container_id);

    /**
     * @brief Wait for container to exit
     * @param container_id Container ID
     * @return Exit code
     */
    int WaitForContainer(const std::string& container_id);

    /**
     * @brief Check if container exists
     * @param container_id Container ID
     * @return true if exists
     */
    bool ContainerExists(const std::string& container_id);

    /**
     * @brief Cleanup all tracked containers
     */
    void CleanupAll();

    /**
     * @brief Get current runtime
     * @return Container runtime
     */
    ContainerRuntime GetRuntime() const { return runtime_; }

private:
    ContainerRuntime runtime_;                          ///< Container runtime
    std::map<std::string, ContainerInfo> tracked_containers_;  ///< Tracked containers

    // Internal methods
    ContainerExecResult ExecuteDockerCommand(const std::vector<std::string>& args) const;
    std::vector<std::string> BuildRunCommand(const ContainerConfig& config);
    ContainerInfo ParseInspectOutput(const std::string& json);
    ContainerStats ParseStatsOutput(const std::string& json);
    std::filesystem::path GetDockerBinary() const;
    bool IsDockerDaemonRunning() const;
    std::string GenerateSeccompProfile(bool strict = true);
    std::string GenerateAppArmorProfile(const std::string& container_name);
    bool ValidateConfig(const ContainerConfig& config);
    std::vector<std::string> CheckSecurityIssues(const ContainerConfig& config);
    std::string GenerateContainerName(const std::string& prefix = "paramite");
    ContainerState ParseState(const std::string& state_str);
    std::string StateToString(ContainerState state);
    std::string FormatSize(std::size_t bytes);
    bool WaitForCondition(std::function<bool()> condition,
                         std::chrono::seconds timeout);
};

/**
 * @class ContainerBuilder
 * @brief Fluent API for building container configurations
 */
class ContainerBuilder {
public:
    ContainerBuilder& WithName(const std::string& name);
    ContainerBuilder& WithImage(const std::string& image);
    ContainerBuilder& WithMemoryLimit(std::size_t mb);
    ContainerBuilder& WithCPULimit(double cpus);
    ContainerBuilder& WithNetwork(NetworkMode mode);
    ContainerBuilder& WithMount(const std::filesystem::path& host,
                               const std::filesystem::path& container);
    ContainerBuilder& WithEnvironment(const std::string& key, 
                                     const std::string& value);
    ContainerBuilder& WithTimeout(std::chrono::seconds timeout);
    ContainerBuilder& WithAutoRemove(bool auto_remove = true);
    ContainerBuilder& WithReadOnlyRootfs(bool read_only = true);
    ContainerBuilder& DropAllCapabilities();
    ContainerBuilder& AddCapability(const std::string& capability);
    ContainerBuilder& WithSeccompProfile(const std::string& profile);
    ContainerBuilder& WithUser(const std::string& user);
    
    ContainerConfig Build() const;

private:
    ContainerConfig config_;  ///< Configuration being built
};

/**
 * @namespace seccomp
 * @brief Seccomp profile generation utilities
 */
namespace seccomp {

/// Strict seccomp profile (blocks dangerous syscalls)
const char* STRICT_PROFILE = R"({
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_X32"],
  "syscalls": [
    {
      "names": [
        "read", "write", "open", "close", "stat", "fstat", "lstat",
        "poll", "lseek", "mmap", "mprotect", "munmap", "brk",
        "rt_sigaction", "rt_sigprocmask", "rt_sigreturn",
        "access", "pipe", "select", "sched_yield", "mremap",
        "msync", "mincore", "madvise", "dup", "dup2", "pause",
        "nanosleep", "getitimer", "alarm", "setitimer", "getpid",
        "sendfile", "socket", "connect", "accept", "sendto", "recvfrom",
        "sendmsg", "recvmsg", "shutdown", "bind", "listen",
        "getsockname", "getpeername", "socketpair", "setsockopt",
        "getsockopt", "clone", "fork", "vfork", "execve", "exit",
        "wait4", "kill", "uname", "fcntl", "flock", "fsync",
        "fdatasync", "truncate", "ftruncate", "getdents", "getcwd",
        "chdir", "fchdir", "rename", "mkdir", "rmdir", "creat",
        "link", "unlink", "symlink", "readlink", "chmod", "fchmod",
        "chown", "fchown", "lchown", "umask", "gettimeofday",
        "getrlimit", "getrusage", "sysinfo", "times", "getuid",
        "getgid", "geteuid", "getegid", "setuid", "setgid"
      ],
      "action": "SCMP_ACT_ALLOW"
    },
    {
      "names": ["ptrace", "reboot", "init_module", "delete_module"],
      "action": "SCMP_ACT_ERRNO",
      "comment": "Blocked for security"
    }
  ]
})";

/**
 * @brief Generate custom seccomp profile
 * @param allowed_syscalls Syscalls to allow
 * @param blocked_syscalls Syscalls to explicitly block
 * @return Seccomp profile JSON
 */
std::string GenerateProfile(const std::vector<std::string>& allowed_syscalls,
                           const std::vector<std::string>& blocked_syscalls);

} // namespace seccomp

} // namespace utils
} // namespace paramite