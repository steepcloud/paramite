/**
 * @file sandbox_engine.hpp
 * @brief Isolated malware execution environment with comprehensive monitoring
 * 
 * Manages Docker-based sandbox environments for safe malware execution with
 * resource limits, network isolation, and multi-source monitoring. Supports
 * both local Docker execution and remote VM communication for Windows malware
 * analysis on Linux platforms.
 * 
 * @date 2025
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <filesystem>
#include <optional>
#include <chrono>
#include <functional>
#include <future>

namespace paramite {
namespace core {

/**
 * @enum SandboxStatus
 * @brief Current state of sandbox execution
 * 
 * Tracks the lifecycle of a sandbox execution from preparation through
 * completion or failure.
 */
enum class SandboxStatus {
    IDLE,        ///< Sandbox not running
    PREPARING,   ///< Setting up container and environment
    EXECUTING,   ///< Malware actively running
    MONITORING,  ///< Collecting monitoring data
    COMPLETED,   ///< Execution finished successfully
    TIMEOUT,     ///< Execution exceeded time limit
    CRASHED,     ///< Sample or container crashed
    FAILED       ///< Execution failed (setup error, Docker error)
};

/**
 * @enum NetworkMode
 * @brief Network isolation configuration for sandbox
 * 
 * Controls network access level within the sandbox environment.
 * Higher levels increase risk of malware escaping or causing damage.
 */
enum class NetworkMode {
    ISOLATED,     ///< No network access (safest)
    SIMULATED,    ///< Fake internet with INetSim (safe, allows network analysis)
    RESTRICTED,   ///< Limited real internet with firewall rules (moderate risk)
    FULL          ///< Full internet access (DANGEROUS - use only in isolated VM)
};

/**
 * @struct SandboxExecutionResult
 * @brief Complete results of sandbox execution
 * 
 * Contains execution status, outputs, monitoring data paths, resource
 * usage statistics, and timing information from a sandbox run.
 */
struct SandboxExecutionResult {
    SandboxStatus status{SandboxStatus::IDLE};  ///< Final execution status
    int exit_code{0};                           ///< Process exit code
    std::string stdout_output;                  ///< Standard output capture
    std::string stderr_output;                  ///< Standard error capture
    
    // Monitoring Output Paths
    std::filesystem::path strace_log;           ///< System call trace log
    std::filesystem::path wine_log;             ///< Wine debug output (for Windows PE)
    std::filesystem::path network_pcap;         ///< Network packet capture
    std::filesystem::path file_changes_log;     ///< File system modification log
    
    // Execution Timing
    std::chrono::system_clock::time_point start_time;  ///< Execution start
    std::chrono::system_clock::time_point end_time;    ///< Execution end
    std::chrono::milliseconds execution_duration{0};   ///< Total runtime
    
    // Resource Usage Statistics
    std::size_t peak_memory_mb{0};      ///< Maximum memory usage (MB)
    float peak_cpu_percent{0.0f};       ///< Peak CPU utilization (%)
    std::size_t disk_writes_bytes{0};   ///< Total bytes written to disk
    int network_connections{0};         ///< Number of network connections attempted
    
    // Error Information
    bool has_error{false};              ///< Error occurred during execution
    std::string error_message;          ///< Error description
};

/**
 * @struct ResourceLimits
 * @brief Resource constraints for sandbox execution
 * 
 * Defines hard limits on system resources to prevent malware from
 * exhausting host resources or causing denial of service.
 */
struct ResourceLimits {
    std::size_t max_memory_mb{2048};           ///< Memory limit (2GB default)
    int max_cpu_cores{2};                      ///< CPU core limit
    float max_cpu_percent{80.0f};              ///< CPU utilization cap (%)
    std::size_t max_disk_mb{1024};             ///< Disk space limit (1GB default)
    int max_network_bandwidth_kbps{1024};      ///< Network bandwidth cap (1 Mbps)
    int max_processes{100};                    ///< Maximum process count
    int max_open_files{1024};                  ///< File descriptor limit
};

/**
 * @struct SandboxConfig
 * @brief Comprehensive sandbox configuration
 * 
 * Controls all aspects of sandbox behavior including execution parameters,
 * monitoring options, resource limits, network settings, and Docker configuration.
 */
struct SandboxConfig {
    // Execution Settings
    std::chrono::seconds timeout{300};                ///< Execution timeout (5 min default)
    NetworkMode network_mode{NetworkMode::ISOLATED};  ///< Network isolation level
    ResourceLimits resource_limits;                   ///< Resource constraints
    
    // Monitoring Options
    bool enable_strace{true};            ///< Capture system calls
    bool enable_network_capture{true};   ///< Capture network traffic (PCAP)
    bool enable_file_monitoring{true};   ///< Monitor file system changes
    bool enable_process_monitoring{true}; ///< Track process creation/termination
    bool capture_screenshots{false};     ///< Periodic screenshots (Windows malware)
    
    // Environment Configuration
    std::map<std::string, std::string> environment_variables;  ///< Custom env vars
    std::vector<std::string> command_line_args;                ///< Args to pass to sample
    std::filesystem::path working_directory{"/tmp"};           ///< Initial working dir
    
    // Docker Settings
    std::string docker_image{"paramite-sandbox:latest"};  ///< Container image name
    bool privileged_mode{false};                           ///< Run privileged (dangerous)
    std::vector<std::string> docker_volumes;               ///< Volume mounts
    std::vector<std::string> docker_capabilities;          ///< Linux capabilities to add
    
    // VM Communication (Windows host → Linux VM setup)
    std::string vm_ssh_host{"192.168.56.101"};        ///< VM SSH address
    int vm_ssh_port{22};                               ///< VM SSH port
    std::string vm_ssh_user{"kali"};                   ///< VM SSH username
    std::filesystem::path vm_shared_folder{"/mnt/shared"};  ///< Shared directory path
    
    // Output Configuration
    std::filesystem::path output_directory{"./sandbox_output"};  ///< Monitoring output dir
    bool preserve_container{false};                              ///< Keep container for forensics
    bool verbose_logging{false};                                 ///< Enable debug logging
};

/**
 * @class SandboxEngine
 * @brief Isolated malware execution environment manager
 * 
 * Orchestrates secure malware execution in Docker containers with:
 * 
 * - **Isolation**: Container-based execution with resource limits
 * - **Monitoring**: Multi-source data collection (syscalls, network, files, processes)
 * - **Safety**: Network isolation, resource constraints, timeout enforcement
 * - **Cross-platform**: Supports Windows PE execution via Wine on Linux
 * - **VM Integration**: SSH-based communication with remote analysis VM
 * - **Artifact Management**: Automated collection and cleanup
 * 
 * **Architecture**:
 * ```
 * Windows Host (Paramite)
 *     ↓ SSH/Shared Folder
 * Linux VM (Kali)
 *     ↓ Docker API
 * Sandbox Container
 *     ├─ Wine (PE execution)
 *     ├─ strace (syscall monitoring)
 *     ├─ tcpdump (network capture)
 *     └─ inotify (file monitoring)
 * ```
 * 
 * **Thread Safety**: NOT thread-safe. Use separate instances for concurrent execution.
 * 
 * **Usage Example**:
 * @code
 * // Configure sandbox
 * SandboxConfig config;
 * config.timeout = std::chrono::seconds(300);
 * config.network_mode = NetworkMode::ISOLATED;
 * config.resource_limits.max_memory_mb = 2048;
 * config.enable_strace = true;
 * config.enable_network_capture = true;
 * 
 * SandboxEngine sandbox(config);
 * 
 * // Initialize
 * if (!sandbox.Initialize()) {
 *     std::cerr << "Failed to initialize sandbox" << std::endl;
 *     return;
 * }
 * 
 * // Execute malware
 * auto result = sandbox.Execute("/path/to/malware.exe");
 * 
 * if (result.status == SandboxStatus::COMPLETED) {
 *     std::cout << "Execution completed" << std::endl;
 *     std::cout << "Exit code: " << result.exit_code << std::endl;
 *     std::cout << "Strace log: " << result.strace_log << std::endl;
 *     std::cout << "PCAP: " << result.network_pcap << std::endl;
 * } else if (result.status == SandboxStatus::TIMEOUT) {
 *     std::cout << "Execution timed out" << std::endl;
 * }
 * 
 * // Cleanup
 * sandbox.Cleanup();
 * @endcode
 */
class SandboxEngine {
public:
    /**
     * @brief Construct sandbox engine with custom configuration
     * @param config Sandbox configuration
     */
    explicit SandboxEngine(const SandboxConfig& config = SandboxConfig{});
    
    ~SandboxEngine();

    SandboxEngine(const SandboxEngine&) = delete;
    SandboxEngine& operator=(const SandboxEngine&) = delete;

    /**
     * @brief Initialize sandbox environment
     * 
     * Performs setup and validation:
     * - Checks Docker availability and version
     * - Builds sandbox container image (if needed)
     * - Creates shared folders for VM communication
     * - Tests VM SSH connectivity
     * - Validates configuration
     * 
     * @return true if initialization successful
     * 
     * @note Must be called before Execute()
     */
    bool Initialize();

    /**
     * @brief Execute malware sample in sandbox
     * 
     * Complete execution workflow:
     * 1. Prepare sample (copy to VM, set permissions)
     * 2. Create Docker container with monitoring
     * 3. Execute sample (Wine for PE, native for ELF/scripts)
     * 4. Monitor execution (strace, tcpdump, inotify, process tree)
     * 5. Enforce timeout and resource limits
     * 6. Collect artifacts (logs, PCAP, file changes)
     * 7. Stop and remove container
     * 
     * @param sample_path Path to malware sample file
     * @return SandboxExecutionResult with status, outputs, and monitoring data
     * 
     * @throws std::runtime_error if sandbox not initialized
     * @throws std::runtime_error if sample file doesn't exist
     * 
     * **Performance**: Execution time = sample runtime + ~5s overhead
     */
    SandboxExecutionResult Execute(const std::filesystem::path& sample_path);

    /**
     * @brief Execute malware sample asynchronously
     * 
     * Starts execution in background thread with progress monitoring.
     * Useful for long-running samples or GUI applications.
     * 
     * @param sample_path Path to malware sample
     * @param callback Progress callback (status, progress percentage)
     * @return Future that resolves to SandboxExecutionResult
     * 
     * **Example**:
     * @code
     * auto future = sandbox.ExecuteAsync("/path/to/malware.exe", 
     *     [](SandboxStatus status, float progress) {
     *         std::cout << "Status: " << static_cast<int>(status) 
     *                   << ", Progress: " << progress << "%" << std::endl;
     *     }
     * );
     * 
     * // Do other work...
     * 
     * auto result = future.get();  // Wait for completion
     * @endcode
     */
    std::future<SandboxExecutionResult> ExecuteAsync(
        const std::filesystem::path& sample_path,
        std::function<void(SandboxStatus, float)> callback = nullptr
    );

    /**
     * @brief Stop currently executing sandbox
     * 
     * Forcefully terminates running container and processes.
     * Monitoring data collected up to this point is preserved.
     * 
     * @return true if stopped successfully
     */
    bool StopExecution();

    /**
     * @brief Clean up sandbox artifacts
     * 
     * Removes containers, temporary files, and shared folder contents.
     * Preserves monitoring outputs in configured output directory.
     */
    void Cleanup();

    /**
     * @brief Check if Docker is available and accessible
     * @return true if Docker daemon is running and responsive
     */
    bool IsDockerAvailable() const;

    /**
     * @brief Check if VM is reachable via SSH
     * @return true if VM responds to SSH connection attempt
     */
    bool IsVMReachable() const;

    /**
     * @brief Get current sandbox execution status
     * @return Current SandboxStatus enum value
     */
    SandboxStatus GetStatus() const { return current_status_; }

    /**
     * @brief Get current configuration
     * @return Reference to SandboxConfig structure
     */
    const SandboxConfig& GetConfig() const { return config_; }

    /**
     * @brief Update sandbox configuration
     * 
     * @param config New configuration
     * @note Changes apply to next execution only (not active runs)
     */
    void UpdateConfig(const SandboxConfig& config);

    /**
     * @brief Build Docker sandbox container image
     * 
     * Builds image from Dockerfile.sandbox with all monitoring tools
     * and Wine runtime. Only needs to be done once or when updating.
     * 
     * @return true if build successful
     * 
     * **Build Time**: ~5-10 minutes (downloads packages, installs Wine)
     */
    bool BuildSandboxImage();

    /**
     * @brief List available sandbox images on system
     * @return Vector of image names/tags
     */
    std::vector<std::string> ListSandboxImages() const;

    /**
     * @brief Get resource usage of running sandbox
     * 
     * @return Map of resource type to usage value
     * 
     * **Keys**: "memory_mb", "cpu_percent", "disk_read_bytes", "disk_write_bytes",
     * "network_rx_bytes", "network_tx_bytes"
     */
    std::map<std::string, double> GetResourceUsage() const;

private:
    SandboxConfig config_;                        ///< Configuration
    SandboxStatus current_status_{SandboxStatus::IDLE};  ///< Current status
    std::string current_container_id_;            ///< Running container ID
    
    // Internal methods
    bool PrepareSample(const std::filesystem::path& sample_path,
                      std::filesystem::path& sandbox_sample_path);
    std::string CreateContainer(const std::filesystem::path& sample_path);
    bool StartMonitoring(const std::string& container_id);
    SandboxExecutionResult ExecuteInContainer(
        const std::string& container_id,
        const std::filesystem::path& sample_path
    );
    void CollectMonitoringData(SandboxExecutionResult& result);
    void RemoveContainer(const std::string& container_id);
    bool CopyToVM(const std::filesystem::path& local_path,
                  const std::filesystem::path& vm_path);
    bool CopyFromVM(const std::filesystem::path& vm_path,
                    const std::filesystem::path& local_path);
    std::string ExecuteOnVM(const std::string& command);
    std::string GenerateDockerCommand(
        const std::filesystem::path& sample_path,
        const std::string& container_name
    );
    std::vector<std::string> GetResourceLimitArgs() const;
    std::vector<std::string> GetNetworkArgs() const;
    void MonitorResourceUsage(const std::string& container_id,
                             SandboxExecutionResult& result);
    bool CheckTimeout(const std::chrono::system_clock::time_point& start_time) const;
    std::vector<std::string> ParseStraceLog(const std::filesystem::path& log_path);
    std::vector<std::string> ParseNetworkCapture(const std::filesystem::path& pcap_path);
    void DetectAnomalies(SandboxExecutionResult& result);
    std::string GenerateContainerName() const;
    bool ValidateConfig() const;
    void LogEvent(const std::string& event, const std::string& details = "");
};

/**
 * @class SandboxBuilder
 * @brief Fluent API for constructing sandbox configurations
 * 
 * Provides a convenient builder pattern for creating SandboxConfig objects
 * with method chaining for improved readability.
 * 
 * **Usage Example**:
 * @code
 * auto config = SandboxBuilder()
 *     .WithTimeout(std::chrono::seconds(600))
 *     .WithNetworkMode(NetworkMode::SIMULATED)
 *     .WithMemoryLimit(4096)
 *     .WithCPULimit(4)
 *     .EnableStrace()
 *     .EnableNetworkCapture()
 *     .WithOutputDirectory("./analysis_results")
 *     .Build();
 * 
 * SandboxEngine sandbox(config);
 * @endcode
 */
class SandboxBuilder {
public:
    /**
     * @brief Set execution timeout
     * @param timeout Timeout duration
     * @return Reference to builder for chaining
     */
    SandboxBuilder& WithTimeout(std::chrono::seconds timeout) {
        config_.timeout = timeout;
        return *this;
    }
    
    /**
     * @brief Set network isolation mode
     * @param mode Network mode
     * @return Reference to builder for chaining
     */
    SandboxBuilder& WithNetworkMode(NetworkMode mode) {
        config_.network_mode = mode;
        return *this;
    }
    
    /**
     * @brief Set memory limit
     * @param mb Memory limit in megabytes
     * @return Reference to builder for chaining
     */
    SandboxBuilder& WithMemoryLimit(std::size_t mb) {
        config_.resource_limits.max_memory_mb = mb;
        return *this;
    }
    
    /**
     * @brief Set CPU core limit
     * @param cores Number of CPU cores
     * @return Reference to builder for chaining
     */
    SandboxBuilder& WithCPULimit(int cores) {
        config_.resource_limits.max_cpu_cores = cores;
        return *this;
    }
    
    /**
     * @brief Enable/disable strace monitoring
     * @param enable Enable flag (default: true)
     * @return Reference to builder for chaining
     */
    SandboxBuilder& EnableStrace(bool enable = true) {
        config_.enable_strace = enable;
        return *this;
    }
    
    /**
     * @brief Enable/disable network packet capture
     * @param enable Enable flag (default: true)
     * @return Reference to builder for chaining
     */
    SandboxBuilder& EnableNetworkCapture(bool enable = true) {
        config_.enable_network_capture = enable;
        return *this;
    }
    
    /**
     * @brief Set output directory for monitoring artifacts
     * @param dir Output directory path
     * @return Reference to builder for chaining
     */
    SandboxBuilder& WithOutputDirectory(const std::filesystem::path& dir) {
        config_.output_directory = dir;
        return *this;
    }
    
    /**
     * @brief Set VM SSH host address
     * @param host VM hostname or IP
     * @return Reference to builder for chaining
     */
    SandboxBuilder& WithVMHost(const std::string& host) {
        config_.vm_ssh_host = host;
        return *this;
    }
    
    /**
     * @brief Set command-line arguments for sample
     * @param args Vector of arguments
     * @return Reference to builder for chaining
     */
    SandboxBuilder& WithCommandLineArgs(const std::vector<std::string>& args) {
        config_.command_line_args = args;
        return *this;
    }
    
    /**
     * @brief Build final configuration
     * @return Constructed SandboxConfig
     */
    SandboxConfig Build() const {
        return config_;
    }

private:
    SandboxConfig config_;  ///< Configuration being built
};

} // namespace core
} // namespace paramite