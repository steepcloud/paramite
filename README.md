# Paramite

**Container-based malware analysis with behavioral monitoring and threat reporting**

*Inspired by Oddworld's Paramites — small, persistent, and loyal trackers of their targets.*

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![C++](https://img.shields.io/badge/C%2B%2B-20-blue.svg)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey.svg)

Paramite tracks malware with the same persistence as its Oddworld namesake. This comprehensive analysis framework combines static analysis, dynamic behavior monitoring, and containerized sandbox execution to hunt down threats and provide detailed intelligence reports. Built with modern C++, it offers both command-line and programmatic interfaces for automated malware analysis workflows.

---

## Features

### Static Analysis
- **File Type Detection**: Automatic identification of executables, scripts, and documents
- **Hash Generation**: MD5, SHA-1, SHA-256 for sample fingerprinting
- **String Extraction**: URLs, IPs, file paths, registry keys, and suspicious patterns
- **Signature Matching**: YARA-like pattern detection for known malware families
- **Entropy Analysis**: Detection of packed/encrypted sections

### Dynamic Analysis
- **Sandboxed Execution**: Docker-based isolation for safe malware detonation
- **System Call Monitoring**: strace integration for low-level API tracking
- **File System Monitoring**: Track file creation, modification, and deletion
- **Network Monitoring**: Capture DNS queries, HTTP requests, and network connections
- **Process Monitoring**: Parent-child relationships and process injection detection

### Behavioral Analysis
- **Threat Scoring**: Automated risk assessment based on observed behaviors
- **IOC Extraction**: Automatic extraction of Indicators of Compromise
- **Pattern Recognition**: Detection of common malware techniques (persistence, privilege escalation, etc.)
- **Timeline Generation**: Chronological reconstruction of malware execution

### Reporting
- **HTML Reports**: Rich, interactive reports with visualizations
- **JSON Reports**: Machine-readable output for integration with SIEM/SOAR platforms
- **IOC Export**: Structured IOC lists for threat intelligence sharing
- **Summary Reports**: Executive summaries with threat scores and key findings

---

## Quick Start

### Prerequisites

**Linux (Recommended for sandbox execution):**
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install build-essential cmake git libssl-dev docker.io

# RHEL/Fedora
sudo dnf install gcc gcc-c++ cmake git openssl-devel docker
```

**Windows (Development):**
- Visual Studio 2019+ with C++ development tools
- CMake 3.20+
- vcpkg for package management

See WINDOWS_BUILD.md for detailed Windows setup instructions.

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/paramite.git
cd paramite

# Run setup script (Linux)
chmod +x scripts/*.sh
./scripts/setup_environment.sh

# Build
./scripts/build.sh

# Or build manually
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build .
```

### Basic Usage

```bash
# Static analysis only
./bin/paramite /path/to/sample.exe

# With sandboxed execution
./bin/paramite /path/to/sample.exe --sandbox --timeout 60 -v

# Specify custom output directory
./bin/paramite /path/to/sample.exe --output ./reports --sandbox
```

### Docker Sandbox

```bash
# Build the sandbox container
docker build -f containers/Dockerfile.sandbox -t paramite-sandbox:latest .

# Paramite will automatically use the container when --sandbox is specified
```

---

## Command-Line Options

```
USAGE:
  paramite [OPTIONS] <sample_path>

POSITIONAL ARGUMENTS:
  sample_path         Path to the malware sample to analyze

OPTIONS:
  -h,--help           Print this help message and exit
  -v,--verbose        Enable verbose logging
  -s,--sandbox        Enable sandboxed execution (requires Docker)
  -t,--timeout <sec>  Sandbox execution timeout in seconds (default: 60)
  -o,--output <dir>   Output directory for reports (default: ./reports)
  --no-static         Skip static analysis
  --no-dynamic        Skip dynamic analysis
  --format <type>     Report format: html, json, or both (default: both)
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Analysis Engine                      │
│  ┌───────────────┐  ┌──────────────┐  ┌─────────────┐ │
│  │Static Analyzer│  │Sandbox Engine│  │Behavior     │ │
│  │- Hash         │  │- Docker Mgmt │  │Analyzer     │ │
│  │- Strings      │  │- strace      │  │- IOC Extract│ │
│  │- Entropy      │  │- Monitoring  │  │- Scoring    │ │
│  └───────────────┘  └──────────────┘  └─────────────┘ │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│                    Monitors & Parsers                    │
│  ┌──────────┐  ┌──────────┐  ┌────────┐  ┌──────────┐ │
│  │File      │  │Network   │  │Process │  │Syscall   │ │
│  │Monitor   │  │Monitor   │  │Monitor │  │Monitor   │ │
│  └──────────┘  └──────────┘  └────────┘  └──────────┘ │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│                    Report Generation                     │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │
│  │HTML Reporter │  │JSON Reporter │  │IOC Extractor │ │
│  └──────────────┘  └──────────────┘  └──────────────┘ │
└─────────────────────────────────────────────────────────┘
```

---

## Output Examples

### Console Output
```
╔═══════════════════════════════════════════════════════════════╗
║                     ANALYSIS SUMMARY                          ║
╚═══════════════════════════════════════════════════════════════╝
║  Sample: suspicious.exe                                       ║
║  SHA-256: 3110324542ac6391881ed6d8ad69843d52fd11f5399cb8...  ║
║  Type: PE32 executable                                        ║
║  Size: 245.5 KB                                               ║
║  Threat Score: 87/100 - HIGH RISK                             ║
╠═══════════════════════════════════════════════════════════════╣
║  Key Findings:                                                ║
║    • Registry modification detected                           ║
║    • Network connections to suspicious domains                ║
║    • Process injection attempt                                ║
║    • File system tampering                                    ║
╚═══════════════════════════════════════════════════════════════╝

Reports generated:
  • reports/sample_20241216_summary.json
  • reports/sample_20241216_report.html
  • reports/sample_20241216_iocs.json
```

### Report Files
- **HTML Report**: Interactive visualization with charts, timelines, and detailed findings
- **JSON Report**: Complete analysis data in machine-readable format
- **IOC Export**: IP addresses, domains, file hashes, registry keys for threat intelligence

---

## Project Structure

```
paramite/
├── include/paramite/         # Header files
│   ├── analyzers/           # Static & behavior analysis
│   ├── core/                # Analysis engine, sandbox
│   ├── monitors/            # System monitors
│   ├── parsers/             # Log parsers (strace, wine)
│   ├── reporters/           # Report generators
│   └── utils/               # Utilities (hash, string, container)
├── src/                     # Implementation files
├── containers/              # Docker sandbox definition
├── scripts/                 # Build and setup scripts
├── samples/                 # Test samples
├── reports/                 # Generated reports (output)
└── docs/                    # Documentation
```

---

## Dependencies

Paramite uses the following libraries:
- **spdlog**: Fast logging library
- **nlohmann/json**: JSON parsing and generation
- **CLI11**: Command-line argument parsing
- **Boost**: Filesystem and system utilities
- **OpenSSL**: Cryptographic hash functions

All dependencies are managed via [vcpkg](https://github.com/microsoft/vcpkg).

---

## Development

### Building from Source

```bash
# Install dependencies
./scripts/setup_environment.sh

# Build in debug mode
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug
cmake --build .

# Run tests (if available)
ctest --output-on-failure
```

### Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## Roadmap

- [x] Static analysis engine
- [x] Docker sandbox integration
- [x] Behavioral analysis and IOC extraction
- [x] HTML/JSON reporting
- [ ] YARA rule integration
- [ ] Machine learning-based threat classification
- [ ] Distributed analysis cluster support
- [ ] API server for remote analysis
- [ ] Web-based dashboard

---

## License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## Disclaimer

**This tool is intended for security research and malware analysis purposes only.** Always analyze malware samples in isolated environments. I'm not responsible for any misuse or damage caused by this tool.

---

## Acknowledgments

- Inspired by tools like Cuckoo Sandbox and Sandboxie
- Built with modern C++ best practices
