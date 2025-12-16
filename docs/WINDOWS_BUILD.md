# Building Paramite on Windows

This guide covers building Paramite on Windows for development and running the sandbox on Linux.

---

## Setup: Windows Development Environment

### Option 1: Visual Studio (Recommended)

#### Step 1: Install Visual Studio
1. Download [Visual Studio Community](https://visualstudio.microsoft.com/downloads/) (2019 or later)
2. During installation, select:
   - Desktop development with C++
   - CMake tools for Windows
   - Git for Windows

#### Step 2: Install vcpkg (Package Manager)
```powershell
# Open PowerShell as Administrator
cd C:\
git clone https://github.com/microsoft/vcpkg.git
cd vcpkg
.\bootstrap-vcpkg.bat
.\vcpkg integrate install

# Install OpenSSL
.\vcpkg install openssl:x64-windows
```

#### Step 3: Build Paramite
```powershell
# Clone or navigate to project
cd C:\path\to\paramite

# Create build directory
mkdir build
cd build

# Configure with CMake (vcpkg integration)
cmake .. -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake

# Build
cmake --build . --config Release

# Executable will be in: build\bin\Release\paramite.exe
```

---

### Option 2: MinGW-w64 (Lightweight Alternative)

#### Step 1: Install MSYS2
1. Download [MSYS2](https://www.msys2.org/)
2. Install to `C:\msys64`
3. Open MSYS2 MinGW 64-bit terminal

#### Step 2: Install Dependencies
```bash
# Update package database
pacman -Syu

# Install build tools
pacman -S mingw-w64-x86_64-gcc \
          mingw-w64-x86_64-cmake \
          mingw-w64-x86_64-openssl \
          git
```

#### Step 3: Build Paramite
```bash
cd /c/path/to/paramite

mkdir build && cd build
cmake .. -G "MinGW Makefiles"
cmake --build . --config Release

# Executable: build/bin/paramite.exe
```

---

## Hybrid Workflow: Windows Dev + Linux Sandbox

### Architecture
```
┌─────────────────────────────────────────────────────────┐
│                    Windows Host                         │
│  ┌───────────────────────────────────────────────────┐ │
│  │  Development                                       │ │
│  │  - Write C++ code (Visual Studio / VS Code)       │ │
│  │  - Test static analysis                           │ │
│  │  - Generate reports                               │ │
│  └───────────────────────────────────────────────────┘ │
│                         │                               │
│                         │ Shared Folder                 │
│                         ▼                               │
│  ┌───────────────────────────────────────────────────┐ │
│  │         VirtualBox - Linux VM                     │ │
│  │  ┌─────────────────────────────────────────────┐ │ │
│  │  │  Sandbox Environment                        │ │ │
│  │  │  - Docker for sample execution              │ │ │
│  │  │  - strace / tcpdump monitoring              │ │ │
│  │  │  - Copy samples from shared folder          │ │ │
│  │  └─────────────────────────────────────────────┘ │ │
│  └───────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

### Setup VirtualBox Shared Folder

#### On Windows:
1. Open VirtualBox Manager
2. Select your Linux VM → **Settings**
3. Go to **Shared Folders**
4. Add new folder:
   - **Folder Path**: `C:\path\to\paramite`
   - **Folder Name**: `paramite`
   - Auto-mount
   - Make Permanent

#### On Linux:
```bash
# Install VirtualBox Guest Additions (if not already)
sudo apt update
sudo apt install -y virtualbox-guest-utils virtualbox-guest-dkms

# Add your user to vboxsf group
sudo usermod -aG vboxsf $USER

# Reboot or re-login
sudo reboot

# Shared folder will be at: /media/sf_paramite
ls -la /media/sf_paramite

# Create a symlink for convenience
ln -s /media/sf_paramite ~/paramite
cd ~/paramite
```

---

## Development Workflow

### Step 1: Code on Windows
```powershell
# Edit code in Visual Studio or VS Code
code C:\path\to\paramite

# Build and test static analysis on Windows
cd C:\path\to\paramite\build
cmake --build . --config Release

# Test with EICAR sample
.\bin\Release\paramite.exe ..\samples\eicar.txt

# Check reports
dir ..\reports\
```

### Step 2: Test Sandbox on Linux
```bash
# SSH or directly on Linux VM
cd ~/paramite  # or /media/sf_paramite

# Build on Linux
mkdir build-linux && cd build-linux
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build .

# Run analysis on Linux
./bin/paramite ../samples/eicar.txt

# Build Docker sandbox image
docker build -f containers/Dockerfile.sandbox -t paramite-sandbox:latest .

# Test Docker sandbox
sudo docker run --rm -v $(pwd)/samples:/samples paramite-sandbox /samples/malware.exe
```

### Step 3: Sync Results
All reports are written to the shared folder, so they're instantly available on both systems!

---

## Building on Linux (for Sandbox Phase)

### Initial Setup
```bash
# On Linux VM (Ubuntu/Debian-based)
sudo apt update
sudo apt install -y \
    build-essential \
    cmake \
    git \
    libssl-dev \
    docker.io

# For RHEL/Fedora-based systems
# sudo dnf install -y gcc gcc-c++ cmake git openssl-devel docker

# Enable Docker
sudo systemctl enable docker
sudo systemctl start docker
sudo usermod -aG docker $USER

# Re-login for group changes
```

### Build Paramite
```bash
cd ~/paramite  # or /media/sf_paramite

# Run setup script
chmod +x scripts/*.sh
./scripts/setup_environment.sh

# Build
./scripts/build.sh

# Test
./build/bin/paramite samples/eicar.txt
```

### Build Docker Sandbox
```bash
# Build the sandbox container image
docker build -f containers/Dockerfile.sandbox -t paramite-sandbox:latest .

# Verify image was created
docker images | grep paramite-sandbox
```

---

## IDE Setup: Visual Studio Code (Cross-Platform)

### Install Extensions
```
- C/C++ (Microsoft)
- CMake Tools
- Remote - SSH (for Linux development)
```

### Configure CMake
Create settings.json:
```json
{
  "cmake.configureSettings": {
    "CMAKE_TOOLCHAIN_FILE": "C:/vcpkg/scripts/buildsystems/vcpkg.cmake"
  },
  "cmake.buildDirectory": "${workspaceFolder}/build",
  "C_Cpp.default.configurationProvider": "ms-vscode.cmake-tools"
}
```

### Remote Development (Optional)
Connect VS Code to Linux VM via SSH:
```bash
# On Linux, enable SSH
sudo systemctl enable ssh
sudo systemctl start ssh

# On Windows, in VS Code:
# Ctrl+Shift+P → "Remote-SSH: Connect to Host"
# Enter: user@linux-vm-ip
```

---

## Testing Your Setup

### Test 1: Build on Windows
```powershell
cd C:\path\to\paramite
mkdir build; cd build
cmake .. -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake
cmake --build . --config Release

# Should see: build\bin\Release\paramite.exe
```

### Test 2: Run Static Analysis
```powershell
# Create test sample
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > test.txt

# Analyze
.\build\bin\Release\paramite.exe test.txt

# Check output
dir reports\
```

### Test 3: Verify Shared Folder
```bash
# On Linux VM
ls -la /media/sf_paramite/
# Should see same files as Windows
```

---

## Running Paramite with Sandbox

### Basic Usage
```bash
# Navigate to your build directory
cd ~/paramite-build

# Run with sandbox on a suspicious executable
./bin/paramite \
    ~/malware-samples/suspicious.exe \
    --sandbox \
    --timeout 10 \
    -v

# Example with nested paths
./bin/paramite \
    ~/samples/malware/trojan.exe \
    --sandbox \
    --timeout 30 \
    -v
```

### Command Options
- `--sandbox`: Enable sandboxed execution
- `--timeout <seconds>`: Maximum execution time (default: 60)
- `-v`: Verbose output for detailed analysis logs

### Output
Reports will be generated in the reports directory with:
- JSON report with IOCs and behavior analysis
- HTML report for visualization
- Timeline of system events

---

## Common Issues & Solutions

### Issue 1: CMake can't find OpenSSL
**Solution**:
```powershell
# Make sure vcpkg is integrated
C:\vcpkg\vcpkg integrate install

# Specify toolchain file explicitly
cmake .. -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake
```

### Issue 2: "Permission denied" on shared folder (Linux)
**Solution**:
```bash
# Add user to vboxsf group
sudo usermod -aG vboxsf $USER
# Logout and login again
```

### Issue 3: Build fails with "filesystem not found"
**Solution**: Ensure C++17 is enabled
```cmake
# In CMakeLists.txt (already set):
set(CMAKE_CXX_STANDARD 17)
```

### Issue 4: Docker not working in Linux
**Solution**:
```bash
# Install Docker properly
sudo apt install -y docker.io
sudo systemctl start docker
sudo usermod -aG docker $USER
# Logout/login
```

---

## Next Steps

**Phase 1 Complete**: Static analysis works on Windows
**Phase 2 Next**: Implement Docker sandbox on Linux
   - Create Dockerfile for isolation
   - Implement container execution
   - Add monitoring (strace, tcpdump)

---

## Quick Reference Commands

### Windows (PowerShell)
```powershell
# Build
cd C:\path\to\paramite\build
cmake --build . --config Release

# Run analysis
.\bin\Release\paramite.exe ..\samples\test.exe

# View reports
explorer ..\reports\
```

### Linux (Bash)
```bash
# Build Paramite
cd ~/paramite/build-linux
cmake --build .

# Build Docker sandbox
docker build -f containers/Dockerfile.sandbox -t paramite-sandbox:latest .

# Run analysis with sandbox
./bin/paramite ~/samples/malware.exe --sandbox --timeout 10 -v

# View reports
ls -la ../reports/
```

---

Your Windows + Linux hybrid setup is ready for malware analysis.