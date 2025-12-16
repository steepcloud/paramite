#!/bin/bash
# Setup development environment for Paramite

set -e

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║       Paramite Malware Analyzer - Environment Setup          ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
    echo "Detected OS: Linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
    echo "Detected OS: macOS"
else
    echo "Unsupported OS: $OSTYPE"
    exit 1
fi

# Install dependencies based on OS
if [ "$OS" == "linux" ]; then
    echo ""
    echo "Installing dependencies for Linux..."
    
    # Check for package manager
    if command -v apt-get &> /dev/null; then
        echo "Using apt (Debian/Ubuntu)..."
        sudo apt-get update
        sudo apt-get install -y \
            build-essential \
            cmake \
            git \
            libssl-dev \
            pkg-config
    elif command -v dnf &> /dev/null; then
        echo "Using dnf (Fedora/RHEL)..."
        sudo dnf install -y \
            gcc-c++ \
            cmake \
            git \
            openssl-devel \
            pkg-config
    elif command -v pacman &> /dev/null; then
        echo "Using pacman (Arch Linux)..."
        sudo pacman -S --noconfirm \
            base-devel \
            cmake \
            git \
            openssl \
            pkg-config
    else
        echo "Unknown package manager. Please install manually:"
        echo "  - build-essential / gcc-c++"
        echo "  - cmake (3.15+)"
        echo "  - git"
        echo "  - OpenSSL development libraries"
        exit 1
    fi
    
elif [ "$OS" == "macos" ]; then
    echo ""
    echo "Installing dependencies for macOS..."
    
    if ! command -v brew &> /dev/null; then
        echo "Homebrew not found. Installing..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi
    
    brew install cmake openssl pkg-config
fi

# Create directories
echo ""
echo "Creating project directories..."
mkdir -p samples reports

# Create test samples
echo ""
echo "Creating test samples..."

# EICAR test file
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > samples/eicar.txt
echo "  ✓ Created samples/eicar.txt"

# High entropy file (simulates encrypted content)
if command -v dd &> /dev/null; then
    dd if=/dev/urandom of=samples/high_entropy.bin bs=1K count=10 2>/dev/null
    echo "  ✓ Created samples/high_entropy.bin"
fi

# Suspicious script
cat > samples/suspicious_test.sh << 'EOF'
#!/bin/bash
# TEST SAMPLE - Contains IOC strings for analysis
# This script is safe and does not execute malicious actions

# Fake C2 URLs
C2_SERVERS=(
    "http://malware-c2.example.com/api/register"
    "https://command.badactor.net/tasks"
    "ftp://exfil.evil.org/upload"
)

# Fake IPs
ATTACKER_IPS=(
    "192.168.100.50"
    "10.0.0.13"
    "203.0.113.37"
)

# Fake file paths
SENSITIVE_FILES=(
    "/etc/shadow"
    "/root/.ssh/id_rsa"
    "C:\\Windows\\System32\\config\\SAM"
    "C:\\Users\\Administrator\\Desktop\\passwords.txt"
)

echo "Test sample with interesting strings"
EOF
chmod +x samples/suspicious_test.sh
echo "  ✓ Created samples/suspicious_test.sh"

echo ""
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║              ENVIRONMENT SETUP COMPLETE!                      ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""
echo "Next steps:"
echo "  1. Build the project:    ./scripts/build.sh"
echo "  2. Run analysis:         ./build/bin/paramite samples/eicar.txt"
echo "  3. View reports:         ls -la reports/"
echo ""
