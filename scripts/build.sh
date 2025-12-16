#!/bin/bash
# Build script for Paramite Malware Analyzer

set -e  # Exit on error

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║            Paramite Malware Analyzer - Build Script           ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Paths
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="$HOME/paramite-build"
VCPKG_ROOT="$HOME/vcpkg"

# Check for CMake
if ! command -v cmake &> /dev/null; then
    echo -e "${RED}✗ CMake not found. Please install CMake 3.20+${NC}"
    exit 1
fi
echo -e "${GREEN}✓ CMake found: $(cmake --version | head -n 1)${NC}"

# Check for Ninja
if ! command -v ninja &> /dev/null; then
    echo -e "${RED}✗ Ninja not found. Installing...${NC}"
    sudo apt install -y ninja-build
fi
echo -e "${GREEN}✓ Ninja found: $(ninja --version)${NC}"

# Check for C++ compiler
if ! command -v g++ &> /dev/null && ! command -v clang++ &> /dev/null; then
    echo -e "${RED}✗ C++ compiler not found. Please install g++ or clang++${NC}"
    exit 1
fi
COMPILER_VERSION=$(g++ --version | head -n 1)
echo -e "${GREEN}✓ C++ compiler found: ${COMPILER_VERSION}${NC}"

# Check for vcpkg
if [ ! -d "$VCPKG_ROOT" ]; then
    echo -e "${YELLOW}⚠ vcpkg not found at $VCPKG_ROOT${NC}"
    echo -e "${YELLOW}  Please run: ${NC}"
    echo -e "${BLUE}    cd ~ && git clone https://github.com/Microsoft/vcpkg.git${NC}"
    echo -e "${BLUE}    cd vcpkg && ./bootstrap-vcpkg.sh${NC}"
    exit 1
fi
echo -e "${GREEN}✓ vcpkg found at $VCPKG_ROOT${NC}"

# Check for Docker
if command -v docker &> /dev/null; then
    echo -e "${GREEN}✓ Docker found: $(docker --version | cut -d' ' -f3)${NC}"
else
    echo -e "${YELLOW}⚠ Docker not found (optional for sandboxing)${NC}"
fi

# Parse arguments
CLEAN=false
VERBOSE=false
BUILD_TYPE="Release"

while [[ $# -gt 0 ]]; do
    case $1 in
        clean|--clean|-c)
            CLEAN=true
            shift
            ;;
        verbose|--verbose|-v)
            VERBOSE=true
            shift
            ;;
        debug|--debug|-d)
            BUILD_TYPE="Debug"
            shift
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            echo "Usage: $0 [clean] [verbose] [debug]"
            exit 1
            ;;
    esac
done

# Clean build directory if requested
if [ "$CLEAN" = true ]; then
    echo -e "${YELLOW}Cleaning build directory...${NC}"
    rm -rf "$BUILD_DIR"/*
fi

# Create build directory
mkdir -p "$BUILD_DIR"

echo ""
echo -e "${BLUE}Configuring with CMake...${NC}"
cmake -B "$BUILD_DIR" -S "$SOURCE_DIR" \
    -DCMAKE_BUILD_TYPE=$BUILD_TYPE \
    -DCMAKE_TOOLCHAIN_FILE="$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" \
    -G Ninja

echo ""
echo -e "${BLUE}Building Paramite...${NC}"
if [ "$VERBOSE" = true ]; then
    cmake --build "$BUILD_DIR" --config $BUILD_TYPE -j$(nproc) -v
else
    cmake --build "$BUILD_DIR" --config $BUILD_TYPE -j$(nproc)
fi

# Check if build succeeded
if [ ! -f "$BUILD_DIR/bin/paramite" ]; then
    echo -e "${RED}✗ Build failed - binary not found${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}╔═════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                 BUILD SUCCESSFUL!                   ║${NC}"
echo -e "${GREEN}╚═════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "Executable: ${BLUE}$BUILD_DIR/bin/paramite${NC}"
echo -e "Build type: ${BLUE}$BUILD_TYPE${NC}"
echo -e "Source dir: ${BLUE}$SOURCE_DIR${NC}"
echo ""

# Show binary info
BINARY_SIZE=$(du -h "$BUILD_DIR/bin/paramite" | cut -f1)
echo -e "Binary size: ${BLUE}$BINARY_SIZE${NC}"
echo ""

echo "Quick start:"
echo -e "  ${BLUE}$BUILD_DIR/bin/paramite --help${NC}"
echo -e "  ${BLUE}$BUILD_DIR/bin/paramite samples/test.txt${NC}"
echo -e "  ${BLUE}$BUILD_DIR/bin/paramite samples/test.txt -v${NC}"
echo ""

# Create convenience symlink
if [ ! -L "$SOURCE_DIR/paramite" ]; then
    ln -sf "$BUILD_DIR/bin/paramite" "$SOURCE_DIR/paramite"
    echo -e "${GREEN}✓ Created symlink: ./paramite -> $BUILD_DIR/bin/paramite${NC}"
fi

echo "You can also run: ${BLUE}./paramite samples/test.txt${NC}"
echo ""