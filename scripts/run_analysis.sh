#!/bin/bash
# Quick analysis script - runs Paramite on a sample

if [ $# -eq 0 ]; then
    echo "Usage: $0 <sample_file> [options]"
    echo ""
    echo "Examples:"
    echo "  $0 malware.exe"
    echo "  $0 -v suspicious.pdf"
    echo "  $0 --json-only payload.bin"
    exit 1
fi

PARAMITE_BIN="./build/bin/paramite"

if [ ! -f "$PARAMITE_BIN" ]; then
    echo "Error: Paramite not built. Run ./scripts/build.sh first"
    exit 1
fi

echo "Running Paramite Malware Analyzer..."
echo "═══════════════════════════════════════════════════════════════"
echo ""

$PARAMITE_BIN "$@"

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "Analysis complete. Check ./reports/ for detailed results."
