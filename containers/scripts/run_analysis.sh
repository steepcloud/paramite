#!/bin/bash
set -e

SAMPLE="$1"
TIMEOUT="${2:-300}"

if [ -z "$SAMPLE" ]; then
    echo "Usage: $0 <sample_path> [timeout_seconds]"
    exit 1
fi

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║        PARAMITE SANDBOX EXECUTION ENVIRONMENT                 ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""
echo "Sample: $SAMPLE"
echo "Timeout: ${TIMEOUT}s"
echo "Start time: $(date)"
echo ""

echo "Starting monitors..."
bash /usr/local/bin/monitors/file_monitor.sh &
bash /usr/local/bin/monitors/network_monitor.sh &
bash /usr/local/bin/monitors/process_monitor.sh &

sleep 2

echo "Monitors active. Executing sample..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

timeout "$TIMEOUT" bash /usr/local/bin/monitors/syscall_monitor.sh "$SAMPLE" || true

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Execution complete. Stopping monitors..."

for pid_file in /var/run/*_monitor.pid; do
    if [ -f "$pid_file" ]; then
        PID=$(cat "$pid_file")
        kill $PID 2>/dev/null || true
        rm "$pid_file"
    fi
done

echo ""
echo "Analysis artifacts:"
ls -lh /analysis/*/

echo ""
echo "End time: $(date)"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                   ANALYSIS COMPLETE                           ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
