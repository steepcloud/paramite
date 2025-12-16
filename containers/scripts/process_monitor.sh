#!/bin/bash
OUTPUT_FILE="/analysis/processes/process_tree.log"
echo "Process Monitor Started: $(date)" > "$OUTPUT_FILE"

while true; do
    echo "=== $(date) ===" >> "$OUTPUT_FILE"
    ps auxf >> "$OUTPUT_FILE"
    sleep 2
done &

echo $! > /var/run/process_monitor.pid
