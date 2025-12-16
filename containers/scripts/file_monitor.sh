#!/bin/bash
OUTPUT_FILE="/analysis/files/file_changes.log"
echo "File Monitor Started: $(date)" > "$OUTPUT_FILE"

inotifywait -m -r -e create,delete,modify,move \
    --format '%T %e %w%f' \
    --timefmt '%Y-%m-%d %H:%M:%S' \
    /tmp /home /var 2>&1 | tee -a "$OUTPUT_FILE" &

echo $! > /var/run/file_monitor.pid
