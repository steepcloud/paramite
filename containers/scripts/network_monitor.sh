#!/bin/bash
OUTPUT_FILE="/analysis/network/traffic.pcap"
echo "Network Monitor Started: $(date)"

tcpdump -i any -w "$OUTPUT_FILE" -v 2>&1 &
echo $! > /var/run/network_monitor.pid
