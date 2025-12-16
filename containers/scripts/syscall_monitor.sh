#!/bin/bash
SAMPLE="$1"
OUTPUT_FILE="/analysis/syscalls/strace.log"

if [ -z "$SAMPLE" ]; then
    echo "Usage: $0 <sample_path>"
    exit 1
fi

echo "Syscall Monitor: Tracing $SAMPLE" > "$OUTPUT_FILE"

FILE_TYPE=$(file "$SAMPLE")

if echo "$FILE_TYPE" | grep -q "PE32"; then
    strace -f -o "$OUTPUT_FILE" -s 200 wine "$SAMPLE" 2>&1
elif echo "$FILE_TYPE" | grep -q "ELF"; then
    strace -f -o "$OUTPUT_FILE" -s 200 "$SAMPLE" 2>&1
elif echo "$FILE_TYPE" | grep -q "script"; then
    if head -n1 "$SAMPLE" | grep -q "bash"; then
        strace -f -o "$OUTPUT_FILE" -s 200 bash "$SAMPLE" 2>&1
    elif head -n1 "$SAMPLE" | grep -q "python"; then
        strace -f -o "$OUTPUT_FILE" -s 200 python3 "$SAMPLE" 2>&1
    else
        bash "$SAMPLE" 2>&1
    fi
else
    echo "Unknown file type: $FILE_TYPE"
    exit 1
fi
