#!/bin/bash
# 
# Wrapper script for http_grabber.py to match original binary interface
# Usage: ./http_grabber_wrapper.sh -h <hosts> -p <paths> -s <search> -o <output> -v <vipcode>
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_SCRIPT="$SCRIPT_DIR/http_grabber.py"

# Default values
THREADS=10
TIMEOUT=10

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h)
            HOSTS="$2"
            shift 2
            ;;
        -p)
            PATHS="$2"
            shift 2
            ;;
        -s)
            SEARCH="$2"
            shift 2
            ;;
        -o)
            OUTPUT="$2"
            shift 2
            ;;
        -t)
            THREADS="$2"
            shift 2
            ;;
        -v)
            # VIPCODE - ignored in our free implementation
            VIPCODE="$2"
            echo "Note: VIPCODE is not required in this free implementation"
            shift 2
            ;;
        -H|-P)
            # Ignore main send host/port for now
            shift 2
            ;;
        --help)
            echo "HTTP Grabber - Free Python Implementation"
            echo "Usage: $0 -h <hosts_file> -p <paths_file> -s <search_file> -o <output_file> [-t threads] [-v vipcode]"
            echo ""
            echo "Note: This is a free replacement for the original binary. No VIPCODE required!"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Check required parameters
if [[ -z "$HOSTS" || -z "$PATHS" || -z "$SEARCH" || -z "$OUTPUT" ]]; then
    echo "Error: Missing required parameters"
    echo "Usage: $0 -h <hosts_file> -p <paths_file> -s <search_file> -o <output_file> [-t threads] [-v vipcode]"
    exit 1
fi

# Run the Python script
python3 "$PYTHON_SCRIPT" --hosts "$HOSTS" -p "$PATHS" -s "$SEARCH" -o "$OUTPUT" -t "$THREADS" --timeout "$TIMEOUT"