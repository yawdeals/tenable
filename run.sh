#!/bin/bash
# Tenable HEC Collector Runner
# Runs the collector using Python 3.11 (no virtual environment)

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Python executable (use python3.11 explicitly)
PYTHON_CMD="python3.11"

# Check if Python 3.11 is available
if ! command -v "$PYTHON_CMD" &> /dev/null; then
    echo "ERROR: $PYTHON_CMD not found"
    echo "Install Python 3.11 or update PYTHON_CMD in this script"
    exit 1
fi

# Verify Python version is 3.10+
PYTHON_VERSION=$("$PYTHON_CMD" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "Using Python $PYTHON_VERSION"

# Create logs directory if needed
mkdir -p logs

# Run the collector
"$PYTHON_CMD" tenable_collector.py "$@"

# Capture exit code
EXIT_CODE=$?

exit $EXIT_CODE
