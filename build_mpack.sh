#!/usr/bin/env bash
#
# Build script for the ODPSC Ambari Management Pack v2.
# Creates odpsc-mpack-2.0.tar.gz ready for installation via:
#   ambari-server install-mpack --mpack=odpsc-mpack-2.0.tar.gz
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MPACK_NAME="odpsc-mpack"
MPACK_VERSION="2.0"
MPACK_DIR="${SCRIPT_DIR}/odpsc-mpack"
BUILD_DIR="${SCRIPT_DIR}/build"
OUTPUT="${BUILD_DIR}/${MPACK_NAME}-${MPACK_VERSION}.tar.gz"

echo "=== Building ODPSC Management Pack v${MPACK_VERSION} ==="

# Validate mpack structure
echo "Validating mpack structure..."
required_files=(
    "${MPACK_DIR}/metainfo.xml"
    "${MPACK_DIR}/services/ODPSC/metainfo.xml"
    "${MPACK_DIR}/services/ODPSC/configuration/odpsc-site.xml"
    "${MPACK_DIR}/services/ODPSC/scripts/master.py"
    "${MPACK_DIR}/services/ODPSC/scripts/agent.py"
    "${MPACK_DIR}/services/ODPSC/resources/odpsc_master.py"
    "${MPACK_DIR}/services/ODPSC/resources/odpsc_agent.py"
    "${MPACK_DIR}/services/ODPSC/resources/analyzer.py"
    "${MPACK_DIR}/services/ODPSC/resources/audit.py"
    "${MPACK_DIR}/services/ODPSC/resources/collectors.py"
    "${MPACK_DIR}/services/ODPSC/resources/wsgi.py"
    "${MPACK_DIR}/services/ODPSC/resources/requirements.txt"
)

for f in "${required_files[@]}"; do
    if [[ ! -f "$f" ]]; then
        echo "ERROR: Missing required file: $f"
        exit 1
    fi
done
echo "All required files present."

# Verify Python syntax
echo "Checking Python syntax..."
python_files=(
    "${MPACK_DIR}/services/ODPSC/scripts/master.py"
    "${MPACK_DIR}/services/ODPSC/scripts/agent.py"
    "${MPACK_DIR}/services/ODPSC/resources/odpsc_master.py"
    "${MPACK_DIR}/services/ODPSC/resources/odpsc_agent.py"
    "${MPACK_DIR}/services/ODPSC/resources/analyzer.py"
    "${MPACK_DIR}/services/ODPSC/resources/audit.py"
    "${MPACK_DIR}/services/ODPSC/resources/collectors.py"
    "${MPACK_DIR}/services/ODPSC/resources/wsgi.py"
)

for f in "${python_files[@]}"; do
    python3 -c "import py_compile; py_compile.compile('$f', doraise=True)" || {
        echo "ERROR: Syntax error in $f"
        exit 1
    }
done
echo "Python syntax OK."

# Create build directory
mkdir -p "${BUILD_DIR}"

# Create tarball
echo "Creating tarball..."
tar -czf "${OUTPUT}" \
    -C "${SCRIPT_DIR}" \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    --transform "s|^odpsc-mpack|${MPACK_NAME}-${MPACK_VERSION}|" \
    odpsc-mpack/

echo "=== Build complete ==="
echo "Output: ${OUTPUT}"
echo ""
echo "Install with:"
echo "  ambari-server install-mpack --mpack=${OUTPUT}"
echo "  ambari-server restart"
