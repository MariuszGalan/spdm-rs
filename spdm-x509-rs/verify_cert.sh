#!/bin/bash
#
# X.509 Certificate Verification Script
#
# This script provides a convenient wrapper around the Rust certificate
# verification tool with enhanced error handling and output formatting.
#
# Usage: ./verify_cert.sh <certificate-file> [--json output.json]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"  # Parent workspace (spdm-rs)
CERT_FILE=""
JSON_OUTPUT=""

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Parse arguments
if [ $# -lt 1 ]; then
    echo "X.509 Certificate Verification Tool"
    echo ""
    echo "Usage: $0 <certificate-file> [--json output.json]"
    echo ""
    echo "Examples:"
    echo "  $0 mycert.der"
    echo "  $0 mycert.pem --json report.json"
    echo ""
    echo "Supported formats: DER (.der, .crt), PEM (.pem)"
    exit 1
fi

CERT_FILE="$1"

if [ ! -f "$CERT_FILE" ]; then
    echo -e "${RED}Error: Certificate file not found: $CERT_FILE${NC}"
    exit 1
fi

# Convert to absolute path before changing directory
CERT_FILE="$(cd "$(dirname "$CERT_FILE")" && pwd)/$(basename "$CERT_FILE")"

# Check for JSON output flag
if [ $# -ge 3 ] && [ "$2" = "--json" ]; then
    JSON_OUTPUT="$3"
fi

# Build the command
MANIFEST_PATH="$PROJECT_DIR/Cargo.toml"
CMD="cargo run --quiet --manifest-path \"$MANIFEST_PATH\" -p spdm-x509-rs --example cert_verify '$CERT_FILE'"
if [ -n "$JSON_OUTPUT" ]; then
    CMD="$CMD --output '$JSON_OUTPUT'"
fi

# Run verification
echo -e "${BLUE}Verifying certificate: $(basename $CERT_FILE)${NC}"
echo ""

cd "$PROJECT_DIR"

if [ -n "$JSON_OUTPUT" ]; then
    eval "$CMD"
    EXIT_CODE=$?
else
    eval "$CMD"
    EXIT_CODE=$?
fi

echo ""

# Interpret exit code
case $EXIT_CODE in
    0)
        echo -e "${GREEN}✓ Certificate validation: PASSED${NC}"
        ;;
    1)
        echo -e "${YELLOW}⚠ Certificate validation: WARNINGS${NC}"
        echo -e "${YELLOW}The certificate has some warnings but is structurally valid${NC}"
        ;;
    2)
        echo -e "${RED}✗ Certificate validation: FAILED${NC}"
        echo -e "${RED}The certificate has critical validation errors${NC}"
        ;;
    *)
        echo -e "${RED}✗ Verification tool error (exit code: $EXIT_CODE)${NC}"
        ;;
esac

exit $EXIT_CODE
