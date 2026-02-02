#!/bin/bash
#
# SPDM Certificate Validation Script
#
# Wrapper script for easy SPDM certificate validation
#
# Usage: ./validate_spdm.sh <certificate> [OPTIONS]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"  # Parent workspace (spdm-rs)
PACKAGE_DIR="$SCRIPT_DIR"  # spdm-x509-rs package directory

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
MODEL=""
MODEL_AUTO_DETECT=true
ROLE="responder"
ASYM="all"
HASH="all"
VERBOSE=""
SKIP_TIME=""
OUTPUT_FILE=""

# Print usage
usage() {
    echo "SPDM Certificate Validation Script"
    echo ""
    echo "Usage: $0 <certificate> [OPTIONS]"
    echo ""
    echo "Arguments:"
    echo "  <certificate>          Path to certificate file (DER or PEM)"
    echo ""
    echo "Options:"
    echo "  --model <MODEL>        Certificate model: device, alias, generic"
    echo "                         If not specified, auto-detects (device → alias → generic)"
    echo "  --role <ROLE>          Certificate role: requester, responder"
    echo "                         (default: responder)"
    echo "  --asym <ALGO>          Asymmetric algorithm"
    echo "                         (default: all)"
    echo "  --hash <ALGO>          Hash algorithm"
    echo "                         (default: all)"
    echo "  --verbose, -v          Show detailed information"
    echo "  --skip-time            Skip time validation"
    echo "  --output, -o <FILE>    Save results to file (JSON or TXT based on extension)"
    echo "  --help, -h             Show this help message"
    echo ""
    echo "Certificate Models:"
    echo "  device    - DeviceCert: requires Hardware Identity OID"
    echo "  alias     - AliasCert: no Hardware Identity OID"
    echo "  generic   - GenericCert: standard X.509 (CA/intermediate)"
    echo ""
    echo "Examples:"
    echo "  $0 cert.der                              # Auto-detect model"
    echo "  $0 cert.der --output report.json         # Save to JSON"
    echo "  $0 cert.der --output report.txt          # Save to TXT"
    echo "  $0 cert.pem --model device               # Explicit DeviceCert"
    echo "  $0 cert.der --model alias --role requester"
    echo "  $0 cert.der --asym ecdsa-p256 --hash sha256 -v"
}

# Parse arguments
if [ $# -lt 1 ]; then
    usage
    exit 1
fi

# Check for help flag first
if [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    usage
    exit 0
fi

CERT_FILE="$1"
shift

# Check if certificate file exists
if [ ! -f "$CERT_FILE" ]; then
    echo -e "${RED}Error: Certificate file not found: $CERT_FILE${NC}"
    exit 1
fi

# Convert to absolute path before changing directory
CERT_FILE="$(cd "$(dirname "$CERT_FILE")" && pwd)/$(basename "$CERT_FILE")"

# Parse options
while [ $# -gt 0 ]; do
    case "$1" in
        --model|-m)
            MODEL="$2"
            MODEL_AUTO_DETECT=false
            shift 2
            ;;
        --role|-r)
            ROLE="$2"
            shift 2
            ;;
        --asym|-a)
            ASYM="$2"
            shift 2
            ;;
        --hash)
            HASH="$2"
            shift 2
            ;;
        --verbose|-v)
            VERBOSE="--verbose"
            shift
            ;;
        --skip-time)
            SKIP_TIME="--skip-time"
            shift
            ;;
        --output|-o)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            echo -e "${RED}Error: Unknown option: $1${NC}"
            echo ""
            usage
            exit 1
            ;;
    esac
done

# Function to try validation with a specific model
try_validate() {
    local test_model=$1
    local quiet=$2

    MANIFEST_PATH="$PROJECT_DIR/Cargo.toml"
    local cmd="cargo run --quiet --manifest-path \"$MANIFEST_PATH\" -p spdm-x509-rs --features spdm --example validate_spdm_cert -- \"$CERT_FILE\""
    cmd="$cmd --model $test_model --role $ROLE --asym $ASYM --hash $HASH"

    if [ -n "$VERBOSE" ] && [ "$quiet" != "quiet" ]; then
        cmd="$cmd $VERBOSE"
    fi

    if [ -n "$SKIP_TIME" ]; then
        cmd="$cmd $SKIP_TIME"
    fi

    if [ -n "$OUTPUT_FILE" ] && [ "$quiet" != "quiet" ]; then
        cmd="$cmd --output \"$OUTPUT_FILE\""
    fi

    if [ "$quiet" = "quiet" ]; then
        eval "$cmd" >/dev/null 2>&1
    else
        eval "$cmd" 2>&1
    fi

    return $?
}

# Change to project directory
cd "$PROJECT_DIR"

# Print info
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}SPDM Certificate Validation${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo "Certificate: $CERT_FILE"

if [ "$MODEL_AUTO_DETECT" = true ]; then
    echo "Model:       auto-detect"
    echo "Role:        $ROLE"
    echo "Asym Algo:   $ASYM"
    echo "Hash Algo:   $HASH"
    echo ""
    echo -e "${BLUE}Auto-detecting certificate model...${NC}"
    echo ""

    # Try models in order: device -> alias -> generic
    MODELS=("device" "alias" "generic")
    DETECTED_MODEL=""

    for test_model in "${MODELS[@]}"; do
        echo -e "${YELLOW}→ Trying model: $test_model${NC}"

        if try_validate "$test_model" "quiet"; then
            DETECTED_MODEL="$test_model"
            echo -e "${GREEN}  ✓ Model $test_model - PASSED${NC}"
            break
        else
            echo -e "${RED}  ✗ Model $test_model - FAILED${NC}"
        fi
    done

    echo ""

    if [ -n "$DETECTED_MODEL" ]; then
        echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
        echo -e "${GREEN}Certificate Model Detected: ${DETECTED_MODEL^^}${NC}"
        echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
        echo ""
        echo -e "${BLUE}Running final validation with detected model...${NC}"
        echo ""

        # Run final validation with verbose output
        if try_validate "$DETECTED_MODEL" "verbose"; then
            echo ""
            echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
            echo -e "${GREEN}✓ VALIDATION PASSED${NC}"
            echo -e "${GREEN}Certificate Type: ${DETECTED_MODEL^^}${NC}"
            echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
            exit 0
        else
            echo ""
            echo -e "${RED}═══════════════════════════════════════════════════════════════${NC}"
            echo -e "${RED}✗ VALIDATION FAILED${NC}"
            echo -e "${RED}═══════════════════════════════════════════════════════════════${NC}"
            exit 1
        fi
    else
        echo ""
        echo -e "${RED}═══════════════════════════════════════════════════════════════${NC}"
        echo -e "${RED}✗ CERTIFICATE MODEL DETECTION FAILED${NC}"
        echo -e "${RED}None of the models (device, alias, generic) passed validation${NC}"
        echo -e "${RED}═══════════════════════════════════════════════════════════════${NC}"
        exit 1
    fi
else
    # User specified model explicitly
    echo "Model:       $MODEL"
    echo "Role:        $ROLE"
    echo "Asym Algo:   $ASYM"
    echo "Hash Algo:   $HASH"
    echo ""

    # Run validation
    echo -e "${BLUE}Running validation...${NC}"
    echo ""

    if try_validate "$MODEL" "verbose"; then
        echo ""
        echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
        echo -e "${GREEN}✓ VALIDATION PASSED${NC}"
        echo -e "${GREEN}Certificate Type: ${MODEL^^}${NC}"
        echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
        exit 0
    else
        echo ""
        echo -e "${RED}═══════════════════════════════════════════════════════════════${NC}"
        echo -e "${RED}✗ VALIDATION FAILED${NC}"
        echo -e "${RED}═══════════════════════════════════════════════════════════════${NC}"
        exit 1
    fi
fi
