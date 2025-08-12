#!/usr/bin/env bash

set -euo pipefail

# validate_pcap.sh
# Validate pkt2flow by splitting a pcap into flows and checking generated files.
# - Verifies dependencies (pkt2flow, tcpdump)
# - Runs pkt2flow with flags to dump TCP, UDP, and other flows
# - Validates that output directories and files are created
# - Uses tcpdump to ensure each generated pcap is readable
# - Optionally compares packet counts between input and outputs
#
# Usage:
#   scripts/validate_pcap.sh <pcap_file> [--outdir <dir>] [--keep]
#
# Notes:
# - Exits non-zero on any validation failure.
# - By default, creates a temporary output directory and removes it at the end.

print_usage() {
  echo "Usage: $0 <pcap_file> [--outdir <dir>] [--keep]" >&2
}

cleanup() {
  if [[ "${KEEP_OUTPUT:-0}" == "0" && "${CREATED_OUTPUT_DIR:-0}" == "1" && -n "${OUTPUT_DIR:-}" && -d "$OUTPUT_DIR" ]]; then
    rm -rf "$OUTPUT_DIR"
  fi
}

err() {
  echo "[ERROR] $*" >&2
}

info() {
  echo "[INFO] $*"
}

# --- Parse args ---
if [[ $# -lt 1 ]]; then
  print_usage
  exit 2
fi

PCAP_FILE=""
OUTPUT_DIR=""
KEEP_OUTPUT=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --outdir)
      shift
      OUTPUT_DIR="${1:-}"
      if [[ -z "$OUTPUT_DIR" ]]; then
        err "--outdir requires a value"
        exit 2
      fi
      ;;
    --keep)
      KEEP_OUTPUT=1
      ;;
    -h|--help)
      print_usage
      exit 0
      ;;
    *)
      if [[ -z "$PCAP_FILE" ]]; then
        PCAP_FILE="$1"
      else
        err "Unexpected argument: $1"
        print_usage
        exit 2
      fi
      ;;
  esac
  shift
done

if [[ -z "$PCAP_FILE" ]]; then
  err "pcap file is required"
  print_usage
  exit 2
fi

if [[ ! -f "$PCAP_FILE" ]]; then
  err "pcap file not found: $PCAP_FILE"
  exit 1
fi

trap cleanup EXIT

# --- Dependencies ---
if ! command -v tcpdump >/dev/null 2>&1; then
  err "tcpdump not found in PATH"
  exit 1
fi

# Allow running either from repo root (./pkt2flow built) or installed in PATH
PKT2FLOW_BIN=""
if [[ -x "./pkt2flow" ]]; then
  PKT2FLOW_BIN="./pkt2flow"
elif command -v pkt2flow >/dev/null 2>&1; then
  PKT2FLOW_BIN="$(command -v pkt2flow)"
else
  err "pkt2flow binary not found. Build it (make) or install and ensure it is in PATH."
  exit 1
fi

# --- Prepare output dir ---
if [[ -z "$OUTPUT_DIR" ]]; then
  OUTPUT_DIR="/tmp/pkt2flow_validate_$(date +%s)_$$"
  CREATED_OUTPUT_DIR=1
else
  CREATED_OUTPUT_DIR=0
fi
mkdir -p "$OUTPUT_DIR"
info "Using output directory: $OUTPUT_DIR"

# --- Validate input pcap reads with tcpdump ---
info "Validating input pcap readability via tcpdump"
if ! tcpdump -r "$PCAP_FILE" -c 1 > /dev/null 2>&1; then
  err "tcpdump failed to read input pcap: $PCAP_FILE"
  exit 1
fi

# Count input packets
INPUT_PKT_COUNT=$(tcpdump -n -r "$PCAP_FILE" 2>/dev/null | wc -l | awk '{print $1}')
info "Input packet count: $INPUT_PKT_COUNT"

# --- Run pkt2flow ---
# Use flags: -u (UDP), -v (TCP without SYN), -x (others)
info "Running: $PKT2FLOW_BIN -u -v -x -o $OUTPUT_DIR $PCAP_FILE"
set +e
"$PKT2FLOW_BIN" -u -v -x -o "$OUTPUT_DIR" "$PCAP_FILE"
RET=$?
set -e
if [[ $RET -ne 0 ]]; then
  err "pkt2flow exited with code $RET"
  exit $RET
fi

# --- Validate output structure ---
EXPECTED_DIRS=("tcp_syn" "tcp_nosyn" "udp" "others")
FOUND_ANY=0
for d in "${EXPECTED_DIRS[@]}"; do
  if [[ -d "$OUTPUT_DIR/$d" ]]; then
    info "Found directory: $d"
    FOUND_ANY=1
  else
    info "Directory not present (may be empty for this pcap): $d"
  fi
done

if [[ $FOUND_ANY -eq 0 ]]; then
  err "No output subdirectories found under $OUTPUT_DIR."
  exit 1
fi

# --- Validate each generated pcap ---
TOTAL_FLOW_FILES=0
TOTAL_OUTPUT_PKTS=0

for d in "${EXPECTED_DIRS[@]}"; do
  SUBDIR="$OUTPUT_DIR/$d"
  [[ -d "$SUBDIR" ]] || continue

  shopt -s nullglob
  for f in "$SUBDIR"/*.pcap; do
    ((TOTAL_FLOW_FILES++))

    # File non-empty
    if [[ ! -s "$f" ]]; then
      err "Generated pcap is empty: $f"
      exit 1
    fi

    # tcpdump can read it
    if ! tcpdump -r "$f" -c 1 > /dev/null 2>&1; then
      err "tcpdump failed to read generated pcap: $f"
      exit 1
    fi

    # Count packets in this flow file
    PKTS=$(tcpdump -n -r "$f" 2>/dev/null | wc -l | awk '{print $1}')
    TOTAL_OUTPUT_PKTS=$((TOTAL_OUTPUT_PKTS + PKTS))
  done
  shopt -u nullglob
done

info "Total generated flow files: $TOTAL_FLOW_FILES"
info "Total packets across generated flows (approx): $TOTAL_OUTPUT_PKTS"

# --- Sanity checks ---
if [[ $TOTAL_FLOW_FILES -eq 0 ]]; then
  err "No flow files were generated."
  exit 1
fi

# Packet count comparison is best-effort; tcpdump lines may include non-packet lines on some versions.
# We allow a small delta due to potential metadata/non-IP packets not being dumped depending on flags.
DELTA=$(( INPUT_PKT_COUNT - TOTAL_OUTPUT_PKTS ))
ABS_DELTA=${DELTA#-}
ALLOWED_DELTA=5

if [[ $ABS_DELTA -gt $ALLOWED_DELTA ]]; then
  err "Packet count mismatch too large: input=$INPUT_PKT_COUNT, outputs=$TOTAL_OUTPUT_PKTS, delta=$DELTA (> $ALLOWED_DELTA)"
  exit 1
fi

# --- File naming and size heuristics ---
# Ensure filenames end with .pcap and look non-trivial in size (> 24 bytes pcap header)
for d in "${EXPECTED_DIRS[@]}"; do
  SUBDIR="$OUTPUT_DIR/$d"
  [[ -d "$SUBDIR" ]] || continue
  shopt -s nullglob
  for f in "$SUBDIR"/*.pcap; do
    BASENAME=$(basename "$f")
    if [[ "$BASENAME" != *.pcap ]]; then
      err "Unexpected file extension (expected .pcap): $f"
      exit 1
    fi
    SIZE=$(stat -f%z "$f")
    if [[ "$SIZE" -le 24 ]]; then
      err "Flow file too small to contain packets (size=$SIZE): $f"
      exit 1
    fi
  done
  shopt -u nullglob
done

info "Validation PASSED"
exit 0