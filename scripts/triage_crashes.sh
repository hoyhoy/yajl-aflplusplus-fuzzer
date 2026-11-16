#!/usr/bin/env bash
#
# Automated crash triage for YAJL fuzzing campaign
# Reproduces crashes, gets stack traces, minimizes, and classifies
#

set -euo pipefail

FUZZER="./build/fuzzer"
OUT_DIR="${1:-out}"
TRIAGE_DIR="triage-$(date +%Y-%m-%d-%H-%M-%S)"

if [[ ! -d "$OUT_DIR" ]]; then
  echo "Error: Output directory $OUT_DIR does not exist"
  exit 1
fi

if [[ ! -f "$FUZZER" ]]; then
  echo "Error: Fuzzer binary $FUZZER not found"
  exit 1
fi

mkdir -p "$TRIAGE_DIR"/{crashes,hangs,unique,minimized,reports}

echo "=== YAJL Crash Triage ==="
echo "Output dir: $OUT_DIR"
echo "Triage dir: $TRIAGE_DIR"
echo "Fuzzer: $FUZZER"
echo ""

# Export ASAN options for reproduction
export ASAN_OPTIONS="symbolize=1:\
halt_on_error=1:\
external_symbolizer_path=$(which llvm-symbolizer):\
verbosity=1:\
strict_string_checks=1:\
detect_stack_use_after_return=1:\
check_initialization_order=1:\
detect_invalid_pointer_pairs=1:\
alloc_dealloc_mismatch=1:\
exitcode=1:\
fast_unwind_on_malloc=0:\
color=always:\
print_cmdline=1:\
print_summary=1:\
abort_on_error=1:\
detect_leaks=1"

# Find all crash files
CRASHES=$(find "$OUT_DIR" -type f -path "*/crashes/id:*" 2>/dev/null | sort)
CRASH_COUNT=$(echo "$CRASHES" | grep -c "^" || echo 0)

echo "Found $CRASH_COUNT crash files"
echo ""

if [[ $CRASH_COUNT -eq 0 ]]; then
  echo "No crashes found. Checking for hangs..."
  HANGS=$(find "$OUT_DIR" -type f -path "*/hangs/id:*" 2>/dev/null | sort)
  HANG_COUNT=$(echo "$HANGS" | grep -c "^" || echo 0)
  echo "Found $HANG_COUNT hang files"
  
  if [[ $HANG_COUNT -eq 0 ]]; then
    echo "No crashes or hangs found."
    exit 0
  fi
  
  # Copy hangs for analysis
  echo "$HANGS" | while read -r hang; do
    cp "$hang" "$TRIAGE_DIR/hangs/"
  done
  
  echo "Hangs copied to $TRIAGE_DIR/hangs/"
  exit 0
fi

# Process each crash
crash_num=0
declare -A crash_types

echo "$CRASHES" | while read -r crash_file; do
  crash_num=$((crash_num + 1))
  crash_name=$(basename "$crash_file")
  
  echo "[$crash_num/$CRASH_COUNT] Processing: $crash_name"
  
  # Copy crash file
  cp "$crash_file" "$TRIAGE_DIR/crashes/"
  
  # Try to reproduce and capture output
  report_file="$TRIAGE_DIR/reports/${crash_name}.txt"
  
  echo "Reproducing crash..." | tee "$report_file"
  if timeout 5 "$FUZZER" "$crash_file" > /dev/null 2>&1; then
    echo "  WARNING: Crash did not reproduce!" | tee -a "$report_file"
    continue
  fi
  
  # Get detailed crash info
  echo "Getting crash details..." | tee -a "$report_file"
  timeout 5 "$FUZZER" "$crash_file" 2>&1 | tee -a "$report_file" || true
  
  # Classify crash type
  crash_type="unknown"
  if grep -q "heap-buffer-overflow" "$report_file"; then
    crash_type="heap-buffer-overflow"
  elif grep -q "heap-use-after-free" "$report_file"; then
    crash_type="heap-use-after-free"
  elif grep -q "stack-buffer-overflow" "$report_file"; then
    crash_type="stack-buffer-overflow"
  elif grep -q "stack-overflow" "$report_file"; then
    crash_type="stack-overflow"
  elif grep -q "double-free" "$report_file"; then
    crash_type="double-free"
  elif grep -q "SEGV" "$report_file"; then
    crash_type="segv"
  elif grep -q "integer overflow" "$report_file"; then
    crash_type="integer-overflow"
  elif grep -q "undefined behavior" "$report_file"; then
    crash_type="ubsan"
  fi
  
  echo "  Type: $crash_type" | tee -a "$report_file"
  
  # Extract function name from stack trace
  func=$(grep -oP '#0 0x[0-9a-f]+ in \K[^ ]+' "$report_file" | head -1 || echo "unknown")
  echo "  Function: $func" | tee -a "$report_file"
  
  # Try to minimize
  echo "  Minimizing..." | tee -a "$report_file"
  min_file="$TRIAGE_DIR/minimized/${crash_name}.min"
  
  # Simple minimization: try removing bytes from end
  cp "$crash_file" "$min_file"
  orig_size=$(wc -c < "$crash_file")
  
  for ((i=orig_size-1; i>0; i--)); do
    head -c $i "$crash_file" > "$min_file.tmp"
    if ! timeout 2 "$FUZZER" "$min_file.tmp" > /dev/null 2>&1; then
      cp "$min_file.tmp" "$min_file"
    else
      break
    fi
  done
  rm -f "$min_file.tmp"
  
  min_size=$(wc -c < "$min_file")
  echo "  Minimized: $orig_size -> $min_size bytes" | tee -a "$report_file"
  
  # Create unique identifier based on crash type and function
  unique_id="${crash_type}_${func}"
  crash_types[$unique_id]=1
  
  # Copy to unique directory
  unique_dir="$TRIAGE_DIR/unique/$unique_id"
  mkdir -p "$unique_dir"
  cp "$crash_file" "$unique_dir/"
  cp "$min_file" "$unique_dir/"
  cp "$report_file" "$unique_dir/"
  
  echo ""
done

# Summary
echo "=== Triage Summary ==="
echo "Total crashes: $CRASH_COUNT"
echo "Unique crash types: ${#crash_types[@]}"
echo ""
echo "Crash types found:"
for crash_type in "${!crash_types[@]}"; do
  count=$(find "$TRIAGE_DIR/unique/$crash_type" -type f -name "id:*" 2>/dev/null | wc -l)
  echo "  $crash_type: $count"
done
echo ""
echo "Results saved to: $TRIAGE_DIR/"
echo ""
echo "Next steps:"
echo "1. Review reports in $TRIAGE_DIR/reports/"
echo "2. Analyze unique crashes in $TRIAGE_DIR/unique/"
echo "3. Create minimal reproducers from $TRIAGE_DIR/minimized/"
echo "4. Report vulnerabilities with details from reports"
