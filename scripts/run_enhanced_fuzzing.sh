#!/usr/bin/env bash
#
# Enhanced AFL++ fuzzing campaign for YAJL
# Uses targeted seeds, enhanced fuzzer, and optimized settings
#

set -euo pipefail

chance() { [ $((RANDOM % 100)) -lt "$1" ]; }

if [[ "$(uname)" == "Darwin" ]]; then
  N=$(( $(sysctl -n hw.physicalcpu) / 2 ))
elif command -v nproc &> /dev/null; then
  N=$(( $(nproc) / 4 ))
else
  N=4
fi

OUT_DIR="out-$(date +%Y-%m-%d-%H-%M-%S)"
SEED_DIR="in-combined-all"

echo "=== Enhanced YAJL Fuzzing Campaign ==="
echo "Workers: $N"
echo "Output: $OUT_DIR"
echo "Seeds: $SEED_DIR ($(ls $SEED_DIR | wc -l) files)"
echo ""

# ASAN options for crash detection
export ASAN_OPTIONS="symbolize=0:\
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
debug=1:\
color=always:\
print_cmdline=1:\
print_summary=1:\
abort_on_error=1:\
log_path=$PWD/asan_log/asan:\
log_exe_name=1:\
detect_leaks=1"

export AFL_TESTCACHE_SIZE=10000

mkdir -p asan_log

echo "Starting $N parallel fuzzing instances..."
echo ""

for i in $(seq 1 ${N}); do
  envs=(AFL_NO_UI=1)
  envs+=(AFL_USE_UBSAN=1)
  envs+=(AFL_FINAL_SYNC=1)
  envs+=(AFL_USE_LSAN=1)
  envs+=(AFL_USE_ASAN=1)
  envs+=(AFL_AUTORESUME=1)
  envs+=(AFL_PIZZA_MODE=-1)
  envs+=(AFL_FAST_CALL=1)

  args=(-S "s$i" -t 1000+ -o ${OUT_DIR} -i ${SEED_DIR})
  bin=./build/fuzzer

  # 30% use LAF_ALL build
  chance 30 && bin=./build/fuzzer_laf

  # 20% use enhanced fuzzer with validation
  chance 20 && bin=./build/fuzzer_enhanced

  # 65% disable trimming
  chance 65 && envs+=(AFL_DISABLE_TRIM=1)
  
  # 50% keep timeouts
  chance 50 && envs+=(AFL_KEEP_TIMEOUTS=1)

  # 80% use dictionaries
  chance 80 && args+=(-x llvm.dict)
  chance 75 && args+=(-x json.dict)
  chance 70 && args+=(-x json_surrogates.dict)
  chance 85 && args+=(-x unicode.dict)
  chance 60 && args+=(-x boundary.dict)

  # 25% use QEMU mode
  chance 25 && args+=(-Q)

  # 40% expand havoc
  chance 40 && envs+=(AFL_EXPAND_HAVOC_NOW=1)
  
  # 20% old queue processing
  chance 20 && args+=(-Z)

  # 30% use CMPLOG
  if chance 30; then
    envs+=(AFL_CMPLOG_ONLY_NEW=1)
    r=$((RANDOM % 10))
    if   [ $r -lt 7 ]; then l=2
    elif [ $r -lt 8 ]; then l=3
    else                    l=2AT
    fi
    args+=(-c ./build/fuzzer_cmplog -l "$l")
  fi

  echo "Worker $i: ${bin##*/} with ${#args[@]} args"
  env "${envs[@]}" afl-fuzz "${args[@]}" -- "${bin}" >/dev/null 2>&1 &
done

echo ""
echo "All workers started!"
echo ""
echo "Monitor with: watch -n 5 'afl-whatsup $OUT_DIR'"
echo "Stop with: pkill -9 afl-fuzz"
echo "Triage crashes: ./triage_crashes.sh $OUT_DIR"
echo ""
echo "Fuzzing in progress... Press Ctrl+C to stop monitoring"
echo ""

# Monitor fuzzing progress
sleep 5
while true; do
  clear
  echo "=== YAJL Fuzzing Status ==="
  echo "Output: $OUT_DIR"
  echo "Time: $(date)"
  echo ""
  
  if command -v afl-whatsup &> /dev/null; then
    afl-whatsup "$OUT_DIR" 2>/dev/null || echo "Waiting for fuzzer stats..."
  else
    echo "Workers running: $(pgrep -c afl-fuzz || echo 0)"
    
    # Check for crashes
    crashes=$(find "$OUT_DIR" -type f -path "*/crashes/id:*" 2>/dev/null | wc -l)
    hangs=$(find "$OUT_DIR" -type f -path "*/hangs/id:*" 2>/dev/null | wc -l)
    
    echo "Crashes found: $crashes"
    echo "Hangs found: $hangs"
    
    if [[ $crashes -gt 0 ]]; then
      echo ""
      echo "!!! CRASHES DETECTED !!!"
      echo "Run: ./triage_crashes.sh $OUT_DIR"
    fi
  fi
  
  sleep 30
done
