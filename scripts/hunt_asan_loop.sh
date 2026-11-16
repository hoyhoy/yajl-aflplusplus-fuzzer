#!/usr/bin/env bash

# Script to continuously run AFL swarm with different seed inputs until ASAN violation found

set -e

SEED_DIRS=("in-cve" "in-surrogate" "in-yajl" "pool-min")
ASAN_LOG_DIR="${HOME}/yajl-aflplusplus-fuzzer/asan_log"
FUZZ_DURATION=120  # Run each fuzzing session for 2 minutes

mkdir -p "${ASAN_LOG_DIR}"

echo "=== Starting ASAN violation hunt ==="
echo "Seed directories: ${SEED_DIRS[@]}"
echo "ASAN log directory: ${ASAN_LOG_DIR}"
echo "Fuzzing duration per seed: ${FUZZ_DURATION} seconds"
echo ""

running=true

on_interrupt() {
    echo
    echo "Caught Ctrl-C, shutting down..."
    running=false
}

trap on_interrupt INT

iteration=1
while $running; do
    for seed_dir in "${SEED_DIRS[@]}"; do
        echo "----------------------------------------"
        echo "Iteration ${iteration} - Using seed directory: ${seed_dir}"
        echo "Started at: $(date)"
        
        # Clean previous ASAN logs
        rm -f "${ASAN_LOG_DIR}"/asan.*
        
        # Modify run_afl_swarm.sh to use current seed directory
        sed "s|-i in-cve|-i ${seed_dir}|g" run_afl_swarm.sh > run_afl_swarm_temp.sh
        chmod +x run_afl_swarm_temp.sh
        
        # Start fuzzing
        echo "Starting AFL swarm..."
        ./run_afl_swarm_temp.sh
        
        # Let it run for specified duration
        echo "Fuzzing for ${FUZZ_DURATION} seconds..."
        sleep ${FUZZ_DURATION}
        
        # Stop all AFL processes
        echo "Stopping AFL processes..."
        pkill -9 afl-fuzz 2>/dev/null || true
        sleep 2
        
        # Check for ASAN violations
        if ls "${ASAN_LOG_DIR}"/asan.* 1> /dev/null 2>&1; then
            echo ""
            echo "!!! ASAN VIOLATION FOUND !!!"
            echo "Seed directory: ${seed_dir}"
            echo "Iteration: ${iteration}"
            echo ""
            echo "ASAN log files:"
            ls -lh "${ASAN_LOG_DIR}"/asan.*
            echo ""
            echo "First ASAN log content:"
            cat "${ASAN_LOG_DIR}"/asan.* | head -100
            echo ""
            echo "Checking for crashes in out/*/crashes/"
            find out -name "crashes" -type d -exec ls -lh {} \; 2>/dev/null || true
            exit 0
        else
            echo "No ASAN violation found in this run."
        fi
        
        echo "Completed at: $(date)"
        echo ""
    done
    
    iteration=$((iteration + 1))
    echo "=== Completed iteration ${iteration}, continuing... ==="
    echo ""
done
