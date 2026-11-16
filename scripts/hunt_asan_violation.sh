#!/usr/bin/env bash

set -e

ASAN_LOG_DIR="${HOME}/yajl-aflplusplus-fuzzer/asan_log"
MAX_ITERATIONS=10000
FUZZ_DURATION=300  # 5 minutes per iteration

echo "=== ASAN Violation Hunter ==="
echo "Will run up to ${MAX_ITERATIONS} fuzzing iterations"
echo "Each iteration runs for ${FUZZ_DURATION} seconds"
echo "ASAN logs will be in: ${ASAN_LOG_DIR}"
echo ""

# Clean up any previous runs
if [ -d "out" ]; then
    find out -type f -delete 2>/dev/null || true
    find out -type d -delete 2>/dev/null || true
fi
mkdir -p out
mkdir -p "${ASAN_LOG_DIR}"

for iteration in $(seq 1 ${MAX_ITERATIONS}); do
    echo "=== Iteration ${iteration}/${MAX_ITERATIONS} ==="
    echo "Starting fuzzing swarm at $(date)"
    
    # Clear old ASAN logs
    find "${ASAN_LOG_DIR}" -name "asan.*" -type f -delete 2>/dev/null || true
    
    # Start the fuzzing swarm
    bash run_afl_swarm.sh
    
    # Let it run for the specified duration
    echo "Fuzzing for ${FUZZ_DURATION} seconds..."
    sleep ${FUZZ_DURATION}
    
    # Kill all AFL processes
    echo "Stopping fuzzers..."
    pkill -9 afl-fuzz || true
    sleep 2
    
    # Check for ASAN violations
    if grep -qi error "${ASAN_LOG_DIR}"/asan.*; then
        echo ""
        echo "🎯 ASAN VIOLATION FOUND! 🎯"
        echo "Iteration: ${iteration}"
        echo "Time: $(date)"
        echo ""
        echo "ASAN log files:"
        ls -lh "${ASAN_LOG_DIR}"/asan.*
        echo ""
        echo "First ASAN log content:"
        cat "${ASAN_LOG_DIR}"/asan.* | head -100
        echo ""
        echo "Crashing inputs may be in: out/*/crashes/"
        ls -lh out/*/crashes/ 2>/dev/null || echo "No crashes directory found"
        exit 0
    fi
    
    echo "No ASAN violation found in iteration ${iteration}"
    echo "Continuing with next iteration..."
    echo ""
done

echo "Completed ${MAX_ITERATIONS} iterations without finding an ASAN violation"
exit 1
