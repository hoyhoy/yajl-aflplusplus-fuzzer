#!/usr/bin/env bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== YAJL Fuzzing Campaign - Hunting for ASAN Violations ===${NC}"
echo ""

# Seed directories to try
SEED_DIRS=("in-cve" "in-surrogate" "pool-min")
ITERATION=1
MAX_ITERATIONS=10
FUZZ_DURATION=120  # seconds per iteration

# Clean up function
cleanup() {
    echo -e "\n${YELLOW}Cleaning up fuzzer processes...${NC}"
    pkill -9 afl-fuzz 2>/dev/null || true
    pkill -9 fuzzer 2>/dev/null || true
    sleep 2
}

# Check for ASAN violations
check_asan_violations() {
    if [ -d "asan_log" ] && [ "$(ls -A asan_log 2>/dev/null)" ]; then
        echo -e "${RED}!!! ASAN VIOLATION DETECTED !!!${NC}"
        echo ""
        echo "ASAN log files found:"
        ls -lh asan_log/
        echo ""
        echo "=== First ASAN Report ==="
        cat asan_log/asan.* 2>/dev/null | head -100
        return 0
    fi
    return 1
}

# Check for crashes in AFL output
check_crashes() {
    if [ -d "out" ]; then
        local crash_count=$(find out -type f -path "*/crashes/*" ! -name "README.txt" 2>/dev/null | wc -l)
        if [ "$crash_count" -gt 0 ]; then
            echo -e "${RED}Found $crash_count crash(es) in AFL output!${NC}"
            echo "Crash files:"
            find out -type f -path "*/crashes/*" ! -name "README.txt" 2>/dev/null
            return 0
        fi
    fi
    return 1
}

# Trap to ensure cleanup on exit
trap cleanup EXIT INT TERM

# Main fuzzing loop
while [ $ITERATION -le $MAX_ITERATIONS ]; do
    for SEED_DIR in "${SEED_DIRS[@]}"; do
        echo -e "\n${GREEN}=== Iteration $ITERATION/$MAX_ITERATIONS - Using seed: $SEED_DIR ===${NC}"
        
        # Clean previous run
        cleanup
        rm -rf out asan_log/*.* 2>/dev/null || true
        mkdir -p asan_log
        
        # Modify run_afl_swarm.sh to use current seed directory
        sed -i.bak "s|-i [^ ]* |-i $SEED_DIR |g" run_afl_swarm.sh
        
        echo "Starting fuzzer with $SEED_DIR seeds..."
        bash run_afl_swarm.sh &
        SWARM_PID=$!
        
        # Let it run for specified duration
        echo "Fuzzing for ${FUZZ_DURATION}s..."
        sleep $FUZZ_DURATION
        
        # Stop the swarm
        echo "Stopping fuzzer..."
        cleanup
        
        # Check for violations
        echo "Checking for ASAN violations..."
        if check_asan_violations; then
            echo -e "\n${GREEN}SUCCESS! Found ASAN violation with seed: $SEED_DIR${NC}"
            exit 0
        fi
        
        if check_crashes; then
            echo -e "\n${YELLOW}Found crashes, checking if they trigger ASAN...${NC}"
            # Test crashes directly
            for crash in $(find out -type f -path "*/crashes/*" ! -name "README.txt" 2>/dev/null | head -5); do
                echo "Testing crash: $crash"
                timeout 5 ./fuzzer < "$crash" 2>&1 || true
                if check_asan_violations; then
                    echo -e "\n${GREEN}SUCCESS! Crash triggered ASAN violation!${NC}"
                    exit 0
                fi
            done
        fi
        
        echo -e "${YELLOW}No violations found with $SEED_DIR in iteration $ITERATION${NC}"
    done
    
    ITERATION=$((ITERATION + 1))
done

echo -e "\n${YELLOW}Completed $MAX_ITERATIONS iterations without finding ASAN violations.${NC}"
echo "You may want to:"
echo "  1. Increase FUZZ_DURATION (currently ${FUZZ_DURATION}s)"
echo "  2. Increase MAX_ITERATIONS (currently $MAX_ITERATIONS)"
echo "  3. Run longer manual fuzzing sessions"

exit 1
