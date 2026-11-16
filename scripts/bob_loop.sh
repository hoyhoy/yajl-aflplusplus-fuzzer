#!/usr/bin/env bash

running=true
trap 'running=false' INT TERM

export ASAN_OPTIONS="symbolize=1:halt_on_error=1:external_symbolizer_path=/opt/llvm-latest/bin/llvm-symbolizer:verbosity=1:strict_string_checks=1:detect_stack_use_after_return=1:check_initialization_order=1:detect_invalid_pointer_pairs=1:alloc_dealloc_mismatch=1:exitcode=1:fast_unwind_on_malloc=0:debug=1:color=always:print_cmdline=1:print_summary=1:abort_on_error=1:log_path=$PWD/asan_log/asan:log_exe_name=1:detect_leaks=1:abort_on_error=1"
export AFL_USE_ASAN=1; export AFL_FINAL_SYNC=1; export AFL_USE_UBSAN=1;

while $running; do
  bob -r --yolo --chat-mode="plan" \
    "Try to find an AddressSanitizer or UndefinedBehaviorSanitizer issue in yajl_tree_parse().
    @yajl_tree_parse_fuzzer_enhanced.cpp already implements a fuzzer.  @scripts/run_afl_swarm.sh will run
    a number of fuzzers in parallel.  Make changes to the fuzzer, seeds in @pool-min, @in-yajl, and dictionaries
    continuously until fuzzer exits non-zero or abort()"

  bob -r --yolo --chat-mode="advanced" \
    "Keep running and updating the @yajl_tree_parse_fuzzer_enhanced.cpp fuzzer until you find a heap-buffer-overflow.
    Inject_seeds (campaign) — coverage plateaued with the favored queue exhausted.  Ths current seeds are in
    @in-json-min.  There's a comprehensive JSON test suite in @test-json"

  bob -r --yolo --chat-mode="code" \
      "Refactor @reproductions/test_crash.cpp to find heap-buffer-overflow and undefined behavior.  CMakeLists.txt builds a test_crash binary and all the fuzzers."

  sleep 0.2 &
  wait $! 
done
