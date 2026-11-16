#!/usr/bin/env bash

chance() { [ $((RANDOM % 100)) -lt "$1" ]; }   # chance 30 -> true ~30% of the time

if [[ "$(uname)" == "Darwin" ]]; then
  N=$(( $(sysctl -n hw.physicalcpu) / 2 ))
elif command -v nproc &> /dev/null; then
  N=$(( $(nproc) / 4 ))
fi

OUT_DIR="out-$(date +%Y-%m-%d-%H-%M-%S)"

export ASAN_OPTIONS="symbolize=0:halt_on_error=1:external_symbolizer_path=/usr/bin/llvm-symbolizer:verbosity=1:strict_string_checks=1:detect_stack_use_after_return=1:check_initialization_order=1:detect_invalid_pointer_pairs=1:alloc_dealloc_mismatch=1:exitcode=1:fast_unwind_on_malloc=0:debug=1:color=always:print_cmdline=1:print_summary=1:abort_on_error=1:log_path=${HOME}/yajl-aflplusplus-fuzzer/asan_log/asan:log_exe_name=1:detect_leaks=1"
export AFL_TESTCACHE_SIZE=10000

for i in $(seq 1 ${N}); do
  envs=(AFL_NO_UI=1)
  envs+=(AFL_USE_UBSAN=1)
  envs+=(AFL_FINAL_SYNC=1)
  envs+=(AFL_AUTORESUME=1)
  envs+=(AFL_PIZZA_MODE=-1)
  envs+=(AFL_FAST_CALL=1)

  args=(-S "s$i" -t 1000+ -o ${OUT_DIR} -i in-json-min)
  
  if chance 30; then                                  # CMPLOG
    envs+=(AFL_CMPLOG_ONLY_NEW=1)
    r=$((RANDOM % 10))

    if   [ $r -lt 7 ]; then l=2                       # 70%
    elif [ $r -lt 8 ]; then l=3                       # 10%
    else                    l=2AT                     # 20%
    fi

    args+=(-l "$l")
    args+=(-c ./build/bin/ytp.asan.cmplog)
  fi

  if chance 50; then
    envs+=(AFL_USE_LSAN=1)
    envs+=(AFL_USE_ASAN=1)

    bin=./build/bin/ytp.asan
  else
    envs+=(AFL_USE_LSAN=1)
    envs+=(AFL_USE_ASAN=1)

    bin=./build/bin/ytp.asan.laf  # LAF_ALL build
  # else
  #   envs+=(AFL_USE_CFISAN=1)
  #
  #   bin=./build/bin/ytp.cfisan
  fi

  chance 65 && envs+=(AFL_DISABLE_TRIM=1)
  chance 50 && envs+=(AFL_KEEP_TIMEOUTS=1)

  chance 80 && args+=(-x dictionaries/llvm.dict)              # DICT2FILE dictionary
  chance 75 && args+=(-x dictionaries/json.dict)
  chance 70 && args+=(-x dictionaries/json_surrogates.dict)
  chance 85 && args+=(-x dictionaries/unicode.dict)

  # chance 25 && args+=(-Q)

  chance 40 && envs+=(AFL_EXPAND_HAVOC_NOW=1)
  chance 20 && args+=(-Z)                             # old queue processing

  echo env "${envs[@]}" afl-fuzz "${args[@]}" -- "${bin}" ">/dev/null 2>&1 &"
  # env "${envs[@]}" afl-fuzz "${args[@]}" -- "${bin}" >/dev/null 2>&1 &
done
