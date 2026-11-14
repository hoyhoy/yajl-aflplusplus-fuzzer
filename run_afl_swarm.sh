#!/usr/bin/env bash

N=$(nproc)
chance() { [ $((RANDOM % 100)) -lt "$1" ]; }   # chance 30 -> true ~30% of the time

mkdir -p out

export ASAN_OPTIONS="symbolize=0:halt_on_error=1:external_symbolizer_path=/usr/bin/llvm-symbolizer:verbosity=1:strict_string_checks=1:detect_stack_use_after_return=1:check_initialization_order=1:detect_invalid_pointer_pairs=1:alloc_dealloc_mismatch=1:exitcode=1:fast_unwind_on_malloc=0:debug=1:color=always:print_cmdline=1:print_summary=1:abort_on_error=1:log_path=/home/jperrie/yajl-aflplusplus-fuzzer/asan_log/asan:log_exe_name=1:detect_leaks=1"

# Main instance: defaults
AFL_NO_UI=1 afl-fuzz -M main -t 1000+ \
  -x json.dict -x json_surrogates.dict -x llvm.dict \
  -i pool -o out -- ./fuzzer @@ >/dev/null 2>&1 &

for i in $(seq 1 $((N-1))); do
  envs=(AFL_NO_UI=1)
  envs+=(AFL_USE_UBSAN=1)
  envs+=(AFL_FINAL_SYNC=1)
  envs+=(AFL_USE_LSAN=1)
  envs+=(AFL_USE_ASAN=1)

  args=(-S "s$i" -t 1000+ -i pool-min -o out)
  bin=./fuzzer

  chance 5  && bin=./fuzzer_laf                       # LAF_ALL build
  chance 65 && envs+=(AFL_DISABLE_TRIM=1)
  chance 50 && envs+=(AFL_KEEP_TIMEOUTS=1)
  chance 50 && args+=(-x llvm.dict)              # DICT2FILE dictionary
  chance 50 && args+=(-x json.dict)
  chance 50 && args+=(-x json_surrogates.dict)
  chance 50 && args+=(-x llvm.dict)
  chance 50 && args+=(-x unicode.dict)

  chance 40 && envs+=(AFL_EXPAND_HAVOC_NOW=1)
  chance 20 && args+=(-Z)                             # old queue processing

  if chance 30; then                                  # CMPLOG
    r=$((RANDOM % 10))
    if   [ $r -lt 7 ]; then l=2                       # 70%
    elif [ $r -lt 8 ]; then l=3                       # 10%
    else                    l=2AT                     # 20%
    fi
    args+=(-c ./fuzzer_cmplog -l "$l")
  fi

  env "${envs[@]}" afl-fuzz "${args[@]}" -- "$bin" @@ >/dev/null 2>&1 &
done
