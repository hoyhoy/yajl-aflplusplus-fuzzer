#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <ctype.h>
#include <string>

extern "C" {
  #include <yajl/yajl_tree.h>
}

// mkdir -p ./asan_log/asan
//
// export ASAN_OPTIONS="symbolize=0:\
// halt_on_error=1:\
// external_symbolizer_path=/opt/llvm-latest/bin/llvm-symbolizer:\
// verbosity=1:\
// strict_string_checks=1:\
// detect_stack_use_after_return=1:\
// check_initialization_order=1:\
// detect_invalid_pointer_pairs=1:\
// alloc_dealloc_mismatch=1:\
// exitcode=1:\
// fast_unwind_on_malloc=0:\
// debug=1:\
// color=always:\
// print_cmdline=1:\
// print_summary=1:\
// abort_on_error=1:\
// log_path=$PWD/asan_log/asan:\
// log_exe_name=1:\
// detect_leaks=1"

// afl-clang-fast++ -I ~/yajl-2.0.1/include -L ~/yajl-2.0.1/yajl-2.1.0/lib -lyajl_s \
//   -glldb -fsanitize=fuzzer,address,undefined -fsanitize-address-use-after-scope  \\
//   -fsanitize-address-use-after-return=always -fno-omit-frame-pointer \\
/    -fno-optimize-sibling-calls -o fuzzer yajl_fuzzer2.cpp 

// afl-fuzz -M $(sysctl -n hw.ncpu) -x json.dict -i in-yajl -o out-yajl2 -- ./fuzzer

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  unsigned int val = 0U;
    char error_buffer[4096] = {0};

    std::string s(reinterpret_cast<const char*>(data), size);

    yajl_val node = yajl_tree_parse(s.data(), error_buffer, sizeof(error_buffer));

    yajl_tree_free(node);

    return 0;
}
