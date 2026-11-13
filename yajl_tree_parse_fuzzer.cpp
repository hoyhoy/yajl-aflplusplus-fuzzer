// Fuzz harness for yajl_tree_parse (works with AFL++ and libFuzzer).
//
// ---------------------------------------------------------------------------
// 1. Build yajl with AFL++ instrumentation so the library itself reports
//    coverage. A plain clang build only instruments the harness.
//
// git clone https://github.com/lloyd/yajl.git
// cd yajl
// patch -p1 < ../cmake4.diff
// git commit -m "cmake 4 fixes"

// export AFL_USE_ASAN=1
// export AFL_USE_UBSAN=1
// export AFL_FINAL_SYNC=1
// export AFL_LLVM_DICT2FILE=/Users/jperrie/backup/examples/yajl_fuzzer/llvm.dict;
// unset AFL_USE_CFISAN
// rm -rf build
// git clean -fdx
// cmake -S . -B build \
//   -Wno-deprecated -Wno-author \
//   -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=OFF \
//   -DBUILD_SHARED_LIBS=OFF \
//   -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
//   -DCMAKE_POLICY_DEFAULT_CMP0153=OLD \
//   -DCMAKE_BUILD_TYPE=Debug \
//   -DCMAKE_C_COMPILER=afl-clang-fast \
//   -DCMAKE_CXX_COMPILER=afl-clang-fast++ \
//   -DCMAKE_C_FLAGS_DEBUG="-DDEBUG -g -fPIC -O1 -fsanitize=address,undefined -fsanitize-address-use-after-scope -fsanitize-address-use-after-return=always -fno-omit-frame-pointer -fno-optimize-sibling-calls -mtune=native -march=native -fuse-ld=lld" \
//   -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined -mtune=native -march=native -fuse-ld=lld" \
//   -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=address,undefined -mtune=native -march=native -fuse-ld=lld"
// cmake --build build
//
// 2. Build the harness. Source file first, libraries after it, otherwise the
//    static library's symbols may not resolve.
//
//   afl-clang-fast++ -DDEBUG -g -O1 \
//     -fsanitize=fuzzer,address,undefined \
//     -fsanitize-address-use-after-scope \
//     -fsanitize-address-use-after-return=always \
//     -fno-omit-frame-pointer -fno-optimize-sibling-calls \
//     -I ./yajl/build/yajl-2.1.1/include \
//     yajl_tree_parse_fuzzer.cpp \
//     -L ./yajl/build/yajl-2.1.1/lib -lyajl_s \
//     -o fuzzer

// rm -Rf in-yajl-min
// afl-cmin -T all -i in-yajl -o in-yajl-min -- ./fuzzer --

//
// 3. Run.
//
//   mkdir -p ./asan_log
//   export ASAN_OPTIONS="symbolize=0:\
//   halt_on_error=1:\
//   external_symbolizer_path=/opt/llvm-latest/bin/llvm-symbolizer:\
//   verbosity=1:\
//   strict_string_checks=1:\
//   detect_stack_use_after_return=1:\
//   check_initialization_order=1:\
//   detect_invalid_pointer_pairs=1:\
//   alloc_dealloc_mismatch=1:\
//   exitcode=1:\
//   fast_unwind_on_malloc=0:\
//   debug=1:\
//   color=always:\
//   print_cmdline=1:\
//   print_summary=1:\
//   abort_on_error=1:\
//   log_path=$PWD/asan_log/asan:\
//   log_exe_name=1:\
//   detect_leaks=1"
//
//   rm -Rf out-*
//   afl-fuzz -M main-$HOSTNAME -x json.dict -x json_surrogates.dict -x llvm-fuzzer.dict -x llvm.dict -i in-yajl-min -o out-$(date +%Y-%m-%d-%H-%M-%S) -- ./fuzzer
// ---------------------------------------------------------------------------

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <string>

extern "C" {
#include <yajl/yajl_tree.h>
}

namespace {

// Inputs larger than this mostly waste time without finding new paths.
constexpr size_t kMaxInputSize = 1 << 20;

// Read every string, key, and number in the tree. Parsing alone only proves
// the parser didn't crash; reading the results lets ASan catch bad lengths,
// unterminated buffers, and uninitialized bytes in decoded strings (which is
// where surrogate handling bugs tend to show up).
size_t Walk(yajl_val node) {
  if (node == nullptr) {
    return 0;
  }

  size_t sum = 0;
  if (YAJL_IS_STRING(node)) {
    sum += strlen(YAJL_GET_STRING(node));
  } else if (YAJL_IS_NUMBER(node)) {
    sum += strlen(YAJL_GET_NUMBER(node));
  } else if (YAJL_IS_ARRAY(node)) {
    for (size_t i = 0; i < node->u.array.len; ++i) {
      sum += Walk(node->u.array.values[i]);
    }
  } else if (YAJL_IS_OBJECT(node)) {
    for (size_t i = 0; i < node->u.object.len; ++i) {
      sum += strlen(node->u.object.keys[i]);
      sum += Walk(node->u.object.values[i]);
    }
  }
  return sum;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == 0 || size > kMaxInputSize) {
    return 0;
  }

  // yajl_tree_parse takes a NUL-terminated string with no length argument, so
  // copy into a std::string to guarantee termination. Bytes after an embedded
  // NUL are never seen by the parser, so skip those inputs rather than let the
  // fuzzer spend time mutating bytes that are ignored.
  std::string input(reinterpret_cast<const char *>(data), size);

  if (input.empty()) {
    return 0;
  }

  char error_buffer[4096] = {0};
  yajl_val node = yajl_tree_parse(input.c_str(), error_buffer, sizeof(error_buffer));

  // Keep the reads from being optimized away.
  static volatile size_t sink;
  sink = (node != nullptr) ? Walk(node) : strlen(error_buffer);

  yajl_tree_free(node);  // safe on NULL
  return 0;
}
