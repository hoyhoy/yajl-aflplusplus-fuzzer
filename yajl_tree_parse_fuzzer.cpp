#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <ctype.h>
#include <string>

extern "C" {
  #include <yajl/yajl_tree.h>
}

// afl-clang-fast++ -I ~/yajl-2.0.1/include -L ~/yajl-2.0.1/yajl-2.1.0/lib -lyajl_s \
//   -glldb -fsanitize=fuzzer,address,undefined -fsanitize-address-use-after-scope  \\
//   -fsanitize-address-use-after-return=always -fno-omit-frame-pointer \\
/    -fno-optimize-sibling-calls -o fuzzer yajl_fuzzer2.cpp 

// afl-fuzz -M $(sysctl -n hw.ncpu) -x ~/AFLplusplus/dictionaries/json.dict -i in-yajl -o out-yajl2 -- ./fuzzer

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  unsigned int val = 0U;
    char error_buffer[4096] = {0};

    std::string s(reinterpret_cast<const char*>(data), size);

    yajl_val node = yajl_tree_parse(s.data(), error_buffer, sizeof(error_buffer));

    yajl_tree_free(node);

    return 0;
}
