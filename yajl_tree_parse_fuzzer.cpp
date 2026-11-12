#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <ctype.h>
#include <string>

extern "C" {
#include <yajl/yajl_tree.h>
}

// afl-clang-fast++  -glldb -fsanitize=fuzzer,address,undefined -fsanitize-address-use-after-scope \
//   -fsanitize-address-use-after-return=always -fno-omit-frame-pointer -fno-optimize-sibling-calls -o fuzzer yajl_main.cpp

// afl-fuzz -M $(sysctl -n hw.ncpu) -x ~/AFLplusplus/dictionaries/json.dict -i in-yajl -o out-yajl2 -- ./fuzzer

static void hexToDigit(unsigned int * val, const unsigned char * hex)
{
    unsigned int i;
    for (i=0;i<4;i++) {
        unsigned char c = hex[i];          // <-- unconditionally reads 4 bytes
        if (c >= 'A') c = (c & ~0x20) - 7;
        c -= '0';
        *val = (*val << 4) | c;
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  unsigned int val = 0U;
    yajl_val node = NULL;
    char error_buffer[4096] = {0};

    std::string s(reinterpret_cast<const char*>(data), size);

    node = yajl_tree_parse(s.data(), error_buffer, sizeof(error_buffer));

    return 0;
}
