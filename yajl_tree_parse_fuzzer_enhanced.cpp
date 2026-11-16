// Enhanced fuzz harness for yajl_tree_parse targeting CVE-2017-16516
// Changes from original:
// 1. Uses malloc() instead of calloc() to avoid zero-initialization
// 2. Enhanced Walk() with byte-by-byte access to trigger ASAN
// 3. Removed direct decode (causes SEGV - needs proper yajl_buf setup)

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>

extern "C" {
#include <yajl/yajl_tree.h>
}

namespace {

constexpr size_t kMaxInputSize = 100 << 20;

// Enhanced Walk that forces byte-by-byte access to trigger ASAN on overflows
size_t Walk(yajl_val node) {
  if (node == nullptr) {
    return 0ULL;
  }

  size_t sum = 0ULL;
  
  if (YAJL_IS_STRING(node)) {
    const char *str = YAJL_GET_STRING(node);
    size_t len = strlen(str);
    
    // Force byte-by-byte access - volatile prevents optimization
    volatile size_t byte_sum = 0;
    for (size_t i = 0; i < len; i++) {
      byte_sum += static_cast<unsigned char>(str[i]);
    }
    sum += byte_sum;
  } else if (YAJL_IS_NUMBER(node)) {
    const char *num = YAJL_GET_NUMBER(node);
    size_t len = strlen(num);
    volatile size_t byte_sum = 0ULL;
    for (size_t i = 0; i < len; i++) {
      byte_sum += static_cast<unsigned char>(num[i]);
    }
    sum += byte_sum;
    
  } else if (YAJL_IS_ARRAY(node)) {
    for (size_t i = 0ULL; i < node->u.array.len; ++i) {
      sum += Walk(node->u.array.values[i]);
    }
    
  } else if (YAJL_IS_OBJECT(node)) {
    for (size_t i = 0ULL; i < node->u.object.len; ++i) {
      // Force byte-by-byte access to keys
      const char *key = node->u.object.keys[i];
      size_t key_len = strlen(key);
      volatile size_t byte_sum = 0;
      for (size_t j = 0; j < key_len; j++) {
        byte_sum += static_cast<unsigned char>(key[j]);
      }
      sum += byte_sum;
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

  // Skip inputs with embedded NUL bytes
  size_t new_size = size;
  if (memchr(data, '\0', size) != nullptr) {
    new_size = size - 1ULL;
  }
  
  if (new_size == 0) {
    return 0;
  }

  // CRITICAL: Use malloc() instead of calloc() to avoid zero-initialization
  // This makes ASAN more likely to detect overflows
  char *input = static_cast<char *>(malloc(new_size + 1ULL));
  if (input == nullptr) {
    return 0;
  }
  
  memcpy(input, data, new_size);
  input[new_size] = '\0';

  // Parse and walk tree with enhanced overflow detection
  char error_buffer[4096] = {0};
  yajl_val node = yajl_tree_parse(input, error_buffer, sizeof(error_buffer));

  static volatile size_t sink;
  sink = (node != nullptr) ? Walk(node) : strlen(error_buffer);

  yajl_tree_free(node);
  free( (void*) input);

  return 0;
}
