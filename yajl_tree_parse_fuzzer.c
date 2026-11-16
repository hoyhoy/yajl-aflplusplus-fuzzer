// Fuzz harness for yajl_tree_parse (works with AFL++ and libFuzzer).

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <yajl/yajl_tree.h>

__AFL_FUZZ_INIT();

// Read every string, key, and number in the tree. Parsing alone only proves
// the parser didn't crash; reading the results lets ASan catch bad lengths,
// unterminated buffers, and uninitialized bytes in decoded strings (which is
// where surrogate handling bugs tend to show up).
size_t walk(yajl_val node) {
  if (node == NULL) {
    return 0ULL;
  }

  size_t sum = 0ULL;
  if (YAJL_IS_STRING(node)) {
    sum += strlen(YAJL_GET_STRING(node));
  } else if (YAJL_IS_NUMBER(node)) {
    sum += strlen(YAJL_GET_NUMBER(node));
  } else if (YAJL_IS_ARRAY(node)) {
    for (size_t i = 0ULL; i < node->u.array.len; ++i) {
      sum += walk(node->u.array.values[i]);
    }
  } else if (YAJL_IS_OBJECT(node)) {
    for (size_t i = 0ULL; i < node->u.object.len; ++i) {
      sum += strlen(node->u.object.keys[i]);
      sum += walk(node->u.object.values[i]);
    }
  }
  return sum;
}

int main() {

  // anything else here, e.g. command line arguments, initialization, etc.

#ifdef __AFL_HAVE_MANUAL_CONTROL
  __AFL_INIT();
#endif

  unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;  // must be after __AFL_INIT
                                                 // and before __AFL_LOOP!

  while (__AFL_LOOP(10000)) {

    int len = __AFL_FUZZ_TESTCASE_LEN;  // don't use the macro directly in a
                                        // call!

    if (len < 2) continue;  // check for a required/useful minimum input length

    const size_t new_size = len + 1ULL;
    char *input = (char *) calloc(new_size, sizeof(char));
    memcpy((void*) input, (void*) buf, new_size);

    char error_buffer[4096] = {0};
    yajl_val node = yajl_tree_parse((const char*) buf, error_buffer, sizeof(error_buffer));

    // Keep the reads from being optimized away.
    static volatile size_t sink;
    sink = (node != NULL) ? walk(node) : strnlen(error_buffer, sizeof(error_buffer));

    yajl_tree_free(node);  // safe on NULL
    free( (void*) input);

    return EXIT_SUCCESS;
  }

  return 0;

}
