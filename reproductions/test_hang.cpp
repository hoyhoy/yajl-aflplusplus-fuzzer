#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/stat.h>

extern "C" {
#include <yajl/yajl_tree.h>
}

size_t Walk(yajl_val node) {
  if (node == nullptr) return 0;
  
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

int main(int argc, char** argv) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <json_file>\n", argv[0]);
    return 1;
  }

  FILE* f = fopen(argv[1], "rb");
  if (!f) {
    perror("fopen");
    return 1;
  }

  fseek(f, 0, SEEK_END);
  long size = ftell(f);
  fseek(f, 0, SEEK_SET);

  char* input = (char*)calloc(size + 1, 1);
  fread(input, 1, size, f);
  fclose(f);

  printf("Testing file: %s (size: %ld bytes)\n", argv[1], size);
  
  char error_buffer[4096] = {0};
  yajl_val node = yajl_tree_parse(input, error_buffer, sizeof(error_buffer));

  if (node) {
    printf("Parse succeeded\n");
    size_t result = Walk(node);
    printf("Walk result: %zu\n", result);
    yajl_tree_free(node);
  } else {
    printf("Parse failed: %s\n", error_buffer);
  }

  free(input);
  return 0;
}
