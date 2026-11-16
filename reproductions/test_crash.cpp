#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <stdint.h>

extern "C" {
#include <yajl/yajl_tree.h>
// Direct access to internal YAJL function for testing
void yajl_string_decode(unsigned char *str, unsigned int *len);
}

// ASAN interface for manual poisoning (if available)
#ifdef __has_feature
#if __has_feature(address_sanitizer)
extern "C" {
    void __asan_poison_memory_region(void const volatile *addr, size_t size);
    void __asan_unpoison_memory_region(void const volatile *addr, size_t size);
}
#define HAS_ASAN 1
#endif
#endif

#ifndef HAS_ASAN
#define __asan_poison_memory_region(addr, size) ((void)0)
#define __asan_unpoison_memory_region(addr, size) ((void)0)
#endif

// Canary value for overflow detection
#define CANARY_VALUE 0xDEADBEEF
#define CANARY_SIZE 16

// Test modes
enum TestMode {
    MODE_NORMAL,           // Standard yajl_tree_parse
    MODE_TIGHT_ALLOC,      // Tight allocation (no extra space)
    MODE_DIRECT_DECODE,    // Direct yajl_string_decode call
    MODE_UNINITIALIZED,    // Use malloc instead of calloc
    MODE_SURROGATE_PAIR,   // Specific surrogate pair testing
    MODE_BOUNDARY_OVERFLOW,// Test buffer boundary conditions
    MODE_CVE_2017_16516    // Exact CVE-2017-16516 reproduction
};

void print_usage(const char* prog) {
    fprintf(stderr, "Usage: %s [options] <crash_file>\n", prog);
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -m <mode>  Test mode:\n");
    fprintf(stderr, "             0 = Normal (default)\n");
    fprintf(stderr, "             1 = Tight allocation\n");
    fprintf(stderr, "             2 = Direct decode\n");
    fprintf(stderr, "             3 = Uninitialized memory\n");
    fprintf(stderr, "             4 = Surrogate pair testing\n");
    fprintf(stderr, "             5 = Boundary overflow detection\n");
    fprintf(stderr, "             6 = CVE-2017-16516 exact reproduction\n");
    fprintf(stderr, "  -v         Verbose output\n");
    fprintf(stderr, "  -h         Show this help\n");
}

// Check if canaries are intact
bool check_canaries(const uint32_t* before, const uint32_t* after, const char* label) {
    bool intact = true;
    
    for (int i = 0; i < CANARY_SIZE / 4; i++) {
        if (before[i] != CANARY_VALUE) {
            printf("✗ OVERFLOW DETECTED: %s before-canary[%d] corrupted: 0x%08x (expected 0x%08x)\n",
                   label, i, before[i], CANARY_VALUE);
            intact = false;
        }
        if (after[i] != CANARY_VALUE) {
            printf("✗ OVERFLOW DETECTED: %s after-canary[%d] corrupted: 0x%08x (expected 0x%08x)\n",
                   label, i, after[i], CANARY_VALUE);
            intact = false;
        }
    }
    
    return intact;
}

void test_normal(const char* input, size_t size, bool verbose) {
    if (verbose) {
        printf("[NORMAL MODE] Testing with calloc allocation\n");
    }
    
    char* buffer = (char*)calloc(size + 1, 1);
    memcpy(buffer, input, size);
    
    char error_buffer[4096] = {0};
    yajl_val node = yajl_tree_parse(buffer, error_buffer, sizeof(error_buffer));
    
    if (node) {
        printf("✓ Parse succeeded\n");
        yajl_tree_free(node);
    } else {
        printf("✗ Parse failed: %s\n", error_buffer);
    }
    
    free(buffer);
}

void test_tight_alloc(const char* input, size_t size, bool verbose) {
    if (verbose) {
        printf("[TIGHT ALLOC MODE] Testing with exact size allocation\n");
    }
    
    // Allocate exactly the size needed (no extra null terminator space)
    char* buffer = (char*)malloc(size);
    memcpy(buffer, input, size);
    
    char error_buffer[4096] = {0};
    yajl_val node = yajl_tree_parse(buffer, error_buffer, sizeof(error_buffer));
    
    if (node) {
        printf("✓ Parse succeeded\n");
        yajl_tree_free(node);
    } else {
        printf("✗ Parse failed: %s\n", error_buffer);
    }
    
    free(buffer);
}

void test_direct_decode(const char* input, size_t size, bool verbose) {
    if (verbose) {
        printf("[DIRECT DECODE MODE] Testing yajl_string_decode directly\n");
    }
    
    // Extract string content between quotes if present
    const char* start = NULL;
    const char* end = NULL;
    for (size_t i = 0; i < size; i++) {
        if (input[i] == '"') {
            if (!start) {
                start = input + i + 1;
            } else {
                end = input + i;
                break;
            }
        }
    }
    
    if (start && end && end > start) {
        size_t str_len = end - start;
        
        // Allocate with canaries
        size_t total_size = CANARY_SIZE + str_len + CANARY_SIZE;
        unsigned char* full_buffer = (unsigned char*)malloc(total_size);
        
        uint32_t* before_canary = (uint32_t*)full_buffer;
        unsigned char* buffer = full_buffer + CANARY_SIZE;
        uint32_t* after_canary = (uint32_t*)(buffer + str_len);
        
        // Set canaries
        for (int i = 0; i < CANARY_SIZE / 4; i++) {
            before_canary[i] = CANARY_VALUE;
            after_canary[i] = CANARY_VALUE;
        }
        
        memcpy(buffer, start, str_len);
        
        if (verbose) {
            printf("String length: %zu\n", str_len);
            printf("Buffer: %p, Before: %p, After: %p\n", buffer, before_canary, after_canary);
        }
        
        unsigned int len = str_len;
        printf("Calling yajl_string_decode()...\n");
        
        yajl_string_decode(buffer, &len);
        
        printf("Decode completed (new length: %u)\n", len);
        
        // Check canaries
        if (check_canaries(before_canary, after_canary, "direct_decode")) {
            printf("✓ No overflow detected\n");
        }
        
        free(full_buffer);
    } else {
        printf("⚠ Could not extract quoted string from input\n");
    }
}

void test_uninitialized(const char* input, size_t size, bool verbose) {
    if (verbose) {
        printf("[UNINITIALIZED MODE] Testing with malloc (uninitialized memory)\n");
    }
    
    char* buffer = (char*)malloc(size + 1);
    memcpy(buffer, input, size);
    buffer[size] = '\0';
    
    char error_buffer[4096] = {0};
    yajl_val node = yajl_tree_parse(buffer, error_buffer, sizeof(error_buffer));
    
    if (node) {
        printf("✓ Parse succeeded\n");
        yajl_tree_free(node);
    } else {
        printf("✗ Parse failed: %s\n", error_buffer);
    }
    
    free(buffer);
}

void test_surrogate_pair(const char* input, size_t size, bool verbose) {
    if (verbose) {
        printf("[SURROGATE PAIR MODE] Testing surrogate pair handling\n");
    }
    
    // Look for surrogate pairs in input
    bool has_surrogate = false;
    for (size_t i = 0; i < size - 6; i++) {
        if (input[i] == '\\' && input[i+1] == 'u' && 
            input[i+2] == 'D' && (input[i+3] == '8' || input[i+3] == '9' || 
                                   input[i+3] == 'A' || input[i+3] == 'B')) {
            has_surrogate = true;
            printf("Found high surrogate at offset %zu: \\u%c%c%c%c\n", 
                   i, input[i+2], input[i+3], input[i+4], input[i+5]);
        }
    }
    
    if (!has_surrogate) {
        printf("⚠ No surrogate pairs detected in input\n");
    }
    
    // Extract and test string with tight allocation
    const char* start = strchr(input, '"');
    if (start) {
        start++;
        const char* end = strchr(start, '"');
        if (end) {
            size_t str_len = end - start;
            
            // Allocate exactly str_len bytes (tight)
            unsigned char* buffer = (unsigned char*)malloc(str_len);
            memcpy(buffer, start, str_len);
            
            printf("Testing with tight buffer (%zu bytes)...\n", str_len);
            
            unsigned int len = str_len;
            yajl_string_decode(buffer, &len);
            
            printf("✓ Decode completed (length: %u -> %u)\n", (unsigned int)str_len, len);
            
            // Check if length increased (surrogate pair decoded to UTF-8)
            if (len > str_len) {
                printf("⚠ WARNING: Output length (%u) > input length (%zu) - potential overflow!\n", 
                       len, str_len);
            }
            
            free(buffer);
        }
    }
}

void test_boundary_overflow(const char* input, size_t size, bool verbose) {
    if (verbose) {
        printf("[BOUNDARY OVERFLOW MODE] Testing with poisoned guard pages\n");
    }
    
    // Extract string
    const char* start = strchr(input, '"');
    if (!start) {
        printf("⚠ No quoted string found\n");
        return;
    }
    
    start++;
    const char* end = strchr(start, '"');
    if (!end) {
        printf("⚠ Unterminated string\n");
        return;
    }
    
    size_t str_len = end - start;
    
    // Allocate buffer with guard pages
    size_t page_size = 4096;
    size_t alloc_size = CANARY_SIZE + str_len + CANARY_SIZE;
    size_t total_pages = (alloc_size + page_size - 1) / page_size + 2; // +2 for guard pages
    
    unsigned char* full_buffer = (unsigned char*)malloc(total_pages * page_size);
    
    // Setup: [CANARY][DATA][CANARY][POISON]
    uint32_t* before_canary = (uint32_t*)full_buffer;
    unsigned char* buffer = full_buffer + CANARY_SIZE;
    uint32_t* after_canary = (uint32_t*)(buffer + str_len);
    unsigned char* poison_zone = full_buffer + CANARY_SIZE + str_len + CANARY_SIZE;
    
    // Set canaries
    for (int i = 0; i < CANARY_SIZE / 4; i++) {
        before_canary[i] = CANARY_VALUE;
        after_canary[i] = CANARY_VALUE;
    }
    
    // Poison memory after buffer
    size_t poison_size = page_size;
    __asan_poison_memory_region(poison_zone, poison_size);
    
    memcpy(buffer, start, str_len);
    
    if (verbose) {
        printf("Buffer layout:\n");
        printf("  Before canary: %p\n", before_canary);
        printf("  Buffer:        %p (size: %zu)\n", buffer, str_len);
        printf("  After canary:  %p\n", after_canary);
        printf("  Poison zone:   %p (size: %zu)\n", poison_zone, poison_size);
    }
    
    unsigned int len = str_len;
    printf("Calling yajl_string_decode() with boundary protection...\n");
    
    yajl_string_decode(buffer, &len);
    
    printf("Decode completed (length: %u)\n", len);
    
    // Unpoison for checking
    __asan_unpoison_memory_region(poison_zone, poison_size);
    
    // Check canaries
    if (check_canaries(before_canary, after_canary, "boundary")) {
        printf("✓ No overflow detected\n");
    }
    
    // Check poison zone
    bool poison_intact = true;
    for (size_t i = 0; i < 64; i++) {
        if (poison_zone[i] != 0) {
            printf("✗ OVERFLOW: Poison zone byte %zu modified: 0x%02x\n", i, poison_zone[i]);
            poison_intact = false;
        }
    }
    
    if (poison_intact) {
        printf("✓ Poison zone intact\n");
    }
    
    free(full_buffer);
}

void test_cve_2017_16516(const char* input, size_t size, bool verbose) {
    if (verbose) {
        printf("[CVE-2017-16516 MODE] Exact vulnerability reproduction\n");
        printf("Testing: High surrogate without low surrogate in tight buffer\n");
    }
    
    // CVE-2017-16516: When a high surrogate (\\uD800-\\uDBFF) is not followed
    // by a low surrogate (\\uDC00-\\uDFFF), yajl_string_decode writes a 
    // replacement character (\\uFFFD) which is 3 bytes in UTF-8, but only
    // allocated space for the original 6-byte escape sequence.
    
    // Extract string
    const char* start = strchr(input, '"');
    if (!start) {
        printf("⚠ No quoted string found\n");
        return;
    }
    
    start++;
    const char* end = strchr(start, '"');
    if (!end) {
        printf("⚠ Unterminated string\n");
        return;
    }
    
    size_t str_len = end - start;
    
    // Check for high surrogate pattern
    bool has_high_surrogate = false;
    for (size_t i = 0; i < str_len - 5; i++) {
        if (start[i] == '\\' && start[i+1] == 'u' && 
            start[i+2] == 'D' && (start[i+3] >= '8' && start[i+3] <= 'B')) {
            has_high_surrogate = true;
            printf("Found high surrogate at offset %zu: \\u%c%c%c%c\n",
                   i, start[i+2], start[i+3], start[i+4], start[i+5]);
            
            // Check if followed by low surrogate
            if (i + 11 < str_len && start[i+6] == '\\' && start[i+7] == 'u' &&
                start[i+8] == 'D' && (start[i+9] >= 'C' && start[i+9] <= 'F')) {
                printf("  → Followed by low surrogate (valid pair)\n");
            } else {
                printf("  → NOT followed by low surrogate (VULNERABLE CASE)\n");
            }
        }
    }
    
    if (!has_high_surrogate) {
        printf("⚠ No high surrogate found - not CVE-2017-16516 test case\n");
        return;
    }
    
    // Allocate EXACTLY str_len bytes (the vulnerable condition)
    unsigned char* buffer = (unsigned char*)malloc(str_len);
    
    // Add canary immediately after
    uint32_t* canary = (uint32_t*)malloc(CANARY_SIZE);
    for (int i = 0; i < CANARY_SIZE / 4; i++) {
        canary[i] = CANARY_VALUE;
    }
    
    memcpy(buffer, start, str_len);
    
    printf("\nVulnerability test:\n");
    printf("  Allocated buffer: %zu bytes at %p\n", str_len, buffer);
    printf("  Canary location:  %p\n", canary);
    printf("  Input contains:   High surrogate without low surrogate\n");
    printf("  Expected:         3-byte UTF-8 replacement (\\uFFFD)\n");
    printf("  Allocated space:  Only original 6 bytes\n");
    printf("  Result:           Should overflow by 3 bytes!\n\n");
    
    unsigned int len = str_len;
    printf("Calling yajl_string_decode()...\n");
    
    // This SHOULD trigger heap-buffer-overflow with ASAN
    yajl_string_decode(buffer, &len);
    
    printf("Decode completed (length: %u)\n", len);
    
    if (len > str_len) {
        printf("✗ OVERFLOW CONFIRMED: Output length (%u) > allocated size (%zu)\n", 
               len, str_len);
        printf("   Overflow amount: %u bytes\n", len - (unsigned int)str_len);
    }
    
    // Check canary (may already be corrupted)
    bool intact = true;
    for (int i = 0; i < CANARY_SIZE / 4; i++) {
        if (canary[i] != CANARY_VALUE) {
            printf("✗ CANARY CORRUPTED[%d]: 0x%08x (expected 0x%08x)\n",
                   i, canary[i], CANARY_VALUE);
            intact = false;
        }
    }
    
    if (intact) {
        printf("✓ Canary intact (overflow may not have reached canary)\n");
    }
    
    free(buffer);
    free(canary);
}

int main(int argc, char** argv) {
    TestMode mode = MODE_NORMAL;
    bool verbose = false;
    int opt;
    
    while ((opt = getopt(argc, argv, "m:vh")) != -1) {
        switch (opt) {
            case 'm':
                mode = (TestMode)atoi(optarg);
                if (mode < MODE_NORMAL || mode > MODE_CVE_2017_16516) {
                    fprintf(stderr, "Invalid mode: %d\n", mode);
                    print_usage(argv[0]);
                    return 1;
                }
                break;
            case 'v':
                verbose = true;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    if (optind >= argc) {
        fprintf(stderr, "Error: Missing crash file argument\n\n");
        print_usage(argv[0]);
        return 1;
    }
    
    const char* crash_file = argv[optind];
    
    FILE* f = fopen(crash_file, "rb");
    if (!f) {
        perror("fopen");
        return 1;
    }
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char* input = (char*)malloc(size);
    size_t bytes_read = fread(input, 1, size, f);
    fclose(f);
    
    if (bytes_read != (size_t)size) {
        fprintf(stderr, "Warning: Read %zu bytes, expected %ld\n", bytes_read, size);
    }
    
    printf("═══════════════════════════════════════════════════════════\n");
    printf("Test Crash File: %s\n", crash_file);
    printf("Input Size: %ld bytes\n", size);
    printf("Test Mode: %d\n", mode);
#ifdef HAS_ASAN
    printf("ASAN: Enabled\n");
#else
    printf("ASAN: Not detected\n");
#endif
    printf("═══════════════════════════════════════════════════════════\n");
    
    if (verbose) {
        printf("\nInput content:\n");
        for (long i = 0; i < size; i++) {
            char c = input[i];
            if (c >= 32 && c < 127) {
                printf("%c", c);
            } else if (c == '\n') {
                printf("\\n");
            } else {
                printf("\\x%02x", (unsigned char)c);
            }
        }
        printf("\n\n");
    }
    
    printf("Running test...\n");
    printf("───────────────────────────────────────────────────────────\n");
    
    switch (mode) {
        case MODE_NORMAL:
            test_normal(input, size, verbose);
            break;
        case MODE_TIGHT_ALLOC:
            test_tight_alloc(input, size, verbose);
            break;
        case MODE_DIRECT_DECODE:
            test_direct_decode(input, size, verbose);
            break;
        case MODE_UNINITIALIZED:
            test_uninitialized(input, size, verbose);
            break;
        case MODE_SURROGATE_PAIR:
            test_surrogate_pair(input, size, verbose);
            break;
        case MODE_BOUNDARY_OVERFLOW:
            test_boundary_overflow(input, size, verbose);
            break;
        case MODE_CVE_2017_16516:
            test_cve_2017_16516(input, size, verbose);
            break;
    }
    
    printf("═══════════════════════════════════════════════════════════\n");
    
    free(input);
    return 0;
}
