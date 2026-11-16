#!/usr/bin/env python3
"""
Generate targeted seed files for YAJL fuzzing campaign.

This script creates minimal, focused test cases targeting specific vulnerability
classes in yajl_tree_parse(), particularly around UTF-16 surrogate handling,
buffer boundaries, and memory allocation edge cases.
"""

import os
import json
from pathlib import Path

# Output directory
SEED_DIR = Path("in-targeted")
SEED_DIR.mkdir(exist_ok=True)

def write_seed(filename, content):
    """Write seed file (raw bytes, not JSON-encoded)."""
    path = SEED_DIR / filename
    if isinstance(content, str):
        content = content.encode('utf-8')
    path.write_bytes(content)
    print(f"Created: {path}")

def generate_surrogate_seeds():
    """Generate seeds targeting UTF-16 surrogate edge cases."""
    print("\n=== Generating Surrogate Seeds ===")
    
    # High surrogate only (unpaired)
    write_seed("surrogate_high_only.json", '["\\uD800"]')
    write_seed("surrogate_high_only_key.json", '{"\\uD800":"value"}')
    
    # Low surrogate only (unpaired)
    write_seed("surrogate_low_only.json", '["\\uDC00"]')
    
    # Double high surrogate
    write_seed("surrogate_double_high.json", '["\\uD800\\uD800"]')
    
    # Reversed pair (low then high)
    write_seed("surrogate_reversed.json", '["\\uDC00\\uD800"]')
    
    # High surrogate followed by non-surrogate
    write_seed("surrogate_high_then_char.json", '["\\uD800A"]')
    write_seed("surrogate_high_then_bmp.json", '["\\uD800\\u0041"]')
    
    # High surrogate followed by escape
    write_seed("surrogate_high_then_escape.json", '["\\uD800\\n"]')
    write_seed("surrogate_high_then_backslash.json", '["\\uD800\\\\"]')
    
    # High surrogate at end of string (no closing quote)
    write_seed("surrogate_high_eos.json", b'["\\uD800')
    
    # Multiple unpaired surrogates
    write_seed("surrogate_multi_high.json", '["\\uD800\\uD801\\uD802"]')
    write_seed("surrogate_multi_low.json", '["\\uDC00\\uDC01\\uDC02"]')
    
    # Valid pair followed by unpaired
    write_seed("surrogate_valid_then_high.json", '["\\uD800\\uDC00\\uD800"]')
    
    # Surrogate in nested structure
    write_seed("surrogate_nested.json", '{"a":{"b":{"c":"\\uD800"}}}')
    write_seed("surrogate_nested_array.json", '[[["\\uD800"]]]')
    
    # Surrogate with null bytes
    write_seed("surrogate_with_null.json", '["\\uD800\\u0000"]')

def generate_boundary_seeds():
    """Generate seeds targeting buffer boundary conditions."""
    print("\n=== Generating Buffer Boundary Seeds ===")
    
    # Strings at exact boundary sizes
    for size in [4095, 4096, 4097, 8191, 8192, 8193]:
        # Plain string
        content = '["' + 'A' * size + '"]'
        write_seed(f"string_{size}.json", content)
        
        # String with surrogate at end
        content = '["' + 'A' * (size - 6) + '\\uD800"]'
        write_seed(f"string_{size}_surrogate_end.json", content)
        
        # Object key at boundary
        content = '{"' + 'k' * size + '":"value"}'
        write_seed(f"key_{size}.json", content)
    
    # Escape sequences that expand near boundary
    # \uXXXX (6 bytes) -> 1-4 bytes UTF-8
    base = 'A' * 4090
    write_seed("escape_expansion_4096.json", f'["{base}\\u0041\\u0042\\u0043"]')
    
    # Surrogate pair (12 bytes) -> 4 bytes UTF-8
    base = 'A' * 4084
    write_seed("surrogate_pair_4096.json", f'["{base}\\uD800\\uDC00"]')
    
    # Multiple escapes near boundary
    base = 'A' * 4000
    escapes = '\\n' * 48  # 96 bytes of escapes
    write_seed("multi_escape_4096.json", f'["{base}{escapes}"]')

def generate_realloc_seeds():
    """Generate seeds targeting realloc boundaries."""
    print("\n=== Generating Realloc Boundary Seeds ===")
    
    # Alternating small and large strings
    parts = []
    for i in range(100):
        if i % 2 == 0:
            parts.append('"' + 'x' * 10000 + '"')
        else:
            parts.append('"x"')
    write_seed("alternating_sizes.json", '[' + ','.join(parts) + ']')
    
    # Many small allocations
    parts = [f'"k{i}":"v{i}"' for i in range(10000)]
    write_seed("many_keys_10k.json", '{' + ','.join(parts) + '}')
    
    # Large array
    write_seed("array_100k.json", '[' + ','.join(['1'] * 100000) + ']')
    
    # Deep nesting with strings at each level
    content = '{"a":'
    for i in range(100):
        content += '{"level' + str(i) + '":"' + 'x' * 1000 + '",'
    content += '"end":"value"'
    content += '}' * 100
    write_seed("deep_nest_long_str.json", content)

def generate_integer_overflow_seeds():
    """Generate seeds targeting integer overflow."""
    print("\n=== Generating Integer Overflow Seeds ===")
    
    # Numbers near integer limits
    write_seed("int64_max.json", '[9223372036854775807]')
    write_seed("int64_max_plus1.json", '[9223372036854775808]')
    write_seed("int64_min.json", '[-9223372036854775808]')
    write_seed("int64_min_minus1.json", '[-9223372036854775809]')
    
    write_seed("uint32_max.json", '[4294967295]')
    write_seed("uint32_max_plus1.json", '[4294967296]')
    
    write_seed("uint64_max.json", '[18446744073709551615]')
    write_seed("uint64_max_plus1.json", '[18446744073709551616]')
    
    # Huge exponents
    write_seed("exp_308.json", '[1e308]')
    write_seed("exp_309.json", '[1e309]')
    write_seed("exp_neg308.json", '[1e-308]')
    write_seed("exp_neg324.json", '[1e-324]')
    
    # Very long number string
    write_seed("huge_number.json", '[' + '9' * 100000 + ']')
    
    # Exponent that could overflow
    write_seed("exp_huge.json", '[1e' + '9' * 10000 + ']')

def generate_deep_nesting_seeds():
    """Generate seeds targeting deep nesting."""
    print("\n=== Generating Deep Nesting Seeds ===")
    
    # Deep array nesting
    content = '[' * 1000 + '1' + ']' * 1000
    write_seed("deep_array_1000.json", content)
    
    # Deep object nesting
    content = '{"a":' * 1000 + '1' + '}' * 1000
    write_seed("deep_object_1000.json", content)
    
    # Alternating array/object
    content = ''
    for i in range(500):
        if i % 2 == 0:
            content += '{"a":['
        else:
            content += '["x",{'
    content += '1'
    for i in range(500):
        if i % 2 == 0:
            content += ']}'
        else:
            content += '}]'
    write_seed("alternating_deep_500.json", content)
    
    # Deep nesting with surrogates at each level
    content = ''
    for i in range(100):
        content += '{"level' + str(i) + '":"\\uD800",'
    content += '"end":"value"'
    content += '}' * 100
    write_seed("deep_surrogate_100.json", content)

def generate_escape_seeds():
    """Generate seeds targeting escape sequence handling."""
    print("\n=== Generating Escape Sequence Seeds ===")
    
    # Incomplete escapes
    write_seed("esc_u_only.json", b'["\\u')
    write_seed("esc_u_1hex.json", b'["\\uD')
    write_seed("esc_u_2hex.json", b'["\\uD8')
    write_seed("esc_u_3hex.json", b'["\\uD80')
    
    # Invalid hex digits
    write_seed("esc_u_nonhex.json", '["\\uGGGG"]')
    write_seed("esc_u_mixed.json", '["\\uD8GG"]')
    
    # Escape at end of buffer
    write_seed("esc_at_end.json", b'["test\\')
    
    # Multiple backslashes
    write_seed("multi_backslash.json", '["\\\\\\\\\\\\\\\\"]')
    
    # Mixed valid and invalid
    write_seed("mixed_escapes.json", '["\\n\\r\\t\\uD800\\uGGGG"]')
    
    # Null byte escapes
    write_seed("null_escapes.json", '["\\u0000\\u0000\\u0000"]')
    
    # Control character escapes
    write_seed("control_escapes.json", '["\\u0001\\u0002\\u001F"]')

def generate_utf8_seeds():
    """Generate seeds targeting UTF-8 edge cases."""
    print("\n=== Generating UTF-8 Seeds ===")
    
    # Invalid UTF-8 sequences (raw bytes)
    write_seed("invalid_utf8.json", b'["\xC0\x80"]')  # Overlong encoding
    write_seed("invalid_utf8_2.json", b'["\xE0\x80\x80"]')  # Overlong
    write_seed("invalid_utf8_3.json", b'["\xF0\x80\x80\x80"]')  # Overlong
    
    # Incomplete UTF-8 sequences
    write_seed("incomplete_utf8.json", b'["\xC2"]')  # Missing continuation
    write_seed("incomplete_utf8_2.json", b'["\xE0\xA0"]')  # Missing byte
    write_seed("incomplete_utf8_3.json", b'["\xF0\x90\x80"]')  # Missing byte
    
    # Invalid continuation bytes
    write_seed("invalid_continuation.json", b'["\xC2\x00"]')
    
    # Surrogate in UTF-8 (invalid)
    write_seed("utf8_surrogate.json", b'["\xED\xA0\x80"]')  # U+D800 in UTF-8

def generate_mixed_seeds():
    """Generate seeds combining multiple edge cases."""
    print("\n=== Generating Mixed Edge Case Seeds ===")
    
    # Surrogate at buffer boundary
    base = 'A' * 4090
    write_seed("surrogate_at_boundary.json", f'["{base}\\uD800"]')
    
    # Multiple surrogates near boundary
    base = 'A' * 4080
    write_seed("multi_surrogate_boundary.json", f'["{base}\\uD800\\uD801"]')
    
    # Deep nesting with boundary strings
    content = '{"a":' * 50
    content += '"' + 'x' * 4096 + '"'
    content += '}' * 50
    write_seed("deep_with_boundary_string.json", content)
    
    # Surrogate in key at boundary
    base = 'k' * 4090
    write_seed("surrogate_key_boundary.json", f'{{"{base}\\uD800":"value"}}')
    
    # Array with many boundary strings
    parts = ['"' + 'x' * 4096 + '"' for _ in range(10)]
    write_seed("array_boundary_strings.json", '[' + ','.join(parts) + ']')
    
    # Alternating valid/invalid surrogates
    write_seed("alternating_surrogates.json", 
               '["\\uD800\\uDC00","\\uD800","\\uD800\\uDC00","\\uD801"]')
    
    # Nested surrogates with escapes
    write_seed("nested_surrogate_escapes.json",
               '{"a":["\\uD800\\n","\\uD801\\t","\\uD802\\\\"]}')

def generate_stress_seeds():
    """Generate seeds for stress testing."""
    print("\n=== Generating Stress Test Seeds ===")
    
    # Very long string (10MB)
    write_seed("string_10mb.json", '["' + 'A' * (10 * 1024 * 1024) + '"]')
    
    # Many keys (100k)
    parts = [f'"k{i}":"v{i}"' for i in range(100000)]
    write_seed("keys_100k.json", '{' + ','.join(parts) + '}')
    
    # Large array (1M elements)
    write_seed("array_1m.json", '[' + ','.join(['1'] * 1000000) + ']')
    
    # Many small strings
    parts = ['"x"' for _ in range(100000)]
    write_seed("many_small_strings.json", '[' + ','.join(parts) + ']')

def generate_cve_specific_seeds():
    """Generate seeds specifically targeting CVE-2017-16516."""
    print("\n=== Generating CVE-2017-16516 Specific Seeds ===")
    
    # Original CVE pattern: high surrogate at end
    write_seed("cve_2017_16516_original.json", '["\\uD800"]')
    
    # Variations
    write_seed("cve_pattern_key.json", '{"\\uD800":"value"}')
    write_seed("cve_pattern_nested.json", '{"a":{"b":"\\uD800"}}')
    write_seed("cve_pattern_array.json", '[["\\uD800"]]')
    
    # At exact buffer boundaries (where CVE is most likely to trigger)
    for size in [4095, 4096, 8191, 8192]:
        base = 'A' * (size - 6)
        write_seed(f"cve_boundary_{size}.json", f'["{base}\\uD800"]')
    
    # Multiple high surrogates at boundary
    base = 'A' * 4084
    write_seed("cve_multi_boundary.json", f'["{base}\\uD800\\uD801"]')

def main():
    """Generate all seed files."""
    print("Generating targeted seed corpus for YAJL fuzzing...")
    print(f"Output directory: {SEED_DIR}")
    
    generate_surrogate_seeds()
    generate_boundary_seeds()
    generate_realloc_seeds()
    generate_integer_overflow_seeds()
    generate_deep_nesting_seeds()
    generate_escape_seeds()
    generate_utf8_seeds()
    generate_mixed_seeds()
    generate_stress_seeds()
    generate_cve_specific_seeds()
    
    # Count total seeds
    seed_count = len(list(SEED_DIR.glob("*.json")))
    print(f"\n=== Summary ===")
    print(f"Generated {seed_count} targeted seed files in {SEED_DIR}/")
    print("\nNext steps:")
    print("1. Review generated seeds")
    print("2. Run: afl-cmin -i in-targeted -o in-targeted-min -- ./fuzzer")
    print("3. Start fuzzing campaign with: ./run_afl_swarm.sh")

if __name__ == "__main__":
    main()
