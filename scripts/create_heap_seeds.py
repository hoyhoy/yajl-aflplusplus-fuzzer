#!/usr/bin/env python3
import os

# Create aggressive seeds targeting heap buffer overflows
os.makedirs("in-heap-overflow", exist_ok=True)

# 1. String at exact realloc boundary with surrogate
with open("in-heap-overflow/realloc_boundary_surrogate.json", "wb") as f:
    # 4095 bytes + surrogate that expands during decode
    s = '["' + 'A' * 4090 + '\\uD800\\uDC00"]'
    f.write(s.encode())

# 2. Key at realloc boundary
with open("in-heap-overflow/key_realloc_boundary.json", "wb") as f:
    s = '{"' + 'K' * 8190 + '":"value"}'
    f.write(s.encode())

# 3. Multiple surrogates at buffer edge
with open("in-heap-overflow/multi_surrogate_edge.json", "wb") as f:
    s = '["' + 'X' * 4080 + '\\uD800\\uDC00\\uD801\\uDC01\\uD802\\uDC02"]'
    f.write(s.encode())

# 4. Escaped sequences that expand
with open("in-heap-overflow/escape_expansion.json", "wb") as f:
    # Each \uXXXX becomes UTF-8 bytes
    s = '["' + '\\u0041' * 2000 + '"]'
    f.write(s.encode())

# 5. Nested with surrogates at each level
with open("in-heap-overflow/nested_surrogate_levels.json", "wb") as f:
    s = '{"a' + '\\uD800\\uDC00' + '":' * 100
    s += '"value"' + '}' * 100
    f.write(s.encode())

# 6. Array with many surrogate strings
with open("in-heap-overflow/array_many_surrogates.json", "wb") as f:
    items = ['"\\uD800\\uDC00"'] * 1000
    s = '[' + ','.join(items) + ']'
    f.write(s.encode())

# 7. Object with surrogate keys
with open("in-heap-overflow/surrogate_keys.json", "wb") as f:
    pairs = ['"k\\uD800\\uDC00' + str(i) + '":"v"' for i in range(500)]
    s = '{' + ','.join(pairs) + '}'
    f.write(s.encode())

# 8. Invalid UTF-8 + escape sequences
with open("in-heap-overflow/invalid_utf8_escape.json", "wb") as f:
    f.write(b'["\\u0000\xed\xa0\x80\\uDC00"]')

# 9. Surrogate at exact 4096 boundary
with open("in-heap-overflow/surrogate_4096.json", "wb") as f:
    s = '["' + 'B' * 4091 + '\\uD800\\uDC00"]'
    f.write(s.encode())

# 10. High surrogate followed by invalid low
with open("in-heap-overflow/high_invalid_low.json", "wb") as f:
    s = '["\\uD800\\uE000"]'  # E000 is not a low surrogate
    f.write(s.encode())

# 11. Surrogate pair split across buffer boundary
with open("in-heap-overflow/split_surrogate.json", "wb") as f:
    s = '["' + 'C' * 4094 + '\\uD800'
    f.write(s.encode())

# 12. Multiple buffer boundaries
with open("in-heap-overflow/multi_boundary.json", "wb") as f:
    s = '["' + 'D' * 4095 + 'E' * 4095 + 'F' * 4095 + '"]'
    f.write(s.encode())

print(f"Created {len(os.listdir('in-heap-overflow'))} heap overflow seed files")
