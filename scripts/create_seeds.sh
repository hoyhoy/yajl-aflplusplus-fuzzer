#!/bin/bash
cd /Users/jperrie/yajl-aflplusplus-fuzzer/in-targeted

# Integer boundaries
echo '{"num":2147483648}' > int32_max_plus1.json
echo '{"num":4294967295}' > uint32_max.json
echo '{"num":4294967296}' > uint32_max_plus1.json
echo '{"num":9223372036854775807}' > int64_max.json
echo '{"num":-9223372036854775808}' > int64_min.json
echo '{"num":9223372036854775808}' > int64_max_plus1.json
echo '{"num":18446744073709551615}' > uint64_max.json
echo '{"num":18446744073709551616}' > uint64_max_plus1.json

# Powers of 2
echo '{"num":256}' > pow2_8.json
echo '{"num":65536}' > pow2_16.json
echo '{"num":16777216}' > pow2_24.json
echo '{"num":2147483648}' > pow2_31.json
echo '{"num":4294967296}' > pow2_32.json
echo '{"num":9223372036854775808}' > pow2_63.json

# Buffer boundaries
echo '{"key":"'"$(python3 -c "print('A'*4095)")"'"}' > key_4095.json
echo '{"key":"'"$(python3 -c "print('A'*4096)")"'"}' > key_4096.json
echo '{"key":"'"$(python3 -c "print('A'*4097)")"'"}' > key_4097.json
echo '{"key":"'"$(python3 -c "print('A'*8191)")"'"}' > key_8191.json
echo '{"key":"'"$(python3 -c "print('A'*8192)")"'"}' > key_8192.json
echo '{"key":"'"$(python3 -c "print('A'*8193)")"'"}' > key_8193.json

# Very long strings
echo '["'"$(python3 -c "print('B'*10000)")"'"]' > string_10k.json
echo '["'"$(python3 -c "print('C'*100000)")"'"]' > string_100k.json

# Many small allocations
python3 -c "import json; print(json.dumps({'k'+str(i):'v'+str(i) for i in range(1000)}))" > many_keys_1k.json
python3 -c "import json; print(json.dumps({'k'+str(i):'v'+str(i) for i in range(10000)}))" > many_keys_10k.json

# Large arrays
python3 -c "import json; print(json.dumps([i for i in range(10000)]))" > array_10k.json
python3 -c "import json; print(json.dumps([i for i in range(100000)]))" > array_100k.json

# Alternating sizes (stress realloc)
python3 -c "import json; d={}; [d.update({'k'+str(i):'x'*((i%2)*1000+1)}) for i in range(1000)]; print(json.dumps(d))" > alternating_sizes.json

# Deep nesting with long strings
python3 -c "s='{\"a\":'; print(s*100 + '\"'+'X'*1000+'\"' + '}'*100)" > deep_nest_long_str.json

# Surrogate + large number
echo '{"str":"\ud800\udc00","num":9223372036854775807}' > surrogate_plus_int64max.json

# Truncated surrogates at buffer boundary
python3 -c "print('{\"key\":\"' + 'A'*4090 + '\\\\ud800' + '\"}')" > surrogate_at_boundary.json

# Invalid UTF-8 + escape sequences
printf '{"key":"\\u0000\xed\xa0\x80\\udc00"}' > invalid_utf8_escapes.json

# Extreme exponents
echo '{"num":1e308}' > exp_308.json
echo '{"num":1e309}' > exp_309.json
echo '{"num":1e-308}' > exp_neg308.json
echo '{"num":1e-324}' > exp_neg324.json
echo '{"num":1e999999}' > exp_huge.json

# Malformed escapes
echo '["\\u"]' > esc_u_only.json
echo '["\\u0"]' > esc_u_1hex.json
echo '["\\u00"]' > esc_u_2hex.json
echo '["\\u000"]' > esc_u_3hex.json
echo '["\\uGGGG"]' > esc_u_nonhex.json
echo '["\\u{1F600}"]' > esc_u_braces.json
echo '["\\U00010000"]' > esc_U_capital.json

# Surrogate edge cases
echo '["\\ud800"]' > surrogate_high_only.json
echo '["\\udc00"]' > surrogate_low_only.json
echo '["\\ud800\\ud800"]' > surrogate_high_high.json
echo '["\\udc00\\udc00"]' > surrogate_low_low.json
echo '["\\udc00\\ud800"]' > surrogate_reversed.json
echo '["\\ud800A"]' > surrogate_high_then_char.json
echo '["\\ud800\\n"]' > surrogate_high_then_newline.json
echo '["\\ud800\\u0041"]' > surrogate_high_then_bmp.json

# Null bytes in various positions
printf '{"key":"test\x00null"}' > null_in_string.json
printf '{"key\x00":"value"}' > null_in_key.json
printf '{\x00"key":"value"}' > null_before_key.json

# Truncated inputs
echo '{"key":"val' > truncated_string.json
echo '{"key":123' > truncated_number.json
echo '{"key":[1,2,3' > truncated_array.json
echo '{"key":{"nested":' > truncated_nested.json

echo "Created $(ls -1 | wc -l) seed files"
