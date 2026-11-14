#!/bin/bash
# Bypass validation fuzzing - send valid structure with malformed nested content

echo "Creating bypass fuzzing payloads..."

# Create payloads that pass initial validation but have issues deep inside
cat > bypass1.json << 'EOF'
{"path":"/test","metadata":{"nested":{"deep":{"value":[1,2,3,
EOF

cat > bypass2.json << 'EOF'
{"path":"/test","tags":["valid","tags","\uD800
EOF

cat > bypass3.json << 'EOF'
{"path":"/test","config":{"key1":"value1","key2":
EOF

# Create payload with valid path but malformed nested object
python3 << 'PYTHON'
import json
# Valid outer structure, malformed inner
payload = {
    "path": "/test",
    "metadata": {
        "nested": "valid"
    }
}
# Convert to string and inject malformed content
s = json.dumps(payload)
# Insert malformed content in the middle
s = s.replace('"valid"', '"valid","bad":' + '[' * 1000 + '1' + ']' * 999)
with open('bypass4.json', 'w') as f:
    f.write(s)
PYTHON

# Payload with extremely long key name
python3 -c "print('{\"path\":\"/test\",\"' + 'k' * 1000000 + '\":\"value\"}')" > bypass5.json

# Payload with null bytes in strings
printf '{"path":"/test","data":"test\x00null\x00bytes"}' > bypass6.json

# Rapid fire test
echo "Starting bypass fuzzing..."
counter=0

for file in bypass*.json n_deeply_nested*.json n_extreme*.json n_structure_100000*.json; do
    if [ ! -f "$file" ]; then
        continue
    fi
    
    counter=$((counter + 1))
    echo "[$counter] Bypass test: $file"
    
    # Send with different methods
    curl -sS -u access_key1:aspera http://localhost:9091/access_keys \
        -H "Content-Type: application/json" \
        --data-binary "@$file" \
        -w "\nHTTP:%{http_code}\n" 2>&1 | head -10
    
    if [ $? -ne 0 ]; then
        echo "!!! CURL FAILED - SERVER MAY BE DOWN !!!"
        exit 1
    fi
    
    # Try with chunked encoding
    curl -sS -u access_key1:aspera http://localhost:9091/access_keys \
        -H "Content-Type: application/json" \
        -H "Transfer-Encoding: chunked" \
        --data-binary "@$file" 2>&1 | head -5
    
    sleep 0.1
    echo "---"
done

# Rapid fire - send many requests quickly to trigger race conditions
echo "Rapid fire test..."
for i in {1..100}; do
    curl -sS -u access_key1:aspera http://localhost:9091/access_keys \
        -H "Content-Type: application/json" \
        --data-binary '{"path":"/test","data":[' \
        -w "." 2>&1 &
done
wait

echo ""
echo "Checking if server is still alive..."
response=$(curl -sS -u access_key1:aspera http://localhost:9091/access_keys \
    -H "Content-Type: application/json" \
    --data-binary '{"path":"/test"}' 2>&1)

if [ $? -ne 0 ]; then
    echo "!!! SERVER CRASHED OR NOT RESPONDING !!!"
    exit 1
else
    echo "Server still responding"
fi

echo "Bypass fuzzing completed."
