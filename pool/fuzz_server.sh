#!/bin/bash
# Fuzzing script that wraps JSON payloads with required structure

counter=0
for file in *.json; do
    counter=$((counter + 1))
    echo "[$counter] Testing: $file"
    
    # Read the original payload
    payload=$(cat "$file")
    
    # Wrap it in a structure with "path" field and the payload as a nested value
    # Try different injection points to trigger parsing issues
    wrapped="{\"path\":\"/test\",\"data\":$payload}"
    
    # Send the request
    response=$(curl -sS -u access_key1:aspera http://localhost:9091/access_keys \
        -H "Content-Type: application/json" \
        --data-binary "$wrapped" \
        -w "\nHTTP_STATUS:%{http_code}" 2>&1)
    
    echo "$response"
    
    # Check if server is still responding
    if [ $? -ne 0 ]; then
        echo "Server may have crashed! Last payload: $file"
        exit 1
    fi
    
    # Small delay to avoid overwhelming the server
    sleep 0.05
    echo "---"
done

echo "Completed $counter tests. Server still running."
