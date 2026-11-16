#!/bin/bash

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

URL="http://localhost:9091/access_keys"
AUTH="access_key1:aspera"
INPUT_DIR="in-yajl"
COUNTER=0
FAILED_COUNT=0

echo -e "${GREEN}Starting fuzzing of $URL${NC}"
echo "Press Ctrl+C to stop"
echo "================================"

# Function to check if server is alive
check_server() {
    curl -sS -u "$AUTH" "$URL" -m 2 > /dev/null 2>&1
    return $?
}

# Initial server check
if ! check_server; then
    echo -e "${RED}Server is not responding at $URL${NC}"
    echo "Please start the server first"
    exit 1
fi

echo -e "${GREEN}Server is responding. Starting fuzzing...${NC}\n"

# Find all files in in-yajl directory
find "$INPUT_DIR" -type f -name "*.json" | sort | while read -r file; do
    COUNTER=$((COUNTER + 1))
    filename=$(basename "$file")
    
    echo -e "${YELLOW}[$COUNTER] Testing: $filename${NC}"
    
    # Send the payload
    response=$(curl -sS -u "$AUTH" "$URL" \
        -H 'Content-Type: application/json' \
        --data-binary "@$file" \
        -w "\nHTTP_CODE:%{http_code}" \
        -m 5 2>&1)
    
    curl_exit=$?
    
    if [ $curl_exit -ne 0 ]; then
        echo -e "${RED}  ✗ Curl failed with exit code: $curl_exit${NC}"
        echo -e "${RED}  Response: $response${NC}"
        
        # Check if server is still alive
        sleep 0.5
        if ! check_server; then
            echo -e "\n${RED}================================${NC}"
            echo -e "${RED}SERVER CRASHED OR STOPPED!${NC}"
            echo -e "${RED}Last payload: $file${NC}"
            echo -e "${RED}Total payloads sent: $COUNTER${NC}"
            echo -e "${RED}================================${NC}"
            exit 0
        fi
        FAILED_COUNT=$((FAILED_COUNT + 1))
    else
        http_code=$(echo "$response" | grep "HTTP_CODE:" | cut -d: -f2)
        echo -e "${GREEN}  ✓ HTTP $http_code${NC}"
    fi
    
    # Small delay between requests
    sleep 0.1
done

echo -e "\n${GREEN}================================${NC}"
echo -e "${GREEN}Fuzzing completed!${NC}"
echo -e "${GREEN}Total payloads sent: $COUNTER${NC}"
echo -e "${GREEN}Failed requests: $FAILED_COUNT${NC}"
echo -e "${GREEN}Server is still running${NC}"
echo -e "${GREEN}================================${NC}"
