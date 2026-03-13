#!/bin/bash

# Configuration
API_URL="http://localhost:8080"
PLAIN_TEXT="Hello Crow Microservice!"
AES_KEY="12345678901234567890123456789012" # Exactly 32 bytes for AES-256

echo "--- Testing crowRESTmicroservice ---"

# 1. Test SHA-256 Hashing
echo -e "\n[1] Testing SHA-256..."
curl -s -X POST "$API_URL/hash" \
     -H "Content-Type: application/json" \
     -d "{\"data\": \"$PLAIN_TEXT\"}" | jq .

# 2. Test Benchmarking
echo -e "\n[2] Testing Benchmark..."
curl -s -X POST "$API_URL/benchmark" \
     -H "Content-Type: application/json" \
     -d "{\"data\": \"$PLAIN_TEXT\"}" | jq .

# 3. Test AES-256 Encryption
echo -e "\n[3] Testing AES-256 Encryption..."
RESPONSE=$(curl -s -X POST "$API_URL/encrypt/aes256" \
     -H "Content-Type: application/json" \
     -d "{\"data\": \"$PLAIN_TEXT\", \"key\": \"$AES_KEY\"}")

echo "$RESPONSE" | jq .

# Extract IV and Ciphertext for a future Decrypt test
IV=$(echo "$RESPONSE" | jq -r '.iv')
CIPHER=$(echo "$RESPONSE" | jq -r '.ciphertext')

echo -e "\nCaptured IV: $IV"
echo "Captured Ciphertext: $CIPHER"
echo "--- Tests Complete ---"
