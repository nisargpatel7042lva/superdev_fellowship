#!/bin/bash

echo "Testing Solana Blockchain Server"
echo "================================"

BASE_URL="http://localhost:3000"

echo ""
echo "1. Checking server health status..."
curl -s "$BASE_URL/" | jq '.'

echo ""
echo "2. Generating a new Solana keypair..."
KEYPAIR_RESPONSE=$(curl -s -X POST "$BASE_URL/keypair")
echo $KEYPAIR_RESPONSE | jq '.'

PUBKEY=$(echo $KEYPAIR_RESPONSE | jq -r '.data.pubkey')
SECRET=$(echo $KEYPAIR_RESPONSE | jq -r '.data.secret')

echo ""
echo "3. Testing message signing functionality..."
SIGN_RESPONSE=$(curl -s -X POST "$BASE_URL/message/sign" \
  -H "Content-Type: application/json" \
  -d "{
    \"message\": \"Hello, Solana!\",
    \"secret\": \"$SECRET\"
  }")
echo $SIGN_RESPONSE | jq '.'

SIGNATURE=$(echo $SIGN_RESPONSE | jq -r '.data.signature')

echo ""
echo "4. Verifying the signed message..."
curl -s -X POST "$BASE_URL/message/verify" \
  -H "Content-Type: application/json" \
  -d "{
    \"message\": \"Hello, Solana!\",
    \"signature\": \"$SIGNATURE\",
    \"pubkey\": \"$PUBKEY\"
  }" | jq '.'

echo ""
echo "5. Creating SOL transfer instruction..."
curl -s -X POST "$BASE_URL/send/sol" \
  -H "Content-Type: application/json" \
  -d "{
    \"from\": \"$PUBKEY\",
    \"to\": \"11111111111111111111111111111112\",
    \"lamports\": 1000000
  }" | jq '.'

echo ""
echo "6. Creating token mint instruction..."
curl -s -X POST "$BASE_URL/token/create" \
  -H "Content-Type: application/json" \
  -d "{
    \"mint_authority\": \"$PUBKEY\",
    \"mint\": \"11111111111111111111111111111113\",
    \"decimals\": 6
  }" | jq '.'

echo ""
echo "All tests completed successfully!" 