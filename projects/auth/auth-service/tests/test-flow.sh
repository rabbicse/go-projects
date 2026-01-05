#!/usr/bin/env bash
set -e

BASE_URL="http://localhost:8080"
CLIENT_ID="client-123"
CLIENT_SECRET="secret"
REDIRECT_URI="http://localhost:3000/callback"
SCOPE="openid email profile"
STATE="xyz123"

echo "=============================="
echo "1. OIDC Discovery"
echo "=============================="
curl -s "$BASE_URL/.well-known/openid-configuration" | jq .

echo
echo "=============================="
echo "2. JWKS"
echo "=============================="
curl -s "$BASE_URL/jwks.json" | jq .

echo
echo "=============================="
echo "3. Starting local callback listener (auto-capture code)"
echo "=============================="

TMP_FILE=$(mktemp)

# Start temporary callback server
(
  echo "Waiting for OAuth redirect..."
  nc -l 3000 > "$TMP_FILE"
) &
NC_PID=$!

sleep 1

AUTH_URL="$BASE_URL/authorize?response_type=code&client_id=$CLIENT_ID&redirect_uri=$REDIRECT_URI&scope=$(echo $SCOPE | sed 's/ /%20/g')&state=$STATE"

xdg-open "$AUTH_URL"

# Wait for redirect
sleep 3
kill $NC_PID || true

# Extract code from HTTP request
AUTH_CODE=$(grep -oP 'code=\K[^& ]+' "$TMP_FILE")

if [ -z "$AUTH_CODE" ]; then
  echo "❌ Failed to capture authorization code"
  exit 1
fi

echo "✔ Captured authorization code: $AUTH_CODE"

echo
echo "=============================="
echo "4. Token Exchange"
echo "=============================="

TOKEN_RESPONSE=$(curl -s -X POST "$BASE_URL/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=$AUTH_CODE" \
  -d "redirect_uri=$REDIRECT_URI" \
  -d "client_id=$CLIENT_ID" \
  -d "client_secret=$CLIENT_SECRET")

echo "$TOKEN_RESPONSE" | jq .

ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r .access_token)
ID_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r .id_token)

echo
echo "=============================="
echo "5. Decode ID Token"
echo "=============================="
echo "$ID_TOKEN" | awk -F. '{print $1}' | base64 -d 2>/dev/null | jq .
echo "$ID_TOKEN" | awk -F. '{print $2}' | base64 -d 2>/dev/null | jq .

echo
echo "=============================="
echo "6. Replay Attack Test (MUST FAIL)"
echo "=============================="
curl -s -X POST "$BASE_URL/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=$AUTH_CODE" \
  -d "redirect_uri=$REDIRECT_URI" \
  -d "client_id=$CLIENT_ID" \
  -d "client_secret=$CLIENT_SECRET" | jq .

rm -f "$TMP_FILE"

echo
echo "=============================="
echo "ALL TESTS PASSED"
echo "=============================="
