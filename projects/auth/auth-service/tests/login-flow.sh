#!/bin/bash
set -e

BASE_URL="http://localhost:8080"
USERNAME="alice"
PASSWORD="password123"

decode_base64url() {
  local input="$1"
  input="${input//-/+}"
  input="${input//_/\/}"
  case $((${#input} % 4)) in
    2) input="${input}==";;
    3) input="${input}=";;
  esac
  echo "$input" | base64 -d
}

echo "=============================="
echo "1. Request Login Challenge"
echo "=============================="

RESP=$(curl -s -X POST "$BASE_URL/login/challenge" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$USERNAME\"}")

echo "$RESP"
echo

CHALLENGE_ID=$(echo "$RESP" | jq -r '.challenge_id')
CHALLENGE=$(echo "$RESP" | jq -r '.challenge')
SALT=$(echo "$RESP" | jq -r '.salt')

if [ -z "$CHALLENGE_ID" ] || [ "$CHALLENGE_ID" = "null" ]; then
  echo "Failed to get challenge_id"
  exit 1
fi

echo "Challenge ID: $CHALLENGE_ID"
echo "Challenge:    $CHALLENGE"
echo "Salt:         $SALT"
echo

echo "=============================="
echo "2. Compute Proof"
echo "=============================="

# Decode base64url salt and challenge
SALT_BIN=$(decode_base64url "$SALT")
CHALLENGE_BIN=$(decode_base64url "$CHALLENGE")

# Derive verifier (must match Go Argon2 params)
VERIFIER_HEX=$(echo -n "$PASSWORD" \
  | argon2 "$SALT_BIN" -id -t 1 -m 16 -p 4 -l 32 -r)

echo "Verifier (hex):"
echo "$VERIFIER_HEX"
echo

# Compute proof (HMAC-SHA256) and encode as base64url (no padding)
PROOF=$(echo -n "$CHALLENGE_BIN" \
  | openssl dgst -sha256 \
    -mac HMAC \
    -macopt hexkey:"$VERIFIER_HEX" \
    -binary \
  | base64 \
  | tr '+/' '-_' \
  | tr -d '=' \
  | tr -d '\n')

echo "Proof (base64url):"
echo "$PROOF"
echo

echo "=============================="
echo "3. Verify Login"
echo "=============================="

VERIFY_RESP=$(curl -s -X POST "$BASE_URL/login/verify" \
  -H "Content-Type: application/json" \
  -d "{
    \"username\": \"$USERNAME\",
    \"challenge_id\": \"$CHALLENGE_ID\",
    \"proof\": \"$PROOF\"
  }")

echo "$VERIFY_RESP"
echo

LOGIN_TOKEN=$(echo "$VERIFY_RESP" | jq -r '.login_token')

if [ "$LOGIN_TOKEN" = "null" ] || [ -z "$LOGIN_TOKEN" ]; then
  echo "Login failed"
  exit 1
fi

echo "=============================="
echo "LOGIN SUCCESS"
echo "Login Token:"
echo "$LOGIN_TOKEN"
echo "=============================="