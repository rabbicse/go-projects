# #!/bin/bash
# set -euo pipefail

# BASE_URL="http://localhost:8080"
# USERNAME="alice"
# PASSWORD="password123"

# # Decode base64url → raw bytes (macOS-safe)
# decode_base64url() {
#   local input="$1"

#   # remove whitespace/newlines
#   input="$(printf "%s" "$input" | tr -d '\n\r ')"

#   # url-safe → standard
#   input="${input//-/+}"
#   input="${input//_/\/}"

#   # padding
#   case $(( ${#input} % 4 )) in
#     2) input="${input}==";;
#     3) input="${input}=";;
#   esac

#   printf "%s" "$input" | base64 -d
# }

# echo "=============================="
# echo "1. Request Login Challenge"
# echo "=============================="

# RESP=$(curl -s -X POST "$BASE_URL/login/challenge" \
#   -H "Content-Type: application/json" \
#   -d "{\"username\":\"$USERNAME\"}")

# echo "$RESP"
# echo

# CHALLENGE_ID=$(printf "%s" "$RESP" | jq -r '.challenge_id')
# CHALLENGE=$(printf "%s" "$RESP" | jq -r '.challenge')
# SALT=$(printf "%s" "$RESP" | jq -r '.salt')

# if [ -z "$CHALLENGE_ID" ] || [ "$CHALLENGE_ID" = "null" ]; then
#   echo "❌ Failed to get challenge_id"
#   exit 1
# fi

# echo "Challenge ID: $CHALLENGE_ID"
# echo "Challenge:    $CHALLENGE"
# echo "Salt:         $SALT"
# echo

# echo "=============================="
# echo "2. Compute Proof"
# echo "=============================="

# # Decode base64url values into raw bytes
# SALT_BIN=$(decode_base64url "$SALT")
# CHALLENGE_BIN=$(decode_base64url "$CHALLENGE")

# # Show server-aligned debugging (optional but useful)
# echo "Client salt (hex):"
# printf "%s" "$SALT_BIN" | xxd -p
# echo

# echo "Client challenge (hex):"
# printf "%s" "$CHALLENGE_BIN" | xxd -p
# echo

# # Derive verifier using Argon2 (must match server params)
# VERIFIER_HEX=$(printf "%s" "$PASSWORD" \
#   | argon2 "$SALT_BIN" -id -t 1 -m 16 -p 4 -l 32 -r)

# echo "Verifier (hex):"
# echo "$VERIFIER_HEX"
# echo

# # Compute proof = HMAC-SHA256(verifier, challenge)
# PROOF_BIN=$(printf "%s" "$CHALLENGE_BIN" \
#   | openssl dgst -sha256 \
#     -mac HMAC \
#     -macopt hexkey:"$VERIFIER_HEX" \
#     -binary)

# echo "Proof (hex):"
# printf "%s" "$PROOF_BIN" | xxd -p
# echo

# # Encode proof as base64url (no padding)
# PROOF=$(printf "%s" "$PROOF_BIN" \
#   | base64 \
#   | tr '+/' '-_' \
#   | tr -d '=' \
#   | tr -d '\n')

# echo "Proof (base64url):"
# echo "$PROOF"
# echo

# echo "=============================="
# echo "3. Verify Login"
# echo "=============================="

# VERIFY_RESP=$(curl -s -X POST "$BASE_URL/login/verify" \
#   -H "Content-Type: application/json" \
#   -d "{
#     \"username\": \"$USERNAME\",
#     \"challenge_id\": \"$CHALLENGE_ID\",
#     \"proof\": \"$PROOF\"
#   }")

# echo "$VERIFY_RESP"
# echo

# LOGIN_TOKEN=$(printf "%s" "$VERIFY_RESP" | jq -r '.login_token')

# if [ "$LOGIN_TOKEN" = "null" ] || [ -z "$LOGIN_TOKEN" ]; then
#   echo "❌ Login failed"
#   exit 1
# fi

# echo "=============================="
# echo "✅ LOGIN SUCCESS"
# echo "Login Token:"
# echo "$LOGIN_TOKEN"
# echo "=============================="





#!/bin/bash
set -e

BASE_URL="http://localhost:8080"
USERNAME="alice"
PASSWORD="password123"

TMP_DIR="/tmp/login_flow"
mkdir -p "$TMP_DIR"

b64url_to_file() {
  local input="$1"
  local outfile="$2"

  # remove whitespace
  input="$(printf "%s" "$input" | tr -d '\n\r ')"

  # base64url → base64
  input="${input//-/+}"
  input="${input//_/\/}"

  # restore padding
  while [ $(( ${#input} % 4 )) -ne 0 ]; do
    input="${input}="
  done

  # macOS uses -D
  printf "%s" "$input" | base64 -D > "$outfile"
}

echo "=============================="
echo "1. Request Login Challenge"
echo "=============================="

RESP=$(curl -s -X POST "$BASE_URL/login/challenge" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$USERNAME\"}")

echo "$RESP"
echo

CHALLENGE_ID=$(printf "%s" "$RESP" | jq -r '.challenge_id')
CHALLENGE_B64URL=$(printf "%s" "$RESP" | jq -r '.challenge')
SALT_B64URL=$(printf "%s" "$RESP" | jq -r '.salt')

echo "Challenge ID: $CHALLENGE_ID"
echo "Challenge:    $CHALLENGE_B64URL"
echo "Salt:         $SALT_B64URL"
echo

echo "=============================="
echo "2. Decode salt & challenge"
echo "=============================="

b64url_to_file "$SALT_B64URL" "$TMP_DIR/salt.bin"
b64url_to_file "$CHALLENGE_B64URL" "$TMP_DIR/challenge.bin"

echo "Salt (hex):"
xxd -p "$TMP_DIR/salt.bin"
echo

echo "Challenge (hex):"
xxd -p "$TMP_DIR/challenge.bin"
echo

echo "=============================="
echo "3. Derive verifier (Argon2id)"
echo "=============================="

printf "%s" "$PASSWORD" \
  | argon2 "$TMP_DIR/salt.bin" -id -t 1 -m 16 -p 4 -l 32 -r \
  > "$TMP_DIR/verifier.hex"

VERIFIER_HEX=$(cat "$TMP_DIR/verifier.hex")

echo "Verifier (hex):"
echo "$VERIFIER_HEX"
echo

echo "=============================="
echo "4. Compute Proof = HMAC(verifier, challenge)"
echo "=============================="

openssl dgst -sha256 \
  -mac HMAC \
  -macopt hexkey:"$VERIFIER_HEX" \
  -binary "$TMP_DIR/challenge.bin" \
  > "$TMP_DIR/proof.bin"

echo "Proof (hex):"
xxd -p "$TMP_DIR/proof.bin"
echo

# encode proof as base64url
base64 < "$TMP_DIR/proof.bin" \
  | tr '+/' '-_' \
  | tr -d '=' \
  | tr -d '\n' \
  > "$TMP_DIR/proof.b64url"

PROOF_B64URL=$(cat "$TMP_DIR/proof.b64url")

echo "Proof (base64url):"
echo "$PROOF_B64URL"
echo

echo "=============================="
echo "5. Verify Login"
echo "=============================="

VERIFY_RESP=$(curl -s -X POST "$BASE_URL/login/verify" \
  -H "Content-Type: application/json" \
  -d "{
    \"username\": \"$USERNAME\",
    \"challenge_id\": \"$CHALLENGE_ID\",
    \"proof\": \"$PROOF_B64URL\"
  }")

echo "$VERIFY_RESP"
echo

LOGIN_TOKEN=$(printf "%s" "$VERIFY_RESP" | jq -r '.login_token')

if [ "$LOGIN_TOKEN" = "null" ] || [ -z "$LOGIN_TOKEN" ]; then
  echo "❌ Login failed"
  exit 1
fi

echo "=============================="
echo "✅ LOGIN SUCCESS"
echo "Login Token:"
echo "$LOGIN_TOKEN"
echo "=============================="