#!/bin/bash
set -e

# Usage:
# ./compute-proof.sh "password123" "<base64-salt>" "<base64-challenge>"
#
# Example:
# ./compute-proof.sh "password123" "U2FsdFZhbHVl" "Q2hhbGxlbmdlVmFsdWU"

PASSWORD="$1"
SALT_B64="$2"
CHALLENGE_B64="$3"

if [ -z "$PASSWORD" ] || [ -z "$SALT_B64" ] || [ -z "$CHALLENGE_B64" ]; then
  echo "Usage: $0 <password> <base64-salt> <base64-challenge>"
  exit 1
fi

# Decode salt and challenge
SALT=$(echo "$SALT_B64" | base64 -d)
CHALLENGE=$(echo "$CHALLENGE_B64" | base64 -d)

# Derive verifier using Argon2id
# Parameters must match your Go code:
# argon2.IDKey(password, salt, 1, 64*1024, 4, 32)
VERIFIER_HEX=$(echo -n "$PASSWORD" \
  | argon2 "$SALT" -id -t 1 -m 16 -p 4 -l 32 -r)

# Convert hex verifier to raw bytes
VERIFIER_BIN=$(echo "$VERIFIER_HEX" | xxd -r -p)

# # Compute HMAC-SHA256(verifier, challenge)
# PROOF=$(echo -n "$CHALLENGE" \
#   | openssl dgst -sha256 \
#     -mac HMAC \
#     -macopt hexkey:"$VERIFIER_HEX" \
#     -binary \
#   | base64 -w0)

# Compute proof and encode as base64url (no padding)
PROOF=$(echo -n "$CHALLENGE" \
  | openssl dgst -sha256 \
    -mac HMAC \
    -macopt hexkey:"$VERIFIER_HEX" \
    -binary \
  | base64 \
  | tr '+/' '-_' \
  | tr -d '=' \
  | tr -d '\n')

echo "=============================="
echo "Derived Verifier (hex):"
echo "$VERIFIER_HEX"
echo
echo "Proof (base64):"
echo "$PROOF"
echo "=============================="