#!/bin/bash

echo "🚀 Testing OAuth 2.0 Flow..."

echo ""
echo "=== 1. Health Check ==="
curl -s http://localhost:8080/health | jq '.'

echo ""
echo "=== 2. Authorization Request ==="
AUTH_URL="http://localhost:8080/oauth/authorize?response_type=code&client_id=test-client&redirect_uri=http://localhost:3000/callback&state=xyz123&scope=read"
echo "Testing: $AUTH_URL"

# Make request and capture full response
RESPONSE=$(curl -s -i "$AUTH_URL")
echo "Full Response:"
echo "$RESPONSE"

# Extract Location header (without following redirect)
LOCATION=$(echo "$RESPONSE" | grep -i "^location:" | sed 's/^[Ll]ocation: //' | tr -d '\r')
echo "Location Header: $LOCATION"

if [[ -z "$LOCATION" ]]; then
    echo "❌ No redirect location found. Response was HTML instead of redirect."
    exit 1
fi

echo ""
echo "=== 3. Extract Authorization Code ==="
# Parse code from location header
if [[ $LOCATION == *"code="* ]]; then
    CODE=$(echo "$LOCATION" | grep -o 'code=[^&]*' | cut -d'=' -f2)
    echo "✅ Authorization Code: $CODE"
    
    echo ""
    echo "=== 4. Token Exchange ==="
    TOKEN_RESPONSE=$(curl -s -X POST http://localhost:8080/oauth/token \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "grant_type=authorization_code&code=$CODE&redirect_uri=http://localhost:3000/callback&client_id=test-client&client_secret=test-secret")
    
    echo "Token Response:"
    if command -v jq &> /dev/null; then
        echo "$TOKEN_RESPONSE" | jq '.'
    else
        echo "$TOKEN_RESPONSE"
    fi
    
    # Extract access token
    if command -v jq &> /dev/null; then
        ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token')
    else
        # Simple extraction without jq
        ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)
    fi
    
    if [[ -n "$ACCESS_TOKEN" && "$ACCESS_TOKEN" != "null" ]]; then
        echo ""
        echo "=== 5. Access Protected Resource ==="
        curl -s -H "Authorization: Bearer $ACCESS_TOKEN" \
          http://localhost:8080/api/profile
        
        echo ""
        echo ""
        echo "=== 6. Test Refresh Token ==="
        REFRESH_TOKEN=$(echo "$TOKEN_RESPONSE" | grep -o '"refresh_token":"[^"]*"' | cut -d'"' -f4)
        if [[ -n "$REFRESH_TOKEN" ]]; then
            REFRESH_RESPONSE=$(curl -s -X POST http://localhost:8080/oauth/token \
              -H "Content-Type: application/x-www-form-urlencoded" \
              -d "grant_type=refresh_token&refresh_token=$REFRESH_TOKEN&client_id=test-client&client_secret=test-secret&scope=read")
            
            echo "Refresh Response:"
            if command -v jq &> /dev/null; then
                echo "$REFRESH_RESPONSE" | jq '.'
            else
                echo "$REFRESH_RESPONSE"
            fi
        fi
    else
        echo "❌ Failed to get access token"
    fi
else
    echo "❌ No authorization code in redirect URL"
    echo "Redirect was to: $LOCATION"
fi

echo ""
echo "✅ Test completed!"