#!/bin/bash
# Test script to verify performance optimizations

BASE_URL="http://localhost:5000"
COOKIES_FILE="/tmp/cookies.txt"

echo "🔐 Logging in..."
curl -s -c "$COOKIES_FILE" -X POST "$BASE_URL/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=Ömer&password=123456789" \
  > /dev/null

echo "✅ Login complete"

echo -e "\n📊 Accessing /guclendirme-merkezi..."
curl -s -b "$COOKIES_FILE" "$BASE_URL/guclendirme-merkezi" | head -50

echo -e "\n✅ Test complete"
