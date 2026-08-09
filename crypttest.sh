#!/bin/bash

echo "=== SHA-256 Test ==="
RESULT=$(echo -n "Hello, World!" | openssl dgst -sha256 | awk '{print $2}')
echo "OpenSSL: $RESULT"
echo "Your code: dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"
[ "$RESULT" = "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f" ] && echo "✅ PASS" || echo "❌ FAIL"

echo ""
echo "=== HMAC-SHA256 Test ==="
RESULT=$(echo -n "Hello, World!" | openssl dgst -sha256 -hmac "defaultkey" | awk '{print $2}')
echo "OpenSSL: $RESULT"
echo "Your code: bbd643f252983642df9149b068af1b592e06949239ea49c3b727506ea45719ac"
[ "$RESULT" = "bbd643f252983642df9149b068af1b592e06949239ea49c3b727506ea45719ac" ] && echo "✅ PASS" || echo "❌ FAIL"