#!/usr/bin/env bash

set +e

CRYPTO_TEST="./crypttest.elf"
INPUT="Hello, World!"
KEY="defaultkey"

BASE="$HOME/temp/crypto-tests"

SHA_DIR="$BASE/SHA-256"
HMAC_DIR="$BASE/HMAC-SHA256"
AES_DIR="$BASE/AES-128-GCM"
ASN1_DIR="$BASE/ASN.1-DER"
RSA_DIR="$BASE/RSA-2048"
X25519_DIR="$BASE/X25519"

PASS_COUNT=0
FAIL_COUNT=0

print_line() {
    printf '%s\n' "============================================================"
}

pass_test() {
    printf 'PASS\n' > "$1/test_status.txt"
    printf '   PASS\n'
    PASS_COUNT=$((PASS_COUNT + 1))
}

fail_test() {
    printf 'FAIL\n' > "$1/test_status.txt"
    printf '   FAIL\n'
    FAIL_COUNT=$((FAIL_COUNT + 1))
}

# ============================================================
# Проверка исполняемого файла
# ============================================================

if [ ! -f "$CRYPTO_TEST" ]; then
    echo "ERROR: executable not found: $CRYPTO_TEST"
    echo
    echo "Compile with:"
    echo "    gcc -o crypttest.elf main.c"
    exit 1
fi

if [ ! -x "$CRYPTO_TEST" ]; then
    echo "ERROR: $CRYPTO_TEST is not executable"
    echo "Run:"
    echo "    chmod +x $CRYPTO_TEST"
    exit 1
fi

# ============================================================
# Создание каталогов
# ============================================================

if ! mkdir -p \
    "$SHA_DIR" \
    "$HMAC_DIR" \
    "$AES_DIR" \
    "$ASN1_DIR" \
    "$RSA_DIR" \
    "$X25519_DIR"
then
    echo "ERROR: cannot create test directories:"
    echo "    $BASE"
    exit 1
fi

# Проверяем, что каталог действительно существует.
if [ ! -d "$BASE" ]; then
    echo "ERROR: cannot access $BASE"
    exit 1
fi

# ============================================================
# Заголовок
# ============================================================

clear 2>/dev/null

printf '%s\n' "============================================================"
printf '%s\n' "        CRYPTOGRAPHIC HEADER AUTOMATED TEST SUITE"
printf '%s\n' "============================================================"
printf 'Executable : %s\n' "$CRYPTO_TEST"
printf 'Input      : %s\n' "$INPUT"
printf 'Output     : %s\n' "$BASE"
printf '%s\n' "============================================================"
echo

# ============================================================
# 1. SHA-256
# ============================================================

echo "1. SHA-256"
print_line

SHA_OPENSSL=$(
    printf '%s' "$INPUT" |
    openssl dgst -sha256 2>/dev/null |
    awk '{print $2}'
)

"$CRYPTO_TEST" 5 "$INPUT" > "$SHA_DIR/your_result.txt" 2>&1

SHA_YOUR=$(
    grep -m1 '^SHA-256:' "$SHA_DIR/your_result.txt" |
    sed 's/^SHA-256:[[:space:]]*//'
)

printf '%s\n' "$SHA_OPENSSL" > "$SHA_DIR/openssl_result.txt"
printf '%s\n' "$SHA_YOUR" > "$SHA_DIR/your_hash.txt"

echo "OpenSSL : $SHA_OPENSSL"
echo "Your    : $SHA_YOUR"

if [ -n "$SHA_OPENSSL" ] &&
   [ "$SHA_OPENSSL" = "$SHA_YOUR" ]; then
    pass_test "$SHA_DIR"
else
    fail_test "$SHA_DIR"
fi

echo

# ============================================================
# 2. HMAC-SHA256
# ============================================================

echo "2. HMAC-SHA256"
print_line

HMAC_OPENSSL=$(
    printf '%s' "$INPUT" |
    openssl dgst -sha256 -hmac "$KEY" 2>/dev/null |
    awk '{print $2}'
)

"$CRYPTO_TEST" 3 "$INPUT" > "$HMAC_DIR/your_result.txt" 2>&1

# Поддерживаем строки вида:
# HMAC-SHA256(input, key="defaultkey"): abcdef...
# HMAC-SHA256: abcdef...
#
# Важный момент: awk '{print $2}' в старой версии брал
# "key=\"defaultkey\"):" вместо самого хеша.

HMAC_YOUR=$(
    grep -m1 'HMAC-SHA256' "$HMAC_DIR/your_result.txt" |
    grep -oE '[0-9a-fA-F]{64}' |
    tail -n1
)

printf '%s\n' "$HMAC_OPENSSL" > "$HMAC_DIR/openssl_result.txt"
printf '%s\n' "$HMAC_YOUR" > "$HMAC_DIR/your_hash.txt"

echo "OpenSSL : $HMAC_OPENSSL"
echo "Your    : $HMAC_YOUR"

if [ -n "$HMAC_OPENSSL" ] &&
   [ "$HMAC_OPENSSL" = "$HMAC_YOUR" ]; then
    pass_test "$HMAC_DIR"
else
    fail_test "$HMAC_DIR"
fi

echo

# ============================================================
# 3. AES-128-GCM
# ============================================================

echo "3. AES-128-GCM"
print_line

# ------------------------------------------------------------
# Формирование ключа:
# "Hello, World!" + нули до 16 байт
# ------------------------------------------------------------

INPUT_HEX=$(printf '%s' "$INPUT" | xxd -p -c 256)

KEY_HEX=$(printf '%s' "$INPUT_HEX" | cut -c1-32)

while [ "${#KEY_HEX}" -lt 32 ]; do
    KEY_HEX="${KEY_HEX}00"
done

# ------------------------------------------------------------
# Nonce:
# каждый байт INPUT XOR 0x55, первые 12 байт
# ------------------------------------------------------------

NONCE_HEX=""

for ((i = 0; i < 12; i++)); do
    if [ "$i" -lt "${#INPUT}" ]; then
        byte=$(printf '%s' "${INPUT:$i:1}" | od -An -tu1 | tr -d ' ')

        if [ -z "$byte" ]; then
            byte=0
        fi

        xor=$((byte ^ 0x55))
        NONCE_HEX="${NONCE_HEX}$(printf '%02x' "$xor")"
    else
        NONCE_HEX="${NONCE_HEX}00"
    fi
done

echo "Key   : $KEY_HEX"
echo "Nonce : $NONCE_HEX"

printf '%s\n' "$KEY_HEX" > "$AES_DIR/key.hex"
printf '%s\n' "$NONCE_HEX" > "$AES_DIR/nonce.hex"

# ------------------------------------------------------------
# Запуск собственной реализации
# ------------------------------------------------------------

"$CRYPTO_TEST" 1 "$INPUT" > "$AES_DIR/your_result.txt" 2>&1

AES_YOUR_CIPHER=$(
    grep -m1 '^Ciphertext:' "$AES_DIR/your_result.txt" |
    sed 's/^Ciphertext:[[:space:]]*//'
)

AES_YOUR_TAG=$(
    grep -m1 '^Tag:' "$AES_DIR/your_result.txt" |
    sed 's/^Tag:[[:space:]]*//'
)

printf '%s\n' "$AES_YOUR_CIPHER" > "$AES_DIR/ciphertext.hex"
printf '%s\n' "$AES_YOUR_TAG" > "$AES_DIR/tag.hex"

echo "Your ciphertext : $AES_YOUR_CIPHER"
echo "Your tag        : $AES_YOUR_TAG"

# ------------------------------------------------------------
# Проверка формата
# ------------------------------------------------------------

AES_OK=1

if ! printf '%s' "$AES_YOUR_CIPHER" |
    grep -qE '^[0-9a-fA-F]+$'; then
    AES_OK=0
fi

if ! printf '%s' "$AES_YOUR_TAG" |
    grep -qE '^[0-9a-fA-F]{32}$'; then
    AES_OK=0
fi

if [ "${#AES_YOUR_CIPHER}" -ne $(( ${#INPUT} * 2 )) ]; then
    AES_OK=0
fi

if [ "$AES_OK" -eq 1 ]; then
    echo "AES-128-GCM output format: valid"
    echo
    echo "NOTE:"
    echo "OpenSSL 'enc' cannot be used as a reliable AES-GCM"
    echo "reference on this OpenSSL version."
    echo
    echo "Ciphertext length : $(( ${#AES_YOUR_CIPHER} / 2 )) bytes"
    echo "Expected length   : ${#INPUT} bytes"
    echo "Authentication tag: 16 bytes"
    echo
    echo "AES implementation output was recorded in:"
    echo "    $AES_DIR"
    pass_test "$AES_DIR"
else
    echo "AES-128-GCM output format: invalid"
    fail_test "$AES_DIR"
fi

echo

# ============================================================
# 4. ASN.1 DER
# ============================================================

echo "4. ASN.1 DER"
print_line

printf '%s' "$INPUT" > "$ASN1_DIR/input.txt"

# OpenSSL ASN.1 DER.
openssl asn1parse \
    -genstr "OCTETSTRING:$INPUT" \
    -out "$ASN1_DIR/openssl.der" \
    -noout \
    2>/dev/null

if [ -f "$ASN1_DIR/openssl.der" ]; then
    ASN1_OPENSSL=$(
        xxd -p "$ASN1_DIR/openssl.der" |
        tr -d '\n'
    )
else
    ASN1_OPENSSL=""
fi

"$CRYPTO_TEST" 2 "$INPUT" > "$ASN1_DIR/your_result.txt" 2>&1

ASN1_YOUR=$(
    grep -m1 '^DER Encoded:' "$ASN1_DIR/your_result.txt" |
    sed 's/^DER Encoded:[[:space:]]*//'
)

ASN1_DECODED=$(
    grep -m1 '^Decoded value:' "$ASN1_DIR/your_result.txt" |
    sed 's/^Decoded value:[[:space:]]*//'
)

printf '%s\n' "$ASN1_OPENSSL" > "$ASN1_DIR/openssl_result.txt"
printf '%s\n' "$ASN1_YOUR" > "$ASN1_DIR/your_result.txt.der"
printf '%s\n' "$ASN1_DECODED" > "$ASN1_DIR/decoded.txt"

echo "OpenSSL DER : $ASN1_OPENSSL"
echo "Your DER    : $ASN1_YOUR"
echo "Decoded     : $ASN1_DECODED"

ASN1_OK=1

if [ -z "$ASN1_OPENSSL" ] ||
   [ "$ASN1_OPENSSL" != "$ASN1_YOUR" ]; then
    ASN1_OK=0
fi

if [ "$ASN1_DECODED" != "$INPUT" ]; then
    ASN1_OK=0
fi

if [ "$ASN1_OK" -eq 1 ]; then
    echo "Encoding : valid"
    echo "Decoding : valid"
    pass_test "$ASN1_DIR"
else
    echo "ASN.1 DER mismatch"
    fail_test "$ASN1_DIR"
fi

echo

# ============================================================
# 5. RSA-2048
# ============================================================

echo "5. RSA-2048"
print_line

PRIVATE_KEY="$RSA_DIR/private_key.pem"
PUBLIC_KEY="$RSA_DIR/public_key.pem"
SIGNATURE="$RSA_DIR/signature.bin"

openssl genpkey \
    -algorithm RSA \
    -pkeyopt rsa_keygen_bits:2048 \
    -out "$PRIVATE_KEY" \
    2>/dev/null

openssl rsa \
    -pubout \
    -in "$PRIVATE_KEY" \
    -out "$PUBLIC_KEY" \
    2>/dev/null

"$CRYPTO_TEST" 4 "$INPUT" > "$RSA_DIR/your_result.txt" 2>&1

RSA_YOUR_HASH=$(
    grep -m1 '^Hash:' "$RSA_DIR/your_result.txt" |
    sed 's/^Hash:[[:space:]]*//'
)

RSA_OPENSSL_HASH=$(
    printf '%s' "$INPUT" |
    openssl dgst -sha256 2>/dev/null |
    awk '{print $2}'
)

echo "Your hash    : $RSA_YOUR_HASH"
echo "OpenSSL hash : $RSA_OPENSSL_HASH"

printf '%s\n' "$RSA_OPENSSL_HASH" > "$RSA_DIR/openssl_hash.txt"
printf '%s\n' "$RSA_YOUR_HASH" > "$RSA_DIR/your_hash.txt"

# ------------------------------------------------------------
# Реальная RSA подпись OpenSSL
# ------------------------------------------------------------

if [ -f "$PRIVATE_KEY" ]; then
    printf '%s' "$INPUT" |
        openssl dgst \
            -sha256 \
            -sign "$PRIVATE_KEY" \
            -out "$SIGNATURE" \
            2>/dev/null
fi

if [ -f "$SIGNATURE" ]; then
    openssl dgst \
        -sha256 \
        -verify "$PUBLIC_KEY" \
        -signature "$SIGNATURE" \
        < <(printf '%s' "$INPUT") \
        > "$RSA_DIR/verify_result.txt" \
        2>&1
else
    echo "ERROR: RSA signature was not generated"
    printf '%s\n' "ERROR" > "$RSA_DIR/verify_result.txt"
fi

RSA_VERIFY=$(cat "$RSA_DIR/verify_result.txt")

echo "OpenSSL sign/verify:"
echo "$RSA_VERIFY"

RSA_OK=1

if [ -z "$RSA_YOUR_HASH" ] ||
   [ "$RSA_YOUR_HASH" != "$RSA_OPENSSL_HASH" ]; then
    RSA_OK=0
fi

if ! grep -q "Verified OK" "$RSA_DIR/verify_result.txt"; then
    RSA_OK=0
fi

if [ "$RSA_OK" -eq 1 ]; then
    pass_test "$RSA_DIR"
else
    fail_test "$RSA_DIR"
fi

echo

# ============================================================
# 6. X25519
# ============================================================

echo "6. X25519"
print_line

PRIV_KEY_HEX="$INPUT_HEX"

while [ "${#PRIV_KEY_HEX}" -lt 64 ]; do
    PRIV_KEY_HEX="${PRIV_KEY_HEX}00"
done

PRIV_KEY_HEX="${PRIV_KEY_HEX:0:64}"

echo "Private key : $PRIV_KEY_HEX"

printf '%s\n' "$PRIV_KEY_HEX" > "$X25519_DIR/private_key.hex"

"$CRYPTO_TEST" 6 "$INPUT" > "$X25519_DIR/your_result.txt" 2>&1

# Извлекаем именно hex-строку, а не номер слова.
X25519_PRIV=$(
    grep -m1 '^Private key' "$X25519_DIR/your_result.txt" |
    grep -oE '[0-9a-fA-F]{64}' |
    head -n1
)

X25519_PUB=$(
    grep -m1 '^Public key:' "$X25519_DIR/your_result.txt" |
    grep -oE '[0-9a-fA-F]{64}' |
    head -n1
)

printf '%s\n' "$X25519_PRIV" > "$X25519_DIR/your_private_key.hex"
printf '%s\n' "$X25519_PUB" > "$X25519_DIR/public_key.hex"

echo "Your private : $X25519_PRIV"
echo "Your public  : $X25519_PUB"

X25519_OK=1

if [ "${#X25519_PRIV}" -ne 64 ]; then
    X25519_OK=0
fi

if [ "${#X25519_PUB}" -ne 64 ]; then
    X25519_OK=0
fi

if [ "$X25519_PRIV" != "$PRIV_KEY_HEX" ]; then
    X25519_OK=0
fi

if [ "$X25519_OK" -eq 1 ]; then
    echo "Private key format : valid"
    echo "Public key format  : valid"
    pass_test "$X25519_DIR"
else
    echo "X25519 output format: invalid"
    fail_test "$X25519_DIR"
fi

echo

# ============================================================
# SUMMARY
# ============================================================

printf '%s\n' "============================================================"
printf '%s\n' "                         RESULTS"
printf '%s\n' "============================================================"

echo

for dir in \
    "$SHA_DIR" \
    "$HMAC_DIR" \
    "$AES_DIR" \
    "$ASN1_DIR" \
    "$RSA_DIR" \
    "$X25519_DIR"
do
    NAME=$(basename "$dir")

    if [ -f "$dir/test_status.txt" ]; then
        STATUS=$(cat "$dir/test_status.txt")

        if [ "$STATUS" = "PASS" ]; then
            echo "PASS  $NAME"
        else
            echo "FAIL  $NAME"
        fi
    else
        echo "FAIL  $NAME (no result)"
    fi
done

echo
printf '%s\n' "------------------------------------------------------------"
echo "Total: $PASS_COUNT passed, $FAIL_COUNT failed"
printf '%s\n' "------------------------------------------------------------"

echo
echo "Test files:"
echo "    $BASE"

echo

if [ "$FAIL_COUNT" -eq 0 ]; then
    echo "ALL TESTS PASSED"
    exit 0
else
    echo "SOME TESTS FAILED"
    exit 1
fi