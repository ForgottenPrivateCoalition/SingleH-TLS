#define u8 unsigned char
#define u32 unsigned int
#define u64 unsigned long long
#define usize unsigned long long
#define size_t unsigned long long

typedef struct {
    u8 modulus[256];
    u32 exponent;
} RSA2048PublicKey;

static const u8 sha256_digest_info[] = {
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
};

#define BN2048_LIMBS 32
#define BN2048_WORDS 64

typedef struct {
    u32 d[BN2048_LIMBS];
} bn2048;

static void bn_zero(bn2048 *a) {
    u32 i;
    for (i = 0; i < BN2048_LIMBS; i++) a->d[i] = 0;
}

static u32 bn_is_zero(const bn2048 *a) {
    u32 i, r = 0;
    for (i = 0; i < BN2048_LIMBS; i++) r |= a->d[i];
    return r == 0;
}

static int bn_cmp(const bn2048 *a, const bn2048 *b) {
    u32 i;
    for (i = BN2048_LIMBS; i > 0; i--) {
        if (a->d[i-1] > b->d[i-1]) return 1;
        if (a->d[i-1] < b->d[i-1]) return -1;
    }
    return 0;
}

static void bn_add(bn2048 *r, const bn2048 *a, const bn2048 *b) {
    u64 carry = 0;
    u32 i;
    for (i = 0; i < BN2048_LIMBS; i++) {
        u64 sum = (u64)a->d[i] + (u64)b->d[i] + carry;
        r->d[i] = (u32)sum;
        carry = sum >> 32;
    }
}

static void bn_sub(bn2048 *r, const bn2048 *a, const bn2048 *b) {
    u64 borrow = 0;
    u32 i;
    for (i = 0; i < BN2048_LIMBS; i++) {
        u64 diff = (u64)a->d[i] - (u64)b->d[i] - borrow;
        r->d[i] = (u32)diff;
        borrow = (diff >> 63) & 1;
    }
}

static u32 bn_add_carry(bn2048 *r, const bn2048 *a, const bn2048 *b, u32 carry) {
    u32 i;
    u64 c = carry;
    for (i = 0; i < BN2048_LIMBS; i++) {
        u64 sum = (u64)a->d[i] + (u64)b->d[i] + c;
        r->d[i] = (u32)sum;
        c = sum >> 32;
    }
    return (u32)c;
}

static u32 bn_sub_borrow(bn2048 *r, const bn2048 *a, const bn2048 *b, u32 borrow) {
    u32 i;
    u64 bv = borrow;
    for (i = 0; i < BN2048_LIMBS; i++) {
        u64 diff = (u64)a->d[i] - (u64)b->d[i] - bv;
        r->d[i] = (u32)diff;
        bv = (diff >> 63) & 1;
    }
    return (u32)bv;
}

static void bn_and(bn2048 *r, const bn2048 *a, const bn2048 *b) {
    u32 i;
    for (i = 0; i < BN2048_LIMBS; i++) r->d[i] = a->d[i] & b->d[i];
}

static void bn_rshift(bn2048 *r, const bn2048 *a, u32 bits) {
    u32 i;
    u32 limb_shift = bits / 32;
    u32 bit_shift = bits % 32;
    if (limb_shift >= BN2048_LIMBS) {
        bn_zero(r);
        return;
    }
    if (bit_shift == 0) {
        for (i = 0; i < BN2048_LIMBS - limb_shift; i++) r->d[i] = a->d[i + limb_shift];
        for (i = BN2048_LIMBS - limb_shift; i < BN2048_LIMBS; i++) r->d[i] = 0;
    } else {
        for (i = 0; i < BN2048_LIMBS - limb_shift - 1; i++)
            r->d[i] = (a->d[i + limb_shift] >> bit_shift) | (a->d[i + limb_shift + 1] << (32 - bit_shift));
        r->d[BN2048_LIMBS - limb_shift - 1] = a->d[BN2048_LIMBS - 1] >> bit_shift;
        for (i = BN2048_LIMBS - limb_shift; i < BN2048_LIMBS; i++) r->d[i] = 0;
    }
}

static void bn_set_ui(bn2048 *a, u32 v) {
    bn_zero(a);
    a->d[0] = v;
}

static u32 bn_get_bit(const bn2048 *a, u32 bit) {
    return (a->d[bit / 32] >> (bit % 32)) & 1;
}

static u32 bn_bitlen(const bn2048 *a) {
    u32 i;
    for (i = BN2048_LIMBS; i > 0; i--) {
        if (a->d[i-1] != 0) {
            u32 w = a->d[i-1];
            u32 bit = 32;
            while (w) { bit--; w >>= 1; }
            return (i-1)*32 + (32 - bit);
        }
    }
    return 0;
}

static void bn_from_bytes_be(bn2048 *a, const u8 *bytes, u32 len) {
    u32 i, j;
    bn_zero(a);
    for (i = 0; i < len; i++) {
        u32 byte_pos = len - 1 - i;
        u32 limb = byte_pos / 4;
        u32 shift = (byte_pos % 4) * 8;
        a->d[limb] |= ((u32)bytes[i]) << shift;
    }
}

static void bn_to_bytes_be(const bn2048 *a, u8 *bytes, u32 len) {
    u32 i;
    for (i = 0; i < len; i++) {
        u32 byte_pos = len - 1 - i;
        u32 limb = byte_pos / 4;
        u32 shift = (byte_pos % 4) * 8;
        bytes[i] = (u8)((a->d[limb] >> shift) & 0xff);
    }
}

static void bn_muladd(bn2048 *r, const bn2048 *a, u32 w) {
    u64 carry = 0;
    u32 i;
    bn2048 tmp;
    for (i = 0; i < BN2048_LIMBS; i++) {
        u64 prod = (u64)a->d[i] * (u64)w + carry;
        tmp.d[i] = (u32)prod;
        carry = prod >> 32;
    }
    bn_add(r, r, &tmp);
}

static void bn_divmod(bn2048 *q, bn2048 *r, const bn2048 *n, const bn2048 *d) {
    u32 n_bits, d_bits;
    bn2048 denom;
    u32 i;
    if (bn_is_zero(d)) { bn_zero(q); bn_zero(r); return; }
    n_bits = bn_bitlen(n);
    d_bits = bn_bitlen(d);
    bn_zero(q);
    *r = *n;
    if (n_bits < d_bits) return;
    for (i = 0; i < BN2048_LIMBS; i++) denom.d[i] = d->d[i];
    u32 shift = n_bits - d_bits;
    if (shift > 0) {
        bn2048 shifted;
        bn_zero(&shifted);
        u32 limb_shift = shift / 32;
        u32 bit_shift = shift % 32;
        for (i = 0; i < BN2048_LIMBS - limb_shift; i++) {
            shifted.d[i + limb_shift] = denom.d[i] << bit_shift;
            if (bit_shift && i + limb_shift + 1 < BN2048_LIMBS)
                shifted.d[i + limb_shift + 1] = denom.d[i] >> (32 - bit_shift);
        }
        for (i = 0; i < BN2048_LIMBS; i++) denom.d[i] = shifted.d[i];
    }
    u32 d_limb = d_bits / 32;
    u32 d_bit = d_bits % 32;
    i = shift + 1;
    while (1) {
        if (bn_cmp(r, &denom) >= 0) {
            bn_sub(r, r, &denom);
            if (i < 2048) {
                u32 limb = i / 32;
                u32 bit = i % 32;
                if (limb < BN2048_LIMBS) q->d[limb] |= (1u << bit);
            }
        }
        if (i == 0) break;
        i--;
        bn_rshift(&denom, &denom, 1);
    }
}

static void bn_modmul(bn2048 *r, const bn2048 *a, const bn2048 *b, const bn2048 *m) {
    bn2048 tmp;
    u32 i;
    bn_zero(&tmp);
    for (i = BN2048_LIMBS; i > 0; i--) {
        u32 w = a->d[i-1];
        u32 j;
        for (j = 0; j < 32; j++) {
            bn_add(&tmp, &tmp, &tmp);
            if (bn_cmp(&tmp, m) >= 0) bn_sub(&tmp, &tmp, m);
            if (w & (1u << 31)) {
                bn_add(&tmp, &tmp, b);
                if (bn_cmp(&tmp, m) >= 0) bn_sub(&tmp, &tmp, m);
            }
            w <<= 1;
        }
    }
    *r = tmp;
}

static void bn_modexp(bn2048 *r, const bn2048 *base, const bn2048 *exp, const bn2048 *mod) {
    bn2048 result, b;
    u32 ebits = bn_bitlen(exp);
    u32 i;
    bn_set_ui(&result, 1);
    b = *base;
    for (i = 0; i < ebits; i++) {
        if (bn_get_bit(exp, i)) {
            bn_modmul(&result, &result, &b, mod);
        }
        bn_modmul(&b, &b, &b, mod);
    }
    *r = result;
}

int rsa2048_verify_sha256(
    const RSA2048PublicKey *key,
    const u8 signature[256],
    const u8 hash[32]
) {
    bn2048 n, e, sig, em, expected, tmp;
    u8 em_bytes[256];
    u32 i;
    bn_from_bytes_be(&n, key->modulus, 256);
    bn_from_bytes_be(&sig, signature, 256);
    bn_set_ui(&e, key->exponent);
    bn_modexp(&em, &sig, &e, &n);
    bn_to_bytes_be(&em, em_bytes, 256);
    if (em_bytes[0] != 0x00 || em_bytes[1] != 0x01) return -1;
    u32 pad_end = 256;
    for (i = 2; i < 256; i++) {
        if (em_bytes[i] == 0x00) {
            pad_end = i;
            break;
        }
        if (em_bytes[i] != 0xff) return -1;
    }
    if (pad_end == 256 || pad_end < 10) return -1;
    u32 digest_info_len = sizeof(sha256_digest_info);
    if (pad_end + 1 + digest_info_len + 32 > 256) return -1;
    for (i = 0; i < digest_info_len; i++) {
        if (em_bytes[pad_end + 1 + i] != sha256_digest_info[i]) return -1;
    }
    u8 diff = 0;
    for (i = 0; i < 32; i++) {
        diff |= em_bytes[pad_end + 1 + digest_info_len + i] ^ hash[i];
    }
    if (diff) return -1;
    return 0;
}