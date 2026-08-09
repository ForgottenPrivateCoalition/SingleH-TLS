#define u8 unsigned char
#define u32 unsigned int
#define u64 unsigned long long
#define usize unsigned long long
#define size_t unsigned long long

typedef struct {
    u32 rk[44];
} AES128GCMContext;

static const u8 sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static u32 sub_word(u32 w) {
    return ((u32)sbox[(w >> 24) & 0xff] << 24) |
           ((u32)sbox[(w >> 16) & 0xff] << 16) |
           ((u32)sbox[(w >> 8) & 0xff] << 8) |
           ((u32)sbox[w & 0xff]);
}

static u32 rot_word(u32 w) {
    return (w << 8) | (w >> 24);
}

static const u8 rcon[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

void aes128gcm_init(AES128GCMContext *ctx, const u8 key[16]) {
    u32 i;
    for (i = 0; i < 4; i++) {
        ctx->rk[i] = ((u32)key[4 * i] << 24) |
                     ((u32)key[4 * i + 1] << 16) |
                     ((u32)key[4 * i + 2] << 8) |
                     ((u32)key[4 * i + 3]);
    }
    for (i = 4; i < 44; i++) {
        u32 t = ctx->rk[i - 1];
        if (i % 4 == 0) {
            t = sub_word(rot_word(t)) ^ ((u32)rcon[(i / 4) - 1] << 24);
        }
        ctx->rk[i] = ctx->rk[i - 4] ^ t;
    }
}

static void aes128_encrypt_block(const AES128GCMContext *ctx, const u8 in[16], u8 out[16]) {
    u32 s0, s1, s2, s3;
    u32 i;
    u8 state[16];
    for (i = 0; i < 16; i++) state[i] = in[i];
    s0 = ((u32)state[0] << 24) | ((u32)state[1] << 16) | ((u32)state[2] << 8) | state[3];
    s1 = ((u32)state[4] << 24) | ((u32)state[5] << 16) | ((u32)state[6] << 8) | state[7];
    s2 = ((u32)state[8] << 24) | ((u32)state[9] << 16) | ((u32)state[10] << 8) | state[11];
    s3 = ((u32)state[12] << 24) | ((u32)state[13] << 16) | ((u32)state[14] << 8) | state[15];
    s0 ^= ctx->rk[0]; s1 ^= ctx->rk[1]; s2 ^= ctx->rk[2]; s3 ^= ctx->rk[3];
    for (i = 1; i < 10; i++) {
        u32 t0, t1, t2, t3;
        t0 = ctx->rk[4 * i] ^
             ((u32)sbox[(s0 >> 24) & 0xff] << 24) ^
             ((u32)sbox[(s1 >> 16) & 0xff] << 16) ^
             ((u32)sbox[(s2 >> 8) & 0xff] << 8) ^
             ((u32)sbox[s3 & 0xff]);
        t1 = ctx->rk[4 * i + 1] ^
             ((u32)sbox[(s1 >> 24) & 0xff] << 24) ^
             ((u32)sbox[(s2 >> 16) & 0xff] << 16) ^
             ((u32)sbox[(s3 >> 8) & 0xff] << 8) ^
             ((u32)sbox[s0 & 0xff]);
        t2 = ctx->rk[4 * i + 2] ^
             ((u32)sbox[(s2 >> 24) & 0xff] << 24) ^
             ((u32)sbox[(s3 >> 16) & 0xff] << 16) ^
             ((u32)sbox[(s0 >> 8) & 0xff] << 8) ^
             ((u32)sbox[s1 & 0xff]);
        t3 = ctx->rk[4 * i + 3] ^
             ((u32)sbox[(s3 >> 24) & 0xff] << 24) ^
             ((u32)sbox[(s0 >> 16) & 0xff] << 16) ^
             ((u32)sbox[(s1 >> 8) & 0xff] << 8) ^
             ((u32)sbox[s2 & 0xff]);
        s0 = t0; s1 = t1; s2 = t2; s3 = t3;
    }
    s0 = ((u32)sbox[(s0 >> 24) & 0xff] << 24) ^
         ((u32)sbox[(s1 >> 16) & 0xff] << 16) ^
         ((u32)sbox[(s2 >> 8) & 0xff] << 8) ^
         ((u32)sbox[s3 & 0xff]) ^ ctx->rk[40];
    s1 = ((u32)sbox[(s1 >> 24) & 0xff] << 24) ^
         ((u32)sbox[(s2 >> 16) & 0xff] << 16) ^
         ((u32)sbox[(s3 >> 8) & 0xff] << 8) ^
         ((u32)sbox[s0 & 0xff]) ^ ctx->rk[41];
    s2 = ((u32)sbox[(s2 >> 24) & 0xff] << 24) ^
         ((u32)sbox[(s3 >> 16) & 0xff] << 16) ^
         ((u32)sbox[(s0 >> 8) & 0xff] << 8) ^
         ((u32)sbox[s1 & 0xff]) ^ ctx->rk[42];
    s3 = ((u32)sbox[(s3 >> 24) & 0xff] << 24) ^
         ((u32)sbox[(s0 >> 16) & 0xff] << 16) ^
         ((u32)sbox[(s1 >> 8) & 0xff] << 8) ^
         ((u32)sbox[s2 & 0xff]) ^ ctx->rk[43];
    out[0]  = (u8)(s0 >> 24); out[1]  = (u8)(s0 >> 16); out[2]  = (u8)(s0 >> 8); out[3]  = (u8)s0;
    out[4]  = (u8)(s1 >> 24); out[5]  = (u8)(s1 >> 16); out[6]  = (u8)(s1 >> 8); out[7]  = (u8)s1;
    out[8]  = (u8)(s2 >> 24); out[9]  = (u8)(s2 >> 16); out[10] = (u8)(s2 >> 8); out[11] = (u8)s2;
    out[12] = (u8)(s3 >> 24); out[13] = (u8)(s3 >> 16); out[14] = (u8)(s3 >> 8); out[15] = (u8)s3;
}

static void ghash_init(u8 h[16]) {
    u32 i;
    for (i = 0; i < 16; i++) h[i] = 0;
}

static void ghash_mul(u8 x[16], const u8 y[16]) {
    u8 z[16];
    u8 v[16];
    u32 i, j;
    for (i = 0; i < 16; i++) { z[i] = 0; v[i] = y[i]; }
    for (i = 0; i < 128; i++) {
        u8 bit = (x[i >> 3] >> (7 - (i & 7))) & 1;
        if (bit) {
            for (j = 0; j < 16; j++) z[j] ^= v[j];
        }
        u8 carry = (v[15] & 1) ? 0xe1 : 0;
        for (j = 15; j > 0; j--) v[j] = (v[j] >> 1) | (v[j - 1] << 7);
        v[0] = (v[0] >> 1) ^ carry;
    }
    for (i = 0; i < 16; i++) x[i] = z[i];
}

static void ghash_update(u8 h[16], const u8 *data, usize len) {
    usize i;
    for (i = 0; i < len; i += 16) {
        usize j;
        for (j = 0; j < 16 && (i + j) < len; j++) {
            h[j] ^= data[i + j];
        }
        ghash_mul(h, h);
    }
}

static void gcm_ctr(const AES128GCMContext *ctx, u8 counter[16], u8 *out, const u8 *in, usize len) {
    usize i;
    for (i = 0; i < len; i += 16) {
        u8 keystream[16];
        aes128_encrypt_block(ctx, counter, keystream);
        u32 j;
        for (j = 15; j >= 0; j--) {
            counter[j]++;
            if (counter[j] != 0) break;
        }
        u32 block_len = 16;
        if (len - i < 16) block_len = (u32)(len - i);
        for (j = 0; j < block_len; j++) {
            out[i + j] = in[i + j] ^ keystream[j];
        }
    }
}

void aes128gcm_encrypt(
    AES128GCMContext *ctx,
    const u8 nonce[12],
    const void *aad,
    usize aad_len,
    const void *plaintext,
    usize plaintext_len,
    void *ciphertext,
    u8 tag[16]
) {
    u8 counter[16];
    u8 hkey[16];
    u8 hash[16];
    u32 i;
    for (i = 0; i < 16; i++) hkey[i] = 0;
    aes128_encrypt_block(ctx, hkey, hkey);
    ghash_init(hash);
    ghash_update(hash, (const u8 *)aad, aad_len);
    for (i = 0; i < 12; i++) counter[i] = nonce[i];
    counter[12] = 0; counter[13] = 0; counter[14] = 0; counter[15] = 1;
    gcm_ctr(ctx, counter, (u8 *)ciphertext, (const u8 *)plaintext, plaintext_len);
    for (i = 0; i < 12; i++) counter[i] = nonce[i];
    counter[12] = 0; counter[13] = 0; counter[14] = 0; counter[15] = 1;
    ghash_update(hash, (const u8 *)ciphertext, plaintext_len);
    {
        u8 len_block[16];
        u64 aad_bits = (u64)aad_len * 8;
        u64 pt_bits = (u64)plaintext_len * 8;
        for (i = 0; i < 16; i++) len_block[i] = 0;
        len_block[0] = (u8)(aad_bits >> 56);
        len_block[1] = (u8)(aad_bits >> 48);
        len_block[2] = (u8)(aad_bits >> 40);
        len_block[3] = (u8)(aad_bits >> 32);
        len_block[4] = (u8)(aad_bits >> 24);
        len_block[5] = (u8)(aad_bits >> 16);
        len_block[6] = (u8)(aad_bits >> 8);
        len_block[7] = (u8)(aad_bits);
        len_block[8] = (u8)(pt_bits >> 56);
        len_block[9] = (u8)(pt_bits >> 48);
        len_block[10] = (u8)(pt_bits >> 40);
        len_block[11] = (u8)(pt_bits >> 32);
        len_block[12] = (u8)(pt_bits >> 24);
        len_block[13] = (u8)(pt_bits >> 16);
        len_block[14] = (u8)(pt_bits >> 8);
        len_block[15] = (u8)(pt_bits);
        ghash_update(hash, len_block, 16);
    }
    gcm_ctr(ctx, counter, tag, hash, 16);
}

int aes128gcm_decrypt(
    AES128GCMContext *ctx,
    const u8 nonce[12],
    const void *aad,
    usize aad_len,
    const void *ciphertext,
    usize ciphertext_len,
    const u8 tag[16],
    void *plaintext
) {
    u8 counter[16];
    u8 hkey[16];
    u8 hash[16];
    u8 computed_tag[16];
    u32 i;
    u8 diff;
    for (i = 0; i < 16; i++) hkey[i] = 0;
    aes128_encrypt_block(ctx, hkey, hkey);
    ghash_init(hash);
    ghash_update(hash, (const u8 *)aad, aad_len);
    for (i = 0; i < 12; i++) counter[i] = nonce[i];
    counter[12] = 0; counter[13] = 0; counter[14] = 0; counter[15] = 1;
    ghash_update(hash, (const u8 *)ciphertext, ciphertext_len);
    {
        u8 len_block[16];
        u64 aad_bits = (u64)aad_len * 8;
        u64 ct_bits = (u64)ciphertext_len * 8;
        for (i = 0; i < 16; i++) len_block[i] = 0;
        len_block[0] = (u8)(aad_bits >> 56);
        len_block[1] = (u8)(aad_bits >> 48);
        len_block[2] = (u8)(aad_bits >> 40);
        len_block[3] = (u8)(aad_bits >> 32);
        len_block[4] = (u8)(aad_bits >> 24);
        len_block[5] = (u8)(aad_bits >> 16);
        len_block[6] = (u8)(aad_bits >> 8);
        len_block[7] = (u8)(aad_bits);
        len_block[8] = (u8)(ct_bits >> 56);
        len_block[9] = (u8)(ct_bits >> 48);
        len_block[10] = (u8)(ct_bits >> 40);
        len_block[11] = (u8)(ct_bits >> 32);
        len_block[12] = (u8)(ct_bits >> 24);
        len_block[13] = (u8)(ct_bits >> 16);
        len_block[14] = (u8)(ct_bits >> 8);
        len_block[15] = (u8)(ct_bits);
        ghash_update(hash, len_block, 16);
    }
    gcm_ctr(ctx, counter, computed_tag, hash, 16);
    diff = 0;
    for (i = 0; i < 16; i++) {
        diff |= (tag[i] ^ computed_tag[i]);
    }
    if (diff) {
        for (i = 0; i < ciphertext_len; i++) ((u8 *)plaintext)[i] = 0;
        return -1;
    }
    gcm_ctr(ctx, counter, (u8 *)plaintext, (const u8 *)ciphertext, ciphertext_len);
    return 0;
}