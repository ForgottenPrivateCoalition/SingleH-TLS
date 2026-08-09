typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;
typedef unsigned long long usize;

typedef struct HMACSHA256Context HMACSHA256Context;

static void _z(void *p, usize n) {
    volatile u8 *b = (volatile u8 *)p;
    while (n--) *b++ = 0;
}

static void _c(void *d, const void *s, usize n) {
    u8 *dst = (u8 *)d;
    const u8 *src = (const u8 *)s;
    while (n--) *dst++ = *src++;
}

static void _s(void *d, u8 v, usize n) {
    u8 *dst = (u8 *)d;
    while (n--) *dst++ = v;
}

static u32 _l32(const u8 *p) {
    return ((u32)p[0] << 24) | ((u32)p[1] << 16) | ((u32)p[2] << 8) | (u32)p[3];
}

static void _s32(u8 *p, u32 v) {
    p[0] = (u8)(v >> 24);
    p[1] = (u8)(v >> 16);
    p[2] = (u8)(v >> 8);
    p[3] = (u8)v;
}

static void _s64(u8 *p, u64 v) {
    _s32(p, (u32)(v >> 32));
    _s32(p + 4, (u32)v);
}

static u32 _rr(u32 x, u32 n) {
    return (x >> n) | (x << (32 - n));
}

typedef struct {
    u32 s[8];
    u64 b;
    u8 p[64];
} S256C;

static const u32 K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static void _tf(S256C *c, const u8 *d) {
    u32 w[64], a, b, x, y, e, f, g, h, t1, t2, i;
    for (i = 0; i < 16; i++) {
        w[i] = _l32(d + i * 4);
    }
    for (i = 16; i < 64; i++) {
        u32 s0 = _rr(w[i - 15], 7) ^ _rr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        u32 s1 = _rr(w[i - 2], 17) ^ _rr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    a = c->s[0]; b = c->s[1]; x = c->s[2]; y = c->s[3];
    e = c->s[4]; f = c->s[5]; g = c->s[6]; h = c->s[7];
    for (i = 0; i < 64; i++) {
        u32 S1 = _rr(e, 6) ^ _rr(e, 11) ^ _rr(e, 25);
        u32 ch = (e & f) ^ (~e & g);
        t1 = h + S1 + ch + K[i] + w[i];
        u32 S0 = _rr(a, 2) ^ _rr(a, 13) ^ _rr(a, 22);
        u32 maj = (a & b) ^ (a & x) ^ (b & x);
        t2 = S0 + maj;
        h = g; g = f; f = e; e = y + t1;
        y = x; x = b; b = a; a = t1 + t2;
    }
    c->s[0] += a; c->s[1] += b; c->s[2] += x; c->s[3] += y;
    c->s[4] += e; c->s[5] += f; c->s[6] += g; c->s[7] += h;
    _z(w, sizeof(w));
}

static void _s256i(S256C *c) {
    c->s[0] = 0x6a09e667; c->s[1] = 0xbb67ae85; c->s[2] = 0x3c6ef372; c->s[3] = 0xa54ff53a;
    c->s[4] = 0x510e527f; c->s[5] = 0x9b05688c; c->s[6] = 0x1f83d9ab; c->s[7] = 0x5be0cd19;
    c->b = 0;
}

static void _s256u(S256C *c, const void *d, usize n) {
    const u8 *p = (const u8 *)d;
    usize rem = (usize)(c->b % 64);
    c->b += n;
    if (rem && n >= 64 - rem) {
        _c(c->p + rem, p, 64 - rem);
        _tf(c, c->p);
        n -= 64 - rem;
        p += 64 - rem;
        rem = 0;
    }
    while (n >= 64) {
        _tf(c, p);
        n -= 64;
        p += 64;
    }
    if (n) {
        _c(c->p + rem, p, n);
    }
}

static void _s256f(S256C *c, u8 o[32]) {
    usize rem = (usize)(c->b % 64);
    u64 bits = c->b * 8;
    c->p[rem++] = 0x80;
    if (rem > 56) {
        _s(c->p + rem, 0, 64 - rem);
        _tf(c, c->p);
        rem = 0;
    }
    _s(c->p + rem, 0, 56 - rem);
    _s64(c->p + 56, bits);
    _tf(c, c->p);
    for (usize i = 0; i < 8; i++) {
        _s32(o + i * 4, c->s[i]);
    }
    _z(c, sizeof(S256C));
}

struct HMACSHA256Context {
    S256C s;
    u8 o[64];
};

void hmac_sha256_init(HMACSHA256Context *ctx, const void *key, usize key_len) {
    u8 k[64];
    u8 i[64];
    _s(k, 0, 64);
    if (key_len > 64) {
        S256C ts;
        _s256i(&ts);
        _s256u(&ts, key, key_len);
        _s256f(&ts, k);
    } else {
        _c(k, key, key_len);
    }
    for (usize j = 0; j < 64; j++) {
        i[j] = k[j] ^ 0x36;
        ctx->o[j] = k[j] ^ 0x5c;
    }
    _s256i(&ctx->s);
    _s256u(&ctx->s, i, 64);
    _z(k, 64);
    _z(i, 64);
}

void hmac_sha256_update(HMACSHA256Context *ctx, const void *data, usize len) {
    _s256u(&ctx->s, data, len);
}

void hmac_sha256_final(HMACSHA256Context *ctx, u8 out[32]) {
    u8 ih[32];
    _s256f(&ctx->s, ih);
    _s256i(&ctx->s);
    _s256u(&ctx->s, ctx->o, 64);
    _s256u(&ctx->s, ih, 32);
    _s256f(&ctx->s, out);
    _z(ih, 32);
    _z(ctx, sizeof(HMACSHA256Context));
}

void hmac_sha256(const void *key, usize key_len, const void *data, usize data_len, u8 out[32]) {
    HMACSHA256Context ctx;
    hmac_sha256_init(&ctx, key, key_len);
    hmac_sha256_update(&ctx, data, data_len);
    hmac_sha256_final(&ctx, out);
}