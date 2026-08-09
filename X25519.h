typedef unsigned char u8;
typedef long long i64;

static void set25519(i64 *out, const i64 *in) {
    int i;
    for (i = 0; i < 16; ++i) {
        out[i] = in[i];
    }
}

static void car25519(i64 *o) {
    int i;
    i64 c;
    for (i = 0; i < 16; ++i) {
        o[i] += 65536LL;
        c = o[i] >> 16;
        if (i < 15) {
            o[i + 1] += c - 1;
        } else {
            o[0] += 38LL * (c - 1);
        }
        o[i] -= c << 16;
    }
}

static void add25519(i64 *o, const i64 *a, const i64 *b) {
    int i;
    for (i = 0; i < 16; ++i) {
        o[i] = a[i] + b[i];
    }
}

static void sub25519(i64 *o, const i64 *a, const i64 *b) {
    int i;
    for (i = 0; i < 16; ++i) {
        o[i] = a[i] - b[i];
    }
}

static void mul25519(i64 *o, const i64 *a, const i64 *b) {
    i64 t[31];
    int i, j;
    for (i = 0; i < 31; ++i) {
        t[i] = 0;
    }
    for (i = 0; i < 16; ++i) {
        for (j = 0; j < 16; ++j) {
            t[i + j] += a[i] * b[j];
        }
    }
    for (i = 0; i < 15; ++i) {
        t[i] += 38LL * t[i + 16];
    }
    for (i = 0; i < 16; ++i) {
        o[i] = t[i];
    }
    car25519(o);
    car25519(o);
}

static void sqr25519(i64 *o, const i64 *a) {
    mul25519(o, a, a);
}

static void inv25519(i64 *o, const i64 *i) {
    i64 c[16];
    int a;
    set25519(c, i);
    for (a = 253; a >= 0; a--) {
        sqr25519(c, c);
        if (a != 2 && a != 4) {
            mul25519(c, c, i);
        }
    }
    set25519(o, c);
}

static void cswap25519(i64 *p, i64 *q, u8 b) {
    int i;
    i64 t, c = ~((i64)b - 1);
    for (i = 0; i < 16; ++i) {
        t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
    }
}

static void unpack25519(i64 *o, const u8 *n) {
    int i;
    for (i = 0; i < 16; ++i) {
        o[i] = n[2 * i] + ((i64)n[2 * i + 1] << 8);
    }
    o[15] &= 0x7fff;
}

static void pack25519(u8 *o, const i64 *n) {
    int i, j, b;
    i64 m[16], t[16];
    set25519(t, n);
    car25519(t);
    car25519(t);
    car25519(t);
    for (j = 0; j < 2; ++j) {
        m[0] = t[0] - 0xffed;
        for (i = 1; i < 15; i++) {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        cswap25519(t, m, 1 - b);
    }
    for (i = 0; i < 16; ++i) {
        o[2 * i] = t[i] & 0xff;
        o[2 * i + 1] = (t[i] >> 8) & 0xff;
    }
}

void x25519(u8 out[32], const u8 scalar[32], const u8 point[32]) {
    u8 e[32];
    i64 x1[16], x2[16], z2[16], x3[16], z3[16];
    i64 t0[16], t1[16];
    int i, r;
    u8 swap = 0, b;

    for (i = 0; i < 32; ++i) {
        e[i] = scalar[i];
    }
    e[0] &= 248;
    e[31] &= 127;
    e[31] |= 64;

    unpack25519(x1, point);

    for (i = 0; i < 16; ++i) {
        x2[i] = 0;
        z2[i] = 0;
        x3[i] = x1[i];
        z3[i] = 0;
    }
    x2[0] = 1;
    z3[0] = 1;

    for (r = 254; r >= 0; --r) {
        b = (e[r / 8] >> (r & 7)) & 1;
        swap ^= b;
        cswap25519(x2, x3, swap);
        cswap25519(z2, z3, swap);
        swap = b;

        sub25519(t0, x3, z3);
        sub25519(t1, x2, z2);
        add25519(x2, x2, z2);
        add25519(z2, x3, z3);
        mul25519(z3, t0, x2);
        mul25519(z2, z2, t1);
        sqr25519(t0, t1);
        sqr25519(t1, x2);
        add25519(x3, z3, z2);
        sub25519(z2, z3, z2);
        mul25519(x2, t1, t0);
        sub25519(t1, t1, t0);
        sqr25519(z2, z2);
        mul25519(z3, z2, x1);
        sqr25519(x3, x3);
        for (i = 0; i < 16; ++i) {
            z2[i] = t1[i] * 121666LL;
        }
        add25519(z2, z2, t0);
        mul25519(z2, z2, t1);
    }

    cswap25519(x2, x3, swap);
    cswap25519(z2, z3, swap);

    inv25519(z2, z2);
    mul25519(x2, x2, z2);
    pack25519(out, x2);
}

void x25519_base(u8 out[32], const u8 scalar[32]) {
    const u8 basepoint[32] = {
        9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };
    x25519(out, scalar, basepoint);
}