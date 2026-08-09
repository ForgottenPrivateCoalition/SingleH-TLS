#define u8 unsigned char
#define u32 unsigned int
#define u64 unsigned long long
#define usize unsigned long long
#define size_t unsigned long long

typedef struct {
    const u8 *data;
    usize len;
    usize pos;
} DERReader;

static int ascii_to_lower(u8 c) {
    if (c >= 'A' && c <= 'Z') return c + 0x20;
    return c;
}

static int mem_equal_nocase(const u8 *a, const u8 *b, usize len) {
    u8 diff = 0;
    usize i;
    for (i = 0; i < len; i++) {
        u8 ca = (u8)ascii_to_lower(a[i]);
        u8 cb = (u8)ascii_to_lower(b[i]);
        diff |= ca ^ cb;
    }
    return diff == 0;
}

static int mem_equal(const u8 *a, const u8 *b, usize len) {
    u8 diff = 0;
    usize i;
    for (i = 0; i < len; i++) diff |= a[i] ^ b[i];
    return diff == 0;
}

static void copy_bytes(u8 *dst, const u8 *src, usize len) {
    usize i;
    for (i = 0; i < len; i++) dst[i] = src[i];
}

int der_init(DERReader *r, const void *data, usize len) {
    r->data = (const u8 *)data;
    r->len = len;
    r->pos = 0;
    return 0;
}

int der_read(DERReader *r, u8 *tag, const u8 **value, usize *value_len) {
    u8 b;
    u32 parsed_tag;
    usize len;
    usize i;

    if (r->pos >= r->len) return -1;
    b = r->data[r->pos++];
    parsed_tag = b;
    if ((b & 0x1f) == 0x1f) {
        parsed_tag = 0;
        for (;;) {
            if (r->pos >= r->len) return -1;
            b = r->data[r->pos++];
            parsed_tag = (parsed_tag << 7) | (b & 0x7f);
            if ((b & 0x80) == 0) break;
            if (parsed_tag > 0xffffffff) return -1;
        }
    }
    *tag = (u8)(parsed_tag & 0xff);
    if (r->pos >= r->len) return -1;
    b = r->data[r->pos++];
    if (b < 0x80) {
        len = b;
    } else {
        u8 num_bytes = b & 0x7f;
        if (num_bytes == 0 || num_bytes > 8) return -1;
        if (r->pos + num_bytes > r->len) return -1;
        len = 0;
        for (i = 0; i < num_bytes; i++) {
            len = (len << 8) | r->data[r->pos++];
        }
        if (len < 0x80) {
            if (num_bytes > 1 || (num_bytes == 1 && len < 0x80)) return -1;
        } else if (len <= 0xff && num_bytes > 1) return -1;
        else if (len <= 0xffff && num_bytes > 2) return -1;
        else if (len <= 0xffffff && num_bytes > 3) return -1;
        else if (len <= 0xffffffff && num_bytes > 4) return -1;
    }
    if (r->pos + len > r->len) return -1;
    *value = r->data + r->pos;
    *value_len = len;
    r->pos += len;
    return 0;
}

int der_enter(DERReader *r, u8 expected_tag, DERReader *child) {
    u8 tag;
    const u8 *val;
    usize len;
    if (der_read(r, &tag, &val, &len) != 0) return -1;
    if (tag != expected_tag) return -1;
    if ((tag & 0x20) == 0) {
        if (expected_tag == 0x30 || expected_tag == 0x31 || expected_tag == 0xa0 || expected_tag == 0xa3) return -1;
    }
    child->data = val;
    child->len = len;
    child->pos = 0;
    return 0;
}

int der_read_integer(DERReader *r, const u8 **data, usize *len) {
    u8 tag;
    const u8 *val;
    usize vlen;
    if (der_read(r, &tag, &val, &vlen) != 0) return -1;
    if (tag != 0x02) return -1;
    if (vlen == 0) return -1;
    *data = val;
    *len = vlen;
    return 0;
}

int der_read_oid(DERReader *r, const u8 **data, usize *len) {
    u8 tag;
    const u8 *val;
    usize vlen;
    if (der_read(r, &tag, &val, &vlen) != 0) return -1;
    if (tag != 0x06) return -1;
    *data = val;
    *len = vlen;
    return 0;
}

int x509_get_signature_algorithm(const u8 *cert, usize cert_len, const u8 **oid, usize *oid_len) {
    DERReader c, sigalg;
    u8 tag;
    const u8 *val;
    usize len;
    der_init(&c, cert, cert_len);
    if (der_enter(&c, 0x30, &c) != 0) return -1;
    if (der_read(&c, &tag, &val, &len) != 0) return -1;
    if (der_read(&c, &tag, &val, &len) != 0) return -1;
    if (tag != 0x30) return -1;
    der_init(&sigalg, val, len);
    if (der_read(&sigalg, &tag, &val, &len) != 0) return -1;
    if (tag != 0x06) return -1;
    *oid = val;
    *oid_len = len;
    return 0;
}

static int skip_tbs_header(DERReader *tbs) {
    u8 tag;
    const u8 *val;
    usize len;
    if (der_read(tbs, &tag, &val, &len) != 0) return -1;
    if (tag == 0xa0) {
        if (der_read(tbs, &tag, &val, &len) != 0) return -1;
    }
    if (der_read(tbs, &tag, &val, &len) != 0) return -1;
    if (der_read(tbs, &tag, &val, &len) != 0) return -1;
    if (der_read(tbs, &tag, &val, &len) != 0) return -1;
    if (der_read(tbs, &tag, &val, &len) != 0) return -1;
    return 0;
}

int x509_get_issuer(const u8 *cert, usize cert_len, const u8 **issuer, usize *issuer_len) {
    DERReader c, tbs;
    u8 tag;
    const u8 *val;
    usize len;
    der_init(&c, cert, cert_len);
    if (der_enter(&c, 0x30, &c) != 0) return -1;
    if (der_enter(&c, 0x30, &tbs) != 0) return -1;
    if (skip_tbs_header(&tbs) != 0) return -1;
    if (der_read(&tbs, &tag, &val, &len) != 0) return -1;
    if (tag != 0x30) return -1;
    *issuer = val;
    *issuer_len = len;
    return 0;
}

int x509_get_subject(const u8 *cert, usize cert_len, const u8 **subject, usize *subject_len) {
    DERReader c, tbs;
    u8 tag;
    const u8 *val;
    usize len;
    der_init(&c, cert, cert_len);
    if (der_enter(&c, 0x30, &c) != 0) return -1;
    if (der_enter(&c, 0x30, &tbs) != 0) return -1;
    if (skip_tbs_header(&tbs) != 0) return -1;
    if (der_read(&tbs, &tag, &val, &len) != 0) return -1;
    if (der_read(&tbs, &tag, &val, &len) != 0) return -1;
    if (der_read(&tbs, &tag, &val, &len) != 0) return -1;
    if (tag != 0x30) return -1;
    *subject = val;
    *subject_len = len;
    return 0;
}

int x509_get_validity(const u8 *cert, usize cert_len,
                      const u8 **not_before, usize *not_before_len,
                      const u8 **not_after, usize *not_after_len) {
    DERReader c, tbs, validity;
    u8 tag;
    const u8 *val;
    usize len;
    der_init(&c, cert, cert_len);
    if (der_enter(&c, 0x30, &c) != 0) return -1;
    if (der_enter(&c, 0x30, &tbs) != 0) return -1;
    if (skip_tbs_header(&tbs) != 0) return -1;
    if (der_read(&tbs, &tag, &val, &len) != 0) return -1;
    if (der_enter(&tbs, 0x30, &validity) != 0) return -1;
    if (der_read(&validity, &tag, not_before, not_before_len) != 0) return -1;
    if (tag != 0x17 && tag != 0x18) return -1;
    if (der_read(&validity, &tag, not_after, not_after_len) != 0) return -1;
    if (tag != 0x17 && tag != 0x18) return -1;
    return 0;
}

static int read_public_key_info(const u8 *cert, usize cert_len,
                                DERReader *alg_id, const u8 **pubkey, usize *pubkey_len) {
    DERReader c, tbs, spki;
    u8 tag;
    const u8 *val;
    usize len;
    der_init(&c, cert, cert_len);
    if (der_enter(&c, 0x30, &c) != 0) return -1;
    if (der_enter(&c, 0x30, &tbs) != 0) return -1;
    if (skip_tbs_header(&tbs) != 0) return -1;
    if (der_read(&tbs, &tag, &val, &len) != 0) return -1;
    if (der_read(&tbs, &tag, &val, &len) != 0) return -1;
    if (der_read(&tbs, &tag, &val, &len) != 0) return -1;
    if (der_enter(&tbs, 0x30, &spki) != 0) return -1;
    if (der_enter(&spki, 0x30, alg_id) != 0) return -1;
    if (der_read(&spki, &tag, pubkey, pubkey_len) != 0) return -1;
    if (tag != 0x03) return -1;
    if (*pubkey_len < 1) return -1;
    return 0;
}

int x509_get_rsa_public_key(const u8 *cert, usize cert_len,
                            const u8 **modulus, usize *modulus_len,
                            u32 *exponent) {
    DERReader alg_id;
    const u8 *pubkey;
    usize pubkey_len;
    const u8 *rsa_oid;
    usize rsa_oid_len;
    const u8 *bit_string_data;
    usize bit_string_len;
    DERReader rsa_seq;
    u8 tag;
    const u8 *val;
    usize len;
    const u8 *n_val, *e_val;
    usize n_len, e_len;
    u32 exp = 0;
    usize i;

    if (read_public_key_info(cert, cert_len, &alg_id, &pubkey, &pubkey_len) != 0) return -1;
    if (der_read_oid(&alg_id, &rsa_oid, &rsa_oid_len) != 0) return -1;
    if (rsa_oid_len != 9) return -1;
    {
        const u8 expected_rsa[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01};
        if (!mem_equal(rsa_oid, expected_rsa, 9)) return -1;
    }
    {
        u8 dummy_tag;
        const u8 *dummy_val;
        usize dummy_len;
        if (der_read(&alg_id, &dummy_tag, &dummy_val, &dummy_len) != 0) return -1;
        if (dummy_tag != 0x05) return -1;
        if (dummy_len != 0) return -1;
    }
    if (pubkey_len < 1) return -1;
    if (pubkey[0] != 0) return -1;
    bit_string_data = pubkey + 1;
    bit_string_len = pubkey_len - 1;
    der_init(&rsa_seq, bit_string_data, bit_string_len);
    if (der_enter(&rsa_seq, 0x30, &rsa_seq) != 0) return -1;
    if (der_read_integer(&rsa_seq, &n_val, &n_len) != 0) return -1;
    if (der_read_integer(&rsa_seq, &e_val, &e_len) != 0) return -1;
    if (e_len > 4) return -1;
    for (i = 0; i < e_len; i++) exp = (exp << 8) | e_val[i];
    *modulus = n_val;
    *modulus_len = n_len;
    *exponent = exp;
    return 0;
}

int x509_get_ec_public_key(const u8 *cert, usize cert_len,
                           const u8 **point, usize *point_len,
                           const u8 **curve_oid, usize *curve_oid_len) {
    DERReader alg_id;
    const u8 *pubkey;
    usize pubkey_len;
    const u8 *ec_oid;
    usize ec_oid_len;
    u8 tag;
    const u8 *val;
    usize len;

    if (read_public_key_info(cert, cert_len, &alg_id, &pubkey, &pubkey_len) != 0) return -1;
    if (der_read_oid(&alg_id, &ec_oid, &ec_oid_len) != 0) return -1;
    {
        const u8 expected_ec[] = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01};
        if (ec_oid_len != 7 || !mem_equal(ec_oid, expected_ec, 7)) return -1;
    }
    if (der_read_oid(&alg_id, curve_oid, curve_oid_len) != 0) return -1;
    if (pubkey_len < 1) return -1;
    if (pubkey[0] != 0) return -1;
    *point = pubkey + 1;
    *point_len = pubkey_len - 1;
    return 0;
}

int x509_check_san_dns(const u8 *cert, usize cert_len, const u8 *hostname, usize hostname_len) {
    DERReader c, tbs, ext_seq;
    u8 tag;
    const u8 *val;
    usize len;
    int found_ext = 0;

    der_init(&c, cert, cert_len);
    if (der_enter(&c, 0x30, &c) != 0) return -1;
    if (der_enter(&c, 0x30, &tbs) != 0) return -1;
    if (skip_tbs_header(&tbs) != 0) return -1;
    if (der_read(&tbs, &tag, &val, &len) != 0) return -1;
    if (der_read(&tbs, &tag, &val, &len) != 0) return -1;
    if (der_read(&tbs, &tag, &val, &len) != 0) return -1;
    if (der_read(&tbs, &tag, &val, &len) != 0) return -1;
    while (tbs.pos < tbs.len) {
        if (der_read(&tbs, &tag, &val, &len) != 0) return -1;
        if (tag == 0xa3) {
            DERReader ext_wrap;
            der_init(&ext_wrap, val, len);
            if (der_enter(&ext_wrap, 0x30, &ext_seq) != 0) return -1;
            found_ext = 1;
            break;
        }
    }
    if (!found_ext) return -1;
    {
        const u8 san_oid[] = {0x55, 0x1d, 0x11};
        while (ext_seq.pos < ext_seq.len) {
            DERReader ext;
            if (der_enter(&ext_seq, 0x30, &ext) != 0) return -1;
            {
                const u8 *oid;
                usize oid_len;
                if (der_read_oid(&ext, &oid, &oid_len) != 0) return -1;
                if (oid_len == 3 && mem_equal(oid, san_oid, 3)) {
                    u8 tag2;
                    const u8 *val2;
                    usize len2;
                    if (der_read(&ext, &tag2, &val2, &len2) != 0) return -1;
                    if (tag2 == 0x01) {
                        if (der_read(&ext, &tag2, &val2, &len2) != 0) return -1;
                    }
                    if (tag2 != 0x04) return -1;
                    {
                        DERReader san_list;
                        der_init(&san_list, val2, len2);
                        if (der_enter(&san_list, 0x30, &san_list) != 0) return -1;
                        while (san_list.pos < san_list.len) {
                            u8 gn_tag;
                            const u8 *gn_val;
                            usize gn_len;
                            if (der_read(&san_list, &gn_tag, &gn_val, &gn_len) != 0) return -1;
                            if (gn_tag == 0x82) {
                                if (gn_len == hostname_len && mem_equal_nocase(gn_val, hostname, hostname_len))
                                    return 1;
                            }
                        }
                    }
                }
            }
        }
    }
    return 0;
}