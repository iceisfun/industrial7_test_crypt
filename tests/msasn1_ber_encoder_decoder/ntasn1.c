/* ntasn1.dll: ordinal-only DER helper library (the NT-side ASN.1 helpers; not the msasn1 runtime).
 * Encoders write backwards into a context { floor, aux, position, end, aux, grow-callback }:
 * with a zero floor the context only counts bytes (position moves down), otherwise bytes land in [position, end).
 * Decoders use a context with the read position at +0x10 and the end at +0x18. */
#include "asn1t.h"

#define NT_NOSPACE   0x80090028u
#define NT_PARAM     0x80090027u
#define NT_EOD       0x80093102u
#define NT_CORRUPT   0x80093103u
#define NT_LARGE     0x80093104u
#define NT_BADTAG    0x8009310bu
#define NT_RULE      0x8009310du

typedef struct { U64 lo, aux, pos, hi, aux2; void *grow; U64 pad[2]; } NTE;
typedef struct { U64 a, b; const BYTE *pos; const BYTE *end; U64 pad[4]; } NTD;
C_ASSERT(offsetof(NTE, pos) == 0x10 && offsetof(NTE, hi) == 0x18 && offsetof(NTE, grow) == 0x28);
C_ASSERT(offsetof(NTD, pos) == 0x10 && offsetof(NTD, end) == 0x18);

typedef int (WINAPI *f_len_t)(NTE *, U64);
typedef int (WINAPI *f_tag_t)(NTE *, DWORD);
typedef int (WINAPI *f_etag_t)(NTE *, DWORD, U64);
typedef int (WINAPI *f_u32_t)(NTE *, DWORD, DWORD);
typedef int (WINAPI *f_bool_t)(NTE *, int, DWORD);
typedef int (WINAPI *f_oct_t)(NTE *, const void *, U64, DWORD);
typedef int (WINAPI *f_oid_t)(NTE *, const char *, DWORD);
typedef int (WINAPI *d_len_t)(NTD *, U64 *);
typedef int (WINAPI *d_taglen_t)(NTD *, DWORD *, U64 *);
typedef int (WINAPI *d_tag_t)(NTD *, DWORD *);
typedef int (WINAPI *d_etag_t)(NTD *, int, DWORD, U64 *);
typedef int (WINAPI *d_int_t)(NTD *, DWORD *, DWORD);
typedef int (WINAPI *d_null_t)(NTD *, DWORD);
typedef int (WINAPI *d_oct_t)(NTD *, void *, U64, U64 *, DWORD);
typedef int (WINAPI *d_bertl_t)(NTD *, DWORD *, U64 *, int *);

#define NTO(n) t_proc_ord("ntasn1.dll", n)
#define NT_REQ(p, ord) do { if (!(p)) { t_skip("ntasn1.dll ordinal %d missing", ord); return; } } while (0)
#define ENC_LEN ((f_len_t)NTO(14))
#define ENC_TAG ((f_tag_t)NTO(15))
#define ENC_ETAG ((f_etag_t)NTO(16))
#define ENC_U32 ((f_u32_t)NTO(17))
#define ENC_NULL ((f_tag_t)NTO(20))
#define ENC_BOOL ((f_bool_t)NTO(21))
#define ENC_OCT ((f_oct_t)NTO(22))
#define ENC_OIDSTR ((f_oid_t)NTO(31))
#define DEC_LEN ((d_len_t)NTO(36))
#define DEC_TAGLEN ((d_taglen_t)NTO(37))
#define DEC_PEEK ((d_taglen_t)NTO(38))
#define DEC_TAG ((d_tag_t)NTO(39))
#define DEC_ETAG ((d_etag_t)NTO(40))
#define DEC_INT ((d_int_t)NTO(42))
#define DEC_NULL ((d_null_t)NTO(44))
#define DEC_BOOL ((d_int_t)NTO(45))
#define DEC_OCT ((d_oct_t)NTO(52))
#define BER_TAGLEN ((d_bertl_t)NTO(60))

static void nt_real(NTE *c, BYTE *buf, size_t n) { memset(c, 0, sizeof *c); c->lo = (U64)(ULONG_PTR)buf; c->pos = c->hi = (U64)(ULONG_PTR)(buf + n); }
static void nt_size(NTE *c) { memset(c, 0, sizeof *c); c->pos = c->hi = 0x100000; }
static const BYTE *nt_out(const NTE *c) { return (const BYTE *)(ULONG_PTR)c->pos; }
static size_t nt_outlen(const NTE *c) { return (size_t)(c->hi - c->pos); }
static void nt_dec(NTD *d, const BYTE *p, size_t n) { memset(d, 0, sizeof *d); d->pos = p; d->end = p + n; }

/* ---------------------------------------------------------------- exports */
TEST(nt_ordinals_resolve) {
    HMODULE m = t_module("ntasn1.dll");
    if (!m) { t_skip("ntasn1.dll not present"); return; }
    int miss = 0;
    for (int o = 1; o <= 61; o++) {
        if (o == 13) continue;
        if (!GetProcAddress(m, (LPCSTR)(ULONG_PTR)o)) { miss++; t_note("ordinal %d does not resolve", o); }
    }
    CHECK(miss == 0);
}
TEST(nt_ordinal_13_is_unused) {
    HMODULE m = t_module("ntasn1.dll");
    if (!m) { t_skip("ntasn1.dll not present"); return; }
    SetLastError(0);
    CHECK(GetProcAddress(m, (LPCSTR)(ULONG_PTR)13) == NULL);
    CHECK(GetProcAddress(m, (LPCSTR)(ULONG_PTR)62) == NULL);
    CHECK(GetProcAddress(m, (LPCSTR)(ULONG_PTR)0xffff) == NULL);
}
TEST(nt_exports_are_ordinal_only) {
    HMODULE m = t_module("ntasn1.dll");
    if (!m) { t_skip("ntasn1.dll not present"); return; }
    /* the names found internally are not exports: none of them is a by-name export */
    static const char *names[] = { "ASN1DER_EncLength32", "ASN1DER_DecTag", "RtlAsn1Encode", "RtlAsn1Decode", "CryptEncodeObjectEx", "ASN1_FindOidInfo" };
    for (unsigned i = 0; i < sizeof names / sizeof names[0]; i++) CHECKF(GetProcAddress(m, names[i]) == NULL, "%s", names[i]);
}
TEST(nt_ntasn1_is_not_the_msasn1_runtime) {
    /* the 60 ordinals do not alias msasn1's functions: names such as ASN1_CreateModule are not exported */
    HMODULE m = t_module("ntasn1.dll");
    if (!m) { t_skip("ntasn1.dll not present"); return; }
    CHECK(GetProcAddress(m, "ASN1_CreateModule") == NULL);
    CHECK(GetProcAddress(m, "ASN1BEREncLength") == NULL);
    CHECK(GetProcAddress(m, "ASN1_Encode") == NULL);
}

/* ---------------------------------------------------------------- encoders */
static const struct { U64 len; BYTE b[5]; DWORD n; } k_nlen[] = {
    { 0, { 0x00 }, 1 }, { 1, { 0x01 }, 1 }, { 0x7f, { 0x7f }, 1 }, { 0x80, { 0x81, 0x80 }, 2 }, { 0xff, { 0x81, 0xff }, 2 },
    { 0x100, { 0x82, 0x01, 0x00 }, 3 }, { 0xffff, { 0x82, 0xff, 0xff }, 3 }, { 0x10000, { 0x83, 0x01, 0x00, 0x00 }, 4 },
    { 0xffffff, { 0x83, 0xff, 0xff, 0xff }, 4 }, { 0x1000000, { 0x84, 0x01, 0x00, 0x00, 0x00 }, 5 },
    { 0x7fffffff, { 0x84, 0x7f, 0xff, 0xff, 0xff }, 5 }, { 0xffffffff, { 0x84, 0xff, 0xff, 0xff, 0xff }, 5 },
};
TEST(nt_enc_length32_table) {
    f_len_t f = ENC_LEN; NT_REQ(f, 14);
    for (unsigned i = 0; i < sizeof k_nlen / sizeof k_nlen[0]; i++) {
        NTE c; BYTE buf[16];
        nt_real(&c, buf, sizeof buf);
        XEQ(f(&c, k_nlen[i].len), 0);
        CHECKF(nt_outlen(&c) == k_nlen[i].n, "len %llx: %u bytes want %u", k_nlen[i].len, (unsigned)nt_outlen(&c), k_nlen[i].n);
        if (nt_outlen(&c) == k_nlen[i].n) EXPECT_BYTES(nt_out(&c), nt_outlen(&c), k_nlen[i].b, k_nlen[i].n);
        NTE s; nt_size(&s);
        XEQ(f(&s, k_nlen[i].len), 0);
        CHECKF(0x100000 - s.pos == k_nlen[i].n, "sizing mode counted %llu want %u", 0x100000 - s.pos, k_nlen[i].n);
    }
}
TEST(nt_enc_length32_rejects_lengths_above_32_bits) {
    f_len_t f = ENC_LEN; NT_REQ(f, 14);
    NTE c; BYTE buf[16]; nt_real(&c, buf, sizeof buf);
    XEQ((DWORD)f(&c, 0x100000000ull), NT_LARGE);
    XEQ((DWORD)f(&c, 0xffffffffffffffffull), NT_LARGE);
}
TEST(nt_enc_length32_buffer_too_small) {
    f_len_t f = ENC_LEN; NT_REQ(f, 14);
    NTE c; BYTE buf[2]; nt_real(&c, buf, sizeof buf);
    XEQ((DWORD)f(&c, 0x100), NT_NOSPACE);                 /* needs three octets */
    nt_real(&c, buf, sizeof buf);
    XEQ(f(&c, 0x80), 0);                                  /* two octets fit exactly */
    XEQ(buf[0], 0x81); XEQ(buf[1], 0x80);
    nt_real(&c, buf, 0);
    XEQ((DWORD)f(&c, 1), NT_NOSPACE);
}
TEST(nt_enc_length32_grows_through_the_callback_slot_only_when_set) {
    /* with no grow callback a full buffer is an error; the field is the 6th pointer-sized slot */
    f_len_t f = ENC_LEN; NT_REQ(f, 14);
    NTE c; BYTE buf[1]; nt_real(&c, buf, sizeof buf);
    CHECK(c.grow == NULL);
    XEQ(f(&c, 5), 0);
    XEQ(buf[0], 5);
    XEQ((DWORD)f(&c, 5), NT_NOSPACE);
}
static const struct { DWORD tag; BYTE b[8]; DWORD n; } k_ntag[] = {
    { 2, { 0x02 }, 1 }, { 0x1e, { 0x1e }, 1 }, { 0x20000010, { 0x30 }, 1 }, { 0x20000011, { 0x31 }, 1 }, { 0x80000000, { 0x80 }, 1 },
    { 0xa0000000, { 0xa0 }, 1 }, { 0x40000001, { 0x41 }, 1 }, { 0xc0000005, { 0xc5 }, 1 }, { 0x1f, { 0x1f, 0x1f }, 2 },
    { 0x7f, { 0x1f, 0x7f }, 2 }, { 0x80, { 0x1f, 0x81, 0x00 }, 3 }, { 0x3fff, { 0x1f, 0xff, 0x7f }, 3 }, { 0x4000, { 0x1f, 0x81, 0x80, 0x00 }, 4 },
    { 0x1fffff, { 0x1f, 0xff, 0xff, 0x7f }, 4 }, { 0x200000, { 0x1f, 0x81, 0x80, 0x80, 0x00 }, 5 }, { 0xfffffff, { 0x1f, 0xff, 0xff, 0xff, 0x7f }, 5 },
    { 0x10000000, { 0x1f, 0x81, 0x80, 0x80, 0x80, 0x00 }, 6 }, { 0xa0000000 | 200, { 0xbf, 0x81, 0x48 }, 3 }, { 0x80000000 | 31, { 0x9f, 0x1f }, 2 },
};
TEST(nt_enc_tag_table) {
    f_tag_t f = ENC_TAG; NT_REQ(f, 15);
    for (unsigned i = 0; i < sizeof k_ntag / sizeof k_ntag[0]; i++) {
        NTE c; BYTE buf[16]; nt_real(&c, buf, sizeof buf);
        XEQ(f(&c, k_ntag[i].tag), 0);
        CHECKF(nt_outlen(&c) == k_ntag[i].n, "tag %08x: %u bytes want %u", k_ntag[i].tag, (unsigned)nt_outlen(&c), k_ntag[i].n);
        if (nt_outlen(&c) == k_ntag[i].n) EXPECT_BYTES(nt_out(&c), k_ntag[i].n, k_ntag[i].b, k_ntag[i].n);
        NTE s; nt_size(&s);
        XEQ(f(&s, k_ntag[i].tag), 0);
        CHECKF(0x100000 - s.pos == k_ntag[i].n, "sizing mode tag %08x", k_ntag[i].tag);
    }
}
TEST(nt_enc_tag_null_context) {
    f_tag_t f = ENC_TAG; NT_REQ(f, 15);
    XEQ((DWORD)f(NULL, 2), NT_PARAM);
}
TEST(nt_enc_tag_buffer_too_small) {
    f_tag_t f = ENC_TAG; NT_REQ(f, 15);
    NTE c; BYTE buf[1]; nt_real(&c, buf, sizeof buf);
    XEQ((DWORD)f(&c, 0x80), NT_NOSPACE);                  /* two octets needed */
}
TEST(nt_enc_explicit_tag_writes_length_then_tag) {
    f_etag_t f = ENC_ETAG; NT_REQ(f, 16);
    NTE c; BYTE buf[16]; nt_real(&c, buf, sizeof buf);
    XEQ(f(&c, 0x20000010, 5), 0);                         /* SEQUENCE header for 5 content octets: 30 05 */
    static const BYTE e1[] = { 0x30, 0x05 };
    EXPECT_BYTES(nt_out(&c), nt_outlen(&c), e1, 2);
    nt_real(&c, buf, sizeof buf);
    XEQ(f(&c, 0xa0000001, 300), 0);                       /* A1 82 01 2C */
    static const BYTE e2[] = { 0xa1, 0x82, 0x01, 0x2c };
    EXPECT_BYTES(nt_out(&c), nt_outlen(&c), e2, 4);
    nt_real(&c, buf, sizeof buf);
    XEQ(f(&c, 0x1f, 0x80), 0);                            /* 1F 1F 81 80 */
    static const BYTE e3[] = { 0x1f, 0x1f, 0x81, 0x80 };
    EXPECT_BYTES(nt_out(&c), nt_outlen(&c), e3, 4);
}
TEST(nt_enc_explicit_tag_does_not_add_the_constructed_bit) {
    f_etag_t f = ENC_ETAG; NT_REQ(f, 16);
    NTE c; BYTE buf[8]; nt_real(&c, buf, sizeof buf);
    XEQ(f(&c, 0x10, 0), 0);                               /* tag value taken as given: 10 00, not 30 00 */
    static const BYTE e[] = { 0x10, 0x00 };
    EXPECT_BYTES(nt_out(&c), nt_outlen(&c), e, 2);
}
TEST(nt_enc_explicit_tag_sizing) {
    f_etag_t f = ENC_ETAG; NT_REQ(f, 16);
    NTE s; nt_size(&s);
    XEQ(f(&s, 0x20000010, 300), 0);
    XEQ(0x100000 - s.pos, 4);                             /* tag 1 + length 3 */
}
static const struct { DWORD v; BYTE b[8]; DWORD n; } k_nu32[] = {
    { 0, { 2, 1, 0 }, 3 }, { 0x7f, { 2, 1, 0x7f }, 3 }, { 0x80, { 2, 2, 0, 0x80 }, 4 }, { 0xff, { 2, 2, 0, 0xff }, 4 }, { 0x100, { 2, 2, 1, 0 }, 4 },
    { 0x7fff, { 2, 2, 0x7f, 0xff }, 4 }, { 0x8000, { 2, 3, 0, 0x80, 0 }, 5 }, { 0x7fffff, { 2, 3, 0x7f, 0xff, 0xff }, 5 },
    { 0x800000, { 2, 4, 0, 0x80, 0, 0 }, 6 }, { 0x7fffffff, { 2, 4, 0x7f, 0xff, 0xff, 0xff }, 6 }, { 0x80000000, { 2, 5, 0, 0x80, 0, 0, 0 }, 7 },
    { 0xffffffff, { 2, 5, 0, 0xff, 0xff, 0xff, 0xff }, 7 },
};
TEST(nt_enc_unsigned_integer32_table) {
    f_u32_t f = ENC_U32; NT_REQ(f, 17);
    for (unsigned i = 0; i < sizeof k_nu32 / sizeof k_nu32[0]; i++) {
        NTE c; BYTE buf[16]; nt_real(&c, buf, sizeof buf);
        XEQ(f(&c, k_nu32[i].v, 2), 0);
        CHECKF(nt_outlen(&c) == k_nu32[i].n, "%x: %u bytes want %u", k_nu32[i].v, (unsigned)nt_outlen(&c), k_nu32[i].n);
        if (nt_outlen(&c) == k_nu32[i].n) EXPECT_BYTES(nt_out(&c), k_nu32[i].n, k_nu32[i].b, k_nu32[i].n);
        NTE s; nt_size(&s);
        XEQ(f(&s, k_nu32[i].v, 2), 0);
        CHECKF(0x100000 - s.pos == k_nu32[i].n, "sizing mode %x: %llu want %u", k_nu32[i].v, 0x100000 - s.pos, k_nu32[i].n);
    }
}
TEST(nt_enc_unsigned_integer32_context_tag_and_overflow) {
    f_u32_t f = ENC_U32; NT_REQ(f, 17);
    NTE c; BYTE buf[16]; nt_real(&c, buf, sizeof buf);
    XEQ(f(&c, 300, 0x80000004), 0);
    static const BYTE e[] = { 0x84, 0x02, 0x01, 0x2c };
    EXPECT_BYTES(nt_out(&c), nt_outlen(&c), e, 4);
    BYTE small[2]; nt_real(&c, small, sizeof small);
    XEQ((DWORD)f(&c, 5, 2), NT_NOSPACE);                  /* needs three octets */
}
TEST(nt_enc_null_and_bool) {
    f_tag_t fn = ENC_NULL; f_bool_t fb = ENC_BOOL; NT_REQ(fn, 20); NT_REQ(fb, 21);
    NTE c; BYTE buf[16];
    nt_real(&c, buf, sizeof buf); XEQ(fn(&c, 5), 0);
    { static const BYTE e[] = { 0x05, 0x00 }; EXPECT_BYTES(nt_out(&c), nt_outlen(&c), e, 2); }
    nt_real(&c, buf, sizeof buf); XEQ(fn(&c, 0x80000002), 0);
    { static const BYTE e[] = { 0x82, 0x00 }; EXPECT_BYTES(nt_out(&c), nt_outlen(&c), e, 2); }
    nt_real(&c, buf, sizeof buf); XEQ(fb(&c, 1, 1), 0);
    { static const BYTE e[] = { 0x01, 0x01, 0xff }; EXPECT_BYTES(nt_out(&c), nt_outlen(&c), e, 3); }
    nt_real(&c, buf, sizeof buf); XEQ(fb(&c, 0, 1), 0);
    { static const BYTE e[] = { 0x01, 0x01, 0x00 }; EXPECT_BYTES(nt_out(&c), nt_outlen(&c), e, 3); }
    nt_real(&c, buf, sizeof buf); XEQ(fb(&c, 0x1234, 1), 0);     /* any non-zero int is TRUE (FF) */
    { static const BYTE e[] = { 0x01, 0x01, 0xff }; EXPECT_BYTES(nt_out(&c), nt_outlen(&c), e, 3); }
    nt_real(&c, buf, sizeof buf); XEQ(fb(&c, 1, 0x81), 0);       /* tag number 129 is multi-octet: 1F 81 01 */
    { static const BYTE e[] = { 0x1f, 0x81, 0x01, 0x01, 0xff }; EXPECT_BYTES(nt_out(&c), nt_outlen(&c), e, 5); }
    NTE s; nt_size(&s); XEQ(fn(&s, 5), 0); XEQ(0x100000 - s.pos, 2);
    nt_size(&s); XEQ(fb(&s, 1, 1), 0); XEQ(0x100000 - s.pos, 3);
}
TEST(nt_enc_octet_string) {
    f_oct_t f = ENC_OCT; NT_REQ(f, 22);
    NTE c; BYTE buf[600];
    nt_real(&c, buf, sizeof buf); XEQ(f(&c, "abc", 3, 4), 0);
    { static const BYTE e[] = { 0x04, 0x03, 'a', 'b', 'c' }; EXPECT_BYTES(nt_out(&c), nt_outlen(&c), e, 5); }
    nt_real(&c, buf, sizeof buf); XEQ(f(&c, NULL, 0, 4), 0);
    { static const BYTE e[] = { 0x04, 0x00 }; EXPECT_BYTES(nt_out(&c), nt_outlen(&c), e, 2); }
    nt_real(&c, buf, sizeof buf); XEQ(f(&c, "xy", 2, 0x80000000), 0);
    { static const BYTE e[] = { 0x80, 0x02, 'x', 'y' }; EXPECT_BYTES(nt_out(&c), nt_outlen(&c), e, 4); }
    BYTE body[300]; memset(body, 0x6b, sizeof body);
    nt_real(&c, buf, sizeof buf); XEQ(f(&c, body, 300, 4), 0);
    XEQ(nt_outlen(&c), 304);
    { static const BYTE h[] = { 0x04, 0x82, 0x01, 0x2c }; EXPECT_BYTES(nt_out(&c), 4, h, 4); }
    CHECK(nt_out(&c)[4] == 0x6b && nt_out(&c)[303] == 0x6b);
    NTE s; nt_size(&s); XEQ(f(&s, body, 300, 4), 0); XEQ(0x100000 - s.pos, 304);
}
TEST(nt_enc_octet_string_limits) {
    f_oct_t f = ENC_OCT; NT_REQ(f, 22);
    NTE c; BYTE buf[8];
    nt_real(&c, buf, 7); XEQ((DWORD)f(&c, "abcdef", 6, 4), NT_NOSPACE);        /* 6 + 2 header octets do not fit in 7 */
    nt_real(&c, buf, 8); XEQ(f(&c, "abcdef", 6, 4), 0);                       /* ... but exactly fit in 8 */
    XEQ(nt_outlen(&c), 8);
}
TEST(nt_enc_octet_string_over_2gb_is_large) {
    f_oct_t f = ENC_OCT; NT_REQ(f, 22);
    NTE c; BYTE buf[8]; nt_real(&c, buf, sizeof buf);
    XEQ((DWORD)f(&c, buf, 0x7ffffff1ull, 4), NT_LARGE);
    XEQ((DWORD)f(&c, buf, 0xffffffffffull, 4), NT_LARGE);
}
TEST(nt_enc_sequence_built_back_to_front) {
    f_u32_t fi = ENC_U32; f_oct_t fo = ENC_OCT; f_etag_t fe = ENC_ETAG; f_bool_t fb = ENC_BOOL;
    NT_REQ(fi, 17); NT_REQ(fo, 22); NT_REQ(fe, 16); NT_REQ(fb, 21);
    NTE c; BYTE buf[64]; nt_real(&c, buf, sizeof buf);
    /* SEQUENCE { INTEGER 5, OCTET STRING "hi", BOOLEAN TRUE }: fields are emitted last to first */
    U64 end0 = c.pos;
    XEQ(fb(&c, 1, 1), 0); XEQ(fo(&c, "hi", 2, 4), 0); XEQ(fi(&c, 5, 2), 0);
    XEQ(fe(&c, 0x20000010, end0 - c.pos), 0);
    static const BYTE e[] = { 0x30, 0x0a, 0x02, 0x01, 0x05, 0x04, 0x02, 'h', 'i', 0x01, 0x01, 0xff };
    EXPECT_BYTES(nt_out(&c), nt_outlen(&c), e, sizeof e);
}
TEST(nt_enc_sizing_pass_matches_the_real_pass) {
    f_u32_t fi = ENC_U32; f_oct_t fo = ENC_OCT; f_etag_t fe = ENC_ETAG; f_bool_t fb = ENC_BOOL; f_tag_t fn = ENC_NULL;
    NT_REQ(fi, 17); NT_REQ(fo, 22); NT_REQ(fe, 16); NT_REQ(fb, 21); NT_REQ(fn, 20);
    BYTE body[200]; memset(body, 1, sizeof body);
    NTE s; nt_size(&s); U64 start = s.pos;
    fn(&s, 5); fo(&s, body, sizeof body, 4); fi(&s, 0x80000000, 2); fb(&s, 1, 1); fe(&s, 0x20000010, start - s.pos);
    size_t need = (size_t)(start - s.pos);
    BYTE *buf = malloc(need); NTE c; nt_real(&c, buf, need);
    U64 e0 = c.pos;
    XEQ(fn(&c, 5), 0); XEQ(fo(&c, body, sizeof body, 4), 0); XEQ(fi(&c, 0x80000000, 2), 0); XEQ(fb(&c, 1, 1), 0); XEQ(fe(&c, 0x20000010, e0 - c.pos), 0);
    XEQ(nt_outlen(&c), need);                              /* the buffer is filled exactly */
    XEQ(c.pos, c.lo);
    CHECK(nt_out(&c)[0] == 0x30);
    free(buf);
}
TEST(nt_enc_object_identifier_string) {
    f_oid_t f = ENC_OIDSTR; NT_REQ(f, 31);
    static const struct { const char *s; BYTE b[16]; DWORD n; } c[] = {
        { "2.5.4.3", { 0x06, 0x03, 0x55, 0x04, 0x03 }, 5 },
        { "1.2.840.113549", { 0x06, 0x06, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d }, 8 },
        { "1.2.840.113549.1.1.11", { 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b }, 11 },
        { "1.3.6.1.5.5.7.3.1", { 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01 }, 10 },
        { "2.100.3", { 0x06, 0x03, 0x81, 0x34, 0x03 }, 5 },
    };
    for (unsigned i = 0; i < sizeof c / sizeof c[0]; i++) {
        NTE e; BYTE buf[32]; nt_real(&e, buf, sizeof buf);
        int rc = f(&e, c[i].s, 6);
        CHECKF(rc == 0, "%s rc=%08x", c[i].s, rc);
        if (rc == 0) { CHECKF(nt_outlen(&e) == c[i].n, "%s: %u bytes want %u", c[i].s, (unsigned)nt_outlen(&e), c[i].n); if (nt_outlen(&e) == c[i].n) EXPECT_BYTES(nt_out(&e), c[i].n, c[i].b, c[i].n); }
    }
}
TEST(nt_enc_object_identifier_string_rejects_bad_input) {
    f_oid_t f = ENC_OIDSTR; NT_REQ(f, 31);
    NTE e; BYTE buf[32];
    nt_real(&e, buf, sizeof buf); XEQ((DWORD)f(&e, "1", 6), NT_PARAM);          /* fewer than two arcs */
    nt_real(&e, buf, sizeof buf); XEQ((DWORD)f(&e, "", 6), NT_PARAM);
    nt_real(&e, buf, sizeof buf); XEQ((DWORD)f(&e, "1.x.3", 6), NT_CORRUPT);    /* non-digit */
    nt_real(&e, buf, sizeof buf); XEQ((DWORD)f(&e, "1.2.a", 6), NT_CORRUPT);
}

/* ---------------------------------------------------------------- decoders */
TEST(nt_dec_length32_forms) {
    d_len_t f = DEC_LEN; NT_REQ(f, 36);
    static const struct { BYTE b[6]; DWORD n; U64 want; } c[] = {
        { { 0x00 }, 1, 0 }, { { 0x05 }, 1, 5 }, { { 0x7f }, 1, 0x7f }, { { 0x81, 0x80 }, 2, 0x80 }, { { 0x81, 0x05 }, 2, 5 },
        { { 0x82, 0x01, 0x00 }, 3, 0x100 }, { { 0x83, 0x01, 0x00, 0x00 }, 4, 0x10000 }, { { 0x84, 0x01, 0x02, 0x03, 0x04 }, 5, 0x01020304 },
        { { 0x84, 0x00, 0x00, 0x00, 0x00 }, 5, 0 }, { { 0x84, 0x7f, 0xff, 0xff, 0xf0 }, 5, 0x7ffffff0 }, { { 0x80 + 0 + 1, 0x00 }, 2, 0 },
    };
    for (unsigned i = 0; i < sizeof c / sizeof c[0]; i++) {
        NTD d; nt_dec(&d, c[i].b, c[i].n); U64 len = 0x55;
        int rc = f(&d, &len);
        CHECKF(rc == 0 && len == c[i].want, "case %u: rc %08x len %llx want %llx", i, rc, len, c[i].want);
        CHECKF(d.pos == c[i].b + c[i].n, "case %u: position", i);
    }
}
TEST(nt_dec_length32_errors) {
    d_len_t f = DEC_LEN; NT_REQ(f, 36);
    NTD d; U64 len;
    { static const BYTE in[] = { 0x00 }; nt_dec(&d, in, 0); len = 9; XEQ((DWORD)f(&d, &len), NT_EOD); XEQ(len, 0); }
    { static const BYTE in[] = { 0x80, 0x00 }; nt_dec(&d, in, 2); XEQ((DWORD)f(&d, &len), NT_RULE); }                     /* indefinite length */
    { static const BYTE in[] = { 0x82, 0x01 }; nt_dec(&d, in, 2); XEQ((DWORD)f(&d, &len), NT_CORRUPT); }                  /* missing length octets */
    { static const BYTE in[] = { 0x85, 0, 0, 0, 0, 1 }; nt_dec(&d, in, 6); XEQ((DWORD)f(&d, &len), NT_LARGE); }           /* five length octets */
    { static const BYTE in[] = { 0xff, 0, 0, 0, 0, 0 }; nt_dec(&d, in, 6); XEQ((DWORD)f(&d, &len), NT_LARGE); }
    { static const BYTE in[] = { 0x84, 0x7f, 0xff, 0xff, 0xf1 }; nt_dec(&d, in, 5); XEQ((DWORD)f(&d, &len), NT_LARGE); }  /* above 0x7ffffff0 */
    { static const BYTE in[] = { 0x84, 0xff, 0xff, 0xff, 0xff }; nt_dec(&d, in, 5); XEQ((DWORD)f(&d, &len), NT_LARGE); }
}
TEST(nt_dec_length32_does_not_check_the_contents) {
    d_len_t f = DEC_LEN; NT_REQ(f, 36);
    static const BYTE in[] = { 0x7f };
    NTD d; nt_dec(&d, in, 1); U64 len = 0;
    XEQ(f(&d, &len), 0); XEQ(len, 0x7f);                  /* 127 contents octets announced, none present */
}
static const struct { BYTE b[8]; DWORD n; DWORD tag; } k_ndt[] = {
    { { 0x02 }, 1, 2 }, { { 0x30 }, 1, 0x20000010 }, { { 0x31 }, 1, 0x20000011 }, { { 0x80 }, 1, 0x80000000 }, { { 0xa3 }, 1, 0xa0000003 },
    { { 0x41 }, 1, 0x40000001 }, { { 0x61 }, 1, 0x60000001 }, { { 0xc5 }, 1, 0xc0000005 }, { { 0x1f, 0x1f }, 2, 0x1f }, { { 0x1f, 0x81, 0x00 }, 3, 0x80 },
    { { 0x9f, 0x81, 0x48 }, 3, 0x80000000 | 200 }, { { 0xbf, 0x81, 0x48 }, 3, 0xa0000000 | 200 }, { { 0x1f, 0xff, 0xff, 0xff, 0x7f }, 5, 0xfffffff },
    { { 0x1f, 0x81, 0x80, 0x80, 0x80, 0x00 }, 6, 0x10000000 },
};
TEST(nt_dec_tag_table) {
    d_tag_t f = DEC_TAG; NT_REQ(f, 39);
    for (unsigned i = 0; i < sizeof k_ndt / sizeof k_ndt[0]; i++) {
        NTD d; nt_dec(&d, k_ndt[i].b, k_ndt[i].n); DWORD tag = 0xdead;
        int rc = f(&d, &tag);
        CHECKF(rc == 0 && tag == k_ndt[i].tag, "case %u: rc %08x tag %08x want %08x", i, rc, tag, k_ndt[i].tag);
        CHECKF(d.pos == k_ndt[i].b + k_ndt[i].n, "case %u: position", i);
    }
}
TEST(nt_dec_tag_errors) {
    d_tag_t f = DEC_TAG; NT_REQ(f, 39);
    NTD d; DWORD tag;
    XEQ((DWORD)f(NULL, &tag), NT_PARAM);
    { static const BYTE in[] = { 0 }; nt_dec(&d, in, 0); XEQ((DWORD)f(&d, &tag), NT_EOD); }
    { static const BYTE in[] = { 0x1f }; nt_dec(&d, in, 1); XEQ((DWORD)f(&d, &tag), NT_EOD); }                              /* number missing */
    { static const BYTE in[] = { 0x1f, 0x81 }; nt_dec(&d, in, 2); XEQ((DWORD)f(&d, &tag), NT_EOD); }                        /* continuation cut off */
    { static const BYTE in[] = { 0x1f, 0x80, 0x01 }; nt_dec(&d, in, 3); XEQ((DWORD)f(&d, &tag), NT_RULE); }                 /* non-minimal number */
    { static const BYTE in[] = { 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f }; nt_dec(&d, in, 7); XEQ((DWORD)f(&d, &tag), NT_LARGE); }       /* fifth continuation octet */
    { static const BYTE in[] = { 0x1f, 0xff, 0xff, 0xff, 0xff, 0x7f }; nt_dec(&d, in, 6); XEQ(f(&d, &tag), 0); XEQ(tag, 0xffffffff); }   /* the final octet is not range checked: the value wraps */
}
TEST(nt_dec_peek_tag_restores_the_position) {
    d_taglen_t f = DEC_PEEK; NT_REQ(f, 38);
    static const BYTE in[] = { 0x30, 0x03, 0x02, 0x01, 0x05 };
    NTD d; nt_dec(&d, in, sizeof in); DWORD tag = 0; U64 len = 0;
    XEQ(f(&d, &tag, &len), 0);
    XEQ(tag, 0x20000010); XEQ(len, 3); CHECK(d.pos == in);
    tag = 0; XEQ(f(&d, &tag, NULL), 0); XEQ(tag, 0x20000010); CHECK(d.pos == in);   /* length output is optional */
}
TEST(nt_dec_peek_tag_errors_restore_the_position_too) {
    d_taglen_t f = DEC_PEEK; NT_REQ(f, 38);
    NTD d; DWORD tag; U64 len;
    { static const BYTE in[] = { 0 }; nt_dec(&d, in, 0); XEQ((DWORD)f(&d, &tag, &len), NT_EOD); CHECK(d.pos == in); }
    { static const BYTE in[] = { 0x30, 0x80 }; nt_dec(&d, in, 2); XEQ((DWORD)f(&d, &tag, &len), NT_RULE); CHECK(d.pos == in); }
    { static const BYTE in[] = { 0x30 }; nt_dec(&d, in, 1); XEQ((DWORD)f(&d, &tag, &len), NT_EOD); CHECK(d.pos == in); }
}
TEST(nt_dec_taglength) {
    d_taglen_t f = DEC_TAGLEN; NT_REQ(f, 37);
    static const BYTE in[] = { 0x30, 0x82, 0x01, 0x00, 0xaa };
    NTD d; nt_dec(&d, in, sizeof in); DWORD tag = 0; U64 len = 0;
    XEQ(f(&d, &tag, &len), 0); XEQ(tag, 0x20000010); XEQ(len, 0x100); CHECK(d.pos == in + 4);
}
TEST(nt_dec_taglength_errors) {
    d_taglen_t f = DEC_TAGLEN; NT_REQ(f, 37);
    NTD d; DWORD tag; U64 len;
    { static const BYTE in[] = { 0 }; nt_dec(&d, in, 0); XEQ((DWORD)f(&d, &tag, &len), NT_EOD); }
    { static const BYTE in[] = { 0x02 }; nt_dec(&d, in, 1); XEQ((DWORD)f(&d, &tag, &len), NT_EOD); }                         /* no length octet */
    { static const BYTE in[] = { 0x02, 0x80 }; nt_dec(&d, in, 2); XEQ((DWORD)f(&d, &tag, &len), NT_RULE); }
    { static const BYTE in[] = { 0x02, 0x82, 0x01 }; nt_dec(&d, in, 3); XEQ((DWORD)f(&d, &tag, &len), NT_CORRUPT); }
    { static const BYTE in[] = { 0x02, 0x85, 0, 0, 0, 0, 1 }; nt_dec(&d, in, 7); XEQ((DWORD)f(&d, &tag, &len), NT_LARGE); }
}
TEST(nt_ber_taglength_reports_indefinite_form) {
    d_bertl_t f = BER_TAGLEN; NT_REQ(f, 60);
    {
        static const BYTE in[] = { 0x30, 0x80, 0x02, 0x01, 0x05, 0x00, 0x00 };
        NTD d; nt_dec(&d, in, sizeof in); DWORD tag = 0; U64 len = 9; int ind = 7;
        XEQ(f(&d, &tag, &len, &ind), 0);
        XEQ(tag, 0x20000010); XEQ(ind, 1); XEQ(len, 3); CHECK(d.pos == in + 2);        /* indefinite: remaining octets (5) minus the 00 00 terminator */
    }
    {
        static const BYTE in[] = { 0x30, 0x03, 0x02, 0x01, 0x05 };
        NTD d; nt_dec(&d, in, sizeof in); DWORD tag = 0; U64 len = 9; int ind = 7;
        XEQ(f(&d, &tag, &len, &ind), 0);
        XEQ(ind, 0); XEQ(len, 3);
    }
    {
        static const BYTE in[] = { 0x02, 0x80, 0x00 };                                    /* primitive with 0x80 length: not allowed */
        NTD d; nt_dec(&d, in, sizeof in); DWORD tag = 0; U64 len = 9; int ind = 7;
        XEQ((DWORD)f(&d, &tag, &len, &ind), NT_RULE);
    }
    {
        static const BYTE in[] = { 0x30, 0x03, 0x02 };
        NTD d; nt_dec(&d, in, sizeof in); DWORD tag; U64 len;
        XEQ(f(&d, &tag, &len, NULL), 0);                                                  /* the indefinite flag is optional */
    }
}
TEST(nt_dec_explicit_tag) {
    d_etag_t f = DEC_ETAG; NT_REQ(f, 40);
    static const BYTE in[] = { 0xa0, 0x03, 0x02, 0x01, 0x05, 0x05, 0x00 };
    NTD d; nt_dec(&d, in, sizeof in); U64 len = 0;
    XEQ(f(&d, -1, 0xa0000000, &len), 0);
    XEQ(len, 3); CHECK(d.pos == in + 2);
}
TEST(nt_dec_explicit_tag_mismatch_restores_the_position) {
    d_etag_t f = DEC_ETAG; NT_REQ(f, 40);
    static const BYTE in[] = { 0xa0, 0x03, 0x02, 0x01, 0x05 };
    NTD d; nt_dec(&d, in, sizeof in); U64 len = 0x77;
    XEQ((DWORD)f(&d, -1, 0xa0000001, &len), NT_BADTAG);
    CHECK(d.pos == in); XEQ(len, 0);                        /* the length output is cleared before the tag is compared */
    XEQ((DWORD)f(&d, -1, 0x80000000, &len), NT_BADTAG);   /* constructed bit is part of the tag value */
    CHECK(d.pos == in);
}
TEST(nt_dec_explicit_tag_bounds_check_only_with_negative_flag) {
    d_etag_t f = DEC_ETAG; NT_REQ(f, 40);
    static const BYTE in[] = { 0x04, 0x05, 'a' };
    NTD d; nt_dec(&d, in, sizeof in); U64 len = 0;
    XEQ((DWORD)f(&d, -1, 4, &len), NT_EOD);               /* announces 5, one octet present */
    CHECK(d.pos == in);
    XEQ(f(&d, 0, 4, &len), 0);                            /* flag >= 0: contents not checked */
    XEQ(len, 5); CHECK(d.pos == in + 2);
}
TEST(nt_dec_explicit_tag_header_errors) {
    d_etag_t f = DEC_ETAG; NT_REQ(f, 40);
    NTD d; U64 len;
    { static const BYTE in[] = { 0 }; nt_dec(&d, in, 0); XEQ((DWORD)f(&d, 0, 4, &len), NT_EOD); }
    { static const BYTE in[] = { 0x04 }; nt_dec(&d, in, 1); XEQ((DWORD)f(&d, 0, 4, &len), NT_EOD); CHECK(d.pos == in); }
    { static const BYTE in[] = { 0x04, 0x80 }; nt_dec(&d, in, 2); XEQ((DWORD)f(&d, 0, 4, &len), NT_RULE); CHECK(d.pos == in); }
}
static const struct { BYTE b[8]; DWORD n; DWORD v; } k_ndi[] = {
    { { 2, 1, 0x00 }, 3, 0 }, { { 2, 1, 0x05 }, 3, 5 }, { { 2, 1, 0x7f }, 3, 0x7f }, { { 2, 1, 0x80 }, 3, 0xffffff80 }, { { 2, 1, 0xff }, 3, 0xffffffff },
    { { 2, 2, 0x00, 0x80 }, 4, 0x80 }, { { 2, 2, 0xff, 0x7f }, 4, 0xffffff7f }, { { 2, 2, 0x12, 0x34 }, 4, 0x1234 },
    { { 2, 3, 0x80, 0x00, 0x00 }, 5, 0xff800000 }, { { 2, 4, 0x7f, 0xff, 0xff, 0xff }, 6, 0x7fffffff }, { { 2, 4, 0x80, 0x00, 0x00, 0x00 }, 6, 0x80000000 },
    { { 2, 5, 0x00, 0xff, 0xff, 0xff, 0xff }, 7, 0xffffffff }, { { 2, 5, 0x00, 0x00, 0x00, 0x00, 0x01 }, 7, 1 }, { { 2, 0 }, 2, 0 },
};
TEST(nt_dec_integer32_table) {
    d_int_t f = DEC_INT; NT_REQ(f, 42);
    for (unsigned i = 0; i < sizeof k_ndi / sizeof k_ndi[0]; i++) {
        NTD d; nt_dec(&d, k_ndi[i].b, k_ndi[i].n); DWORD v = 0x5a5a;
        int rc = f(&d, &v, 2);
        CHECKF(rc == 0 && v == k_ndi[i].v, "case %u: rc %08x v %08x want %08x", i, rc, v, k_ndi[i].v);
        CHECKF(d.pos == k_ndi[i].b + k_ndi[i].n, "case %u: position", i);
    }
}
TEST(nt_dec_integer32_errors) {
    d_int_t f = DEC_INT; NT_REQ(f, 42);
    NTD d; DWORD v;
    { static const BYTE in[] = { 2, 5, 0x01, 0, 0, 0, 0 }; nt_dec(&d, in, 7); XEQ((DWORD)f(&d, &v, 2), NT_LARGE); }
    { static const BYTE in[] = { 2, 6, 0, 0, 0, 0, 0, 1 }; nt_dec(&d, in, 8); XEQ((DWORD)f(&d, &v, 2), NT_LARGE); }
    { static const BYTE in[] = { 4, 1, 5 }; nt_dec(&d, in, 3); XEQ((DWORD)f(&d, &v, 2), NT_BADTAG); }
    { static const BYTE in[] = { 2, 3, 1 }; nt_dec(&d, in, 3); XEQ((DWORD)f(&d, &v, 2), NT_EOD); }
    { static const BYTE in[] = { 2 }; nt_dec(&d, in, 1); XEQ((DWORD)f(&d, &v, 2), NT_EOD); }
}
TEST(nt_dec_integer32_context_tag) {
    d_int_t f = DEC_INT; NT_REQ(f, 42);
    static const BYTE in[] = { 0x84, 0x02, 0x01, 0x2c };
    NTD d; nt_dec(&d, in, sizeof in); DWORD v = 0;
    XEQ(f(&d, &v, 0x80000004), 0); XEQ(v, 300);
}
TEST(nt_dec_null) {
    d_null_t f = DEC_NULL; NT_REQ(f, 44);
    NTD d;
    { static const BYTE in[] = { 5, 0 }; nt_dec(&d, in, 2); XEQ(f(&d, 5), 0); CHECK(d.pos == in + 2); }
    { static const BYTE in[] = { 0x82, 0 }; nt_dec(&d, in, 2); XEQ(f(&d, 0x80000002), 0); }
    { static const BYTE in[] = { 5, 1, 0 }; nt_dec(&d, in, 3); XEQ((DWORD)f(&d, 5), NT_CORRUPT); }
    { static const BYTE in[] = { 4, 0 }; nt_dec(&d, in, 2); XEQ((DWORD)f(&d, 5), NT_BADTAG); }
    { static const BYTE in[] = { 5 }; nt_dec(&d, in, 1); XEQ((DWORD)f(&d, 5), NT_EOD); }
}
TEST(nt_dec_bool) {
    d_int_t f = DEC_BOOL; NT_REQ(f, 45);
    NTD d; DWORD v;
    { static const BYTE in[] = { 1, 1, 0xff }; nt_dec(&d, in, 3); v = 7; XEQ(f(&d, &v, 1), 0); XEQ(v, 1); CHECK(d.pos == in + 3); }
    { static const BYTE in[] = { 1, 1, 0x00 }; nt_dec(&d, in, 3); v = 7; XEQ(f(&d, &v, 1), 0); XEQ(v, 0); }
    { static const BYTE in[] = { 1, 1, 0x05 }; nt_dec(&d, in, 3); v = 7; XEQ(f(&d, &v, 1), 0); XEQ(v, 1); }
    { static const BYTE in[] = { 1, 2, 0xff, 0xff }; nt_dec(&d, in, 4); XEQ((DWORD)f(&d, &v, 1), NT_CORRUPT); }
    { static const BYTE in[] = { 1, 0 }; nt_dec(&d, in, 2); XEQ((DWORD)f(&d, &v, 1), NT_CORRUPT); }
    { static const BYTE in[] = { 2, 1, 0xff }; nt_dec(&d, in, 3); XEQ((DWORD)f(&d, &v, 1), NT_BADTAG); }
    { static const BYTE in[] = { 1, 1 }; nt_dec(&d, in, 2); XEQ((DWORD)f(&d, &v, 1), NT_EOD); }
}
TEST(nt_dec_octet_string) {
    d_oct_t f = DEC_OCT; NT_REQ(f, 52);
    NTD d; BYTE out[16]; U64 n;
    { static const BYTE in[] = { 4, 3, 'a', 'b', 'c', 9 }; nt_dec(&d, in, 6); memset(out, 0, sizeof out); n = 99;
      XEQ(f(&d, out, sizeof out, &n, 4), 0); XEQ(n, 3); EXPECT_BYTES(out, 3, "abc", 3); CHECK(d.pos == in + 5); }
    { static const BYTE in[] = { 4, 0 }; nt_dec(&d, in, 2); n = 99; XEQ(f(&d, out, sizeof out, &n, 4), 0); XEQ(n, 0); }
    { static const BYTE in[] = { 0x80, 2, 'x', 'y' }; nt_dec(&d, in, 4); n = 0; XEQ(f(&d, out, sizeof out, &n, 0x80000000), 0); XEQ(n, 2); }
    { static const BYTE in[] = { 4, 3, 'a', 'b', 'c' }; nt_dec(&d, in, 5); n = 0; XEQ(f(&d, NULL, 0, &n, 4), 0); XEQ(n, 3); CHECK(d.pos == in + 5); }  /* size query + skip */
}
TEST(nt_dec_octet_string_errors) {
    d_oct_t f = DEC_OCT; NT_REQ(f, 52);
    NTD d; BYTE out[16]; U64 n;
    { static const BYTE in[] = { 4, 3, 'a', 'b', 'c' }; nt_dec(&d, in, 5); n = 0; memset(out, 0xee, sizeof out);
      XEQ((DWORD)f(&d, out, 2, &n, 4), NT_NOSPACE); XEQ(n, 3); XEQ(out[0], 0xee); }                              /* destination too small: length still reported */
    { static const BYTE in[] = { 4, 5, 'a' }; nt_dec(&d, in, 3); n = 0; XEQ((DWORD)f(&d, out, sizeof out, &n, 4), NT_EOD); }
    { static const BYTE in[] = { 3, 1, 'a' }; nt_dec(&d, in, 3); n = 0; XEQ((DWORD)f(&d, out, sizeof out, &n, 4), NT_BADTAG); XEQ(n, 0); }
}
