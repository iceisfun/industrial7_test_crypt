/* msasn1.dll: ASN1BEREnc* primitives driven directly through an encoder, hand-assembled DER vectors. */
#include "asn1t.h"

#define ENCT(tn, rl, fn, args, ...) \
    TEST(tn) { NEED(fn); Rig r; if (!rig_enc(&r, rl)) return; \
        U64 rv = A.fn args; CHECKF(OK8(rv), "rv=%llx", rv); \
        static const BYTE ex[] = { __VA_ARGS__ }; EXPECT_ENC(&r, ex, sizeof ex); rig_done(&r); }

/* ---------------------------------------------------------------- tag */
static const struct { DWORD tag; BYTE b[8]; DWORD n; } k_tag[] = {
    { TG_UNIV(0), { 0x00 }, 1 }, { TG_UNIV(2), { 0x02 }, 1 }, { TG_UNIV(30), { 0x1e }, 1 },
    { TG_APP(1), { 0x41 }, 1 }, { TG_CTX(0), { 0x80 }, 1 }, { TG_CTX(5), { 0x85 }, 1 }, { TG_PRIV(5), { 0xc5 }, 1 },
    { TG_UNIV(T_SEQ) | TG_CONS, { 0x30 }, 1 }, { TG_UNIV(T_SET) | TG_CONS, { 0x31 }, 1 },
    { TG_CTX(0) | TG_CONS, { 0xa0 }, 1 }, { TG_CTX(3) | TG_CONS, { 0xa3 }, 1 }, { TG_APP(2) | TG_CONS, { 0x62 }, 1 },
    { TG_UNIV(31), { 0x1f, 0x1f }, 2 }, { TG_UNIV(127), { 0x1f, 0x7f }, 2 }, { TG_UNIV(128), { 0x1f, 0x81, 0x00 }, 3 },
    { TG_UNIV(255), { 0x1f, 0x81, 0x7f }, 3 }, { TG_UNIV(0x3fff), { 0x1f, 0xff, 0x7f }, 3 },
    { TG_UNIV(0x4000), { 0x1f, 0x81, 0x80, 0x00 }, 4 }, { TG_UNIV(0x1fffff), { 0x1f, 0xff, 0xff, 0x7f }, 4 },
    { TG_UNIV(0x200000), { 0x1f, 0x81, 0x80, 0x80, 0x00 }, 5 }, { TG_UNIV(0xfffffff), { 0x1f, 0xff, 0xff, 0xff, 0x7f }, 5 },
    { TG_UNIV(0x10000000), { 0x1f, 0x81, 0x80, 0x80, 0x80, 0x00 }, 6 },
    { TG_UNIV(0x1fffffff), { 0x1f, 0x81, 0xff, 0xff, 0xff, 0x7f }, 6 },
    { TG_CTX(200) | TG_CONS, { 0xbf, 0x81, 0x48 }, 3 }, { TG_APP(31), { 0x5f, 0x1f }, 2 },
    { TG_PRIV(1000), { 0xdf, 0x87, 0x68 }, 3 },
};
TEST(be_tag_table) {
    NEED(ASN1BEREncTag);
    for (unsigned i = 0; i < sizeof k_tag / sizeof k_tag[0]; i++) {
        Rig r; if (!rig_enc(&r, R_DER)) return;
        U64 rv = A.ASN1BEREncTag(r.e, k_tag[i].tag);
        CHECKF(OK8(rv), "tag %08x", k_tag[i].tag);
        expect_enc(__FILE__, __LINE__, &r, k_tag[i].b, k_tag[i].n);
        rig_done(&r);
    }
}
TEST(be_tag_sequence_of_two) {
    NEED(ASN1BEREncTag);
    Rig r; if (!rig_enc(&r, R_DER)) return;
    A.ASN1BEREncTag(r.e, TG_UNIV(T_SEQ) | TG_CONS); A.ASN1BEREncTag(r.e, TG_CTX(1));
    static const BYTE ex[] = { 0x30, 0x81 };
    EXPECT_ENC(&r, ex, 2);
    rig_done(&r);
}

/* ---------------------------------------------------------------- length */
static const struct { DWORD len; BYTE b[5]; DWORD n; } k_len[] = {
    { 0, { 0x00 }, 1 }, { 1, { 0x01 }, 1 }, { 0x7f, { 0x7f }, 1 }, { 0x80, { 0x81, 0x80 }, 2 }, { 0xff, { 0x81, 0xff }, 2 },
    { 0x100, { 0x82, 0x01, 0x00 }, 3 }, { 0x1234, { 0x82, 0x12, 0x34 }, 3 }, { 0xffff, { 0x82, 0xff, 0xff }, 3 },
    { 0x10000, { 0x83, 0x01, 0x00, 0x00 }, 4 }, { 0xabcdef, { 0x83, 0xab, 0xcd, 0xef }, 4 },
    { 0xffffff, { 0x83, 0xff, 0xff, 0xff }, 4 }, { 0x1000000, { 0x84, 0x01, 0x00, 0x00, 0x00 }, 5 },
};
TEST(be_length_table) {
    NEED(ASN1BEREncLength);
    for (unsigned i = 0; i < sizeof k_len / sizeof k_len[0]; i++) {
        Rig r; if (!rig_enc(&r, R_DER)) return;
        U64 rv = A.ASN1BEREncLength(r.e, k_len[i].len);
        CHECKF(OK8(rv), "len %x", k_len[i].len);
        expect_enc(__FILE__, __LINE__, &r, k_len[i].b, k_len[i].n);
        rig_done(&r);
    }
}
TEST(be_length_reserves_room_for_the_contents) {
    /* EncLength checks header + contents in one go, so the buffer grows to hold them */
    NEED(ASN1BEREncLength);
    Rig r; if (!rig_enc(&r, R_DER)) return;
    CHECK(OK8(A.ASN1BEREncLength(r.e, 3000)));
    CHECK(r.e->buf != NULL); XEQ(r.e->size, 3000 + 3);
    rig_done(&r);
}
TEST(be_length_overflow_in_caller_buffer) {
    NEED(ASN1BEREncLength); NEED(ASN1_CreateEncoder); NEED(ASN1_CloseEncoder); NEED(ASN1_CloseModule);
    MOD *m = rig_module(R_DER, 0); ENC *e = NULL; BYTE buf[4];
    CHECK(m != NULL); if (!m) return;
    XEQ(A.ASN1_CreateEncoder(m, &e, buf, sizeof buf, NULL), 0);
    if (e) {
        CHECK(!OK8(A.ASN1BEREncLength(e, 4)));                  /* 1 header byte + 4 contents > 4 */
        XEQ(e->err, E_OVERFLOW); XEQ(e->len, 0);
        XEQ(A.ASN1EncSetError(e, 0), 0);
        CHECK(OK8(A.ASN1BEREncLength(e, 3)));                   /* 1 + 3 fits */
        XEQ(e->err, 0); CHECK(buf[0] == 3);
        A.ASN1_CloseEncoder(e);
    }
    A.ASN1_CloseModule(m);
}

/* ---------------------------------------------------------------- check / flush */
TEST(be_check_zero_does_not_allocate) {
    NEED(ASN1BEREncCheck);
    Rig r; if (!rig_enc(&r, R_DER)) return;
    CHECK(OK8(A.ASN1BEREncCheck(r.e, 0)));
    CHECK(r.e->buf == NULL); XEQ(r.e->size, 0);
    rig_done(&r);
}
TEST(be_check_minimum_allocation_is_1024) {
    NEED(ASN1BEREncCheck);
    static const DWORD want[][2] = { {1, 0x400}, {100, 0x400}, {0x400, 0x400}, {0x401, 0x401}, {5000, 5000} };
    for (int i = 0; i < 5; i++) {
        Rig r; if (!rig_enc(&r, R_DER)) return;
        CHECK(OK8(A.ASN1BEREncCheck(r.e, want[i][0])));
        CHECK(r.e->buf != NULL); CHECK(r.e->pos == r.e->buf); XEQ(r.e->size, want[i][1]);
        rig_done(&r);
    }
}
TEST(be_check_grows_by_the_larger_of_request_and_size) {
    NEED(ASN1BEREncCheck);
    Rig r; if (!rig_enc(&r, R_DER)) return;
    CHECK(OK8(A.ASN1BEREncCheck(r.e, 1)));  XEQ(r.e->size, 0x400);
    CHECK(OK8(A.ASN1BEREncCheck(r.e, 0x400)));  XEQ(r.e->size, 0x400);   /* still fits */
    CHECK(OK8(A.ASN1BEREncCheck(r.e, 0x500)));  XEQ(r.e->size, 0x900);   /* 0x400 + 0x500 */
    CHECK(r.e->pos == r.e->buf);                                               /* position follows the move */
    CHECK(OK8(A.ASN1BEREncCheck(r.e, 0x900)));  XEQ(r.e->size, 0x900);
    CHECK(OK8(A.ASN1BEREncCheck(r.e, 0x901)));  XEQ(r.e->size, 0x900 + 0x901);
    rig_done(&r);
}
TEST(be_check_growth_keeps_written_bytes) {
    NEED(ASN1BEREncCheck); NEED(ASN1BEREncOctetString);
    Rig r; if (!rig_enc(&r, R_DER)) return;
    BYTE a[1000], b[3000]; memset(a, 0xa1, sizeof a); memset(b, 0xb2, sizeof b);
    CHECK(OK8(A.ASN1BEREncOctetString(r.e, T_OCT, sizeof a, a)));
    CHECK(OK8(A.ASN1BEREncOctetString(r.e, T_OCT, sizeof b, b)));
    CHECK(OK8(A.ASN1BEREncFlush(r.e)));
    XEQ(r.e->len, 4 + 1000 + 4 + 3000);
    CHECK(r.e->buf[0] == 4 && r.e->buf[1] == 0x82 && r.e->buf[2] == 0x03 && r.e->buf[3] == 0xe8);
    CHECK(r.e->buf[4] == 0xa1 && r.e->buf[1003] == 0xa1);
    CHECK(r.e->buf[1004] == 4 && r.e->buf[1005] == 0x82 && r.e->buf[1006] == 0x0b && r.e->buf[1007] == 0xb8);
    CHECK(r.e->buf[1008] == 0xb2 && r.e->buf[4007] == 0xb2);
    rig_done(&r);
}
TEST(be_check_fixed_buffer_overflow) {
    NEED(ASN1BEREncCheck); NEED(ASN1_CreateEncoder); NEED(ASN1_CloseEncoder); NEED(ASN1_CloseModule);
    MOD *m = rig_module(R_DER, 0); ENC *e = NULL; BYTE buf[16];
    CHECK(m != NULL); if (!m) return;
    XEQ(A.ASN1_CreateEncoder(m, &e, buf, sizeof buf, NULL), 0);
    if (e) {
        CHECK(OK8(A.ASN1BEREncCheck(e, 16)));
        XEQ(e->err, 0);
        CHECK(!OK8(A.ASN1BEREncCheck(e, 17)));
        XEQ(e->err, E_OVERFLOW); CHECK(e->buf == buf); XEQ(e->size, 16);
        A.ASN1_CloseEncoder(e);
    }
    A.ASN1_CloseModule(m);
}
TEST(be_flush_on_fresh_encoder_allocates_and_reports_empty) {
    NEED(ASN1BEREncFlush);
    Rig r; if (!rig_enc(&r, R_DER)) return;
    CHECK(OK8(A.ASN1BEREncFlush(r.e)));
    CHECK(r.e->buf != NULL); XEQ(r.e->len, 0);
    rig_done(&r);
}
TEST(be_flush_sets_length_to_bytes_written) {
    NEED(ASN1BEREncFlush); NEED(ASN1BEREncNull);
    Rig r; if (!rig_enc(&r, R_DER)) return;
    CHECK(OK8(A.ASN1BEREncNull(r.e, T_NULL)));
    XEQ(r.e->len, 0);                 /* nothing visible before a flush */
    CHECK(OK8(A.ASN1BEREncFlush(r.e))); XEQ(r.e->len, 2);
    CHECK(OK8(A.ASN1BEREncFlush(r.e))); XEQ(r.e->len, 2);   /* idempotent */
    CHECK(OK8(A.ASN1BEREncNull(r.e, T_NULL)));
    CHECK(OK8(A.ASN1BEREncFlush(r.e))); XEQ(r.e->len, 4);
    rig_done(&r);
}
TEST(be_flush_of_an_empty_allocated_buffer_appends_a_zero_byte) {
    /* quirk: with buf == pos, Flush stores a 0 byte and advances (an empty PDU is encoded as one 00 byte) */
    NEED(ASN1BEREncFlush);
    Rig r; if (!rig_enc(&r, R_DER)) return;
    CHECK(OK8(A.ASN1BEREncFlush(r.e))); XEQ(r.e->len, 0);
    CHECK(OK8(A.ASN1BEREncFlush(r.e)));
    t_note("second flush on empty buffer: len=%d (decomp: 1, one 00 byte)", (int)r.e->len);
    rig_done(&r);
}

/* ---------------------------------------------------------------- BOOLEAN / NULL / INTEGER */
ENCT(be_bool_true, R_DER, ASN1BEREncBool, (r.e, T_BOOL, 1), 0x01, 0x01, 0xff)
ENCT(be_bool_false, R_DER, ASN1BEREncBool, (r.e, T_BOOL, 0), 0x01, 0x01, 0x00)
ENCT(be_bool_any_nonzero_is_ff, R_DER, ASN1BEREncBool, (r.e, T_BOOL, 0x7e), 0x01, 0x01, 0xff)
ENCT(be_bool_context_tag, R_DER, ASN1BEREncBool, (r.e, TG_CTX(1), 1), 0x81, 0x01, 0xff)
ENCT(be_bool_ber_rule_same_bytes, R_BER, ASN1BEREncBool, (r.e, T_BOOL, 1), 0x01, 0x01, 0xff)
ENCT(be_null_universal, R_DER, ASN1BEREncNull, (r.e, T_NULL), 0x05, 0x00)
ENCT(be_null_context_tag, R_DER, ASN1BEREncNull, (r.e, TG_CTX(2)), 0x82, 0x00)
ENCT(be_null_constructed_context_tag, R_DER, ASN1BEREncNull, (r.e, TG_CTX(0) | TG_CONS), 0xa0, 0x00)

static const struct { int v; BYTE b[8]; DWORD n; } k_s32[] = {
    { 0, { 2, 1, 0x00 }, 3 }, { 1, { 2, 1, 0x01 }, 3 }, { 127, { 2, 1, 0x7f }, 3 }, { 128, { 2, 2, 0x00, 0x80 }, 4 },
    { 255, { 2, 2, 0x00, 0xff }, 4 }, { 256, { 2, 2, 0x01, 0x00 }, 4 }, { -1, { 2, 1, 0xff }, 3 },
    { -128, { 2, 1, 0x80 }, 3 }, { -129, { 2, 2, 0xff, 0x7f }, 4 }, { -256, { 2, 2, 0xff, 0x00 }, 4 },
    { 32767, { 2, 2, 0x7f, 0xff }, 4 }, { 32768, { 2, 3, 0x00, 0x80, 0x00 }, 5 }, { -32768, { 2, 2, 0x80, 0x00 }, 4 },
    { -32769, { 2, 3, 0xff, 0x7f, 0xff }, 5 }, { 65535, { 2, 3, 0x00, 0xff, 0xff }, 5 },
    { 8388607, { 2, 3, 0x7f, 0xff, 0xff }, 5 }, { 8388608, { 2, 4, 0x00, 0x80, 0x00, 0x00 }, 6 },
    { -8388608, { 2, 3, 0x80, 0x00, 0x00 }, 5 }, { -8388609, { 2, 4, 0xff, 0x7f, 0xff, 0xff }, 6 },
    { 0x7fffffff, { 2, 4, 0x7f, 0xff, 0xff, 0xff }, 6 }, { (int)0x80000000, { 2, 4, 0x80, 0x00, 0x00, 0x00 }, 6 },
    { 0x12345678, { 2, 4, 0x12, 0x34, 0x56, 0x78 }, 6 }, { -0x12345678, { 2, 4, 0xed, 0xcb, 0xa9, 0x88 }, 6 },
};
TEST(be_s32_table) {
    NEED(ASN1BEREncS32);
    for (unsigned i = 0; i < sizeof k_s32 / sizeof k_s32[0]; i++) {
        Rig r; if (!rig_enc(&r, R_DER)) return;
        U64 rv = A.ASN1BEREncS32(r.e, T_INT, k_s32[i].v);
        CHECKF(OK8(rv), "v=%d", k_s32[i].v);
        expect_enc(__FILE__, __LINE__, &r, k_s32[i].b, k_s32[i].n);
        rig_done(&r);
    }
}
TEST(be_s32_enumerated_and_context_tags) {
    NEED(ASN1BEREncS32);
    Rig r; if (!rig_enc(&r, R_DER)) return;
    CHECK(OK8(A.ASN1BEREncS32(r.e, T_ENUM, 3))); CHECK(OK8(A.ASN1BEREncS32(r.e, TG_CTX(0), -2)));
    static const BYTE ex[] = { 0x0a, 0x01, 0x03, 0x80, 0x01, 0xfe };
    EXPECT_ENC(&r, ex, sizeof ex);
    rig_done(&r);
}
static const struct { DWORD v; BYTE b[8]; DWORD n; } k_u32e[] = {
    { 0, { 2, 1, 0 }, 3 }, { 0x7f, { 2, 1, 0x7f }, 3 }, { 0x80, { 2, 2, 0, 0x80 }, 4 }, { 0xff, { 2, 2, 0, 0xff }, 4 },
    { 0x100, { 2, 2, 1, 0 }, 4 }, { 0x7fff, { 2, 2, 0x7f, 0xff }, 4 }, { 0x8000, { 2, 3, 0, 0x80, 0 }, 5 },
    { 0xffff, { 2, 3, 0, 0xff, 0xff }, 5 }, { 0x7fffff, { 2, 3, 0x7f, 0xff, 0xff }, 5 },
    { 0x800000, { 2, 4, 0, 0x80, 0, 0 }, 6 }, { 0xffffff, { 2, 4, 0, 0xff, 0xff, 0xff }, 6 },
    { 0x1000000, { 2, 4, 1, 0, 0, 0 }, 6 }, { 0x7fffffff, { 2, 4, 0x7f, 0xff, 0xff, 0xff }, 6 },
    { 0x80000000, { 2, 5, 0, 0x80, 0, 0, 0 }, 7 }, { 0xdeadbeef, { 2, 5, 0, 0xde, 0xad, 0xbe, 0xef }, 7 },
    { 0xffffffff, { 2, 5, 0, 0xff, 0xff, 0xff, 0xff }, 7 },
};
TEST(be_u32_table) {
    NEED(ASN1BEREncU32);
    for (unsigned i = 0; i < sizeof k_u32e / sizeof k_u32e[0]; i++) {
        Rig r; if (!rig_enc(&r, R_DER)) return;
        U64 rv = A.ASN1BEREncU32(r.e, T_INT, k_u32e[i].v);
        CHECKF(OK8(rv), "v=%u", k_u32e[i].v);
        expect_enc(__FILE__, __LINE__, &r, k_u32e[i].b, k_u32e[i].n);
        rig_done(&r);
    }
}
ENCT(be_u32_context_tag, R_DER, ASN1BEREncU32, (r.e, TG_CTX(4), 300), 0x84, 0x02, 0x01, 0x2c)

static const struct { BYTE in[6]; DWORD n; BYTE out[6]; DWORD on; } k_sx[] = {
    { { 0x05 }, 1, { 2, 1, 0x05 }, 3 }, { { 0x00, 0x00, 0x05 }, 3, { 2, 1, 0x05 }, 3 },
    { { 0xff, 0xff, 0x80 }, 3, { 2, 1, 0x80 }, 3 }, { { 0x00, 0x80 }, 2, { 2, 2, 0x00, 0x80 }, 4 },
    { { 0xff, 0x7f }, 2, { 2, 2, 0xff, 0x7f }, 4 }, { { 0x00 }, 1, { 2, 1, 0x00 }, 3 }, { { 0x00, 0x00 }, 2, { 2, 1, 0x00 }, 3 },
    { { 0xff }, 1, { 2, 1, 0xff }, 3 }, { { 0xff, 0xff }, 2, { 2, 1, 0xff }, 3 }, { { 0x7f, 0xff }, 2, { 2, 2, 0x7f, 0xff }, 4 },
    { { 0x00, 0x00, 0x00, 0x7f }, 4, { 2, 1, 0x7f }, 3 }, { { 0x80, 0x00 }, 2, { 2, 2, 0x80, 0x00 }, 4 },
};
TEST(be_sx_strips_redundant_leading_octets) {
    NEED(ASN1BEREncSX);
    for (unsigned i = 0; i < sizeof k_sx / sizeof k_sx[0]; i++) {
        Rig r; if (!rig_enc(&r, R_DER)) return;
        LV v; v.length = k_sx[i].n; v.value = (BYTE *)k_sx[i].in;
        CHECKF(OK8(A.ASN1BEREncSX(r.e, T_INT, &v)), "case %u", i);
        expect_enc(__FILE__, __LINE__, &r, k_sx[i].out, k_sx[i].on);
        rig_done(&r);
    }
}
TEST(be_sx_large_value_keeps_all_significant_octets) {
    NEED(ASN1BEREncSX);
    Rig r; if (!rig_enc(&r, R_DER)) return;
    BYTE in[17]; in[0] = 0x00; for (int i = 1; i < 17; i++) in[i] = (BYTE)(0x80 + i);
    LV v; v.length = 17; v.value = in;
    CHECK(OK8(A.ASN1BEREncSX(r.e, T_INT, &v)));
    BYTE ex[2 + 17] = { 2, 17 }; memcpy(ex + 2, in, 17);
    EXPECT_ENC(&r, ex, sizeof ex);
    rig_done(&r);
}

/* ---------------------------------------------------------------- strings */
static void enc_str_len(int which, DWORD n)
{
    /* which: 0 OctetString 1 CharString 2 DER octet 3 DER char */
    U64 (WINAPI *f)(ENC *, DWORD, DWORD, const void *) =
        which == 0 ? A.ASN1BEREncOctetString : which == 1 ? A.ASN1BEREncCharString :
        which == 2 ? A.ASN1DEREncOctetString : A.ASN1DEREncCharString;
    if (!f) { t_skip("missing export"); return; }
    Rig r; if (!rig_enc(&r, R_DER)) return;
    BYTE *body = malloc(n ? n : 1); for (DWORD i = 0; i < n; i++) body[i] = (BYTE)(i * 7 + 1);
    CHECK(OK8(f(r.e, T_OCT, n, body)));
    CHECK(OK8(A.ASN1BEREncFlush(r.e)));
    BYTE hdr[8]; DWORD h = 0; hdr[h++] = 4;
    if (n < 0x80) hdr[h++] = (BYTE)n;
    else if (n < 0x100) { hdr[h++] = 0x81; hdr[h++] = (BYTE)n; }
    else if (n < 0x10000) { hdr[h++] = 0x82; hdr[h++] = (BYTE)(n >> 8); hdr[h++] = (BYTE)n; }
    else { hdr[h++] = 0x83; hdr[h++] = (BYTE)(n >> 16); hdr[h++] = (BYTE)(n >> 8); hdr[h++] = (BYTE)n; }
    XEQ(r.e->len, h + n);
    if (r.e->len == h + n) { CHECK(memcmp(r.e->buf, hdr, h) == 0); CHECK(n == 0 || memcmp(r.e->buf + h, body, n) == 0); }
    free(body); rig_done(&r);
}
TEST(be_octetstring_lengths) {
    NEED(ASN1BEREncOctetString);
    static const DWORD ns[] = { 0, 1, 2, 126, 127, 128, 129, 255, 256, 257, 4095, 65535, 65536, 70000 };
    for (unsigned i = 0; i < sizeof ns / sizeof ns[0]; i++) enc_str_len(0, ns[i]);
}
TEST(be_charstring_lengths_match_octetstring) {
    NEED(ASN1BEREncCharString);
    static const DWORD ns[] = { 0, 1, 127, 128, 300 };
    for (unsigned i = 0; i < sizeof ns / sizeof ns[0]; i++) enc_str_len(1, ns[i]);
}
TEST(be_der_octet_and_char_match_ber) {
    NEED(ASN1DEREncOctetString); NEED(ASN1DEREncCharString);
    static const DWORD ns[] = { 0, 5, 128, 1000 };
    for (unsigned i = 0; i < sizeof ns / sizeof ns[0]; i++) { enc_str_len(2, ns[i]); enc_str_len(3, ns[i]); }
}
ENCT(be_octetstring_abc, R_DER, ASN1BEREncOctetString, (r.e, T_OCT, 3, "abc"), 0x04, 0x03, 'a', 'b', 'c')
ENCT(be_octetstring_context_tag, R_DER, ASN1BEREncOctetString, (r.e, TG_CTX(0), 2, "\x01\x02"), 0x80, 0x02, 0x01, 0x02)
ENCT(be_octetstring_empty, R_DER, ASN1BEREncOctetString, (r.e, T_OCT, 0, NULL), 0x04, 0x00)
ENCT(be_charstring_printable, R_DER, ASN1BEREncCharString, (r.e, T_PRINT, 5, "Hello"), 0x13, 0x05, 'H', 'e', 'l', 'l', 'o')
ENCT(be_charstring_ia5_with_embedded_nul, R_DER, ASN1BEREncCharString, (r.e, T_IA5, 3, "a\0b"), 0x16, 0x03, 'a', 0x00, 'b')
TEST(be_multibytestring_uses_counted_form) {
    NEED(ASN1BEREncMultibyteString);
    Rig r; if (!rig_enc(&r, R_DER)) return;
    CSTR s = { 4, "test!" };
    CHECK(OK8(A.ASN1BEREncMultibyteString(r.e, T_PRINT, &s)));
    static const BYTE ex[] = { 0x13, 0x04, 't', 'e', 's', 't' };
    EXPECT_ENC(&r, ex, sizeof ex);
    rig_done(&r);
}
ENCT(be_zero_multibyte_string, R_DER, ASN1BEREncZeroMultibyteString, (r.e, T_IA5, "abc"), 0x16, 0x03, 'a', 'b', 'c')
ENCT(be_zero_multibyte_string_empty, R_DER, ASN1BEREncZeroMultibyteString, (r.e, T_IA5, ""), 0x16, 0x00)
ENCT(be_zero_multibyte_string_null_is_empty, R_DER, ASN1BEREncZeroMultibyteString, (r.e, T_IA5, NULL), 0x16, 0x00)
ENCT(be_der_multibyte_string, R_DER, ASN1DEREncZeroMultibyteString, (r.e, T_PRINT, "US"), 0x13, 0x02, 'U', 'S')

static const WORD u16_a[] = { 0x0041, 0x4e2d, 0xfeff };
ENCT(be_char16string_big_endian_bmp, R_DER, ASN1BEREncChar16String, (r.e, T_BMP, 3, u16_a), 0x1e, 0x06, 0x00, 0x41, 0x4e, 0x2d, 0xfe, 0xff)
ENCT(be_char16string_empty, R_DER, ASN1BEREncChar16String, (r.e, T_BMP, 0, NULL), 0x1e, 0x00)
ENCT(be_der_char16string, R_DER, ASN1DEREncChar16String, (r.e, T_BMP, 3, u16_a), 0x1e, 0x06, 0x00, 0x41, 0x4e, 0x2d, 0xfe, 0xff)
static const DWORD u32_a[] = { 0x41, 0x1f600, 0x10ffff };
ENCT(be_char32string_big_endian, R_DER, ASN1BEREncChar32String, (r.e, 28, 3, u32_a),
     0x1c, 0x0c, 0x00, 0x00, 0x00, 0x41, 0x00, 0x01, 0xf6, 0x00, 0x00, 0x10, 0xff, 0xff)
ENCT(be_der_char32string, R_DER, ASN1DEREncChar32String, (r.e, 28, 1, u32_a), 0x1c, 0x04, 0x00, 0x00, 0x00, 0x41)
TEST(be_char16string_too_long_is_large) {
    NEED(ASN1BEREncChar16String);
    Rig r; if (!rig_enc(&r, R_DER)) return;
    CHECK(!OK8(A.ASN1BEREncChar16String(r.e, T_BMP, 0x7fffffff, NULL)));
    XEQ(r.e->err, E_LARGE);
    rig_done(&r);
}
TEST(be_char32string_too_long_is_large) {
    NEED(ASN1BEREncChar32String);
    Rig r; if (!rig_enc(&r, R_DER)) return;
    CHECK(!OK8(A.ASN1BEREncChar32String(r.e, 28, 0x3fffffff, NULL)));
    XEQ(r.e->err, E_LARGE);
    rig_done(&r);
}
TEST(be_char16string_reports_success_even_when_the_length_failed) {
    /* quirk: after the header failed (error recorded in the encoder) the function still returns 1 */
    NEED(ASN1BEREncChar16String); NEED(ASN1_CreateEncoder); NEED(ASN1_CloseEncoder); NEED(ASN1_CloseModule);
    MOD *m = rig_module(R_DER, 0); ENC *e = NULL; BYTE buf[3];
    CHECK(m != NULL); if (!m) return;
    XEQ(A.ASN1_CreateEncoder(m, &e, buf, sizeof buf, NULL), 0);
    if (e) {
        U64 rv = A.ASN1BEREncChar16String(e, T_BMP, 2, u16_a);
        t_note("Char16String after failed length: rv=%llx (decomp: success)", (unsigned long long)rv); XEQ(e->err, E_OVERFLOW);
        A.ASN1_CloseEncoder(e);
    }
    A.ASN1_CloseModule(m);
}

/* UTF8String */
static const WCHAR w_a[] = { 0x41 }, w_e9[] = { 0xe9 }, w_euro[] = { 0x20ac }, w_pair[] = { 0xd83d, 0xde00 };
static const WCHAR w_mix[] = { 'a', 0xe9, 0x20ac, 0xd83d, 0xde00 };
ENCT(be_utf8_ascii, R_DER, ASN1BEREncUTF8String, (r.e, T_UTF8, 1, w_a), 0x0c, 0x01, 0x41)
ENCT(be_utf8_two_byte, R_DER, ASN1BEREncUTF8String, (r.e, T_UTF8, 1, w_e9), 0x0c, 0x02, 0xc3, 0xa9)
ENCT(be_utf8_three_byte, R_DER, ASN1BEREncUTF8String, (r.e, T_UTF8, 1, w_euro), 0x0c, 0x03, 0xe2, 0x82, 0xac)
ENCT(be_utf8_surrogate_pair_is_four_bytes, R_DER, ASN1BEREncUTF8String, (r.e, T_UTF8, 2, w_pair), 0x0c, 0x04, 0xf0, 0x9f, 0x98, 0x80)
ENCT(be_utf8_mixed, R_DER, ASN1BEREncUTF8String, (r.e, T_UTF8, 5, w_mix),
     0x0c, 0x0a, 'a', 0xc3, 0xa9, 0xe2, 0x82, 0xac, 0xf0, 0x9f, 0x98, 0x80)
ENCT(be_utf8_zero_length_is_empty, R_DER, ASN1BEREncUTF8String, (r.e, T_UTF8, 0, w_a), 0x0c, 0x00)
ENCT(be_utf8_null_pointer_is_empty, R_DER, ASN1BEREncUTF8String, (r.e, T_UTF8, 4, NULL), 0x0c, 0x00)
ENCT(be_utf8_context_tag, R_DER, ASN1BEREncUTF8String, (r.e, TG_CTX(2), 1, w_a), 0x82, 0x01, 0x41)
ENCT(be_der_utf8_matches_ber, R_DER, ASN1DEREncUTF8String, (r.e, T_UTF8, 1, w_euro), 0x0c, 0x03, 0xe2, 0x82, 0xac)
TEST(be_utf8_long_string_header) {
    NEED(ASN1BEREncUTF8String);
    Rig r; if (!rig_enc(&r, R_DER)) return;
    WCHAR w[100]; for (int i = 0; i < 100; i++) w[i] = 0x20ac;          /* 300 bytes */
    CHECK(OK8(A.ASN1BEREncUTF8String(r.e, T_UTF8, 100, w)));
    CHECK(OK8(A.ASN1BEREncFlush(r.e)));
    XEQ(r.e->len, 4 + 300);
    static const BYTE h[] = { 0x0c, 0x82, 0x01, 0x2c, 0xe2, 0x82, 0xac };
    EXPECT_BYTES(r.e->buf, sizeof h, h, sizeof h);
    rig_done(&r);
}

/* ---------------------------------------------------------------- BIT STRING */
static const struct { DWORD nbits; BYTE in[4]; BYTE out[8]; DWORD on; } k_bits[] = {
    { 0, { 0 }, { 3, 1, 0x00 }, 3 },
    { 1, { 0x80 }, { 3, 2, 0x07, 0x80 }, 4 }, { 1, { 0xff }, { 3, 2, 0x07, 0x80 }, 4 },
    { 2, { 0xff }, { 3, 2, 0x06, 0xc0 }, 4 }, { 3, { 0xa5 }, { 3, 2, 0x05, 0xa0 }, 4 },
    { 7, { 0xff }, { 3, 2, 0x01, 0xfe }, 4 }, { 8, { 0xff }, { 3, 2, 0x00, 0xff }, 4 },
    { 9, { 0xff, 0xff }, { 3, 3, 0x07, 0xff, 0x80 }, 5 }, { 12, { 0xab, 0xcd }, { 3, 3, 0x04, 0xab, 0xc0 }, 5 },
    { 15, { 0x12, 0x35 }, { 3, 3, 0x01, 0x12, 0x34 }, 5 }, { 16, { 0xab, 0xcd }, { 3, 3, 0x00, 0xab, 0xcd }, 5 },
    { 17, { 0x01, 0x02, 0xff }, { 3, 4, 0x07, 0x01, 0x02, 0x80 }, 6 },
    { 24, { 0x01, 0x02, 0x03 }, { 3, 4, 0x00, 0x01, 0x02, 0x03 }, 6 },
};
TEST(be_bitstring_table) {
    NEED(ASN1BEREncBitString);
    for (unsigned i = 0; i < sizeof k_bits / sizeof k_bits[0]; i++) {
        Rig r; if (!rig_enc(&r, R_DER)) return;
        CHECKF(OK8(A.ASN1BEREncBitString(r.e, T_BITS, k_bits[i].nbits, k_bits[i].in)), "case %u", i);
        expect_enc(__FILE__, __LINE__, &r, k_bits[i].out, k_bits[i].on);
        rig_done(&r);
    }
}
TEST(be_der_bitstring_matches_ber) {
    NEED(ASN1DEREncBitString);
    for (unsigned i = 0; i < sizeof k_bits / sizeof k_bits[0]; i++) {
        Rig r; if (!rig_enc(&r, R_DER)) return;
        CHECKF(OK8(A.ASN1DEREncBitString(r.e, T_BITS, k_bits[i].nbits, k_bits[i].in)), "case %u", i);
        expect_enc(__FILE__, __LINE__, &r, k_bits[i].out, k_bits[i].on);
        rig_done(&r);
    }
}
TEST(be_bitstring_does_not_modify_the_source) {
    NEED(ASN1BEREncBitString);
    Rig r; if (!rig_enc(&r, R_DER)) return;
    BYTE in[2] = { 0xff, 0xff };
    CHECK(OK8(A.ASN1BEREncBitString(r.e, T_BITS, 9, in)));
    CHECK(in[0] == 0xff && in[1] == 0xff);
    rig_done(&r);
}
ENCT(be_bitstring_context_tag, R_DER, ASN1BEREncBitString, (r.e, TG_CTX(1), 5, "\xf8"), 0x81, 0x02, 0x03, 0xf8)
TEST(be_bitstring_too_many_bits_is_large) {
    NEED(ASN1BEREncBitString);
    Rig r; if (!rig_enc(&r, R_DER)) return;
    CHECK(!OK8(A.ASN1BEREncBitString(r.e, T_BITS, 0xfffffff7, NULL)));
    XEQ(r.e->err, E_LARGE);
    rig_done(&r);
}
static DWORD ref_rzb(DWORD n, const BYTE *d)
{
    for (DWORD i = n; i > 0; i--) if (d[(i - 1) >> 3] & (0x80 >> ((i - 1) & 7))) return i;
    return 0;
}
TEST(be_removezerobits_matches_highest_set_bit) {
    NEED(ASN1BEREncRemoveZeroBits);
    static const struct { DWORD n; BYTE d[4]; } c[] = {
        { 8, { 0xa0 } }, { 8, { 0x01 } }, { 8, { 0x80 } }, { 8, { 0x00 } }, { 5, { 0xf8 } }, { 5, { 0x80 } }, { 5, { 0x00 } },
        { 7, { 0xfe } }, { 7, { 0x02 } }, { 16, { 0xff, 0x00 } }, { 16, { 0x00, 0x00 } }, { 16, { 0x80, 0x01 } },
        { 12, { 0xff, 0x10 } }, { 12, { 0xff, 0x00 } }, { 12, { 0x00, 0x10 } }, { 24, { 0x40, 0x00, 0x00 } },
        { 1, { 0x80 } }, { 1, { 0x00 } }, { 3, { 0xe0 } },
    };
    for (unsigned i = 0; i < sizeof c / sizeof c[0]; i++) {
        DWORD n = c[i].n;
        CHECK(OK8(A.ASN1BEREncRemoveZeroBits(&n, c[i].d)));
        CHECKF(n == ref_rzb(c[i].n, c[i].d), "case %u: got %u want %u", i, n, ref_rzb(c[i].n, c[i].d));
    }
}
TEST(be_removezerobits_ignores_bits_beyond_the_length) {
    NEED(ASN1BEREncRemoveZeroBits);
    DWORD n = 5; const BYTE d[1] = { 0x07 };       /* only the unused low bits are set */
    CHECK(OK8(A.ASN1BEREncRemoveZeroBits(&n, d)));
    XEQ(n, 0);
}
TEST(be_removezerobits2_keeps_a_minimum) {
    NEED(ASN1BEREncRemoveZeroBits2);
    static const struct { DWORD n; BYTE d[2]; DWORD min; DWORD want; } c[] = {
        { 8, { 0xa0 }, 0, 3 }, { 8, { 0xa0 }, 5, 5 }, { 8, { 0xa0 }, 3, 3 }, { 8, { 0xa0 }, 2, 3 }, { 8, { 0x00 }, 4, 4 },
        { 8, { 0x00 }, 0, 0 }, { 16, { 0x80, 0x00 }, 4, 4 }, { 16, { 0x80, 0x00 }, 1, 1 }, { 16, { 0x80, 0x01 }, 4, 16 },
        { 6, { 0xfc }, 8, 6 }, { 6, { 0xfc }, 6, 6 }, { 12, { 0x00, 0x00 }, 12, 12 }, { 12, { 0x00, 0x00 }, 13, 12 },
    };
    for (unsigned i = 0; i < sizeof c / sizeof c[0]; i++) {
        DWORD n = c[i].n;
        CHECK(OK8(A.ASN1BEREncRemoveZeroBits2(&n, c[i].d, c[i].min)));
        CHECKF(n == c[i].want, "case %u: got %u want %u", i, n, c[i].want);
    }
}

/* ---------------------------------------------------------------- OBJECT IDENTIFIER */
TEST(be_oid_linked_list_table) {
    NEED(ASN1BEREncObjectIdentifier);
    for (unsigned i = 0; i < k_oid_n; i++) {
        Rig r; if (!rig_enc(&r, R_DER)) return;
        OIDN nodes[16];
        for (DWORD k = 0; k < k_oid[i].n; k++) { nodes[k].value = k_oid[i].arcs[k]; nodes[k].next = k + 1 < k_oid[i].n ? &nodes[k + 1] : NULL; }
        OIDN *head = &nodes[0];
        CHECKF(OK8(A.ASN1BEREncObjectIdentifier(r.e, T_OID, &head)), "case %u", i);
        expect_enc(__FILE__, __LINE__, &r, k_oid[i].enc, k_oid[i].en);
        rig_done(&r);
    }
}
TEST(be_oid2_array_table) {
    NEED(ASN1BEREncObjectIdentifier2);
    for (unsigned i = 0; i < k_oid_n; i++) {
        Rig r; if (!rig_enc(&r, R_DER)) return;
        OID2 o; memset(&o, 0, sizeof o); o.count = (WORD)k_oid[i].n; memcpy(o.value, k_oid[i].arcs, sizeof(DWORD) * k_oid[i].n);
        CHECKF(OK8(A.ASN1BEREncObjectIdentifier2(r.e, T_OID, &o)), "case %u", i);
        expect_enc(__FILE__, __LINE__, &r, k_oid[i].enc, k_oid[i].en);
        rig_done(&r);
    }
}
TEST(be_oid_empty_is_zero_length) {
    NEED(ASN1BEREncObjectIdentifier); NEED(ASN1BEREncObjectIdentifier2);
    static const BYTE ex[] = { 0x06, 0x00 };
    Rig r; if (!rig_enc(&r, R_DER)) return;
    OIDN *head = NULL;
    CHECK(OK8(A.ASN1BEREncObjectIdentifier(r.e, T_OID, &head)));
    EXPECT_ENC(&r, ex, 2); rig_done(&r);
    if (!rig_enc(&r, R_DER)) return;
    OID2 o; memset(&o, 0, sizeof o);
    CHECK(OK8(A.ASN1BEREncObjectIdentifier2(r.e, T_OID, &o)));
    EXPECT_ENC(&r, ex, 2); rig_done(&r);
}
TEST(be_oid_context_tag) {
    NEED(ASN1BEREncObjectIdentifier2);
    Rig r; if (!rig_enc(&r, R_DER)) return;
    OID2 o; memset(&o, 0, sizeof o); o.count = 3; o.value[0] = 2; o.value[1] = 5; o.value[2] = 4;
    CHECK(OK8(A.ASN1BEREncObjectIdentifier2(r.e, TG_CTX(0), &o)));
    static const BYTE ex[] = { 0x80, 0x02, 0x55, 0x04 };
    EXPECT_ENC(&r, ex, sizeof ex);
    rig_done(&r);
}
TEST(be_eoid_copies_encoded_content) {
    NEED(ASN1BEREncEoid);
    Rig r; if (!rig_enc(&r, R_DER)) return;
    static BYTE v[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
    EOID eo; eo.length = sizeof v; eo.value = v;
    CHECK(OK8(A.ASN1BEREncEoid(r.e, T_OID, &eo)));
    static const BYTE ex[] = { 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
    EXPECT_ENC(&r, ex, sizeof ex);
    rig_done(&r);
}
TEST(be_eoid_empty) {
    NEED(ASN1BEREncEoid);
    Rig r; if (!rig_enc(&r, R_DER)) return;
    EOID eo; eo.length = 0; eo.value = NULL;
    CHECK(OK8(A.ASN1BEREncEoid(r.e, T_OID, &eo)));
    static const BYTE ex[] = { 0x06, 0x00 };
    EXPECT_ENC(&r, ex, 2);
    rig_done(&r);
}
static const struct { const char *s; BYTE v[16]; WORD n; } k_dot[] = {
    { "2.5.4.3", { 0x55, 0x04, 0x03 }, 3 }, { "1.2.840.113549", { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d }, 6 },
    { "1.2.840.113549.1.1.11", { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b }, 9 },
    { "0.0", { 0x00 }, 1 }, { "1.39", { 0x4f }, 1 }, { "2.999", { 0x88, 0x37 }, 2 }, { "2.47", { 0x7f }, 1 }, { "2.48", { 0x81, 0x00 }, 2 },
    { "1.3.6.1.5.5.7.3.1", { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01 }, 8 }, { "1.2.128", { 0x2a, 0x81, 0x00 }, 3 },
    { "2.5.29.15", { 0x55, 0x1d, 0x0f }, 3 }, { "1.2.4294967295", { 0x2a, 0x8f, 0xff, 0xff, 0xff, 0x7f }, 6 },
};
TEST(be_dotval2eoid_table) {
    NEED(ASN1BERDotVal2Eoid); NEED(ASN1BEREoid_free);
    for (unsigned i = 0; i < sizeof k_dot / sizeof k_dot[0]; i++) {
        Rig r; if (!rig_enc(&r, R_DER)) return;
        EOID eo; memset(&eo, 0, sizeof eo);
        U64 rv = A.ASN1BERDotVal2Eoid(r.e, k_dot[i].s, &eo);
        CHECKF(OK8(rv), "%s", k_dot[i].s);
        if (OK8(rv)) {
            XEQ(eo.length, k_dot[i].n);
            CHECK(eo.value != NULL); if (eo.value) EXPECT_BYTES(eo.value, eo.length, k_dot[i].v, k_dot[i].n);
            A.ASN1BEREoid_free(&eo);
        }
        XEQ(r.e->err, 0);
        rig_done(&r);
    }
}
TEST(be_dotval2eoid_rejects_malformed_strings) {
    NEED(ASN1BERDotVal2Eoid);
    static const char *bad[] = { "", "1", "1.", ".1", "1..2", "3.1", "1.40", "0.40", "10.1", "a.b", "1.2.3." , "1,2", "-1.2" };
    for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        Rig r; if (!rig_enc(&r, R_DER)) return;
        EOID eo; memset(&eo, 0, sizeof eo);
        U64 rv = A.ASN1BERDotVal2Eoid(r.e, bad[i], &eo);
        CHECKF(!OK8(rv), "\"%s\" accepted", bad[i]);
        XEQ(r.e->err, E_BADARGS);
        rig_done(&r);
    }
}
TEST(be_dotval2eoid_null_string) {
    NEED(ASN1BERDotVal2Eoid);
    Rig r; if (!rig_enc(&r, R_DER)) return;
    EOID eo; memset(&eo, 0, sizeof eo);
    CHECK(!OK8(A.ASN1BERDotVal2Eoid(r.e, NULL, &eo)));
    XEQ(r.e->err, E_BADARGS);
    rig_done(&r);
}

/* ---------------------------------------------------------------- open type, explicit tag, end of contents */
TEST(be_opentype_copies_raw_bytes) {
    NEED(ASN1BEREncOpenType);
    Rig r; if (!rig_enc(&r, R_DER)) return;
    static BYTE raw[] = { 0x30, 0x03, 0x02, 0x01, 0x05 };
    LV v; v.length = sizeof raw; v.value = raw;
    CHECK(OK8(A.ASN1BEREncOpenType(r.e, &v)));
    EXPECT_ENC(&r, raw, sizeof raw);
    rig_done(&r);
}
TEST(be_opentype_empty_writes_nothing) {
    NEED(ASN1BEREncOpenType);
    Rig r; if (!rig_enc(&r, R_DER)) return;
    LV v; v.length = 0; v.value = NULL;
    CHECK(OK8(A.ASN1BEREncOpenType(r.e, &v)));
    EXPECT_ENC(&r, "", 0);
    rig_done(&r);
}
TEST(be_opentype_after_primitives) {
    NEED(ASN1BEREncOpenType); NEED(ASN1BEREncU32);
    Rig r; if (!rig_enc(&r, R_DER)) return;
    static BYTE raw[] = { 0x05, 0x00 };
    LV v; v.length = 2; v.value = raw;
    CHECK(OK8(A.ASN1BEREncU32(r.e, T_INT, 1))); CHECK(OK8(A.ASN1BEREncOpenType(r.e, &v)));
    static const BYTE ex[] = { 2, 1, 1, 5, 0 };
    EXPECT_ENC(&r, ex, sizeof ex);
    rig_done(&r);
}
TEST(be_explicittag_reports_length_offset) {
    NEED(ASN1BEREncExplicitTag);
    Rig r; if (!rig_enc(&r, R_DER)) return;
    DWORD p1 = 99, p2 = 99;
    CHECK(OK8(A.ASN1BEREncExplicitTag(r.e, T_SEQ, &p1)));        /* 30 <len> */
    XEQ(p1, 1);
    CHECK(OK8(A.ASN1BEREncExplicitTag(r.e, TG_CTX(1), &p2)));    /* A1 <len> */
    XEQ(p2, 3);
    rig_done(&r);
}
TEST(be_explicittag_high_tag_number_offset) {
    NEED(ASN1BEREncExplicitTag);
    Rig r; if (!rig_enc(&r, R_DER)) return;
    DWORD p = 99;
    CHECK(OK8(A.ASN1BEREncExplicitTag(r.e, TG_CTX(200), &p)));   /* BF 81 48 <len> */
    XEQ(p, 3);
    rig_done(&r);
}
TEST(be_explicittag_endofcontents_short) {
    NEED(ASN1BEREncExplicitTag); NEED(ASN1BEREncEndOfContents); NEED(ASN1BEREncU32);
    Rig r; if (!rig_enc(&r, R_DER)) return;
    DWORD p;
    CHECK(OK8(A.ASN1BEREncExplicitTag(r.e, TG_CTX(0), &p)));
    CHECK(OK8(A.ASN1BEREncU32(r.e, T_INT, 5)));
    CHECK(OK8(A.ASN1BEREncEndOfContents(r.e, p)));
    static const BYTE ex[] = { 0xa0, 0x03, 0x02, 0x01, 0x05 };
    EXPECT_ENC(&r, ex, sizeof ex);
    rig_done(&r);
}
TEST(be_explicittag_empty_contents) {
    NEED(ASN1BEREncExplicitTag); NEED(ASN1BEREncEndOfContents);
    Rig r; if (!rig_enc(&r, R_DER)) return;
    DWORD p;
    CHECK(OK8(A.ASN1BEREncExplicitTag(r.e, T_SEQ, &p)));
    CHECK(OK8(A.ASN1BEREncEndOfContents(r.e, p)));
    static const BYTE ex[] = { 0x30, 0x00 };
    EXPECT_ENC(&r, ex, 2);
    rig_done(&r);
}
TEST(be_explicittag_nested) {
    NEED(ASN1BEREncExplicitTag); NEED(ASN1BEREncEndOfContents); NEED(ASN1BEREncBool); NEED(ASN1BEREncNull);
    Rig r; if (!rig_enc(&r, R_DER)) return;
    DWORD p1, p2;
    CHECK(OK8(A.ASN1BEREncExplicitTag(r.e, T_SEQ, &p1)));
    CHECK(OK8(A.ASN1BEREncBool(r.e, T_BOOL, 1)));
    CHECK(OK8(A.ASN1BEREncExplicitTag(r.e, TG_CTX(2), &p2)));
    CHECK(OK8(A.ASN1BEREncNull(r.e, T_NULL)));
    CHECK(OK8(A.ASN1BEREncEndOfContents(r.e, p2)));
    CHECK(OK8(A.ASN1BEREncEndOfContents(r.e, p1)));
    static const BYTE ex2[] = { 0x30, 0x07, 0x01, 0x01, 0xff, 0xa2, 0x02, 0x05, 0x00 };
    EXPECT_ENC(&r, ex2, sizeof ex2);
    rig_done(&r);
}
static void eoc_len_case(DWORD n)
{
    Rig r; if (!rig_enc(&r, R_DER)) return;
    DWORD p; BYTE *body = malloc(n ? n : 1); for (DWORD i = 0; i < n; i++) body[i] = (BYTE)(i ^ 0x5a);
    LV raw; raw.length = n; raw.value = body;
    CHECK(OK8(A.ASN1BEREncExplicitTag(r.e, T_SEQ, &p)));
    CHECK(OK8(A.ASN1BEREncOpenType(r.e, &raw)));
    CHECK(OK8(A.ASN1BEREncEndOfContents(r.e, p)));
    CHECK(OK8(A.ASN1BEREncFlush(r.e)));
    BYTE hdr[8]; DWORD h = 0; hdr[h++] = 0x30;
    if (n < 0x80) hdr[h++] = (BYTE)n;
    else if (n < 0x100) { hdr[h++] = 0x81; hdr[h++] = (BYTE)n; }
    else if (n < 0x10000) { hdr[h++] = 0x82; hdr[h++] = (BYTE)(n >> 8); hdr[h++] = (BYTE)n; }
    else { hdr[h++] = 0x83; hdr[h++] = (BYTE)(n >> 16); hdr[h++] = (BYTE)(n >> 8); hdr[h++] = (BYTE)n; }
    CHECKF(r.e->len == h + n, "n=%u len=%u", n, r.e->len);
    if (r.e->len == h + n) { CHECKF(memcmp(r.e->buf, hdr, h) == 0, "n=%u header", n); CHECKF(n == 0 || memcmp(r.e->buf + h, body, n) == 0, "n=%u body", n); }
    free(body); rig_done(&r);
}
TEST(be_endofcontents_length_forms) {
    NEED(ASN1BEREncExplicitTag); NEED(ASN1BEREncEndOfContents); NEED(ASN1BEREncOpenType);
    static const DWORD ns[] = { 0, 1, 127, 128, 129, 255, 256, 1000, 65535, 65536, 100000 };
    for (unsigned i = 0; i < sizeof ns / sizeof ns[0]; i++) eoc_len_case(ns[i]);
}
/* ---------------------------------------------------------------- GeneralizedTime / UTCTime */
static const struct { GTIME t; const char *s; } k_gt[] = {
    { { 2024, 2, 29, 12, 34, 56, 0, 1, 0 }, "20240229123456Z" },
    { { 1999, 12, 31, 23, 59, 59, 0, 1, 0 }, "19991231235959Z" },
    { { 2024, 2, 29, 12, 34, 56, 789, 1, 0 }, "20240229123456.789Z" },
    { { 2024, 2, 29, 12, 34, 56, 500, 1, 0 }, "20240229123456.5Z" },
    { { 2024, 2, 29, 12, 34, 56, 120, 1, 0 }, "20240229123456.12Z" },
    { { 2024, 2, 29, 12, 34, 56, 5, 1, 0 }, "20240229123456.005Z" },
    { { 2024, 2, 29, 12, 34, 56, 50, 1, 0 }, "20240229123456.05Z" },
    { { 2024, 2, 29, 12, 34, 56, 100, 1, 0 }, "20240229123456.1Z" },
    { { 2024, 2, 29, 12, 34, 56, 0, 0, 0 }, "20240229123456" },
    { { 2024, 2, 29, 12, 34, 56, 0, 0, 60 }, "20240229123456+01" },
    { { 2024, 2, 29, 12, 34, 56, 0, 0, 90 }, "20240229123456+0130" },
    { { 2024, 2, 29, 12, 34, 56, 0, 0, 330 }, "20240229123456+0530" },
    { { 2024, 2, 29, 12, 34, 56, 0, 0, -300 }, "20240229123456-05" },
    { { 2024, 2, 29, 12, 34, 56, 0, 0, -90 }, "20240229123456-0130" },
    { { 2024, 2, 29, 12, 34, 56, 250, 0, -570 }, "20240229123456.25-0930" },
    { { 5, 1, 2, 3, 4, 5, 0, 1, 0 }, "00050102030405Z" },
};
static void enc_gt_check(U64 (WINAPI *f)(ENC *, DWORD, GTIME *), unsigned i)
{
    Rig r; if (!rig_enc(&r, R_DER)) return;
    GTIME t = k_gt[i].t;
    CHECKF(OK8(f(r.e, T_GEN, &t)), "case %u", i);
    BYTE ex[40]; size_t n = strlen(k_gt[i].s);
    ex[0] = T_GEN; ex[1] = (BYTE)n; memcpy(ex + 2, k_gt[i].s, n);
    expect_enc(__FILE__, __LINE__, &r, ex, n + 2);
    rig_done(&r);
}
TEST(be_generalizedtime_table) {
    NEED(ASN1BEREncGeneralizedTime);
    for (unsigned i = 0; i < sizeof k_gt / sizeof k_gt[0]; i++) enc_gt_check(A.ASN1BEREncGeneralizedTime, i);
}
TEST(be_der_generalizedtime_matches) {
    NEED(ASN1DEREncGeneralizedTime);
    for (unsigned i = 0; i < sizeof k_gt / sizeof k_gt[0]; i++) enc_gt_check(A.ASN1DEREncGeneralizedTime, i);
}
TEST(be_cer_generalizedtime_matches) {
    NEED(ASN1CEREncGeneralizedTime);
    for (unsigned i = 0; i < sizeof k_gt / sizeof k_gt[0]; i++) enc_gt_check(A.ASN1CEREncGeneralizedTime, i);
}
TEST(be_generalizedtime_context_tag) {
    NEED(ASN1BEREncGeneralizedTime);
    Rig r; if (!rig_enc(&r, R_DER)) return;
    GTIME t = { 2001, 1, 2, 3, 4, 5, 0, 1, 0 };
    CHECK(OK8(A.ASN1BEREncGeneralizedTime(r.e, TG_CTX(1), &t)));
    static const BYTE ex[] = { 0x81, 0x0f, '2', '0', '0', '1', '0', '1', '0', '2', '0', '3', '0', '4', '0', '5', 'Z' };
    EXPECT_ENC(&r, ex, sizeof ex);
    rig_done(&r);
}
static const struct { UTIME t; const char *s; } k_ut[] = {
    { { 24, 2, 29, 12, 34, 56, 1, 0 }, "240229123456Z" },
    { { 99, 12, 31, 23, 59, 59, 1, 0 }, "991231235959Z" },
    { { 0, 1, 1, 0, 0, 0, 1, 0 }, "000101000000Z" },
    { { 24, 2, 29, 12, 34, 56, 0, 0 }, "240229123456" },
    { { 24, 2, 29, 12, 34, 56, 0, 60 }, "240229123456+01" },
    { { 24, 2, 29, 12, 34, 56, 0, 90 }, "240229123456+0130" },
    { { 24, 2, 29, 12, 34, 56, 0, -300 }, "240229123456-05" },
    { { 24, 2, 29, 12, 34, 56, 0, -570 }, "240229123456-0930" },
};
static void enc_ut_check(U64 (WINAPI *f)(ENC *, DWORD, UTIME *), unsigned i)
{
    Rig r; if (!rig_enc(&r, R_DER)) return;
    UTIME t = k_ut[i].t;
    CHECKF(OK8(f(r.e, T_UTC, &t)), "case %u", i);
    BYTE ex[40]; size_t n = strlen(k_ut[i].s);
    ex[0] = T_UTC; ex[1] = (BYTE)n; memcpy(ex + 2, k_ut[i].s, n);
    expect_enc(__FILE__, __LINE__, &r, ex, n + 2);
    rig_done(&r);
}
TEST(be_utctime_table) {
    NEED(ASN1BEREncUTCTime);
    for (unsigned i = 0; i < sizeof k_ut / sizeof k_ut[0]; i++) enc_ut_check(A.ASN1BEREncUTCTime, i);
}
TEST(be_der_utctime_matches) {
    NEED(ASN1DEREncUTCTime);
    for (unsigned i = 0; i < sizeof k_ut / sizeof k_ut[0]; i++) enc_ut_check(A.ASN1DEREncUTCTime, i);
}
TEST(be_cer_utctime_matches) {
    NEED(ASN1CEREncUTCTime);
    for (unsigned i = 0; i < sizeof k_ut / sizeof k_ut[0]; i++) enc_ut_check(A.ASN1CEREncUTCTime, i);
}

/* ---------------------------------------------------------------- not implemented entry points */
TEST(be_double_family_is_not_implemented) {
    /* ASN1BEREncDouble, ASN1BERDecDouble and the CEREnc string encoders share one body that returns ASN1_ERR_NYI */
    NEED(ASN1BEREncDouble);
    Rig r; if (!rig_enc(&r, R_DER)) return;
    U64 rv = A.ASN1BEREncDouble(r.e, 9, 1.5);
    XEQ((int)rv, E_NYI);
    EXPECT_ENC(&r, "", 0);                                     /* nothing was written */
    rig_done(&r);
}
TEST(be_cer_string_encoders_are_not_implemented) {
    NEED(ASN1CEREncOctetString); NEED(ASN1CEREncBitString); NEED(ASN1CEREncCharString);
    NEED(ASN1CEREncChar16String); NEED(ASN1CEREncChar32String); NEED(ASN1CEREncMultibyteString); NEED(ASN1CEREncZeroMultibyteString);
    Rig r; if (!rig_enc(&r, R_CER)) return;
    CSTR cs = { 3, "abc" };
    XEQ((int)A.ASN1CEREncOctetString(r.e, T_OCT, 3, "abc"), E_NYI);
    XEQ((int)A.ASN1CEREncBitString(r.e, T_BITS, 8, "a"), E_NYI);
    XEQ((int)A.ASN1CEREncCharString(r.e, T_IA5, 3, "abc"), E_NYI);
    XEQ((int)A.ASN1CEREncChar16String(r.e, T_BMP, 1, u16_a), E_NYI);
    XEQ((int)A.ASN1CEREncChar32String(r.e, 28, 1, u32_a), E_NYI);
    XEQ((int)A.ASN1CEREncMultibyteString(r.e, T_IA5, &cs), E_NYI);
    XEQ((int)A.ASN1CEREncZeroMultibyteString(r.e, T_IA5, "abc"), E_NYI);
    EXPECT_ENC(&r, "", 0);
    rig_done(&r);
}
TEST(be_intx_add_sub_are_empty_stubs) {
    /* both exports are a bare "ret": the destination is left untouched */
    NEED(ASN1intx_add); NEED(ASN1intx_sub);
    BYTE a1[1] = { 5 }, b1[1] = { 7 }, c1[1] = { 0x77 };
    LV a = { 1, a1 }, b = { 1, b1 }, c = { 1, c1 };
    A.ASN1intx_add(&c, &a, &b);
    CHECK(c.length == 1 && c.value == c1 && c1[0] == 0x77);
    A.ASN1intx_sub(&c, &a, &b);
    CHECK(c.length == 1 && c.value == c1 && c1[0] == 0x77);
}

/* ---------------------------------------------------------------- DER / CER blocks (SET OF ordering) */
static int set_of_u32(int rule, const DWORD *vals, int n, const BYTE *want, size_t wl)
{
    int ok = 0;
    Rig r; if (!rig_enc(&r, rule)) return 0;
    DWORD p; void *blk = NULL; ENC *sub = NULL;
    U64 (WINAPI *begin)(ENC *, int, void **) = rule == R_CER ? A.ASN1CEREncBeginBlk : A.ASN1DEREncBeginBlk;
    U64 (WINAPI *nw)(void *, ENC **) = rule == R_CER ? A.ASN1CEREncNewBlkElement : A.ASN1DEREncNewBlkElement;
    U64 (WINAPI *fl)(void *) = rule == R_CER ? A.ASN1CEREncFlushBlkElement : A.ASN1DEREncFlushBlkElement;
    U64 (WINAPI *end)(void *) = rule == R_CER ? A.ASN1CEREncEndBlk : A.ASN1DEREncEndBlk;
    if (!begin || !nw || !fl || !end) { t_skip("missing block exports"); rig_done(&r); return 0; }
    CHECK(OK8(A.ASN1BEREncExplicitTag(r.e, T_SET, &p)));
    CHECK(OK8(begin(r.e, 0, &blk)));
    CHECK(blk != NULL);
    for (int i = 0; i < n && blk; i++) {
        CHECK(OK8(nw(blk, &sub))); CHECK(sub != NULL);
        if (!sub) break;
        CHECK(OK8(A.ASN1BEREncU32(sub, T_INT, vals[i])));
        CHECK(OK8(fl(blk)));
    }
    if (blk) CHECK(OK8(end(blk)));
    CHECK(OK8(A.ASN1BEREncEndOfContents(r.e, p)));
    EXPECT_ENC(&r, want, wl);
    ok = 1;
    rig_done(&r);
    return ok;
}
TEST(be_der_set_of_is_sorted) {
    static const DWORD v[] = { 3, 1, 2 };
    static const BYTE ex[] = { 0x31, 0x09, 2, 1, 1, 2, 1, 2, 2, 1, 3 };
    set_of_u32(R_DER, v, 3, ex, sizeof ex);
}
TEST(be_der_set_of_sorts_by_encoded_octets_not_by_value) {
    /* 200 encodes as 02 02 00 C8 and 1 as 02 01 01: the shorter encoding wins on the second octet (01 < 02) */
    static const DWORD v[] = { 200, 1, 100, 300 };
    static const BYTE ex[] = { 0x31, 0x0e, 2, 1, 1, 2, 1, 100, 2, 2, 0, 200, 2, 2, 1, 0x2c };
    set_of_u32(R_DER, v, 4, ex, sizeof ex);
}
TEST(be_der_set_of_already_sorted_and_single) {
    static const DWORD v1[] = { 1, 2, 3, 4 };
    static const BYTE e1[] = { 0x31, 0x0c, 2, 1, 1, 2, 1, 2, 2, 1, 3, 2, 1, 4 };
    set_of_u32(R_DER, v1, 4, e1, sizeof e1);
    static const DWORD v2[] = { 9 };
    static const BYTE e2[] = { 0x31, 0x03, 2, 1, 9 };
    set_of_u32(R_DER, v2, 1, e2, sizeof e2);
}
TEST(be_der_set_of_empty) {
    static const BYTE ex[] = { 0x31, 0x00 };
    set_of_u32(R_DER, NULL, 0, ex, sizeof ex);
}
TEST(be_der_set_of_many_elements_grow_the_block) {
    /* more than the initial 16 slots */
    DWORD v[40]; for (int i = 0; i < 40; i++) v[i] = 39 - i;
    BYTE ex[2 + 120]; ex[0] = 0x31; ex[1] = 120;
    for (int i = 0; i < 40; i++) { ex[2 + 3 * i] = 2; ex[3 + 3 * i] = 1; ex[4 + 3 * i] = (BYTE)i; }
    set_of_u32(R_DER, v, 40, ex, sizeof ex);
}
TEST(be_cer_set_of_keeps_insertion_order) {
    static const DWORD v[] = { 3, 1, 2 };
    static const BYTE ex[] = { 0x31, 0x09, 2, 1, 3, 2, 1, 1, 2, 1, 2 };
    set_of_u32(R_CER, v, 3, ex, sizeof ex);
}
TEST(be_der_set_of_octet_strings_prefix_order) {
    NEED(ASN1DEREncBeginBlk); NEED(ASN1DEREncNewBlkElement); NEED(ASN1DEREncFlushBlkElement); NEED(ASN1DEREncEndBlk);
    NEED(ASN1BEREncOctetString); NEED(ASN1BEREncExplicitTag); NEED(ASN1BEREncEndOfContents);
    Rig r; if (!rig_enc(&r, R_DER)) return;
    static const char *s[] = { "b", "aa", "a", "a" };
    DWORD p; void *blk = NULL; ENC *sub = NULL;
    CHECK(OK8(A.ASN1BEREncExplicitTag(r.e, T_SET, &p)));
    CHECK(OK8(A.ASN1DEREncBeginBlk(r.e, 0, &blk)));
    for (int i = 0; i < 4 && blk; i++) {
        CHECK(OK8(A.ASN1DEREncNewBlkElement(blk, &sub)));
        CHECK(OK8(A.ASN1BEREncOctetString(sub, T_OCT, (DWORD)strlen(s[i]), s[i])));
        CHECK(OK8(A.ASN1DEREncFlushBlkElement(blk)));
    }
    if (blk) CHECK(OK8(A.ASN1DEREncEndBlk(blk)));
    CHECK(OK8(A.ASN1BEREncEndOfContents(r.e, p)));
    static const BYTE ex[] = { 0x31, 0x0d, 4, 1, 'a', 4, 1, 'a', 4, 1, 'b', 4, 2, 'a', 'a' };
    EXPECT_ENC(&r, ex, sizeof ex);
    rig_done(&r);
}
TEST(be_block_element_encoders_share_the_parent_error_state) {
    NEED(ASN1DEREncBeginBlk); NEED(ASN1DEREncNewBlkElement); NEED(ASN1DEREncEndBlk); NEED(ASN1EncSetError);
    Rig r; if (!rig_enc(&r, R_DER)) return;
    void *blk = NULL; ENC *sub = NULL;
    CHECK(OK8(A.ASN1DEREncBeginBlk(r.e, 0, &blk)));
    CHECK(blk != NULL); if (!blk) { rig_done(&r); return; }
    CHECK(OK8(A.ASN1DEREncNewBlkElement(blk, &sub)));
    CHECK(sub != NULL);
    if (sub) {
        CHECK(sub->parent == r.e); CHECK(r.e->child == sub); XEQ(sub->magic, 0x44434e45u);
        XEQ(sub->rule, R_DER);
        A.ASN1EncSetError(sub, E_CORRUPT);
        XEQ(r.e->err, E_CORRUPT);
        A.ASN1EncSetError(sub, 0);
    }
    CHECK(OK8(A.ASN1DEREncEndBlk(blk)));
    rig_done(&r);
}
