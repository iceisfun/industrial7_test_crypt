/* msasn1.dll: ASN1BERDec* primitives driven directly through a decoder. */
#include "asn1t.h"

#define POS(r) ((long)((r).d->pos - (r).d->buf))
#define DEC_OPEN(r, ...) static const BYTE in_[] = { __VA_ARGS__ }; Rig r; if (!rig_dec(&r, R_DER, in_, sizeof in_)) return;

/* scalar decoders: success / failure with the error code recorded in the decoder */
#define DECV(tn, fn, ty, tag, val, ...) \
    TEST(tn) { NEED(fn); DEC_OPEN(r, __VA_ARGS__); ty v = 0; \
        U64 rv = A.fn(r.d, tag, &v); CHECKF(OK8(rv), "rv=%llx", rv); \
        CHECKF((long long)v == (long long)(val), "got %lld want %lld", (long long)v, (long long)(val)); \
        XEQ(POS(r), sizeof in_); XEQ(r.d->err, 0); rig_done(&r); }
#define DECE(tn, fn, ty, tag, errc, ...) \
    TEST(tn) { NEED(fn); DEC_OPEN(r, __VA_ARGS__); ty v = 0; \
        U64 rv = A.fn(r.d, tag, &v); CHECKF(!OK8(rv), "rv=%llx", rv); \
        XEQ(r.d->err, errc); rig_done(&r); }

/* ---------------------------------------------------------------- tag */
TEST(bd_tag_primitive_universal) {
    NEED(ASN1BERDecTag);
    DEC_OPEN(r, 0x02, 0x01, 0x05);
    CHECK(OK8(A.ASN1BERDecTag(r.d, T_INT, NULL)));
    XEQ(POS(r), 1);
    rig_done(&r);
}
TEST(bd_tag_mismatch_still_consumes_the_octet) {
    NEED(ASN1BERDecTag);
    DEC_OPEN(r, 0x02, 0x01, 0x05);
    CHECK(!OK8(A.ASN1BERDecTag(r.d, T_OCT, NULL)));
    XEQ(r.d->err, E_BADTAG);
    XEQ(POS(r), 1);
    rig_done(&r);
}
TEST(bd_tag_empty_input) {
    NEED(ASN1BERDecTag);
    static const BYTE nothing[1];
    Rig r; if (!rig_dec(&r, R_DER, nothing, 0)) return;
    CHECK(!OK8(A.ASN1BERDecTag(r.d, T_INT, NULL)));
    XEQ(r.d->err, E_EOD); XEQ(POS(r), 0);
    rig_done(&r);
}
TEST(bd_tag_constructed_bit_part_of_match_without_flag_pointer) {
    NEED(ASN1BERDecTag);
    {
        DEC_OPEN(r, 0x30, 0x00);
        CHECK(OK8(A.ASN1BERDecTag(r.d, TG_UNIV(T_SEQ) | TG_CONS, NULL)));
        rig_done(&r);
    }
    {
        DEC_OPEN(r, 0x30, 0x00);
        CHECK(!OK8(A.ASN1BERDecTag(r.d, T_SEQ, NULL)));               /* constructed bit missing from the request */
        XEQ(r.d->err, E_BADTAG);
        rig_done(&r);
    }
}
TEST(bd_tag_constructed_flag_pointer_reports_and_ignores_the_bit) {
    NEED(ASN1BERDecTag);
    {
        DEC_OPEN(r, 0x30, 0x00);
        DWORD c = 0xff;
        CHECK(OK8(A.ASN1BERDecTag(r.d, T_SEQ, &c)));
        XEQ(c, 0x20);
        rig_done(&r);
    }
    {
        DEC_OPEN(r, 0x10, 0x00);                                       /* primitive encoding of the same number */
        DWORD c = 0xff;
        CHECK(OK8(A.ASN1BERDecTag(r.d, T_SEQ, &c)));
        XEQ(c, 0);
        rig_done(&r);
    }
}
static const struct { BYTE b[8]; DWORD n; DWORD tag; } k_dtag[] = {
    { { 0x02 }, 1, TG_UNIV(2) }, { { 0x41 }, 1, TG_APP(1) }, { { 0x80 }, 1, TG_CTX(0) }, { { 0xc7 }, 1, TG_PRIV(7) },
    { { 0xa3 }, 1, TG_CTX(3) | TG_CONS }, { { 0x1f, 0x1f }, 2, TG_UNIV(31) }, { { 0x1f, 0x7f }, 2, TG_UNIV(127) },
    { { 0x1f, 0x81, 0x00 }, 3, TG_UNIV(128) }, { { 0x9f, 0x81, 0x48 }, 3, TG_CTX(200) },
    { { 0xbf, 0x81, 0x48 }, 3, TG_CTX(200) | TG_CONS }, { { 0x5f, 0xff, 0x7f }, 3, TG_APP(0x3fff) },
    { { 0x1f, 0x81, 0x80, 0x00 }, 4, TG_UNIV(0x4000) }, { { 0x1f, 0xff, 0xff, 0xff, 0x7f }, 5, TG_UNIV(0xfffffff) },
};
TEST(bd_tag_table) {
    NEED(ASN1BERDecTag);
    for (unsigned i = 0; i < sizeof k_dtag / sizeof k_dtag[0]; i++) {
        Rig r; if (!rig_dec(&r, R_DER, k_dtag[i].b, k_dtag[i].n)) return;
        CHECKF(OK8(A.ASN1BERDecTag(r.d, k_dtag[i].tag, NULL)), "case %u", i);
        XEQ(POS(r), k_dtag[i].n);
        rig_done(&r);
    }
}
TEST(bd_tag_high_number_truncated) {
    NEED(ASN1BERDecTag);
    DEC_OPEN(r, 0x1f, 0x81);
    CHECK(!OK8(A.ASN1BERDecTag(r.d, TG_UNIV(128), NULL)));
    XEQ(r.d->err, E_EOD);
    rig_done(&r);
}
TEST(bd_tag_number_wider_than_28_bits_is_rejected) {
    NEED(ASN1BERDecTag);
    DEC_OPEN(r, 0x1f, 0xff, 0xff, 0xff, 0xff, 0x7f);
    CHECK(!OK8(A.ASN1BERDecTag(r.d, TG_UNIV(0x7fffffff), NULL)));
    XEQ(r.d->err, E_BADTAG);
    rig_done(&r);
}
TEST(bd_peektag_does_not_consume) {
    NEED(ASN1BERDecPeekTag);
    static const struct { BYTE b; DWORD tag; } c[] = {
        { 0x02, 2 }, { 0x04, 4 }, { 0x30, T_SEQ }, { 0x31, T_SET }, { 0xa0, TG_CTX(0) }, { 0x83, TG_CTX(3) },
        { 0x41, TG_APP(1) }, { 0x61, TG_APP(1) }, { 0xc5, TG_PRIV(5) },
    };
    for (unsigned i = 0; i < sizeof c / sizeof c[0]; i++) {
        BYTE in[2] = { c[i].b, 0 };
        Rig r; if (!rig_dec(&r, R_DER, in, 2)) return;
        DWORD t = 0xdeadbeef;
        CHECKF(OK8(A.ASN1BERDecPeekTag(r.d, &t)), "byte %02x", c[i].b);
        CHECKF(t == c[i].tag, "byte %02x got %08x want %08x", c[i].b, t, c[i].tag);   /* class + number; the constructed bit is dropped */
        XEQ(POS(r), 0);
        rig_done(&r);
    }
}
TEST(bd_peektag_empty_input_returns_zero_without_error) {
    NEED(ASN1BERDecPeekTag);
    static const BYTE nothing[1];
    Rig r; if (!rig_dec(&r, R_DER, nothing, 0)) return;
    DWORD t = 0x1234;
    CHECK(!OK8(A.ASN1BERDecPeekTag(r.d, &t)));
    XEQ(t, 0); XEQ(r.d->err, 0);
    rig_done(&r);
}

/* ---------------------------------------------------------------- length */
static const struct { BYTE h[6]; DWORD hl; DWORD len; } k_dlen[] = {
    { { 0x00 }, 1, 0 }, { { 0x05 }, 1, 5 }, { { 0x7f }, 1, 0x7f }, { { 0x81, 0x80 }, 2, 0x80 }, { { 0x81, 0x05 }, 2, 5 },
    { { 0x81, 0xff }, 2, 0xff }, { { 0x82, 0x00, 0x03 }, 3, 3 }, { { 0x82, 0x01, 0x00 }, 3, 0x100 }, { { 0x83, 0x00, 0x00, 0x00 }, 4, 0 },
    { { 0x83, 0x01, 0x00, 0x00 }, 4, 0x10000 }, { { 0x84, 0x00, 0x00, 0x00, 0x02 }, 5, 2 }, { { 0x84, 0x00, 0x00, 0x01, 0x00 }, 5, 0x100 },
};
TEST(bd_length_forms) {
    NEED(ASN1BERDecLength);
    for (unsigned i = 0; i < sizeof k_dlen / sizeof k_dlen[0]; i++) {
        DWORD tot = k_dlen[i].hl + k_dlen[i].len;
        BYTE *buf = calloc(1, tot); memcpy(buf, k_dlen[i].h, k_dlen[i].hl);
        Rig r; if (!rig_dec(&r, R_DER, buf, tot)) { free(buf); return; }
        DWORD len = 0xffff; int ind = 77;
        CHECKF(OK8(A.ASN1BERDecLength(r.d, &len, &ind)), "case %u", i);
        CHECKF(len == k_dlen[i].len, "case %u: got %u want %u", i, len, k_dlen[i].len);
        XEQ(ind, 0); XEQ(POS(r), k_dlen[i].hl);
        rig_done(&r); free(buf);
    }
}
TEST(bd_length_four_octet_form_value) {
    NEED(ASN1BERDecLength);
    static const BYTE in[16] = { 0x84, 0x01, 0x02, 0x03, 0x04 };
    /* a 4-octet length larger than the buffer: the value is read, then the bounds check fails */
    Rig r; if (!rig_dec(&r, R_DER, in, sizeof in)) return;
    DWORD len = 0; int ind = 0;
    CHECK(!OK8(A.ASN1BERDecLength(r.d, &len, &ind)));
    XEQ(len, 0x01020304); XEQ(r.d->err, E_EOD);
    rig_done(&r);
}
TEST(bd_length_indefinite_needs_the_flag_pointer) {
    NEED(ASN1BERDecLength);
    {
        DEC_OPEN(r, 0x80, 0x00, 0x00);
        DWORD len = 9; int ind = 0;
        CHECK(OK8(A.ASN1BERDecLength(r.d, &len, &ind)));
        XEQ(len, 0); XEQ(ind, 1); XEQ(POS(r), 1);
        rig_done(&r);
    }
    {
        DEC_OPEN(r, 0x80, 0x00, 0x00);
        DWORD len = 9;
        CHECK(!OK8(A.ASN1BERDecLength(r.d, &len, NULL)));           /* no way to report it: corrupt */
        XEQ(r.d->err, E_CORRUPT);
        rig_done(&r);
    }
}
TEST(bd_length_forms_wider_than_four_octets_are_corrupt) {
    NEED(ASN1BERDecLength);
    static const BYTE first[] = { 0x85, 0x88, 0xa0, 0xc0, 0xff };
    for (unsigned i = 0; i < sizeof first; i++) {
        BYTE in[8] = { first[i], 0, 0, 0, 0, 0, 0, 0 };
        Rig r; if (!rig_dec(&r, R_DER, in, 8)) return;
        DWORD len = 0; int ind = 0;
        CHECKF(!OK8(A.ASN1BERDecLength(r.d, &len, &ind)), "%02x", first[i]);
        XEQ(r.d->err, E_CORRUPT);
        rig_done(&r);
    }
}
TEST(bd_length_truncated) {
    NEED(ASN1BERDecLength);
    {
        static const BYTE nothing[1];
        Rig r; if (!rig_dec(&r, R_DER, nothing, 0)) return;
        DWORD len; int ind;
        CHECK(!OK8(A.ASN1BERDecLength(r.d, &len, &ind))); XEQ(r.d->err, E_EOD);
        rig_done(&r);
    }
    {
        DEC_OPEN(r, 0x82, 0x01);                                       /* second length octet missing */
        DWORD len; int ind;
        CHECK(!OK8(A.ASN1BERDecLength(r.d, &len, &ind))); XEQ(r.d->err, E_EOD);
        rig_done(&r);
    }
    {
        DEC_OPEN(r, 0x05, 0x01, 0x02);                                 /* announces 5 contents octets, 2 present */
        DWORD len; int ind;
        CHECK(!OK8(A.ASN1BERDecLength(r.d, &len, &ind))); XEQ(r.d->err, E_EOD);
        XEQ(len, 5);
        rig_done(&r);
    }
}
TEST(bd_length_exact_fit_contents) {
    NEED(ASN1BERDecLength);
    DEC_OPEN(r, 0x03, 0x01, 0x02, 0x03);
    DWORD len = 0; int ind = 5;
    CHECK(OK8(A.ASN1BERDecLength(r.d, &len, &ind)));
    XEQ(len, 3); XEQ(ind, 0);
    rig_done(&r);
}
TEST(bd_length_without_indefinite_pointer_ok_for_definite) {
    NEED(ASN1BERDecLength);
    DEC_OPEN(r, 0x02, 0x01, 0x02);
    DWORD len = 0;
    CHECK(OK8(A.ASN1BERDecLength(r.d, &len, NULL)));
    XEQ(len, 2);
    rig_done(&r);
}

/* ---------------------------------------------------------------- check / flush */
TEST(bd_check_bounds) {
    NEED(ASN1BERDecCheck);
    DEC_OPEN(r, 1, 2, 3, 4);
    CHECK(OK8(A.ASN1BERDecCheck(r.d, 0)));
    CHECK(OK8(A.ASN1BERDecCheck(r.d, 4)));
    XEQ(r.d->err, 0);
    CHECK(!OK8(A.ASN1BERDecCheck(r.d, 5)));
    XEQ(r.d->err, E_EOD);
    A.ASN1DecSetError(r.d, 0);
    CHECK(!OK8(A.ASN1BERDecCheck(r.d, 0xffffffff)));
    XEQ(r.d->err, E_EOD);
    XEQ(POS(r), 0);                                           /* never moves the position */
    rig_done(&r);
}
TEST(bd_check_is_relative_to_the_position) {
    NEED(ASN1BERDecCheck); NEED(ASN1BERDecTag);
    DEC_OPEN(r, 1, 2, 3, 4);
    CHECK(OK8(A.ASN1BERDecTag(r.d, TG_UNIV(1), NULL)));
    CHECK(OK8(A.ASN1BERDecCheck(r.d, 3)));
    CHECK(!OK8(A.ASN1BERDecCheck(r.d, 4)));
    rig_done(&r);
}
TEST(bd_flush_records_consumed_length) {
    NEED(ASN1BERDecFlush); NEED(ASN1BERDecNull);
    DEC_OPEN(r, 0x05, 0x00, 0x05, 0x00);
    CHECK(OK8(A.ASN1BERDecNull(r.d, T_NULL)));
    CHECK(OK8(A.ASN1BERDecFlush(r.d)));
    XEQ(r.d->len, 2); XEQ(r.d->err, W_NOEOD);           /* two octets left over */
    CHECK(OK8(A.ASN1BERDecNull(r.d, T_NULL)));
    A.ASN1DecSetError(r.d, 0);
    CHECK(OK8(A.ASN1BERDecFlush(r.d)));
    XEQ(r.d->len, 4); XEQ(r.d->err, 0);
    rig_done(&r);
}

/* ---------------------------------------------------------------- BOOLEAN / NULL */
DECV(bd_bool_true, ASN1BERDecBool, BYTE, T_BOOL, 1, 0x01, 0x01, 0xff)
DECV(bd_bool_false, ASN1BERDecBool, BYTE, T_BOOL, 0, 0x01, 0x01, 0x00)
DECV(bd_bool_any_nonzero_octet_is_true, ASN1BERDecBool, BYTE, T_BOOL, 1, 0x01, 0x01, 0x01)
DECV(bd_bool_0x80_is_true, ASN1BERDecBool, BYTE, T_BOOL, 1, 0x01, 0x01, 0x80)
DECV(bd_bool_context_tag, ASN1BERDecBool, BYTE, TG_CTX(1), 1, 0x81, 0x01, 0xff)
DECV(bd_bool_long_length_form, ASN1BERDecBool, BYTE, T_BOOL, 1, 0x01, 0x81, 0x01, 0xff)
DECE(bd_bool_wrong_tag, ASN1BERDecBool, BYTE, T_BOOL, E_BADTAG, 0x02, 0x01, 0xff)
DECE(bd_bool_truncated_contents, ASN1BERDecBool, BYTE, T_BOOL, E_EOD, 0x01, 0x01)
DECE(bd_bool_indefinite_length_is_corrupt, ASN1BERDecBool, BYTE, T_BOOL, E_CORRUPT, 0x01, 0x80, 0xff, 0x00, 0x00)
DECE(bd_bool_five_octet_length_is_corrupt, ASN1BERDecBool, BYTE, T_BOOL, E_CORRUPT, 0x01, 0x85, 0, 0, 0, 0, 1, 0xff)
TEST(bd_bool_empty_contents_fail_without_an_error_code) {
    NEED(ASN1BERDecBool);
    DEC_OPEN(r, 0x01, 0x00);
    BYTE v = 0x55;
    CHECK(!OK8(A.ASN1BERDecBool(r.d, T_BOOL, &v)));
    XEQ(r.d->err, 0);
    CHECK(v == 0x55);
    rig_done(&r);
}
TEST(bd_bool_two_octet_contents_use_the_first) {
    NEED(ASN1BERDecBool);
    DEC_OPEN(r, 0x01, 0x02, 0x00, 0xff);
    BYTE v = 7;
    CHECK(OK8(A.ASN1BERDecBool(r.d, T_BOOL, &v)));
    XEQ(v, 0); XEQ(POS(r), 4);
    rig_done(&r);
}
TEST(bd_null_ok) {
    NEED(ASN1BERDecNull);
    DEC_OPEN(r, 0x05, 0x00);
    CHECK(OK8(A.ASN1BERDecNull(r.d, T_NULL)));
    XEQ(POS(r), 2);
    rig_done(&r);
}
TEST(bd_null_context_tag) {
    NEED(ASN1BERDecNull);
    DEC_OPEN(r, 0x85, 0x00);
    CHECK(OK8(A.ASN1BERDecNull(r.d, TG_CTX(5))));
    rig_done(&r);
}
TEST(bd_null_with_contents_is_corrupt) {
    NEED(ASN1BERDecNull);
    DEC_OPEN(r, 0x05, 0x01, 0x00);
    CHECK(!OK8(A.ASN1BERDecNull(r.d, T_NULL)));
    XEQ(r.d->err, E_CORRUPT);
    rig_done(&r);
}
TEST(bd_null_wrong_tag_and_truncated) {
    NEED(ASN1BERDecNull);
    {
        DEC_OPEN(r, 0x04, 0x00);
        CHECK(!OK8(A.ASN1BERDecNull(r.d, T_NULL))); XEQ(r.d->err, E_BADTAG);
        rig_done(&r);
    }
    {
        DEC_OPEN(r, 0x05);
        CHECK(!OK8(A.ASN1BERDecNull(r.d, T_NULL))); XEQ(r.d->err, E_EOD);
        rig_done(&r);
    }
}

/* ---------------------------------------------------------------- integers */
DECV(bd_u8_one_octet, ASN1BERDecU8Val, BYTE, T_INT, 0x7f, 0x02, 0x01, 0x7f)
DECV(bd_u8_one_octet_high_bit_is_not_signed, ASN1BERDecU8Val, BYTE, T_INT, 0xff, 0x02, 0x01, 0xff)
DECV(bd_u8_two_octets_with_leading_zero, ASN1BERDecU8Val, BYTE, T_INT, 0xff, 0x02, 0x02, 0x00, 0xff)
DECE(bd_u8_two_octets_nonzero_lead_is_large, ASN1BERDecU8Val, BYTE, T_INT, E_LARGE, 0x02, 0x02, 0x01, 0x00)
DECE(bd_u8_three_octets_is_large, ASN1BERDecU8Val, BYTE, T_INT, E_LARGE, 0x02, 0x03, 0x00, 0x00, 0x05)
DECE(bd_u8_empty_is_corrupt, ASN1BERDecU8Val, BYTE, T_INT, E_CORRUPT, 0x02, 0x00)
DECE(bd_u8_wrong_tag, ASN1BERDecU8Val, BYTE, T_INT, E_BADTAG, 0x0a, 0x01, 0x01)
DECE(bd_u8_truncated, ASN1BERDecU8Val, BYTE, T_INT, E_EOD, 0x02, 0x02, 0x00)
DECV(bd_s8_one_octet_positive, ASN1BERDecS8Val, signed char, T_INT, 0x7f, 0x02, 0x01, 0x7f)
DECV(bd_s8_one_octet_negative, ASN1BERDecS8Val, signed char, T_INT, -128, 0x02, 0x01, 0x80)
DECV(bd_s8_minus_one, ASN1BERDecS8Val, signed char, T_INT, -1, 0x02, 0x01, 0xff)
DECE(bd_s8_two_octets_is_large, ASN1BERDecS8Val, signed char, T_INT, E_LARGE, 0x02, 0x02, 0x00, 0x05)
DECE(bd_s8_empty_is_corrupt, ASN1BERDecS8Val, signed char, T_INT, E_CORRUPT, 0x02, 0x00)
DECV(bd_enum_context_tag_u8, ASN1BERDecU8Val, BYTE, TG_CTX(0), 3, 0x80, 0x01, 0x03)
DECV(bd_u16_one_octet, ASN1BERDecU16Val, WORD, T_INT, 0x80, 0x02, 0x01, 0x80)
DECV(bd_u16_two_octets, ASN1BERDecU16Val, WORD, T_INT, 0x1234, 0x02, 0x02, 0x12, 0x34)
DECV(bd_u16_three_octets_leading_zero, ASN1BERDecU16Val, WORD, T_INT, 0xffff, 0x02, 0x03, 0x00, 0xff, 0xff)
DECE(bd_u16_three_octets_nonzero_lead_is_large, ASN1BERDecU16Val, WORD, T_INT, E_LARGE, 0x02, 0x03, 0x01, 0x00, 0x00)
DECE(bd_u16_four_octets_is_large, ASN1BERDecU16Val, WORD, T_INT, E_LARGE, 0x02, 0x04, 0x00, 0x00, 0x00, 0x01)
DECE(bd_u16_empty_is_corrupt, ASN1BERDecU16Val, WORD, T_INT, E_CORRUPT, 0x02, 0x00)
DECV(bd_s16_two_octets_positive, ASN1BERDecS16Val, short, T_INT, 0x1234, 0x02, 0x02, 0x12, 0x34)
DECV(bd_s16_two_octets_negative, ASN1BERDecS16Val, short, T_INT, -2, 0x02, 0x02, 0xff, 0xfe)
DECV(bd_s16_min, ASN1BERDecS16Val, short, T_INT, -32768, 0x02, 0x02, 0x80, 0x00)
TEST(bd_s16_one_octet_ff_value) {
    NEED(ASN1BERDecS16Val); DEC_OPEN(r, 0x02, 0x01, 0xff); short v = 0;
    CHECK(OK8(A.ASN1BERDecS16Val(r.d, T_INT, &v)));
    t_note("S16Val of 02 01 ff = %d (decomp: 255, zero-extended)", (int)v);
    rig_done(&r);
}
DECE(bd_s16_three_octets_is_large, ASN1BERDecS16Val, short, T_INT, E_LARGE, 0x02, 0x03, 0x00, 0x00, 0x01)
DECE(bd_s16_empty_is_corrupt, ASN1BERDecS16Val, short, T_INT, E_CORRUPT, 0x02, 0x00)
DECE(bd_s16_wrong_tag, ASN1BERDecS16Val, short, T_INT, E_BADTAG, 0x04, 0x01, 0x01)

static const struct { BYTE b[10]; DWORD n; DWORD v; } k_du32[] = {
    { { 2, 1, 0x00 }, 3, 0 }, { { 2, 1, 0x7f }, 3, 0x7f }, { { 2, 1, 0xff }, 3, 0xff }, { { 2, 2, 0x01, 0x00 }, 4, 0x100 },
    { { 2, 2, 0xff, 0xff }, 4, 0xffff }, { { 2, 3, 0x12, 0x34, 0x56 }, 5, 0x123456 }, { { 2, 3, 0xff, 0xff, 0xff }, 5, 0xffffff },
    { { 2, 4, 0x12, 0x34, 0x56, 0x78 }, 6, 0x12345678 }, { { 2, 4, 0xff, 0xff, 0xff, 0xff }, 6, 0xffffffff },
    { { 2, 5, 0x00, 0xff, 0xff, 0xff, 0xff }, 7, 0xffffffff }, { { 2, 5, 0x00, 0x80, 0x00, 0x00, 0x00 }, 7, 0x80000000 },
    { { 2, 5, 0x00, 0x00, 0x00, 0x00, 0x01 }, 7, 1 }, { { 2, 0x81, 0x02, 0x01, 0x02 }, 5, 0x0102 },
};
TEST(bd_u32_table) {
    NEED(ASN1BERDecU32Val);
    for (unsigned i = 0; i < sizeof k_du32 / sizeof k_du32[0]; i++) {
        Rig r; if (!rig_dec(&r, R_DER, k_du32[i].b, k_du32[i].n)) return;
        DWORD v = 0x5a5a5a5a;
        CHECKF(OK8(A.ASN1BERDecU32Val(r.d, T_INT, &v)), "case %u", i);
        CHECKF(v == k_du32[i].v, "case %u: got %08x want %08x", i, v, k_du32[i].v);
        XEQ(POS(r), k_du32[i].n);
        rig_done(&r);
    }
}
DECE(bd_u32_five_octets_nonzero_lead_is_large, ASN1BERDecU32Val, DWORD, T_INT, E_LARGE, 0x02, 0x05, 0x01, 0, 0, 0, 0)
DECE(bd_u32_six_octets_is_large, ASN1BERDecU32Val, DWORD, T_INT, E_LARGE, 0x02, 0x06, 0, 0, 0, 0, 0, 1)
DECE(bd_u32_empty_is_corrupt, ASN1BERDecU32Val, DWORD, T_INT, E_CORRUPT, 0x02, 0x00)
DECE(bd_u32_wrong_tag, ASN1BERDecU32Val, DWORD, T_INT, E_BADTAG, 0x03, 0x01, 0x01)
DECE(bd_u32_truncated, ASN1BERDecU32Val, DWORD, T_INT, E_EOD, 0x02, 0x04, 0x01, 0x02)
DECV(bd_u32_context_tag, ASN1BERDecU32Val, DWORD, TG_CTX(4), 300, 0x84, 0x02, 0x01, 0x2c)

static const struct { BYTE b[10]; DWORD n; int v; } k_ds32[] = {
    { { 2, 1, 0x00 }, 3, 0 }, { { 2, 1, 0x7f }, 3, 127 }, { { 2, 1, 0x80 }, 3, -128 }, { { 2, 1, 0xff }, 3, -1 },
    { { 2, 2, 0x00, 0x80 }, 4, 128 }, { { 2, 2, 0xff, 0x7f }, 4, -129 }, { { 2, 2, 0x7f, 0xff }, 4, 32767 },
    { { 2, 2, 0x80, 0x00 }, 4, -32768 }, { { 2, 3, 0x00, 0x80, 0x00 }, 5, 32768 }, { { 2, 3, 0xff, 0x7f, 0xff }, 5, -32769 },
    { { 2, 3, 0x7f, 0xff, 0xff }, 5, 8388607 }, { { 2, 3, 0x80, 0x00, 0x00 }, 5, -8388608 },
    { { 2, 4, 0x7f, 0xff, 0xff, 0xff }, 6, 0x7fffffff }, { { 2, 4, 0x80, 0x00, 0x00, 0x00 }, 6, (int)0x80000000 },
    { { 2, 4, 0xff, 0xff, 0xff, 0xff }, 6, -1 }, { { 2, 4, 0xed, 0xcb, 0xa9, 0x88 }, 6, -0x12345678 },
    { { 2, 4, 0x00, 0x00, 0x00, 0x05 }, 6, 5 },
};
TEST(bd_s32_table_sign_extension) {
    NEED(ASN1BERDecS32Val);
    for (unsigned i = 0; i < sizeof k_ds32 / sizeof k_ds32[0]; i++) {
        Rig r; if (!rig_dec(&r, R_DER, k_ds32[i].b, k_ds32[i].n)) return;
        int v = 0x5a5a5a5a;
        CHECKF(OK8(A.ASN1BERDecS32Val(r.d, T_INT, &v)), "case %u", i);
        CHECKF(v == k_ds32[i].v, "case %u: got %d want %d", i, v, k_ds32[i].v);
        XEQ(POS(r), k_ds32[i].n);
        rig_done(&r);
    }
}
DECE(bd_s32_five_octets_is_large, ASN1BERDecS32Val, int, T_INT, E_LARGE, 0x02, 0x05, 0, 0, 0, 0, 1)
DECE(bd_s32_empty_is_corrupt, ASN1BERDecS32Val, int, T_INT, E_CORRUPT, 0x02, 0x00)
DECE(bd_s32_wrong_tag, ASN1BERDecS32Val, int, T_INT, E_BADTAG, 0x0a, 0x01, 0x01)
DECE(bd_s32_truncated, ASN1BERDecS32Val, int, T_INT, E_EOD, 0x02, 0x03, 0x01)
DECE(bd_s32_indefinite_length_is_corrupt, ASN1BERDecS32Val, int, T_INT, E_CORRUPT, 0x02, 0x80, 0x01, 0x00, 0x00)
DECV(bd_s32_enumerated_tag, ASN1BERDecS32Val, int, T_ENUM, 2, 0x0a, 0x01, 0x02)
TEST(bd_s32_decodes_consecutive_values) {
    NEED(ASN1BERDecS32Val);
    DEC_OPEN(r, 0x02, 0x01, 0xfe, 0x02, 0x02, 0x01, 0x00, 0x02, 0x01, 0x07);
    int a = 0, b = 0, c = 0;
    CHECK(OK8(A.ASN1BERDecS32Val(r.d, T_INT, &a))); CHECK(OK8(A.ASN1BERDecS32Val(r.d, T_INT, &b))); CHECK(OK8(A.ASN1BERDecS32Val(r.d, T_INT, &c)));
    XEQ(a, -2); XEQ(b, 256); XEQ(c, 7); XEQ(POS(r), 10);
    rig_done(&r);
}
TEST(bd_sx_keeps_raw_octets) {
    NEED(ASN1BERDecSXVal); NEED(ASN1intx_free);
    DEC_OPEN(r, 0x02, 0x04, 0x00, 0x80, 0x01, 0x02);
    LV v = { 99, (BYTE *)1 };
    CHECK(OK8(A.ASN1BERDecSXVal(r.d, T_INT, &v)));
    XEQ(v.length, 4);
    CHECK(v.value != NULL && v.value != in_ + 2);                    /* copy, not a pointer into the input */
    if (v.value) EXPECT_BYTES(v.value, 4, in_ + 2, 4);
    XEQ(POS(r), 6);
    A.ASN1intx_free(&v);
    rig_done(&r);
}
TEST(bd_sx_long_length_form_and_large_value) {
    NEED(ASN1BERDecSXVal); NEED(ASN1intx_free);
    BYTE in[3 + 200]; in[0] = 2; in[1] = 0x81; in[2] = 200; for (int i = 0; i < 200; i++) in[3 + i] = (BYTE)(i + 1);
    Rig r; if (!rig_dec(&r, R_DER, in, sizeof in)) return;
    LV v = { 0, NULL };
    CHECK(OK8(A.ASN1BERDecSXVal(r.d, T_INT, &v)));
    XEQ(v.length, 200);
    if (v.value) EXPECT_BYTES(v.value, 200, in + 3, 200);
    A.ASN1intx_free(&v);
    rig_done(&r);
}
TEST(bd_sx_empty_and_errors) {
    NEED(ASN1BERDecSXVal);
    {
        DEC_OPEN(r, 0x02, 0x00);
        LV v = { 0, NULL };
        CHECK(!OK8(A.ASN1BERDecSXVal(r.d, T_INT, &v))); XEQ(r.d->err, E_CORRUPT);
        rig_done(&r);
    }
    {
        DEC_OPEN(r, 0x04, 0x01, 0x05);
        LV v = { 0, NULL };
        CHECK(!OK8(A.ASN1BERDecSXVal(r.d, T_INT, &v))); XEQ(r.d->err, E_BADTAG);
        rig_done(&r);
    }
    {
        DEC_OPEN(r, 0x02, 0x04, 0x01);
        LV v = { 0, NULL };
        CHECK(!OK8(A.ASN1BERDecSXVal(r.d, T_INT, &v))); XEQ(r.d->err, E_EOD);
        rig_done(&r);
    }
}

/* ---------------------------------------------------------------- octet / bit strings */
TEST(bd_octetstring_copy) {
    NEED(ASN1BERDecOctetString);
    DEC_OPEN(r, 0x04, 0x03, 'a', 'b', 'c');
    LV v = { 0, NULL };
    CHECK(OK8(A.ASN1BERDecOctetString(r.d, T_OCT, &v)));
    XEQ(v.length, 3);
    CHECK(v.value != NULL && v.value != in_ + 2);
    if (v.value) EXPECT_BYTES(v.value, 3, "abc", 3);
    XEQ(POS(r), 5);
    A.ASN1octetstring_free(&v);
    rig_done(&r);
}
TEST(bd_octetstring2_points_into_the_input) {
    NEED(ASN1BERDecOctetString2);
    DEC_OPEN(r, 0x04, 0x03, 'a', 'b', 'c');
    LV v = { 0, NULL };
    CHECK(OK8(A.ASN1BERDecOctetString2(r.d, T_OCT, &v)));
    XEQ(v.length, 3); CHECK(v.value == in_ + 2);
    XEQ(POS(r), 5);
    rig_done(&r);
}
TEST(bd_octetstring_empty) {
    NEED(ASN1BERDecOctetString);
    DEC_OPEN(r, 0x04, 0x00);
    LV v = { 9, (BYTE *)1 };
    CHECK(OK8(A.ASN1BERDecOctetString(r.d, T_OCT, &v)));
    XEQ(v.length, 0); CHECK(v.value == NULL);
    rig_done(&r);
}
TEST(bd_octetstring2_empty_still_points_at_the_position) {
    NEED(ASN1BERDecOctetString2);
    DEC_OPEN(r, 0x04, 0x00, 0x05, 0x00);
    LV v = { 9, NULL };
    CHECK(OK8(A.ASN1BERDecOctetString2(r.d, T_OCT, &v)));
    XEQ(v.length, 0); CHECK(v.value == in_ + 2);
    rig_done(&r);
}
TEST(bd_octetstring_context_tags_primitive_and_constructed) {
    NEED(ASN1BERDecOctetString);
    {
        DEC_OPEN(r, 0x80, 0x02, 0x01, 0x02);
        LV v = { 0, NULL };
        CHECK(OK8(A.ASN1BERDecOctetString(r.d, TG_CTX(0), &v))); XEQ(v.length, 2);
        A.ASN1octetstring_free(&v); rig_done(&r);
    }
    {
        DEC_OPEN(r, 0xa0, 0x04, 0x04, 0x02, 0x01, 0x02);                /* same tag number, constructed */
        LV v = { 0, NULL };
        CHECK(OK8(A.ASN1BERDecOctetString(r.d, TG_CTX(0), &v))); XEQ(v.length, 2);
        if (v.value) EXPECT_BYTES(v.value, 2, "\x01\x02", 2);
        A.ASN1octetstring_free(&v); rig_done(&r);
    }
}
TEST(bd_octetstring_constructed_definite_chunks_are_concatenated) {
    NEED(ASN1BERDecOctetString);
    DEC_OPEN(r, 0x24, 0x0a, 0x04, 0x02, 'a', 'b', 0x04, 0x00, 0x04, 0x02, 'c', 'd');
    LV v = { 0, NULL };
    CHECK(OK8(A.ASN1BERDecOctetString(r.d, T_OCT, &v)));
    XEQ(v.length, 4);
    if (v.value && v.length == 4) EXPECT_BYTES(v.value, 4, "abcd", 4);
    XEQ(POS(r), sizeof in_);
    A.ASN1octetstring_free(&v);
    rig_done(&r);
}
TEST(bd_octetstring_constructed_indefinite_chunks) {
    NEED(ASN1BERDecOctetString);
    DEC_OPEN(r, 0x24, 0x80, 0x04, 0x01, 'x', 0x04, 0x02, 'y', 'z', 0x00, 0x00, 0x05, 0x00);
    LV v = { 0, NULL };
    CHECK(OK8(A.ASN1BERDecOctetString(r.d, T_OCT, &v)));
    XEQ(v.length, 3);
    if (v.value && v.length == 3) EXPECT_BYTES(v.value, 3, "xyz", 3);
    XEQ(POS(r), 11);                                              /* end-of-contents consumed, trailing NULL untouched */
    A.ASN1octetstring_free(&v);
    rig_done(&r);
}
static int nested_octet(int wrappers, BYTE *out)
{
    /* wrappers nested definite constructed OCTET STRINGs around one primitive "Q" */
    BYTE inner[4] = { 4, 1, 'Q' }; int n = 3;
    memcpy(out, inner, 3);
    for (int i = 0; i < wrappers; i++) { memmove(out + 2, out, n); out[0] = 0x24; out[1] = (BYTE)n; n += 2; }
    return n;
}
TEST(bd_octetstring_constructed_nesting_depth_limit) {
    NEED(ASN1BERDecOctetString);
    BYTE in[64]; LV v;
    int n = nested_octet(5, in);
    Rig r; if (!rig_dec(&r, R_DER, in, n)) return;
    v.length = 0; v.value = NULL;
    CHECK(OK8(A.ASN1BERDecOctetString(r.d, T_OCT, &v)));
    XEQ(v.length, 1);
    A.ASN1octetstring_free(&v); rig_done(&r);
    n = nested_octet(10, in);
    if (!rig_dec(&r, R_DER, in, n)) return;
    v.length = 0; v.value = NULL;
    CHECK(!OK8(A.ASN1BERDecOctetString(r.d, T_OCT, &v)));
    XEQ(r.d->err, E_CORRUPT);
    rig_done(&r);
}
TEST(bd_octetstring_errors) {
    NEED(ASN1BERDecOctetString);
    {
        DEC_OPEN(r, 0x03, 0x01, 0x00);
        LV v = { 0, NULL };
        CHECK(!OK8(A.ASN1BERDecOctetString(r.d, T_OCT, &v))); XEQ(r.d->err, E_BADTAG);
        rig_done(&r);
    }
    {
        DEC_OPEN(r, 0x04, 0x05, 'a', 'b');
        LV v = { 0, NULL };
        CHECK(!OK8(A.ASN1BERDecOctetString(r.d, T_OCT, &v))); XEQ(r.d->err, E_EOD);
        rig_done(&r);
    }
    {
        DEC_OPEN(r, 0x04, 0x85, 0, 0, 0, 0, 1, 'a');
        LV v = { 0, NULL };
        CHECK(!OK8(A.ASN1BERDecOctetString(r.d, T_OCT, &v))); XEQ(r.d->err, E_CORRUPT);
        rig_done(&r);
    }
}
TEST(bd_octetstring_long_length_forms) {
    NEED(ASN1BERDecOctetString2);
    static const DWORD ns[] = { 127, 128, 255, 256, 1000 };
    for (unsigned i = 0; i < 5; i++) {
        DWORD n = ns[i];
        BYTE *in = malloc(n + 6); DWORD h = 0; in[h++] = 4;
        if (n < 0x80) in[h++] = (BYTE)n;
        else if (n < 0x100) { in[h++] = 0x81; in[h++] = (BYTE)n; }
        else { in[h++] = 0x82; in[h++] = (BYTE)(n >> 8); in[h++] = (BYTE)n; }
        memset(in + h, 0x3c, n);
        Rig r; if (!rig_dec(&r, R_DER, in, h + n)) { free(in); return; }
        LV v = { 0, NULL };
        CHECKF(OK8(A.ASN1BERDecOctetString2(r.d, T_OCT, &v)), "n=%u", n);
        XEQ(v.length, n); CHECK(v.value == in + h); XEQ(POS(r), h + n);
        rig_done(&r); free(in);
    }
}
TEST(bd_bitstring_copy_masks_unused_bits) {
    NEED(ASN1BERDecBitString);
    DEC_OPEN(r, 0x03, 0x02, 0x03, 0xff);
    LV v = { 0, NULL };
    CHECK(OK8(A.ASN1BERDecBitString(r.d, T_BITS, &v)));
    XEQ(v.length, 5);
    CHECK(v.value != NULL); if (v.value) XEQ(v.value[0], 0xf8);
    XEQ(POS(r), 4);
    A.ASN1bitstring_free(&v);
    rig_done(&r);
}
static const struct { BYTE b[8]; DWORD n; DWORD bits; BYTE v[4]; DWORD vn; } k_dbit[] = {
    { { 3, 2, 7, 0x80 }, 4, 1, { 0x80 }, 1 }, { { 3, 2, 0, 0xab }, 4, 8, { 0xab }, 1 }, { { 3, 3, 0, 0xab, 0xcd }, 5, 16, { 0xab, 0xcd }, 2 },
    { { 3, 3, 4, 0xab, 0xcd }, 5, 12, { 0xab, 0xc0 }, 2 }, { { 3, 3, 7, 0xff, 0xff }, 5, 9, { 0xff, 0x80 }, 2 },
    { { 3, 4, 1, 1, 2, 3 }, 6, 23, { 1, 2, 2 }, 3 },
};
TEST(bd_bitstring_table) {
    NEED(ASN1BERDecBitString);
    for (unsigned i = 0; i < sizeof k_dbit / sizeof k_dbit[0]; i++) {
        Rig r; if (!rig_dec(&r, R_DER, k_dbit[i].b, k_dbit[i].n)) return;
        LV v = { 0, NULL };
        CHECKF(OK8(A.ASN1BERDecBitString(r.d, T_BITS, &v)), "case %u", i);
        XEQ(v.length, k_dbit[i].bits);
        CHECK(v.value != NULL); if (v.value) EXPECT_BYTES(v.value, k_dbit[i].vn, k_dbit[i].v, k_dbit[i].vn);
        A.ASN1bitstring_free(&v);
        rig_done(&r);
    }
}
TEST(bd_bitstring2_points_into_input_and_leaves_bits_unmasked) {
    NEED(ASN1BERDecBitString2);
    DEC_OPEN(r, 0x03, 0x02, 0x03, 0xff);
    LV v = { 0, NULL };
    CHECK(OK8(A.ASN1BERDecBitString2(r.d, T_BITS, &v)));
    XEQ(v.length, 5); CHECK(v.value == in_ + 3); XEQ(v.value[0], 0xff);
    XEQ(POS(r), 4);
    rig_done(&r);
}
TEST(bd_bitstring_empty) {
    NEED(ASN1BERDecBitString);
    DEC_OPEN(r, 0x03, 0x01, 0x00);
    LV v = { 9, (BYTE *)1 };
    CHECK(OK8(A.ASN1BERDecBitString(r.d, T_BITS, &v)));
    XEQ(v.length, 0); CHECK(v.value == NULL); XEQ(POS(r), 3);
    rig_done(&r);
}
TEST(bd_bitstring_unused_bits_over_seven_is_corrupt) {
    NEED(ASN1BERDecBitString);
    DEC_OPEN(r, 0x03, 0x02, 0x08, 0x00);
    LV v = { 0, NULL };
    CHECK(!OK8(A.ASN1BERDecBitString(r.d, T_BITS, &v)));
    XEQ(r.d->err, E_CORRUPT);
    rig_done(&r);
}
TEST(bd_bitstring_zero_length_contents_is_accepted_as_empty) {
    NEED(ASN1BERDecBitString);
    DEC_OPEN(r, 0x03, 0x00);
    LV v = { 9, (BYTE *)1 };
    CHECK(OK8(A.ASN1BERDecBitString(r.d, T_BITS, &v)));
    XEQ(v.length, 0); CHECK(v.value == NULL); XEQ(POS(r), 2);
    rig_done(&r);
}
TEST(bd_bitstring_errors) {
    NEED(ASN1BERDecBitString);
    {
        DEC_OPEN(r, 0x04, 0x02, 0x00, 0x00);
        LV v = { 0, NULL };
        CHECK(!OK8(A.ASN1BERDecBitString(r.d, T_BITS, &v))); XEQ(r.d->err, E_BADTAG);
        rig_done(&r);
    }
    {
        DEC_OPEN(r, 0x03, 0x04, 0x00, 0x01);
        LV v = { 0, NULL };
        CHECK(!OK8(A.ASN1BERDecBitString(r.d, T_BITS, &v))); XEQ(r.d->err, E_EOD);
        rig_done(&r);
    }
}
TEST(bd_bitstring_context_tag) {
    NEED(ASN1BERDecBitString);
    DEC_OPEN(r, 0x81, 0x02, 0x04, 0xa0);
    LV v = { 0, NULL };
    CHECK(OK8(A.ASN1BERDecBitString(r.d, TG_CTX(1), &v)));
    XEQ(v.length, 4); if (v.value) XEQ(v.value[0], 0xa0);
    A.ASN1bitstring_free(&v);
    rig_done(&r);
}

/* ---------------------------------------------------------------- OBJECT IDENTIFIER */
static unsigned oid_count(const OIDN *n) { unsigned c = 0; for (; n; n = n->next) c++; return c; }
TEST(bd_oid_linked_list_roundtrip_table) {
    NEED(ASN1BERDecObjectIdentifier); NEED(ASN1objectidentifier_free);
    for (unsigned i = 0; i < k_oid_n; i++) {
        if (k_oid[i].n < 2) continue;                    /* a single arc is folded into the first two on the wire */
        Rig r; if (!rig_dec(&r, R_DER, k_oid[i].enc, k_oid[i].en)) return;
        OIDN *head = NULL;
        CHECKF(OK8(A.ASN1BERDecObjectIdentifier(r.d, T_OID, &head)), "case %u", i);
        CHECKF(head && oid_count(head) == k_oid[i].n, "case %u: %u arcs want %u", i, oid_count(head), k_oid[i].n);
        const OIDN *p = head;
        for (DWORD k = 0; k < k_oid[i].n && p; k++, p = p->next) CHECKF(p->value == k_oid[i].arcs[k], "case %u arc %u: %u want %u", i, k, p->value, k_oid[i].arcs[k]);
        XEQ(POS(r), k_oid[i].en);
        A.ASN1objectidentifier_free(&head);
        rig_done(&r);
    }
}
TEST(bd_oid2_array_roundtrip_table) {
    NEED(ASN1BERDecObjectIdentifier2);
    for (unsigned i = 0; i < k_oid_n; i++) {
        if (k_oid[i].n < 2) continue;
        Rig r; if (!rig_dec(&r, R_DER, k_oid[i].enc, k_oid[i].en)) return;
        OID2 o; memset(&o, 0xcc, sizeof o);
        CHECKF(OK8(A.ASN1BERDecObjectIdentifier2(r.d, T_OID, &o)), "case %u", i);
        CHECKF(o.count == k_oid[i].n, "case %u: %u arcs want %u", i, o.count, k_oid[i].n);
        for (DWORD k = 0; k < k_oid[i].n && k < 16; k++) CHECKF(o.value[k] == k_oid[i].arcs[k], "case %u arc %u", i, k);
        XEQ(POS(r), k_oid[i].en);
        rig_done(&r);
    }
}
TEST(bd_oid_first_octet_split) {
    NEED(ASN1BERDecObjectIdentifier2);
    static const struct { BYTE b; DWORD a0, a1; } c[] = {
        { 0x00, 0, 0 }, { 0x27, 0, 39 }, { 0x28, 1, 0 }, { 0x4f, 1, 39 }, { 0x50, 2, 0 }, { 0x55, 2, 5 }, { 0x7f, 2, 47 },
    };
    for (unsigned i = 0; i < sizeof c / sizeof c[0]; i++) {
        BYTE in[3] = { 6, 1, c[i].b };
        Rig r; if (!rig_dec(&r, R_DER, in, 3)) return;
        OID2 o; memset(&o, 0, sizeof o);
        CHECKF(OK8(A.ASN1BERDecObjectIdentifier2(r.d, T_OID, &o)), "%02x", c[i].b);
        CHECKF(o.count == 2 && o.value[0] == c[i].a0 && o.value[1] == c[i].a1, "%02x -> %u.%u (%u arcs)", c[i].b, o.value[0], o.value[1], o.count);
        rig_done(&r);
    }
}
TEST(bd_oid2_more_than_16_arcs_is_large) {
    NEED(ASN1BERDecObjectIdentifier2);
    DEC_OPEN(r, 0x06, 0x10, 0x2a, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17);   /* 17 arcs */
    OID2 o; memset(&o, 0, sizeof o);
    CHECK(!OK8(A.ASN1BERDecObjectIdentifier2(r.d, T_OID, &o)));
    XEQ(r.d->err, E_LARGE);
    rig_done(&r);
}
TEST(bd_oid_errors) {
    NEED(ASN1BERDecObjectIdentifier); NEED(ASN1BERDecObjectIdentifier2);
    {
        DEC_OPEN(r, 0x04, 0x01, 0x55);
        OIDN *h = NULL;
        CHECK(!OK8(A.ASN1BERDecObjectIdentifier(r.d, T_OID, &h))); XEQ(r.d->err, E_BADTAG);
        rig_done(&r);
    }
    {
        DEC_OPEN(r, 0x06, 0x03, 0x55, 0x04);
        OID2 o;
        CHECK(!OK8(A.ASN1BERDecObjectIdentifier2(r.d, T_OID, &o))); XEQ(r.d->err, E_EOD);
        rig_done(&r);
    }
}
TEST(bd_oid_context_tag) {
    NEED(ASN1BERDecObjectIdentifier2);
    DEC_OPEN(r, 0x80, 0x02, 0x55, 0x04);
    OID2 o; memset(&o, 0, sizeof o);
    CHECK(OK8(A.ASN1BERDecObjectIdentifier2(r.d, TG_CTX(0), &o)));
    XEQ(o.count, 3); XEQ(o.value[2], 4);
    rig_done(&r);
}
TEST(bd_oid_strictness_depends_on_the_decoding_rules_setting) {
    /* a trailing continuation octet / a leading 0x80 octet are policy dependent (registry DecodingRules value) */
    NEED(ASN1BERDecObjectIdentifier2);
    {
        DEC_OPEN(r, 0x06, 0x02, 0x2a, 0x86);
        OID2 o; memset(&o, 0, sizeof o);
        int ok = OK8(A.ASN1BERDecObjectIdentifier2(r.d, T_OID, &o));
        if (!ok) { CHECKF(r.d->err == E_RULE, "err %d", r.d->err); } else t_note("trailing continuation octet accepted (relaxed DecodingRules)");
        rig_done(&r);
    }
    {
        DEC_OPEN(r, 0x06, 0x03, 0x2a, 0x80, 0x01);
        OID2 o; memset(&o, 0, sizeof o);
        int ok = OK8(A.ASN1BERDecObjectIdentifier2(r.d, T_OID, &o));
        if (!ok) { CHECKF(r.d->err == E_RULE, "err %d", r.d->err); } else t_note("non-minimal sub-identifier accepted (relaxed DecodingRules)");
        rig_done(&r);
    }
}
TEST(bd_eoid_copies_content_octets) {
    NEED(ASN1BERDecEoid); NEED(ASN1BEREoid_free);
    DEC_OPEN(r, 0x06, 0x03, 0x55, 0x04, 0x03);
    EOID e = { 0x77, NULL };
    CHECK(OK8(A.ASN1BERDecEoid(r.d, T_OID, &e)));
    XEQ(e.length, 3);
    CHECK(e.value != NULL && e.value != in_ + 2);
    if (e.value) EXPECT_BYTES(e.value, 3, in_ + 2, 3);
    XEQ(POS(r), 5);
    A.ASN1BEREoid_free(&e);
    rig_done(&r);
}
TEST(bd_eoid_empty_and_errors) {
    NEED(ASN1BERDecEoid);
    {
        DEC_OPEN(r, 0x06, 0x00);
        EOID e = { 0x77, (BYTE *)1 };
        CHECK(OK8(A.ASN1BERDecEoid(r.d, T_OID, &e)));
        XEQ(e.length, 0); CHECK(e.value == NULL);
        rig_done(&r);
    }
    {
        DEC_OPEN(r, 0x04, 0x01, 0x55);
        EOID e = { 0x77, NULL };
        CHECK(!OK8(A.ASN1BERDecEoid(r.d, T_OID, &e)));
        XEQ(r.d->err, E_BADTAG); XEQ(e.length, 0);          /* length cleared up front */
        rig_done(&r);
    }
    {
        DEC_OPEN(r, 0x06, 0x03, 0x55);
        EOID e = { 0x77, NULL };
        CHECK(!OK8(A.ASN1BERDecEoid(r.d, T_OID, &e))); XEQ(r.d->err, E_EOD);
        rig_done(&r);
    }
}
TEST(bd_eoid_to_dotted_string) {
    NEED(ASN1BEREoid2DotVal);
    static const struct { BYTE v[10]; WORD n; const char *s; } c[] = {
        { { 0x55, 0x04, 0x03 }, 3, "2.5.4.3" }, { { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d }, 6, "1.2.840.113549" },
        { { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b }, 9, "1.2.840.113549.1.1.11" },
        { { 0x00 }, 1, "0.0" }, { { 0x4f }, 1, "1.39" }, { { 0x50 }, 1, "2.0" }, { { 0x7f }, 1, "2.47" },
        { { 0x88, 0x37 }, 2, "2.999" }, { { 0x81, 0x34, 0x03 }, 3, "2.100.3" }, { { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01 }, 8, "1.3.6.1.5.5.7.3.1" },
        { { 0x2a, 0x8f, 0xff, 0xff, 0xff, 0x7f }, 6, "1.2.4294967295" },
    };
    Rig r; if (!rig_dec(&r, R_DER, NULL, 0)) return;
    for (unsigned i = 0; i < sizeof c / sizeof c[0]; i++) {
        EOID e; e.length = c[i].n; e.value = (BYTE *)c[i].v;
        char *s = NULL;
        CHECKF(OK8(A.ASN1BEREoid2DotVal(r.d, &e, &s)), "case %u", i);
        CHECK(s != NULL); if (s) { CHECKF(strcmp(s, c[i].s) == 0, "got \"%s\" want \"%s\"", s, c[i].s); A.ASN1Free(s); }
    }
    rig_done(&r);
}
TEST(bd_eoid_to_dotted_string_guards) {
    NEED(ASN1BEREoid2DotVal);
    Rig r; if (!rig_dec(&r, R_DER, NULL, 0)) return;
    EOID e = { 0, NULL }; char *s = (char *)1;
    CHECK(!OK8(A.ASN1BEREoid2DotVal(r.d, &e, &s)));               /* empty encoding */
    CHECK(s == NULL);
    s = (char *)1; BYTE v[1] = { 0x55 }; e.length = 1; e.value = v;
    CHECK(!OK8(A.ASN1BEREoid2DotVal(NULL, &e, &s)));
    CHECK(s == NULL);
    rig_done(&r);
}
TEST(bd_eoid_dotted_string_roundtrip_with_dotval2eoid) {
    NEED(ASN1BEREoid2DotVal); NEED(ASN1BERDotVal2Eoid); NEED(ASN1BEREoid_free);
    static const char *c[] = { "2.5.4.3", "1.2.840.113549.1.1.5", "1.3.6.1.4.1.311.10.3.4", "2.16.840.1.101.3.4.2.1", "1.2.840.10045.4.3.2" };
    Rig re; if (!rig_enc(&re, R_DER)) return;
    Rig rd; if (!rig_dec(&rd, R_DER, NULL, 0)) { rig_done(&re); return; }
    for (unsigned i = 0; i < sizeof c / sizeof c[0]; i++) {
        EOID e; memset(&e, 0, sizeof e); char *s = NULL;
        CHECK(OK8(A.ASN1BERDotVal2Eoid(re.e, c[i], &e)));
        CHECK(OK8(A.ASN1BEREoid2DotVal(rd.d, &e, &s)));
        CHECK(s != NULL); if (s) { CHECKF(strcmp(s, c[i]) == 0, "%s -> %s", c[i], s); A.ASN1Free(s); }
        A.ASN1BEREoid_free(&e);
    }
    rig_done(&re); rig_done(&rd);
}

/* ---------------------------------------------------------------- character strings */
TEST(bd_utf8string_decodes_to_utf16) {
    NEED(ASN1BERDecUTF8String); NEED(ASN1utf8string_free);
    static const struct { BYTE b[12]; DWORD n; DWORD chars; WCHAR w[4]; } c[] = {
        { { 0x0c, 0x01, 0x41 }, 3, 1, { 0x41 } },
        { { 0x0c, 0x02, 0xc3, 0xa9 }, 4, 1, { 0xe9 } },
        { { 0x0c, 0x03, 0xe2, 0x82, 0xac }, 5, 1, { 0x20ac } },
        { { 0x0c, 0x04, 0xf0, 0x9f, 0x98, 0x80 }, 6, 2, { 0xd83d, 0xde00 } },
        { { 0x0c, 0x06, 'a', 0xc3, 0xa9, 0xe2, 0x82, 0xac }, 8, 3, { 'a', 0xe9, 0x20ac } },
    };
    for (unsigned i = 0; i < sizeof c / sizeof c[0]; i++) {
        Rig r; if (!rig_dec(&r, R_DER, c[i].b, c[i].n)) return;
        LV v = { 0, NULL };
        CHECKF(OK8(A.ASN1BERDecUTF8String(r.d, T_UTF8, &v)), "case %u", i);
        XEQ(v.length, c[i].chars);
        CHECK(v.value != NULL); if (v.value) CHECK(memcmp(v.value, c[i].w, c[i].chars * 2) == 0);
        XEQ(POS(r), c[i].n);
        A.ASN1utf8string_free(&v);
        rig_done(&r);
    }
}
TEST(bd_utf8string_empty_and_errors) {
    NEED(ASN1BERDecUTF8String);
    {
        DEC_OPEN(r, 0x0c, 0x00);
        LV v = { 9, (BYTE *)1 };
        CHECK(OK8(A.ASN1BERDecUTF8String(r.d, T_UTF8, &v)));
        XEQ(v.length, 0); CHECK(v.value == NULL);
        rig_done(&r);
    }
    {
        DEC_OPEN(r, 0x13, 0x01, 0x41);
        LV v = { 0, NULL };
        CHECK(!OK8(A.ASN1BERDecUTF8String(r.d, T_UTF8, &v))); XEQ(r.d->err, E_BADTAG);
        rig_done(&r);
    }
    {
        DEC_OPEN(r, 0x0c, 0x04, 0x41);
        LV v = { 0, NULL };
        CHECK(!OK8(A.ASN1BERDecUTF8String(r.d, T_UTF8, &v))); XEQ(r.d->err, E_EOD);
        rig_done(&r);
    }
}
TEST(bd_utf8string_embedded_nul_policy) {
    NEED(ASN1BERDecUTF8String);
    DEC_OPEN(r, 0x0c, 0x03, 'a', 0x00, 'b');
    LV v = { 0, NULL };
    if (OK8(A.ASN1BERDecUTF8String(r.d, T_UTF8, &v))) { t_note("embedded NUL accepted, %u chars", v.length); A.ASN1utf8string_free(&v); }
    else XEQ(r.d->err, E_RULE);
    rig_done(&r);
}
TEST(bd_charstring_copy) {
    NEED(ASN1BERDecCharString);
    DEC_OPEN(r, 0x13, 0x05, 'H', 'e', 'l', 'l', 'o');
    CSTR s = { 0, NULL };
    CHECK(OK8(A.ASN1BERDecCharString(r.d, T_PRINT, &s)));
    XEQ(s.length, 5);
    CHECK(s.value != NULL && (BYTE *)s.value != in_ + 2);
    if (s.value) { EXPECT_BYTES(s.value, 5, "Hello", 5); XEQ(s.value[5], 0); }     /* a terminator is stored after the counted string */
    XEQ(POS(r), 7);
    A.ASN1charstring_free(&s);
    rig_done(&r);
}
TEST(bd_multibytestring_copy) {
    NEED(ASN1BERDecMultibyteString);
    DEC_OPEN(r, 0x16, 0x03, 'a', 'b', 'c');
    CSTR s = { 0, NULL };
    CHECK(OK8(A.ASN1BERDecMultibyteString(r.d, T_IA5, &s)));
    XEQ(s.length, 3);
    if (s.value) EXPECT_BYTES(s.value, 3, "abc", 3);
    A.ASN1charstring_free(&s);
    rig_done(&r);
}
TEST(bd_zero_charstring_is_nul_terminated) {
    NEED(ASN1BERDecZeroCharString);
    DEC_OPEN(r, 0x16, 0x03, 'a', 'b', 'c');
    char *s = NULL;
    CHECK(OK8(A.ASN1BERDecZeroCharString(r.d, T_IA5, &s)));
    CHECK(s != NULL); if (s) { CHECK(strcmp(s, "abc") == 0); A.ASN1ztcharstring_free(s); }
    XEQ(POS(r), 5);
    rig_done(&r);
}
TEST(bd_zero_multibytestring_is_nul_terminated) {
    NEED(ASN1BERDecZeroMultibyteString);
    DEC_OPEN(r, 0x13, 0x02, 'U', 'S');
    char *s = NULL;
    CHECK(OK8(A.ASN1BERDecZeroMultibyteString(r.d, T_PRINT, &s)));
    CHECK(s != NULL); if (s) { CHECK(strcmp(s, "US") == 0); A.ASN1ztcharstring_free(s); }
    rig_done(&r);
}
TEST(bd_charstring_errors) {
    NEED(ASN1BERDecCharString); NEED(ASN1BERDecZeroCharString);
    {
        DEC_OPEN(r, 0x16, 0x03, 'a', 'b', 'c');
        CSTR s = { 0, NULL };
        CHECK(!OK8(A.ASN1BERDecCharString(r.d, T_PRINT, &s))); XEQ(r.d->err, E_BADTAG);
        rig_done(&r);
    }
    {
        DEC_OPEN(r, 0x16, 0x09, 'a', 'b', 'c');
        char *s = NULL;
        CHECK(!OK8(A.ASN1BERDecZeroCharString(r.d, T_IA5, &s))); XEQ(r.d->err, E_EOD);
        rig_done(&r);
    }
}
TEST(bd_char16string_big_endian_with_terminator) {
    NEED(ASN1BERDecChar16String);
    DEC_OPEN(r, 0x1e, 0x06, 0x00, 0x41, 0x4e, 0x2d, 0xfe, 0xff);
    C16STR s = { 0, NULL };
    CHECK(OK8(A.ASN1BERDecChar16String(r.d, T_BMP, &s)));
    XEQ(s.length, 3);
    CHECK(s.value != NULL);
    if (s.value) { XEQ(s.value[0], 0x41); XEQ(s.value[1], 0x4e2d); XEQ(s.value[2], 0xfeff); XEQ(s.value[3], 0); }
    XEQ(POS(r), 8);
    A.ASN1char16string_free(&s);
    rig_done(&r);
}
TEST(bd_char16string_empty) {
    NEED(ASN1BERDecChar16String);
    DEC_OPEN(r, 0x1e, 0x00);
    C16STR s = { 5, (WORD *)1 };
    CHECK(OK8(A.ASN1BERDecChar16String(r.d, T_BMP, &s)));
    XEQ(s.length, 0); CHECK(s.value == NULL);
    rig_done(&r);
}
TEST(bd_char16string_errors) {
    NEED(ASN1BERDecChar16String);
    {
        DEC_OPEN(r, 0x0c, 0x02, 0x00, 0x41);
        C16STR s = { 0, NULL };
        CHECK(!OK8(A.ASN1BERDecChar16String(r.d, T_BMP, &s))); XEQ(r.d->err, E_BADTAG);
        rig_done(&r);
    }
    {
        DEC_OPEN(r, 0x1e, 0x04, 0x00, 0x41);
        C16STR s = { 0, NULL };
        CHECK(!OK8(A.ASN1BERDecChar16String(r.d, T_BMP, &s))); XEQ(r.d->err, E_EOD);
        rig_done(&r);
    }
}
TEST(bd_char32string_big_endian) {
    NEED(ASN1BERDecChar32String);
    DEC_OPEN(r, 0x1c, 0x08, 0x00, 0x00, 0x00, 0x41, 0x00, 0x01, 0xf6, 0x00);
    C32STR s = { 0, NULL };
    CHECK(OK8(A.ASN1BERDecChar32String(r.d, 28, &s)));
    XEQ(s.length, 2);
    CHECK(s.value != NULL);
    if (s.value) { XEQ(s.value[0], 0x41); XEQ(s.value[1], 0x1f600); XEQ(s.value[2], 0); }
    A.ASN1char32string_free(&s);
    rig_done(&r);
}
TEST(bd_zero_wide_string_decoders_are_not_implemented) {
    NEED(ASN1BERDecZeroChar16String); NEED(ASN1BERDecZeroChar32String);
    DEC_OPEN(r, 0x1e, 0x02, 0x00, 0x41);
    WORD *w = NULL;
    CHECK(!OK8(A.ASN1BERDecZeroChar16String(r.d, T_BMP, &w)));
    XEQ(r.d->err, E_NYI); CHECK(w == NULL); XEQ(POS(r), 0);
    A.ASN1DecSetError(r.d, 0);
    DWORD *q = NULL;
    CHECK(!OK8(A.ASN1BERDecZeroChar32String(r.d, 28, &q)));
    XEQ(r.d->err, E_NYI);
    rig_done(&r);
}
TEST(bd_double_decoder_is_not_implemented) {
    NEED(ASN1BERDecDouble);
    DEC_OPEN(r, 0x09, 0x00);
    double v = 1.0;
    XEQ((int)A.ASN1BERDecDouble(r.d, 9, &v), E_NYI);
    XEQ(POS(r), 0);
    rig_done(&r);
}

/* ---------------------------------------------------------------- times */
static const struct { const char *s; GTIME t; } k_dgt[] = {
    { "20240229123456Z", { 2024, 2, 29, 12, 34, 56, 0, 1, 0 } },
    { "19991231235959Z", { 1999, 12, 31, 23, 59, 59, 0, 1, 0 } },
    { "20240229123456", { 2024, 2, 29, 12, 34, 56, 0, 0, 0 } },
    { "202402291234Z", { 2024, 2, 29, 12, 34, 0, 0, 1, 0 } },
    { "2024022912Z", { 2024, 2, 29, 12, 0, 0, 0, 1, 0 } },
    { "20240229", { 0 } },
};
TEST(bd_generalizedtime_table) {
    NEED(ASN1BERDecGeneralizedTime);
    for (unsigned i = 0; i < 5; i++) {
        BYTE in[40]; size_t n = strlen(k_dgt[i].s);
        in[0] = T_GEN; in[1] = (BYTE)n; memcpy(in + 2, k_dgt[i].s, n);
        Rig r; if (!rig_dec(&r, R_DER, in, (DWORD)n + 2)) return;
        GTIME t; memset(&t, 0xcc, sizeof t);
        CHECKF(OK8(A.ASN1BERDecGeneralizedTime(r.d, T_GEN, &t)), "%s", k_dgt[i].s);
        const GTIME *w = &k_dgt[i].t;
        CHECKF(t.year == w->year && t.month == w->month && t.day == w->day && t.hour == w->hour && t.minute == w->minute &&
               t.second == w->second && t.millisecond == w->millisecond && t.universal == w->universal && t.diff == w->diff,
               "%s -> %u-%u-%u %u:%u:%u.%u U%u d%d", k_dgt[i].s, t.year, t.month, t.day, t.hour, t.minute, t.second, t.millisecond, t.universal, t.diff);
        XEQ(POS(r), n + 2);
        rig_done(&r);
    }
}
TEST(bd_generalizedtime_fraction_and_offset_forms_are_observed) {
    /* floating-point scanning of fractions/offsets: logged rather than asserted */
    NEED(ASN1BERDecGeneralizedTime);
    static const char *c[] = { "20240229123456.5Z", "20240229123456.789Z", "20240229123456,25Z", "20240229123456+0530", "20240229123456-05", "20240229123456+01" };
    for (unsigned i = 0; i < sizeof c / sizeof c[0]; i++) {
        BYTE in[40]; size_t n = strlen(c[i]);
        in[0] = T_GEN; in[1] = (BYTE)n; memcpy(in + 2, c[i], n);
        Rig r; if (!rig_dec(&r, R_DER, in, (DWORD)n + 2)) return;
        GTIME t; memset(&t, 0, sizeof t);
        if (OK8(A.ASN1BERDecGeneralizedTime(r.d, T_GEN, &t)))
            t_note("%s -> sec %u ms %u universal %u diff %d", c[i], t.second, t.millisecond, t.universal, t.diff);
        else t_note("%s rejected (err %d)", c[i], r.d->err);
        rig_done(&r);
    }
}
TEST(bd_generalizedtime_rejects_malformed) {
    NEED(ASN1BERDecGeneralizedTime);
    static const char *bad[] = { "", "2024", "202402291", "20240229123456Zx", "20240229123456ZZ", "2024022912345" "6 ", "20240229123456+" };
    for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        BYTE in[40]; size_t n = strlen(bad[i]);
        in[0] = T_GEN; in[1] = (BYTE)n; memcpy(in + 2, bad[i], n);
        Rig r; if (!rig_dec(&r, R_DER, in, (DWORD)n + 2)) return;
        GTIME t; memset(&t, 0, sizeof t);
        int ok = OK8(A.ASN1BERDecGeneralizedTime(r.d, T_GEN, &t));
        if (i < 4) { CHECKF(!ok, "\"%s\" accepted", bad[i]); XEQ(r.d->err, E_CORRUPT); }
        else t_note("\"%s\" -> %s", bad[i], ok ? "accepted" : "rejected");
        rig_done(&r);
    }
}
TEST(bd_generalizedtime_wrong_tag_and_truncated) {
    NEED(ASN1BERDecGeneralizedTime);
    {
        DEC_OPEN(r, 0x17, 0x03, '1', '2', '3');
        GTIME t;
        CHECK(!OK8(A.ASN1BERDecGeneralizedTime(r.d, T_GEN, &t))); XEQ(r.d->err, E_BADTAG);
        rig_done(&r);
    }
    {
        DEC_OPEN(r, 0x18, 0x0f, '2', '0');
        GTIME t;
        CHECK(!OK8(A.ASN1BERDecGeneralizedTime(r.d, T_GEN, &t))); XEQ(r.d->err, E_EOD);
        rig_done(&r);
    }
}
static const struct { const char *s; UTIME t; } k_dut[] = {
    { "240229123456Z", { 24, 2, 29, 12, 34, 56, 1, 0 } },
    { "991231235959Z", { 99, 12, 31, 23, 59, 59, 1, 0 } },
    { "000101000000Z", { 0, 1, 1, 0, 0, 0, 1, 0 } },
    { "240229123456", { 24, 2, 29, 12, 34, 56, 0, 0 } },
    { "2402291234Z", { 24, 2, 29, 12, 34, 0, 1, 0 } },
};
TEST(bd_utctime_table) {
    NEED(ASN1BERDecUTCTime);
    for (unsigned i = 0; i < sizeof k_dut / sizeof k_dut[0]; i++) {
        BYTE in[40]; size_t n = strlen(k_dut[i].s);
        in[0] = T_UTC; in[1] = (BYTE)n; memcpy(in + 2, k_dut[i].s, n);
        Rig r; if (!rig_dec(&r, R_DER, in, (DWORD)n + 2)) return;
        UTIME t; memset(&t, 0xcc, sizeof t);
        CHECKF(OK8(A.ASN1BERDecUTCTime(r.d, T_UTC, &t)), "%s", k_dut[i].s);
        const UTIME *w = &k_dut[i].t;
        CHECKF(t.year == w->year && t.month == w->month && t.day == w->day && t.hour == w->hour && t.minute == w->minute &&
               t.second == w->second && t.universal == w->universal && t.diff == w->diff,
               "%s -> %u-%u-%u %u:%u:%u U%u d%d", k_dut[i].s, t.year, t.month, t.day, t.hour, t.minute, t.second, t.universal, t.diff);
        XEQ(POS(r), n + 2);
        rig_done(&r);
    }
}
TEST(bd_utctime_offsets_are_observed) {
    NEED(ASN1BERDecUTCTime);
    static const char *c[] = { "240229123456+0530", "240229123456-0500", "240229123456+01" };
    for (unsigned i = 0; i < sizeof c / sizeof c[0]; i++) {
        BYTE in[40]; size_t n = strlen(c[i]);
        in[0] = T_UTC; in[1] = (BYTE)n; memcpy(in + 2, c[i], n);
        Rig r; if (!rig_dec(&r, R_DER, in, (DWORD)n + 2)) return;
        UTIME t; memset(&t, 0, sizeof t);
        if (OK8(A.ASN1BERDecUTCTime(r.d, T_UTC, &t))) t_note("%s -> universal %u diff %d", c[i], t.universal, t.diff);
        else t_note("%s rejected (err %d)", c[i], r.d->err);
        rig_done(&r);
    }
}
TEST(bd_utctime_rejects_malformed_and_short) {
    NEED(ASN1BERDecUTCTime);
    static const char *bad[] = { "", "24", "2402291", "24022912Z", "240229123456Zx" };
    for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        BYTE in[40]; size_t n = strlen(bad[i]);
        in[0] = T_UTC; in[1] = (BYTE)n; memcpy(in + 2, bad[i], n);
        Rig r; if (!rig_dec(&r, R_DER, in, (DWORD)n + 2)) return;
        UTIME t; memset(&t, 0, sizeof t);
        CHECKF(!OK8(A.ASN1BERDecUTCTime(r.d, T_UTC, &t)), "\"%s\" accepted", bad[i]);
        XEQ(r.d->err, E_CORRUPT);
        rig_done(&r);
    }
}
TEST(bd_time_roundtrip_through_the_encoder) {
    NEED(ASN1BEREncUTCTime); NEED(ASN1BERDecUTCTime); NEED(ASN1BEREncGeneralizedTime); NEED(ASN1BERDecGeneralizedTime);
    Rig re; if (!rig_enc(&re, R_DER)) return;
    UTIME u = { 25, 7, 4, 1, 2, 3, 1, 0 };
    GTIME g = { 2031, 11, 30, 23, 59, 58, 0, 1, 0 };
    CHECK(OK8(A.ASN1BEREncUTCTime(re.e, T_UTC, &u))); CHECK(OK8(A.ASN1BEREncGeneralizedTime(re.e, T_GEN, &g)));
    CHECK(OK8(A.ASN1BEREncFlush(re.e)));
    Rig rd; if (!rig_dec(&rd, R_DER, re.e->buf, re.e->len)) { rig_done(&re); return; }
    UTIME u2; GTIME g2; memset(&u2, 0, sizeof u2); memset(&g2, 0, sizeof g2);
    CHECK(OK8(A.ASN1BERDecUTCTime(rd.d, T_UTC, &u2))); CHECK(OK8(A.ASN1BERDecGeneralizedTime(rd.d, T_GEN, &g2)));
    CHECK(A.ASN1utctime_cmp(&u, &u2) == 0); CHECK(A.ASN1generalizedtime_cmp(&g, &g2) == 0);
    rig_done(&rd); rig_done(&re);
}

/* ---------------------------------------------------------------- open type / explicit tag / skip */
TEST(bd_opentype_copies_the_whole_tlv) {
    NEED(ASN1BERDecOpenType);
    DEC_OPEN(r, 0x30, 0x03, 0x02, 0x01, 0x05, 0xff);
    LV v = { 0, NULL };
    CHECK(OK8(A.ASN1BERDecOpenType(r.d, &v)));
    XEQ(v.length, 5);
    CHECK(v.value != NULL && v.value != in_);
    if (v.value) EXPECT_BYTES(v.value, 5, in_, 5);
    XEQ(POS(r), 5);
    A.ASN1open_free(&v);
    rig_done(&r);
}
TEST(bd_opentype2_points_into_the_input) {
    NEED(ASN1BERDecOpenType2);
    DEC_OPEN(r, 0x30, 0x03, 0x02, 0x01, 0x05, 0xff);
    LV v = { 0, NULL };
    CHECK(OK8(A.ASN1BERDecOpenType2(r.d, &v)));
    XEQ(v.length, 5); CHECK(v.value == in_); XEQ(POS(r), 5);
    rig_done(&r);
}
TEST(bd_opentype_primitive_and_long_forms) {
    NEED(ASN1BERDecOpenType2);
    {
        DEC_OPEN(r, 0x05, 0x00, 0x05, 0x00);
        LV v = { 0, NULL };
        CHECK(OK8(A.ASN1BERDecOpenType2(r.d, &v))); XEQ(v.length, 2); XEQ(POS(r), 2);
        CHECK(OK8(A.ASN1BERDecOpenType2(r.d, &v))); XEQ(v.length, 2); CHECK(v.value == in_ + 2); XEQ(POS(r), 4);
        rig_done(&r);
    }
    {
        BYTE in[4 + 300]; in[0] = 4; in[1] = 0x82; in[2] = 0x01; in[3] = 0x2c; memset(in + 4, 0x11, 300);
        Rig r; if (!rig_dec(&r, R_DER, in, sizeof in)) return;
        LV v = { 0, NULL };
        CHECK(OK8(A.ASN1BERDecOpenType2(r.d, &v))); XEQ(v.length, 304); CHECK(v.value == in);
        rig_done(&r);
    }
}
TEST(bd_opentype_errors) {
    NEED(ASN1BERDecOpenType2); NEED(ASN1BERDecOpenType);
    {
        static const BYTE nothing[1];
        Rig r; if (!rig_dec(&r, R_DER, nothing, 0)) return;
        LV v = { 0, NULL };
        CHECK(!OK8(A.ASN1BERDecOpenType2(r.d, &v))); XEQ(r.d->err, 0);
        CHECK(!OK8(A.ASN1BERDecOpenType(r.d, &v)));
        rig_done(&r);
    }
    {
        DEC_OPEN(r, 0x30, 0x05, 0x02);
        LV v = { 0, NULL };
        CHECK(!OK8(A.ASN1BERDecOpenType2(r.d, &v))); XEQ(r.d->err, E_EOD);
        rig_done(&r);
    }
}
TEST(bd_explicittag_definite_subdecoder) {
    NEED(ASN1BERDecExplicitTag); NEED(ASN1BERDecEndOfContents); NEED(ASN1BERDecU32Val);
    DEC_OPEN(r, 0xa0, 0x03, 0x02, 0x01, 0x05, 0x05, 0x00);
    DEC *sub = NULL; const BYTE *end = NULL;
    CHECK(OK8(A.ASN1BERDecExplicitTag(r.d, TG_CTX(0), &sub, &end)));
    CHECK(sub != NULL && sub != r.d);
    if (!sub) { rig_done(&r); return; }
    CHECK(end == in_ + 5); XEQ(POS(r), 2);
    CHECK(sub->buf == in_ + 2 && sub->pos == in_ + 2); XEQ(sub->size, 3);
    CHECK(sub->parent == r.d); XEQ(sub->rule, R_DER);
    DWORD v = 0;
    CHECK(OK8(A.ASN1BERDecU32Val(sub, T_INT, &v))); XEQ(v, 5);
    CHECK(OK8(A.ASN1BERDecEndOfContents(r.d, sub, end)));
    XEQ(POS(r), 5); XEQ(r.d->err, 0);
    CHECK(OK8(A.ASN1BERDecNull(r.d, T_NULL)));
    rig_done(&r);
}
TEST(bd_explicittag_without_subdecoder_pointer) {
    NEED(ASN1BERDecExplicitTag);
    DEC_OPEN(r, 0xa1, 0x03, 0x02, 0x01, 0x05);
    const BYTE *end = NULL;
    CHECK(OK8(A.ASN1BERDecExplicitTag(r.d, TG_CTX(1), NULL, &end)));
    CHECK(end == in_ + 5); XEQ(POS(r), 2);
    rig_done(&r);
}
TEST(bd_explicittag_mismatch_cases) {
    NEED(ASN1BERDecExplicitTag);
    static const struct { BYTE b[8]; DWORD tag; int err; } c[] = {
        { { 0x30, 0x03, 0x02, 0x01, 0x05 }, TG_UNIV(T_SET), E_BADTAG },      /* wrong number */
        { { 0x10, 0x03, 0x02, 0x01, 0x05 }, TG_UNIV(T_SEQ), E_BADTAG },      /* primitive encoding of the same number */
        { { 0xa0, 0x03, 0x02, 0x01, 0x05 }, TG_CTX(1), E_BADTAG },
        { { 0x30, 0x05, 0x02, 0x01 }, TG_UNIV(T_SEQ), E_EOD },               /* contents run past the buffer */
        { { 0x30, 0x85, 0, 0, 0, 0, 1 }, TG_UNIV(T_SEQ), E_CORRUPT },        /* five length octets */
    };
    for (unsigned i = 0; i < sizeof c / sizeof c[0]; i++) {
        DWORD n = i == 3 ? 4 : i == 4 ? 7 : 5;
        Rig r; if (!rig_dec(&r, R_DER, c[i].b, n)) return;
        DEC *sub = (DEC *)(ULONG_PTR)1; const BYTE *end = NULL;
        CHECKF(!OK8(A.ASN1BERDecExplicitTag(r.d, c[i].tag, &sub, &end)), "case %u", i);
        CHECKF(r.d->err == c[i].err, "case %u: err %d want %d", i, r.d->err, c[i].err);
        CHECKF(sub == r.d, "case %u: sub output not reset to the parent", i);
        rig_done(&r);
    }
}
TEST(bd_explicittag_empty_buffer) {
    NEED(ASN1BERDecExplicitTag);
    static const BYTE nothing[1];
    Rig r; if (!rig_dec(&r, R_DER, nothing, 0)) return;
    DEC *sub = NULL; const BYTE *end = NULL;
    CHECK(!OK8(A.ASN1BERDecExplicitTag(r.d, TG_UNIV(T_SEQ), &sub, &end)));
    XEQ(r.d->err, E_EOD);
    rig_done(&r);
}
TEST(bd_explicittag_indefinite_length_with_end_of_contents) {
    NEED(ASN1BERDecExplicitTag); NEED(ASN1BERDecNotEndOfContents); NEED(ASN1BERDecEndOfContents); NEED(ASN1BERDecU32Val);
    DEC_OPEN(r, 0x30, 0x80, 0x02, 0x01, 0x05, 0x02, 0x01, 0x06, 0x00, 0x00, 0x05, 0x00);
    DEC *sub = NULL; const BYTE *end = (const BYTE *)1;
    CHECK(OK8(A.ASN1BERDecExplicitTag(r.d, TG_UNIV(T_SEQ), &sub, &end)));
    CHECK(end == NULL);                                         /* indefinite: no end pointer */
    CHECK(sub != NULL && sub != r.d); if (!sub) { rig_done(&r); return; }
    DWORD v[2] = { 0, 0 }; int n = 0;
    while (OK8(A.ASN1BERDecNotEndOfContents(sub, end)) && n < 2) CHECK(OK8(A.ASN1BERDecU32Val(sub, T_INT, &v[n++])));
    XEQ(n, 2); XEQ(v[0], 5); XEQ(v[1], 6);
    CHECK(OK8(A.ASN1BERDecEndOfContents(r.d, sub, end)));
    XEQ(POS(r), 10);                                      /* the 00 00 pair is consumed in the parent too */
    CHECK(OK8(A.ASN1BERDecNull(r.d, T_NULL)));
    rig_done(&r);
}
TEST(bd_endofcontents_length_mismatch_is_corrupt) {
    NEED(ASN1BERDecExplicitTag); NEED(ASN1BERDecEndOfContents);
    DEC_OPEN(r, 0x30, 0x03, 0x02, 0x01, 0x05);
    DEC *sub = NULL; const BYTE *end = NULL;
    CHECK(OK8(A.ASN1BERDecExplicitTag(r.d, TG_UNIV(T_SEQ), &sub, &end)));
    CHECK(!OK8(A.ASN1BERDecEndOfContents(r.d, sub, end)));      /* nothing consumed from the sub-decoder */
    XEQ(r.d->err, E_CORRUPT);
    rig_done(&r);
}
TEST(bd_endofcontents_at_top_level) {
    NEED(ASN1BERDecEndOfContents);
    {
        DEC_OPEN(r, 0x00, 0x00, 0x05, 0x00);
        CHECK(OK8(A.ASN1BERDecEndOfContents(r.d, NULL, NULL)));
        XEQ(POS(r), 2); XEQ(r.d->err, 0);
        rig_done(&r);
    }
    {
        DEC_OPEN(r, 0x00, 0x01, 0x05, 0x00);
        CHECK(!OK8(A.ASN1BERDecEndOfContents(r.d, NULL, NULL)));
        XEQ(r.d->err, E_CORRUPT); XEQ(POS(r), 0);
        rig_done(&r);
    }
    {
        DEC_OPEN(r, 0x00);
        CHECK(!OK8(A.ASN1BERDecEndOfContents(r.d, NULL, NULL)));
        XEQ(r.d->err, E_EOD);
        rig_done(&r);
    }
}
TEST(bd_notendofcontents) {
    NEED(ASN1BERDecNotEndOfContents);
    {
        DEC_OPEN(r, 0x02, 0x01, 0x05);
        CHECK(OK8(A.ASN1BERDecNotEndOfContents(r.d, NULL)));        /* not 00 00 */
        CHECK(OK8(A.ASN1BERDecNotEndOfContents(r.d, in_ + 3)));     /* position before the end pointer */
        CHECK(!OK8(A.ASN1BERDecNotEndOfContents(r.d, in_)));        /* at the end pointer */
        rig_done(&r);
    }
    {
        DEC_OPEN(r, 0x00, 0x00);
        CHECK(!OK8(A.ASN1BERDecNotEndOfContents(r.d, NULL)));
        rig_done(&r);
    }
    {
        DEC_OPEN(r, 0x02);
        CHECK(!OK8(A.ASN1BERDecNotEndOfContents(r.d, NULL)));       /* fewer than two octets left */
        rig_done(&r);
    }
}
static const struct { BYTE b[16]; DWORD n; DWORD skip; } k_skip[] = {
    { { 0x02, 0x01, 0x05, 0x99 }, 4, 3 },
    { { 0x04, 0x00, 0x99 }, 3, 2 },
    { { 0x30, 0x06, 0x02, 0x01, 0x05, 0x04, 0x01, 0xaa, 0x99 }, 9, 8 },
    { { 0x30, 0x00, 0x99 }, 3, 2 },
    { { 0xa0, 0x80, 0x02, 0x01, 0x05, 0x00, 0x00, 0x99 }, 8, 7 },
    { { 0x30, 0x80, 0xa0, 0x80, 0x02, 0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x99 }, 12, 11 },
    { { 0x30, 0x80, 0x00, 0x00, 0x99 }, 5, 4 },
    { { 0x30, 0x80, 0x30, 0x03, 0x02, 0x01, 0x05, 0x04, 0x01, 0x07, 0x00, 0x00, 0x99 }, 13, 12 },
    { { 0x81, 0x01, 0xaa, 0x99 }, 4, 3 },
};
TEST(bd_skip_table) {
    NEED(ASN1BERDecSkip);
    for (unsigned i = 0; i < sizeof k_skip / sizeof k_skip[0]; i++) {
        Rig r; if (!rig_dec(&r, R_DER, k_skip[i].b, k_skip[i].n)) return;
        CHECKF(OK8(A.ASN1BERDecSkip(r.d)), "case %u", i);
        CHECKF(POS(r) == (long)k_skip[i].skip, "case %u: pos %ld want %u", i, POS(r), k_skip[i].skip);
        XEQ(r.d->err, 0);
        rig_done(&r);
    }
}
TEST(bd_skip_consecutive_elements) {
    NEED(ASN1BERDecSkip);
    DEC_OPEN(r, 0x02, 0x01, 0x05, 0x30, 0x80, 0x05, 0x00, 0x00, 0x00, 0x04, 0x01, 0x01);
    CHECK(OK8(A.ASN1BERDecSkip(r.d))); CHECK(OK8(A.ASN1BERDecSkip(r.d))); CHECK(OK8(A.ASN1BERDecSkip(r.d)));
    XEQ(POS(r), sizeof in_);
    rig_done(&r);
}
TEST(bd_skip_errors) {
    NEED(ASN1BERDecSkip);
    {
        DEC_OPEN(r, 0x02, 0x05, 0x01);
        CHECK(!OK8(A.ASN1BERDecSkip(r.d))); XEQ(r.d->err, E_EOD);
        rig_done(&r);
    }
    {
        DEC_OPEN(r, 0x30, 0x80, 0x02, 0x01, 0x05);                  /* indefinite without end-of-contents */
        CHECK(!OK8(A.ASN1BERDecSkip(r.d)));
        CHECKF(r.d->err < 0, "err %d", r.d->err);
        rig_done(&r);
    }
}
TEST(bd_skip_on_empty_input_leaves_the_extended_warning) {
    /* quirk: Skip first records ASN1_WRN_EXTENDED and only clears it on success; PeekTag fails silently */
    NEED(ASN1BERDecSkip);
    static const BYTE nothing[1];
    Rig r; if (!rig_dec(&r, R_DER, nothing, 0)) return;
    CHECK(!OK8(A.ASN1BERDecSkip(r.d)));
    t_note("skip on empty: err=%d (decomp: warning extended)", (int)r.d->err);
    rig_done(&r);
}
TEST(bd_decoder_sequence_of_primitives_end_to_end) {
    NEED(ASN1BERDecExplicitTag); NEED(ASN1BERDecEndOfContents); NEED(ASN1BERDecBool); NEED(ASN1BERDecSXVal);
    NEED(ASN1BERDecOctetString2); NEED(ASN1BERDecObjectIdentifier2); NEED(ASN1BERDecNotEndOfContents);
    /* SEQUENCE { OID 2.5.4.3, BOOLEAN TRUE, INTEGER 00 80, OCTET STRING "hi" } */
    DEC_OPEN(r, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x03, 0x01, 0x01, 0xff, 0x02, 0x02, 0x00, 0x80, 0x04, 0x02, 'h', 'i', 0x05, 0x00);
    DEC *sub; const BYTE *end;
    CHECK(OK8(A.ASN1BERDecExplicitTag(r.d, TG_UNIV(T_SEQ), &sub, &end)));
    OID2 o; BYTE b = 0; LV x = { 0, NULL }, s = { 0, NULL };
    CHECK(OK8(A.ASN1BERDecObjectIdentifier2(sub, T_OID, &o))); XEQ(o.count, 4);
    CHECK(OK8(A.ASN1BERDecBool(sub, T_BOOL, &b))); XEQ(b, 1);
    CHECK(OK8(A.ASN1BERDecSXVal(sub, T_INT, &x))); XEQ(x.length, 2);
    CHECK(OK8(A.ASN1BERDecOctetString2(sub, T_OCT, &s))); XEQ(s.length, 2);
    CHECK(!OK8(A.ASN1BERDecNotEndOfContents(sub, end)));
    CHECK(OK8(A.ASN1BERDecEndOfContents(r.d, sub, end)));
    XEQ(POS(r), 18);
    A.ASN1intx_free(&x);
    rig_done(&r);
}
