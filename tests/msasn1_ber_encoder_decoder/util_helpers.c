/* msasn1.dll: comparison / release helpers, ASN1intx_* arbitrary precision helpers, time comparison. */
#include "asn1t.h"

#define LVC(name, ...) static BYTE name##_b[] = { __VA_ARGS__ }; LV name = { sizeof name##_b, name##_b }
static int sgn(int v) { return v < 0 ? -1 : v > 0; }

/* ---------------------------------------------------------------- ASN1uint32_uoctets / intx */
TEST(uh_uint32_uoctets_table) {
    REQUIRE(A.ASN1uint32_uoctets);
    static const struct { DWORD v, n; } c[] = {
        { 0, 1 }, { 1, 1 }, { 0x7f, 1 }, { 0xff, 1 }, { 0x100, 2 }, { 0xffff, 2 }, { 0x10000, 3 }, { 0xffffff, 3 },
        { 0x1000000, 4 }, { 0x7fffffff, 4 }, { 0xffffffff, 4 },
    };
    for (unsigned i = 0; i < sizeof c / sizeof c[0]; i++) CHECKF(A.ASN1uint32_uoctets(c[i].v) == c[i].n, "%x -> %u want %u", c[i].v, A.ASN1uint32_uoctets(c[i].v), c[i].n);
}
TEST(uh_intx_uoctets_counts_significant_octets) {
    REQUIRE(A.ASN1intx_uoctets);
    static const struct { BYTE b[6]; DWORD n; DWORD want; } c[] = {
        { { 0x05 }, 1, 1 }, { { 0x00, 0x00, 0x05 }, 3, 1 }, { { 0x00 }, 1, 0 }, { { 0x00, 0x00 }, 2, 0 }, { { 0x01, 0x02 }, 2, 2 },
        { { 0x00, 0x80 }, 2, 1 }, { { 0x80, 0x00 }, 2, 2 }, { { 0xff }, 1, 1 }, { { 0x00, 0x01, 0x00, 0x00, 0x00 }, 5, 4 },
        { { 0x7f, 0xff, 0xff, 0xff, 0xff }, 5, 5 },
    };
    for (unsigned i = 0; i < sizeof c / sizeof c[0]; i++) { LV v = { c[i].n, (BYTE *)c[i].b }; CHECKF(A.ASN1intx_uoctets(&v) == c[i].want, "case %u", i); }
    LV empty = { 0, NULL };
    CHECK(A.ASN1intx_uoctets(&empty) == 0);
}
TEST(uh_intx_isuint32) {
    REQUIRE(A.ASN1intxisuint32);
    static const struct { BYTE b[6]; DWORD n; int want; } c[] = {
        { { 0x05 }, 1, 1 }, { { 0x00, 0x00, 0x00, 0x05 }, 4, 1 }, { { 0x00, 0xff, 0xff, 0xff, 0xff }, 5, 1 }, { { 0x7f, 0xff, 0xff, 0xff }, 4, 1 },
        { { 0x01, 0x00, 0x00, 0x00, 0x00 }, 5, 0 }, { { 0x7f, 0xff, 0xff, 0xff, 0xff }, 5, 0 }, { { 0x80, 0x00 }, 2, 0 }, { { 0xff }, 1, 0 },
        { { 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 }, 6, 1 }, { { 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 }, 6, 0 },
    };
    for (unsigned i = 0; i < sizeof c / sizeof c[0]; i++) { LV v = { c[i].n, (BYTE *)c[i].b }; int r = A.ASN1intxisuint32(&v) & 0xff; CHECKF((r != 0) == c[i].want, "case %u", i); }
}
TEST(uh_intx_to_uint32) {
    REQUIRE(A.ASN1intx2uint32);
    static const struct { BYTE b[8]; DWORD n; DWORD want; } c[] = {
        { { 0 }, 0, 0 }, { { 0x05 }, 1, 5 }, { { 0xff }, 1, 0xff }, { { 0x01, 0x02 }, 2, 0x0102 }, { { 0xff, 0xfe }, 2, 0xfffe },
        { { 0x01, 0x02, 0x03 }, 3, 0x010203 }, { { 0x12, 0x34, 0x56, 0x78 }, 4, 0x12345678 }, { { 0xaa, 0xbb, 0xcc, 0xdd, 0xee }, 5, 0xbbccddee },
        { { 0x00, 0xff, 0xff, 0xff, 0xff }, 5, 0xffffffff }, { { 1, 2, 3, 4, 5, 6, 7, 8 }, 8, 0x05060708 },
    };
    for (unsigned i = 0; i < sizeof c / sizeof c[0]; i++) {
        LV v = { c[i].n, (BYTE *)c[i].b };
        CHECKF(A.ASN1intx2uint32(&v) == c[i].want, "case %u: got %08x want %08x", i, A.ASN1intx2uint32(&v), c[i].want);
    }
}
TEST(uh_intx_to_int32_sign_extends) {
    REQUIRE(A.ASN1intx2int32);
    static const struct { BYTE b[8]; DWORD n; int want; } c[] = {
        { { 0 }, 0, 0 }, { { 0x05 }, 1, 5 }, { { 0x7f }, 1, 127 }, { { 0x80 }, 1, -128 }, { { 0xff }, 1, -1 },
        { { 0x00, 0x80 }, 2, 128 }, { { 0xff, 0x7f }, 2, -129 }, { { 0x80, 0x00 }, 2, -32768 }, { { 0x7f, 0xff }, 2, 32767 },
        { { 0x00, 0x80, 0x00 }, 3, 32768 }, { { 0xff, 0x7f, 0xff }, 3, -32769 }, { { 0x80, 0x00, 0x00 }, 3, -8388608 }, { { 0x7f, 0xff, 0xff }, 3, 8388607 },
        { { 0x12, 0x34, 0x56, 0x78 }, 4, 0x12345678 }, { { 0x80, 0x00, 0x00, 0x00 }, 4, (int)0x80000000 }, { { 0xff, 0xff, 0xff, 0xff }, 4, -1 },
        { { 0x00, 0xff, 0xff, 0xff, 0xff }, 5, -1 }, { { 0x00, 0x12, 0x34, 0x56, 0x78 }, 5, 0x12345678 },
    };
    for (unsigned i = 0; i < sizeof c / sizeof c[0]; i++) {
        LV v = { c[i].n, (BYTE *)c[i].b };
        int g = A.ASN1intx2int32(&v);
        CHECKF(g == c[i].want, "case %u: got %d want %d", i, g, c[i].want);
    }
}
TEST(uh_intx_setuint32_minimal_positive_form) {
    REQUIRE(A.ASN1intx_setuint32); NEED(ASN1intx_free);
    static const struct { DWORD v; BYTE b[5]; DWORD n; } c[] = {
        { 0, { 0x00 }, 1 }, { 1, { 0x01 }, 1 }, { 0x7f, { 0x7f }, 1 }, { 0x80, { 0x00, 0x80 }, 2 }, { 0xff, { 0x00, 0xff }, 2 },
        { 0x100, { 0x01, 0x00 }, 2 }, { 0x7fff, { 0x7f, 0xff }, 2 }, { 0x8000, { 0x00, 0x80, 0x00 }, 3 }, { 0xffff, { 0x00, 0xff, 0xff }, 3 },
        { 0x10000, { 0x01, 0x00, 0x00 }, 3 }, { 0x7fffff, { 0x7f, 0xff, 0xff }, 3 }, { 0x800000, { 0x00, 0x80, 0x00, 0x00 }, 4 },
        { 0x7fffffff, { 0x7f, 0xff, 0xff, 0xff }, 4 }, { 0x80000000, { 0x00, 0x80, 0x00, 0x00, 0x00 }, 5 },
        { 0xffffffff, { 0x00, 0xff, 0xff, 0xff, 0xff }, 5 },
    };
    for (unsigned i = 0; i < sizeof c / sizeof c[0]; i++) {
        LV v = { 99, NULL };
        A.ASN1intx_setuint32(&v, c[i].v);
        CHECKF(v.length == c[i].n, "%x: length %u want %u", c[i].v, v.length, c[i].n);
        CHECK(v.value != NULL);
        if (v.value && v.length == c[i].n) EXPECT_BYTES(v.value, c[i].n, c[i].b, c[i].n);
        A.ASN1intx_free(&v);
    }
}
TEST(uh_intx_setuint32_roundtrips_through_conversions) {
    REQUIRE(A.ASN1intx_setuint32); NEED(ASN1intx2uint32); NEED(ASN1intxisuint32); NEED(ASN1intx_free);
    static const DWORD vs[] = { 0, 1, 127, 128, 255, 256, 65535, 65536, 0x7fffffff, 0x80000000, 0xdeadbeef, 0xffffffff };
    for (unsigned i = 0; i < sizeof vs / sizeof vs[0]; i++) {
        LV v = { 0, NULL };
        A.ASN1intx_setuint32(&v, vs[i]);
        CHECKF(A.ASN1intx2uint32(&v) == vs[i], "%x", vs[i]);
        CHECKF((A.ASN1intxisuint32(&v) & 0xff) != 0, "%x", vs[i]);
        A.ASN1intx_free(&v);
    }
}
TEST(uh_intx_cmp_signed_compare) {
    REQUIRE(A.ASN1intx_cmp);
    static const struct { BYTE a[4]; DWORD an; BYTE b[4]; DWORD bn; int sign; } c[] = {
        { { 0x01 }, 1, { 0x02 }, 1, -1 }, { { 0x02 }, 1, { 0x01 }, 1, 1 }, { { 0x05 }, 1, { 0x05 }, 1, 0 },
        { { 0x7f }, 1, { 0x00, 0x7f }, 2, 0 }, { { 0xff }, 1, { 0xff, 0xff }, 2, 0 }, { { 0x00, 0x80 }, 2, { 0x80 }, 1, 1 },
        { { 0x80 }, 1, { 0x7f }, 1, -1 }, { { 0xff }, 1, { 0x01 }, 1, -1 }, { { 0x01, 0x00 }, 2, { 0xff }, 1, 1 },
        { { 0x01, 0x02 }, 2, { 0x01, 0x03 }, 2, -1 }, { { 0x02, 0x00 }, 2, { 0x01, 0xff }, 2, 1 }, { { 0x01, 0x00, 0x00 }, 3, { 0x7f }, 1, 1 },
        { { 0xff, 0x00 }, 2, { 0x80 }, 1, -1 }, { { 0x80 }, 1, { 0xff, 0x00 }, 2, 1 }, { { 0x00 }, 1, { 0x00, 0x00 }, 2, 0 },
        { { 0xfe }, 1, { 0xff }, 1, -1 },
    };
    for (unsigned i = 0; i < sizeof c / sizeof c[0]; i++) {
        LV a = { c[i].an, (BYTE *)c[i].a }, b = { c[i].bn, (BYTE *)c[i].b };
        int r = A.ASN1intx_cmp(&a, &b);
        CHECKF(sgn(r) == c[i].sign, "case %u: got %d want sign %d", i, r, c[i].sign);
    }
}
TEST(uh_intx_cmp_exact_values) {
    /* same-sign operands return the difference of the first octets that differ (after sign padding) */
    REQUIRE(A.ASN1intx_cmp);
    LVC(a, 0x05); LVC(b, 0x02); LVC(c, 0xff, 0x00); LVC(d, 0x80); LVC(e, 0x01, 0x02); LVC(f, 0x01, 0x04);
    XEQ(A.ASN1intx_cmp(&a, &b), 3); XEQ(A.ASN1intx_cmp(&b, &a), -3);
    XEQ(A.ASN1intx_cmp(&c, &d), -128);                 /* -256 vs -128 */
    XEQ(A.ASN1intx_cmp(&e, &f), -2);
    XEQ(A.ASN1intx_cmp(&d, &a), -1);                   /* negative vs positive: -1 */
    XEQ(A.ASN1intx_cmp(&a, &d), 1);
}

/* ---------------------------------------------------------------- string / blob comparisons */
TEST(uh_octetstring_cmp) {
    REQUIRE(A.ASN1octetstring_cmp); NEED(ASN1open_cmp);
    LVC(a, 1, 2, 3); LVC(b, 1, 2, 3); LVC(c, 1, 2, 4); LVC(d, 1, 2); LVC(e, 1, 2, 3, 4); LVC(f, 0xff, 0); LVC(g, 0x01, 0xff);
    XEQ(A.ASN1octetstring_cmp(&a, &b), 0);
    CHECK(A.ASN1octetstring_cmp(&a, &c) < 0); CHECK(A.ASN1octetstring_cmp(&c, &a) > 0);
    XEQ(A.ASN1octetstring_cmp(&d, &a), -1);            /* prefix: length difference */
    XEQ(A.ASN1octetstring_cmp(&e, &d), 2);
    XEQ(A.ASN1octetstring_cmp(&a, &e), -1);
    CHECK(A.ASN1octetstring_cmp(&f, &g) > 0);          /* octets compare unsigned */
    LV z1 = { 0, NULL }, z2 = { 0, NULL };
    XEQ(A.ASN1octetstring_cmp(&z1, &z2), 0);
    XEQ(A.ASN1octetstring_cmp(&z1, &a), -3);
    XEQ(A.ASN1open_cmp(&a, &b), 0);
    CHECK(A.ASN1open_cmp(&a, &c) < 0);
    XEQ(A.ASN1open_cmp(&e, &a), 1);
}
TEST(uh_bitstring_cmp_without_trimming) {
    REQUIRE(A.ASN1bitstring_cmp);
    BYTE x1[] = { 0xf8 }, x2[] = { 0xf0 }, x3[] = { 0xff }, y1[] = { 0xab, 0xcd }, y2[] = { 0xab, 0xce }, z1[] = { 0xa0 }, z2[] = { 0xa0 };
    LV a = { 5, x1 }, b = { 5, x1 }, c = { 5, x2 }, d = { 5, x3 };
    XEQ(A.ASN1bitstring_cmp(&a, &b, 0), 0);
    XEQ(A.ASN1bitstring_cmp(&a, &c, 0), 8);            /* masked partial octets: 0xf8 - 0xf0 */
    XEQ(A.ASN1bitstring_cmp(&c, &a, 0), -8);
    XEQ(A.ASN1bitstring_cmp(&a, &d, 0), 0);            /* bits beyond the length are ignored */
    LV e = { 16, y1 }, f = { 16, y2 };
    XEQ(A.ASN1bitstring_cmp(&e, &e, 0), 0);
    CHECK(A.ASN1bitstring_cmp(&e, &f, 0) < 0); CHECK(A.ASN1bitstring_cmp(&f, &e, 0) > 0);
    LV g = { 8, z1 }, h = { 3, z2 };
    XEQ(A.ASN1bitstring_cmp(&g, &h, 0), 5);            /* equal common prefix: length difference */
    XEQ(A.ASN1bitstring_cmp(&h, &g, 0), -5);
    LV z = { 0, NULL }, zz = { 0, NULL };
    XEQ(A.ASN1bitstring_cmp(&z, &zz, 0), 0);
    XEQ(A.ASN1bitstring_cmp(&z, &g, 0), -8);
}
TEST(uh_bitstring_cmp_trailing_zero_trimming) {
    REQUIRE(A.ASN1bitstring_cmp);
    BYTE x[] = { 0xa0 }, y[] = { 0xa0 }, w[] = { 0xa1, 0x00 };
    LV a = { 8, x }, b = { 3, y };
    XEQ(A.ASN1bitstring_cmp(&a, &b, 0), 5);
    XEQ(A.ASN1bitstring_cmp(&a, &b, 1), 0);            /* the extra zero bits of the longer operand are dropped */
    XEQ(A.ASN1bitstring_cmp(&b, &a, 1), 0);
    (void)w;
}
TEST(uh_charstring_cmp) {
    REQUIRE(A.ASN1charstring_cmp);
    CSTR a = { 3, "abc" }, b = { 3, "abc" }, c = { 3, "abd" }, d = { 3, "abx" }, e = { 2, "ab" }, f = { 4, "abcd" };
    XEQ(A.ASN1charstring_cmp(&a, &b), 0);
    XEQ(A.ASN1charstring_cmp(&a, &c), -1); XEQ(A.ASN1charstring_cmp(&c, &a), 1); XEQ(A.ASN1charstring_cmp(&a, &d), -21);
    XEQ(A.ASN1charstring_cmp(&e, &a), -1); XEQ(A.ASN1charstring_cmp(&f, &e), 2); XEQ(A.ASN1charstring_cmp(&a, &f), -1);
    CSTR g = { 1, "\x80" }, h = { 1, "\x01" };
    XEQ(A.ASN1charstring_cmp(&g, &h), -129);          /* char is signed */
    CSTR z = { 0, NULL };
    XEQ(A.ASN1charstring_cmp(&z, &z), 0); XEQ(A.ASN1charstring_cmp(&z, &a), -3);
}
TEST(uh_char16string_cmp) {
    REQUIRE(A.ASN1char16string_cmp);
    WORD a1[] = { 1, 2, 3 }, a2[] = { 1, 2, 4 }, a3[] = { 1, 2 }, a4[] = { 0xffff }, a5[] = { 1 };
    C16STR a = { 3, a1 }, b = { 3, a2 }, c = { 2, a3 }, d = { 1, a4 }, e = { 1, a5 };
    XEQ(A.ASN1char16string_cmp(&a, &a), 0);
    XEQ(A.ASN1char16string_cmp(&a, &b), -1); XEQ(A.ASN1char16string_cmp(&b, &a), 1);
    XEQ(A.ASN1char16string_cmp(&c, &a), -1); XEQ(A.ASN1char16string_cmp(&a, &c), 1);
    XEQ(A.ASN1char16string_cmp(&d, &e), 0xfffe);      /* unsigned 16-bit units */
}
TEST(uh_char32string_cmp) {
    REQUIRE(A.ASN1char32string_cmp);
    DWORD a1[] = { 1, 2, 3 }, a2[] = { 1, 2, 0x10000 }, a3[] = { 1 }, a4[] = { 0x1f600 }, a5[] = { 0x41 };
    C32STR a = { 3, a1 }, b = { 3, a2 }, c = { 1, a3 }, d = { 1, a4 }, e = { 1, a5 };
    XEQ(A.ASN1char32string_cmp(&a, &a), 0);
    XEQ(A.ASN1char32string_cmp(&a, &b), 3 - 0x10000); XEQ(A.ASN1char32string_cmp(&b, &a), 0x10000 - 3);
    XEQ(A.ASN1char32string_cmp(&c, &a), -2);
    XEQ(A.ASN1char32string_cmp(&d, &e), 0x1f600 - 0x41);
}
TEST(uh_zero_terminated_char_cmp_handles_null) {
    REQUIRE(A.ASN1ztcharstring_cmp);
    XEQ(A.ASN1ztcharstring_cmp("abc", "abc"), 0);
    CHECK(A.ASN1ztcharstring_cmp("abc", "abd") < 0); CHECK(A.ASN1ztcharstring_cmp("abd", "abc") > 0);
    CHECK(A.ASN1ztcharstring_cmp("ab", "abc") < 0);
    XEQ(A.ASN1ztcharstring_cmp(NULL, "abc"), -1); XEQ(A.ASN1ztcharstring_cmp("abc", NULL), 1);
    XEQ(A.ASN1ztcharstring_cmp(NULL, NULL), -1);
}
TEST(uh_zero_terminated_char16_cmp_handles_null) {
    REQUIRE(A.ASN1ztchar16string_cmp);
    XEQ(A.ASN1ztchar16string_cmp(L"abc", L"abc"), 0);
    CHECK(A.ASN1ztchar16string_cmp(L"abc", L"abd") < 0); CHECK(A.ASN1ztchar16string_cmp(L"abd", L"abc") > 0);
    XEQ(A.ASN1ztchar16string_cmp(NULL, L"abc"), -1); XEQ(A.ASN1ztchar16string_cmp(L"abc", NULL), 1);
    XEQ(A.ASN1ztchar16string_cmp(NULL, NULL), -1);
}
TEST(uh_zero_terminated_char32_cmp) {
    REQUIRE(A.ASN1ztchar32string_cmp);
    static const DWORD a[] = { 1, 2, 3, 0 }, b[] = { 1, 2, 3, 0 }, c[] = { 1, 2, 5, 0 }, d[] = { 1, 2, 0 }, e[] = { 0 };
    XEQ(A.ASN1ztchar32string_cmp(a, b), 0);
    XEQ(A.ASN1ztchar32string_cmp(a, c), -2); XEQ(A.ASN1ztchar32string_cmp(c, a), 2);
    XEQ(A.ASN1ztchar32string_cmp(a, d), 3); XEQ(A.ASN1ztchar32string_cmp(d, a), -3);
    XEQ(A.ASN1ztchar32string_cmp(e, e), 0);
    XEQ(A.ASN1ztchar32string_cmp(NULL, a), -1); XEQ(A.ASN1ztchar32string_cmp(a, NULL), 1); XEQ(A.ASN1ztchar32string_cmp(NULL, NULL), -1);
}
static OIDN *mkoid(const DWORD *a, int n, OIDN *store) { for (int i = 0; i < n; i++) { store[i].value = a[i]; store[i].next = i + 1 < n ? &store[i + 1] : NULL; } return store; }
TEST(uh_objectidentifier_cmp) {
    REQUIRE(A.ASN1objectidentifier_cmp);
    static const DWORD a1[] = { 1, 2, 3 }, a2[] = { 1, 2, 4 }, a3[] = { 1, 2 }, a4[] = { 1, 2, 3, 4 }, a5[] = { 2, 5 }, a6[] = { 1, 9 }, a7[] = { 0, 0xffffffff }, a8[] = { 0, 1 };
    OIDN n1[4], n2[4], n3[4], n4[4], n5[4], n6[4], n7[4], n8[4];
    OIDN *p1 = mkoid(a1, 3, n1), *p2 = mkoid(a2, 3, n2), *p3 = mkoid(a3, 2, n3), *p4 = mkoid(a4, 4, n4), *p5 = mkoid(a5, 2, n5), *p6 = mkoid(a6, 2, n6), *p7 = mkoid(a7, 2, n7), *p8 = mkoid(a8, 2, n8);
    XEQ(A.ASN1objectidentifier_cmp(&p1, &p1), 0);
    XEQ(A.ASN1objectidentifier_cmp(&p1, &p2), -1); XEQ(A.ASN1objectidentifier_cmp(&p2, &p1), 1);
    XEQ(A.ASN1objectidentifier_cmp(&p3, &p1), -1);          /* prefix: arc-count difference */
    XEQ(A.ASN1objectidentifier_cmp(&p4, &p3), 2);
    XEQ(A.ASN1objectidentifier_cmp(&p5, &p6), 1);
    XEQ(A.ASN1objectidentifier_cmp(&p7, &p8), -2);          /* signed 32-bit difference: 0xffffffff - 1 */
}
TEST(uh_objectidentifier2_cmp) {
    REQUIRE(A.ASN1objectidentifier2_cmp);
    OID2 a = { 3, { 1, 2, 3 } }, b = { 3, { 1, 2, 4 } }, c = { 2, { 1, 2 } }, d = { 4, { 1, 2, 3, 4 } }, e = { 2, { 2, 5 } }, f = { 2, { 1, 9 } };
    XEQ(A.ASN1objectidentifier2_cmp(&a, &a), 0);
    XEQ(A.ASN1objectidentifier2_cmp(&a, &b), -1); XEQ(A.ASN1objectidentifier2_cmp(&b, &a), 1);
    XEQ(A.ASN1objectidentifier2_cmp(&c, &a), -1); XEQ(A.ASN1objectidentifier2_cmp(&d, &c), 2);
    XEQ(A.ASN1objectidentifier2_cmp(&e, &f), 1);
    OID2 z1 = { 0 }, z2 = { 0 };
    XEQ(A.ASN1objectidentifier2_cmp(&z1, &z2), 0); XEQ(A.ASN1objectidentifier2_cmp(&z1, &a), -3);
}

/* ---------------------------------------------------------------- time comparison */
TEST(uh_utctime_cmp) {
    REQUIRE(A.ASN1utctime_cmp);
    UTIME a = { 24, 2, 29, 12, 34, 56, 1, 0 }, b = a;
    XEQ(A.ASN1utctime_cmp(&a, &b), 0);
    b.second = 50; XEQ(A.ASN1utctime_cmp(&a, &b), 6); XEQ(A.ASN1utctime_cmp(&b, &a), -6);
    b = a; b.minute = 30; XEQ(A.ASN1utctime_cmp(&a, &b), 4);
    b = a; b.hour = 13; XEQ(A.ASN1utctime_cmp(&a, &b), -1);
    b = a; b.day = 1; XEQ(A.ASN1utctime_cmp(&a, &b), 28);
    b = a; b.month = 3; XEQ(A.ASN1utctime_cmp(&a, &b), -1);
    b = a; b.year = 25; XEQ(A.ASN1utctime_cmp(&a, &b), -1);
    b = a; b.year = 25; b.second = 0; XEQ(A.ASN1utctime_cmp(&a, &b), -1);   /* most significant difference wins */
    b = a; b.universal = 0; XEQ(A.ASN1utctime_cmp(&a, &b), 1);              /* different zone kind: unordered, reported as 1 */
    XEQ(A.ASN1utctime_cmp(&b, &a), 1);
    b = a; b.diff = 60; XEQ(A.ASN1utctime_cmp(&a, &b), 1);
    UTIME c = { 24, 2, 29, 12, 34, 56, 0, 60 }, d = c;
    XEQ(A.ASN1utctime_cmp(&c, &d), 0);
}
TEST(uh_generalizedtime_cmp) {
    REQUIRE(A.ASN1generalizedtime_cmp);
    GTIME a = { 2024, 2, 29, 12, 34, 56, 789, 1, 0 }, b = a;
    XEQ(A.ASN1generalizedtime_cmp(&a, &b), 0);
    b.millisecond = 700; XEQ(A.ASN1generalizedtime_cmp(&a, &b), 89); XEQ(A.ASN1generalizedtime_cmp(&b, &a), -89);
    b = a; b.second = 0; XEQ(A.ASN1generalizedtime_cmp(&a, &b), 56);
    b = a; b.minute = 35; XEQ(A.ASN1generalizedtime_cmp(&a, &b), -1);
    b = a; b.hour = 0; XEQ(A.ASN1generalizedtime_cmp(&a, &b), 12);
    b = a; b.day = 30; XEQ(A.ASN1generalizedtime_cmp(&a, &b), -1);
    b = a; b.month = 1; XEQ(A.ASN1generalizedtime_cmp(&a, &b), 1);
    b = a; b.year = 1999; XEQ(A.ASN1generalizedtime_cmp(&a, &b), 25);
    b = a; b.year = 2025; b.millisecond = 0; XEQ(A.ASN1generalizedtime_cmp(&a, &b), -1);
    b = a; b.universal = 0; XEQ(A.ASN1generalizedtime_cmp(&a, &b), 1);
    b = a; b.diff = -300; XEQ(A.ASN1generalizedtime_cmp(&a, &b), 1);
}

/* ---------------------------------------------------------------- release helpers */
TEST(uh_free_helpers_release_the_value_buffer) {
    REQUIRE(A.ASN1octetstring_free); NEED(ASN1bitstring_free); NEED(ASN1open_free); NEED(ASN1utf8string_free); NEED(ASN1intx_free);
    NEED(ASN1charstring_free); NEED(ASN1char16string_free); NEED(ASN1char32string_free); NEED(ASN1BEREoid_free);
    LV lv; CSTR cs; C16STR c16; C32STR c32; EOID eo;
    lv.length = 4; lv.value = LocalAlloc(LPTR, 8); A.ASN1octetstring_free(&lv);
    lv.value = LocalAlloc(LPTR, 8); A.ASN1bitstring_free(&lv);
    lv.value = LocalAlloc(LPTR, 8); A.ASN1open_free(&lv);
    lv.value = LocalAlloc(LPTR, 8); A.ASN1utf8string_free(&lv);
    lv.value = LocalAlloc(LPTR, 8); A.ASN1intx_free(&lv);
    cs.length = 1; cs.value = LocalAlloc(LPTR, 8); A.ASN1charstring_free(&cs);
    c16.length = 1; c16.value = LocalAlloc(LPTR, 8); A.ASN1char16string_free(&c16);
    c32.length = 1; c32.value = LocalAlloc(LPTR, 8); A.ASN1char32string_free(&c32);
    eo.length = 1; eo.value = LocalAlloc(LPTR, 8); A.ASN1BEREoid_free(&eo);
    CHECK(1);
}
TEST(uh_free_helpers_tolerate_null) {
    REQUIRE(A.ASN1octetstring_free);
    A.ASN1octetstring_free(NULL); A.ASN1bitstring_free(NULL); A.ASN1open_free(NULL); A.ASN1utf8string_free(NULL); A.ASN1intx_free(NULL);
    A.ASN1charstring_free(NULL); A.ASN1char16string_free(NULL); A.ASN1char32string_free(NULL); A.ASN1BEREoid_free(NULL);
    A.ASN1objectidentifier_free(NULL);
    LV lv = { 0, NULL }; A.ASN1octetstring_free(&lv);               /* NULL value pointer */
    A.ASN1ztcharstring_free(NULL); A.ASN1ztchar16string_free(NULL); A.ASN1ztchar32string_free(NULL);
    CHECK(1);
}
TEST(uh_objectidentifier_free_releases_the_list_block) {
    REQUIRE(A.ASN1objectidentifier_free);
    OIDN *blk = LocalAlloc(LPTR, 3 * sizeof(OIDN));
    CHECK(blk != NULL); if (!blk) return;
    blk[0].next = &blk[1]; blk[1].next = &blk[2];
    A.ASN1objectidentifier_free(&blk);                             /* one LocalFree of the head block */
    CHECK(1);
}
TEST(uh_zero_terminated_free_helpers_release_the_string) {
    REQUIRE(A.ASN1ztcharstring_free); NEED(ASN1ztchar16string_free); NEED(ASN1ztchar32string_free);
    /* these three exports are the same routine as LocalFree: they take the string pointer itself */
    A.ASN1ztcharstring_free(LocalAlloc(LPTR, 16));
    A.ASN1ztchar16string_free(LocalAlloc(LPTR, 16));
    A.ASN1ztchar32string_free(LocalAlloc(LPTR, 16));
    CHECK(1);
}
TEST(uh_close_module_is_the_same_routine_as_free) {
    /* ASN1_CloseModule, ASN1Free and the ztchar*_free exports resolve to one address */
    REQUIRE(A.ASN1Free); NEED(ASN1_CloseModule); NEED(ASN1ztcharstring_free); NEED(ASN1ztchar16string_free); NEED(ASN1ztchar32string_free);
    CHECK((void *)A.ASN1Free == (void *)A.ASN1_CloseModule);
    CHECK((void *)A.ASN1Free == (void *)A.ASN1ztcharstring_free);
    CHECK((void *)A.ASN1Free == (void *)A.ASN1ztchar16string_free);
    CHECK((void *)A.ASN1Free == (void *)A.ASN1ztchar32string_free);
}
TEST(uh_free_family_shares_one_body) {
    REQUIRE(A.ASN1octetstring_free); NEED(ASN1bitstring_free); NEED(ASN1open_free); NEED(ASN1utf8string_free); NEED(ASN1intx_free);
    NEED(ASN1charstring_free); NEED(ASN1char16string_free); NEED(ASN1char32string_free); NEED(ASN1BEREoid_free);
    void *f = (void *)A.ASN1octetstring_free;
    CHECK((void *)A.ASN1bitstring_free == f); CHECK((void *)A.ASN1open_free == f); CHECK((void *)A.ASN1utf8string_free == f);
    CHECK((void *)A.ASN1intx_free == f); CHECK((void *)A.ASN1charstring_free == f); CHECK((void *)A.ASN1char16string_free == f);
    CHECK((void *)A.ASN1char32string_free == f); CHECK((void *)A.ASN1BEREoid_free == f);
}
TEST(uh_encoder_and_string_aliases) {
    /* exports that are the same code on Windows 10 (decompilation: several ordinals at one address) */
    NEED(ASN1BEREncOctetString); NEED(ASN1BEREncCharString); NEED(ASN1BEREncMultibyteString); NEED(ASN1DEREncMultibyteString);
    NEED(ASN1BEREncGeneralizedTime); NEED(ASN1CEREncGeneralizedTime);     NEED(ASN1BEREncDouble); NEED(ASN1BERDecDouble); NEED(ASN1CEREncOctetString);
    CHECK((void *)A.ASN1BEREncOctetString == (void *)A.ASN1BEREncCharString);
    CHECK((void *)A.ASN1BEREncMultibyteString == (void *)A.ASN1DEREncMultibyteString);
    CHECK((void *)A.ASN1BEREncGeneralizedTime == (void *)A.ASN1CEREncGeneralizedTime);
    CHECK((void *)A.ASN1BEREncDouble == (void *)A.ASN1BERDecDouble);
    CHECK((void *)A.ASN1BEREncDouble == (void *)A.ASN1CEREncOctetString);
}
