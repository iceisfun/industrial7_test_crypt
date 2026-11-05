/* cryptdlg.dll / cryptui.dll helpers that do not raise UI: name formatting, encode/decode helpers,
 * trust-provider hooks, certificate comparison and store serialisation.
 * Chain building (AddChainToStore) and the wizards are intentionally not invoked: they can reach
 * auto-update or load wizard extensions. */
#include "t.h"
#include <wincrypt.h>
#include <wintrust.h>
#include <wchar.h>
#include <stdlib.h>
#include "mm_certs.h"

/* ---- declarations missing from the SDK headers ---- */
UDECL(DWORD, GetFriendlyNameOfCertW, (PCCERT_CONTEXT, LPWSTR, DWORD));
UDECL(DWORD, GetFriendlyNameOfCertA, (PCCERT_CONTEXT, LPSTR, DWORD));
UDECL(int, FormatPKIXEmailProtection, (DWORD, DWORD, DWORD, void *, const char *, const BYTE *, DWORD, void *, DWORD *));
UDECL(int, FormatVerisignExtension, (DWORD, DWORD, DWORD, void *, const char *, const BYTE *, DWORD, void *, DWORD *));
UDECL(int, EncodeRecipientID, (DWORD, const char *, const void *, BYTE *, DWORD *));
UDECL(int, DecodeRecipientID, (DWORD, const char *, const BYTE *, DWORD, DWORD, void *, DWORD *));
UDECL(int, EncodeAttrSequence, (DWORD, const char *, const void *, BYTE *, DWORD *));
UDECL(int, DecodeAttrSequence, (DWORD, const char *, const BYTE *, DWORD, DWORD, void *, DWORD *));
UDECL(LONG, CertTrustInit, (void *));
UDECL(LONG, CertTrustCleanup, (void *));
UDECL(LONG, CertTrustFinalPolicy, (void *));
UDECL(int, MyFormatEnhancedKeyUsageString, (WCHAR **, PCCERT_CONTEXT, int, int));
UDECL(int, CompareCertificate, (PCCERT_CONTEXT, PCCERT_CONTEXT, __int64));
UDECL(int, GetUnknownErrorString, (WCHAR **, DWORD));
UDECL(BOOL, CryptUIFreeCertificatePropertiesPagesW, (void *));
UDECL(BOOL, CryptUIFreeViewSignaturesPagesW, (void *));
UDECL(HRESULT, CertSelectionGetSerializedBlob, (void *, void **, ULONG *));

static int mm_en_ui(void) { return PRIMARYLANGID(GetUserDefaultUILanguage()) == LANG_ENGLISH; }
#define EQ32(got, want) do { unsigned g_ = (unsigned)(got); \
    t_check(g_ == (unsigned)(want), __FILE__, __LINE__, #got " == " #want, "got 0x%08x want 0x%08x", g_, (unsigned)(want)); } while (0)

static PCCERT_CONTEXT mkcert(const unsigned char *der, DWORD n) {
    PCCERT_CONTEXT (WINAPI *cc)(DWORD, const BYTE *, DWORD) = U(CertCreateCertificateContext);
    return cc ? cc(X509_ASN_ENCODING, der, n) : NULL;
}
static void freecert(PCCERT_CONTEXT c) { if (c) U(CertFreeCertificateContext)(c); }
#define CERT_A() mkcert(g_cert_a, sizeof g_cert_a)
#define CERT_B() mkcert(g_cert_b, sizeof g_cert_b)
#define CERT_C() mkcert(g_cert_c, sizeof g_cert_c)

/* ================= GetFriendlyNameOfCertW/A ================================================= */
TEST(mm_dlg_friendly_name_w_size_query) {
    GetFriendlyNameOfCertW_pfn f = (GetFriendlyNameOfCertW_pfn)t_proc_in("cryptdlg.dll", "GetFriendlyNameOfCertW");
    REQUIRE(f); REQUIRE(U(CertCreateCertificateContext));
    PCCERT_CONTEXT c = CERT_A(); CHECK(c != NULL); if (!c) return;
    CHECK(f(c, NULL, 0) == 4);            /* "AAA" plus terminator */
    CHECK(f(c, NULL, 100) == 4);          /* NULL buffer: length only, count ignored */
    freecert(c);
}
TEST(mm_dlg_friendly_name_w_buffer_protocol) {
    GetFriendlyNameOfCertW_pfn f = (GetFriendlyNameOfCertW_pfn)t_proc_in("cryptdlg.dll", "GetFriendlyNameOfCertW");
    REQUIRE(f); REQUIRE(U(CertCreateCertificateContext));
    PCCERT_CONTEXT c = CERT_A(); if (!c) { CHECK(0); return; }
    WCHAR buf[16];
    for (DWORD cap = 0; cap < 4; cap++) {
        for (int i = 0; i < 16; i++) buf[i] = 0x7777;
        SET_ERR(0);
        EXPECT_EQ(f(c, buf, cap), 0); EXPECT_ERR(ERROR_MORE_DATA);
        CHECKF(buf[0] == 0x7777, "cap %lu buffer untouched", cap);
    }
    for (int i = 0; i < 16; i++) buf[i] = 0x7777;
    EXPECT_EQ(f(c, buf, 4), 4);
    EXPECT_WSTR(buf, L"AAA");
    CHECK(buf[4] == 0x7777);
    for (int i = 0; i < 16; i++) buf[i] = 0x7777;
    EXPECT_EQ(f(c, buf, 16), 4);          /* the count includes the terminator, not the capacity */
    EXPECT_WSTR(buf, L"AAA");
    freecert(c);
}
TEST(mm_dlg_friendly_name_w_property_wins) {
    GetFriendlyNameOfCertW_pfn f = (GetFriendlyNameOfCertW_pfn)t_proc_in("cryptdlg.dll", "GetFriendlyNameOfCertW");
    REQUIRE(f); REQUIRE(U(CertSetCertificateContextProperty));
    PCCERT_CONTEXT c = CERT_B(); if (!c) { CHECK(0); return; }
    static const WCHAR fn[] = L"Friendly B";
    CRYPT_DATA_BLOB blob = { sizeof fn, (BYTE *)fn };
    CHECK(U(CertSetCertificateContextProperty)(c, CERT_FRIENDLY_NAME_PROP_ID, 0, &blob));
    WCHAR buf[32] = {0};
    EXPECT_EQ(f(c, NULL, 0), 11);
    EXPECT_EQ(f(c, buf, 32), 11);
    EXPECT_WSTR(buf, L"Friendly B");
    SET_ERR(0);
    EXPECT_EQ(f(c, buf, 10), 0); EXPECT_ERR(ERROR_MORE_DATA);
    /* removing the property falls back to the subject common name */
    CHECK(U(CertSetCertificateContextProperty)(c, CERT_FRIENDLY_NAME_PROP_ID, 0, NULL));
    EXPECT_EQ(f(c, buf, 32), 4);
    EXPECT_WSTR(buf, L"BBB");
    freecert(c);
}
TEST(mm_dlg_friendly_name_w_matches_cert_name_string) {
    GetFriendlyNameOfCertW_pfn f = (GetFriendlyNameOfCertW_pfn)t_proc_in("cryptdlg.dll", "GetFriendlyNameOfCertW");
    REQUIRE(f); REQUIRE(U(CertGetNameStringW));
    PCCERT_CONTEXT cs[3] = { CERT_A(), CERT_B(), CERT_C() };
    for (int i = 0; i < 3; i++) {
        if (!cs[i]) { CHECK(0); continue; }
        WCHAR a[64] = {0}, b[64] = {0};
        DWORD n = U(CertGetNameStringW)(cs[i], CERT_NAME_FRIENDLY_DISPLAY_TYPE, 0, NULL, a, 64);
        DWORD m = f(cs[i], b, 64);
        CHECKF(n == m, "cert %d length", i);
        CHECKF(!lstrcmpW(a, b), "cert %d text", i);
        freecert(cs[i]);
    }
}
TEST(mm_dlg_friendly_name_a_buffer_protocol) {
    GetFriendlyNameOfCertA_pfn f = (GetFriendlyNameOfCertA_pfn)t_proc_in("cryptdlg.dll", "GetFriendlyNameOfCertA");
    REQUIRE(f); REQUIRE(U(CertCreateCertificateContext));
    PCCERT_CONTEXT c = CERT_C(); if (!c) { CHECK(0); return; }
    char buf[16];
    EXPECT_EQ(f(c, NULL, 0), 4);
    EXPECT_EQ(f(c, NULL, 3), 4);
    for (DWORD cap = 0; cap < 4; cap++) {
        memset(buf, 'x', sizeof buf);
        SET_ERR(0);
        EXPECT_EQ(f(c, buf, cap), 0); EXPECT_ERR(ERROR_MORE_DATA);
        CHECK(buf[0] == 'x');
    }
    memset(buf, 'x', sizeof buf);
    EXPECT_EQ(f(c, buf, 4), 4);
    EXPECT_STR(buf, "CCC");
    CHECK(buf[4] == 'x');
    memset(buf, 'x', sizeof buf);
    EXPECT_EQ(f(c, buf, 16), 4);
    EXPECT_STR(buf, "CCC");
    freecert(c);
}
TEST(mm_dlg_friendly_name_a_w_parity) {
    GetFriendlyNameOfCertA_pfn fa = (GetFriendlyNameOfCertA_pfn)t_proc_in("cryptdlg.dll", "GetFriendlyNameOfCertA");
    GetFriendlyNameOfCertW_pfn fw = (GetFriendlyNameOfCertW_pfn)t_proc_in("cryptdlg.dll", "GetFriendlyNameOfCertW");
    REQUIRE(fa); REQUIRE(fw); REQUIRE(U(CertCreateCertificateContext));
    PCCERT_CONTEXT cs[3] = { CERT_A(), CERT_B(), CERT_C() };
    for (int i = 0; i < 3; i++) {
        if (!cs[i]) { CHECK(0); continue; }
        char a[64]; WCHAR w[64]; char conv[64];
        DWORD na = fa(cs[i], a, 64), nw = fw(cs[i], w, 64);
        CHECKF(na == nw, "cert %d counts", i);
        WideCharToMultiByte(CP_ACP, 0, w, -1, conv, sizeof conv, NULL, NULL);
        CHECKF(!strcmp(a, conv), "cert %d text", i);
        freecert(cs[i]);
    }
}

/* ================= FormatPKIXEmailProtection / FormatVerisignExtension ======================== */
TEST(mm_dlg_format_pkix_email_size_query) {
    if (t_is_wine()) { t_skip("emulator export is a stub"); return; }
    FormatPKIXEmailProtection_pfn f = (FormatPKIXEmailProtection_pfn)t_proc_in("cryptdlg.dll", "FormatPKIXEmailProtection");
    REQUIRE(f);
    DWORD cb = 0x1234;
    EXPECT_EQ(f(X509_ASN_ENCODING, 0, 0, NULL, "2.5.29.37", NULL, 0, NULL, &cb), 1);
    CHECK(cb >= 2 && (cb % 2) == 0 && cb < 0x400);
    DWORD cb2 = 0;
    EXPECT_EQ(f(X509_ASN_ENCODING, 0, 0, NULL, "2.5.29.37", NULL, 0, NULL, &cb2), 1);
    EXPECT_EQ(cb2, cb);
}
TEST(mm_dlg_format_pkix_email_buffer_protocol) {
    if (t_is_wine()) { t_skip("emulator export is a stub"); return; }
    FormatPKIXEmailProtection_pfn f = (FormatPKIXEmailProtection_pfn)t_proc_in("cryptdlg.dll", "FormatPKIXEmailProtection");
    REQUIRE(f);
    DWORD need = 0;
    f(X509_ASN_ENCODING, 0, 0, NULL, "2.5.29.37", NULL, 0, NULL, &need);
    WCHAR buf[512]; memset(buf, 0x55, sizeof buf);
    DWORD cb = need - 2;
    EXPECT_EQ(f(X509_ASN_ENCODING, 0, 0, NULL, "2.5.29.37", NULL, 0, buf, &cb), 0);
    EXPECT_EQ(cb, need);                     /* too small: required size is reported */
    CHECK(((unsigned char *)buf)[0] == 0x55);
    cb = 0;
    EXPECT_EQ(f(X509_ASN_ENCODING, 0, 0, NULL, "2.5.29.37", NULL, 0, buf, &cb), 0);
    EXPECT_EQ(cb, need);
    cb = need;
    EXPECT_EQ(f(X509_ASN_ENCODING, 0, 0, NULL, "2.5.29.37", NULL, 0, buf, &cb), 1);
    EXPECT_EQ(cb, need);
    CHECK(lstrlenW(buf) * 2 + 2 == (int)need);   /* NUL-terminated resource string */
    CHECK(buf[0] != 0);
    if (mm_en_ui()) EXPECT_WSTR(buf, L"E-Mail Encryption and Authentication");   /* resource text, pinned on an English UI */
    memset(buf, 0x55, sizeof buf);
    cb = need + 100;
    EXPECT_EQ(f(X509_ASN_ENCODING, 0, 0, NULL, "2.5.29.37", NULL, 0, buf, &cb), 1);
    EXPECT_EQ(cb, need + 100);               /* success leaves the capacity untouched */
}
TEST(mm_dlg_format_pkix_email_ignores_encoded_input) {
    if (t_is_wine()) { t_skip("emulator export is a stub"); return; }
    FormatPKIXEmailProtection_pfn f = (FormatPKIXEmailProtection_pfn)t_proc_in("cryptdlg.dll", "FormatPKIXEmailProtection");
    REQUIRE(f);
    WCHAR a[256] = {0}, b[256] = {0}; DWORD ca = sizeof a, cbb = sizeof b;
    static const BYTE junk[] = {0xff, 0x00, 0x13};
    EXPECT_EQ(f(X509_ASN_ENCODING, 0, 0, NULL, "1.2.3", NULL, 0, a, &ca), 1);
    EXPECT_EQ(f(0, 5, 7, NULL, NULL, junk, sizeof junk, b, &cbb), 1);
    CHECK(!lstrcmpW(a, b));
}
TEST(mm_dlg_format_verisign_size_and_buffer) {
    if (t_is_wine()) { t_skip("emulator export is a stub"); return; }
    FormatVerisignExtension_pfn f = (FormatVerisignExtension_pfn)t_proc_in("cryptdlg.dll", "FormatVerisignExtension");
    REQUIRE(f);
    DWORD cb = 0;
    EXPECT_EQ(f(X509_ASN_ENCODING, 0, 0, NULL, NULL, NULL, 0, NULL, &cb), 1);
    EXPECT_EQ(cb, 0x738);
    BYTE *buf = (BYTE *)malloc(0x800); CHECK(buf != NULL); if (!buf) return;
    memset(buf, 0x55, 0x800);
    cb = 0x737;
    EXPECT_EQ(f(X509_ASN_ENCODING, 0, 0, NULL, NULL, NULL, 0, buf, &cb), 0);
    EXPECT_EQ(cb, 0x738);
    CHECK(buf[0] == 0x55);
    cb = 0;
    EXPECT_EQ(f(X509_ASN_ENCODING, 0, 0, NULL, NULL, NULL, 0, buf, &cb), 0);
    EXPECT_EQ(cb, 0x738);
    cb = 0x738;
    EXPECT_EQ(f(X509_ASN_ENCODING, 0, 0, NULL, NULL, NULL, 0, buf, &cb), 1);
    EXPECT_EQ(cb, 0x738);
    CHECK(buf[0x738] == 0x55);               /* exactly 0x738 bytes are written */
    BYTE *buf2 = (BYTE *)malloc(0x800);
    cb = 0x800;
    EXPECT_EQ(f(X509_ASN_ENCODING, 0, 0, NULL, NULL, NULL, 0, buf2, &cb), 1);
    EXPECT_EQ(cb, 0x800);
    CHECK(!memcmp(buf, buf2, 0x738));        /* constant text */
    free(buf2); free(buf);
}

/* ================= EncodeRecipientID / DecodeRecipientID ====================================== */
#pragma pack(push, 8)
typedef struct { DWORD choice; CRYPT_DATA_BLOB issuer; CRYPT_DATA_BLOB serial; } RID;
#pragma pack(pop)

static int build_rid(RID *r, PCCERT_CONTEXT c, BYTE *serial, DWORD cbs) {
    memset(r, 0, sizeof *r);
    r->choice = 0;
    r->issuer.cbData = c->pCertInfo->Issuer.cbData;
    r->issuer.pbData = c->pCertInfo->Issuer.pbData;
    r->serial.cbData = cbs; r->serial.pbData = serial;
    return 1;
}
TEST(mm_dlg_recipient_id_encode_layout) {
    if (t_is_wine()) { t_skip("emulator export is an aborting stub"); return; }
    EncodeRecipientID_pfn f = (EncodeRecipientID_pfn)t_proc_in("cryptdlg.dll", "EncodeRecipientID");
    REQUIRE(f); REQUIRE(U(CertCreateCertificateContext));
    PCCERT_CONTEXT c = CERT_A(); if (!c) { CHECK(0); return; }
    BYTE ser[1] = {0x2a}; RID r; build_rid(&r, c, ser, 1);
    DWORD cb = 0;
    EXPECT_EQ(f(X509_ASN_ENCODING, NULL, &r, NULL, &cb), 1);
    DWORD ci = c->pCertInfo->Issuer.cbData;
    /* SEQUENCE { issuer Name, INTEGER 42 } */
    BYTE want[256]; DWORD n = 0;
    CHECK(ci + 3 < 0x80);
    want[n++] = 0x30; want[n++] = (BYTE)(ci + 3);
    memcpy(want + n, c->pCertInfo->Issuer.pbData, ci); n += ci;
    want[n++] = 0x02; want[n++] = 0x01; want[n++] = 0x2a;
    EXPECT_EQ(cb, n);
    BYTE out[256] = {0}; DWORD cb2 = sizeof out;
    EXPECT_EQ(f(X509_ASN_ENCODING, NULL, &r, out, &cb2), 1);
    EXPECT_EQ(cb2, n);
    CHECK(!memcmp(out, want, n));
    freecert(c);
}
TEST(mm_dlg_recipient_id_encode_small_buffer) {
    if (t_is_wine()) { t_skip("emulator export is an aborting stub"); return; }
    EncodeRecipientID_pfn f = (EncodeRecipientID_pfn)t_proc_in("cryptdlg.dll", "EncodeRecipientID");
    REQUIRE(f); REQUIRE(U(CertCreateCertificateContext));
    PCCERT_CONTEXT c = CERT_A(); if (!c) { CHECK(0); return; }
    BYTE ser[1] = {0x2a}; RID r; build_rid(&r, c, ser, 1);
    DWORD need = 0; f(X509_ASN_ENCODING, NULL, &r, NULL, &need);
    BYTE out[256]; DWORD cb = need - 1;
    SET_ERR(0);
    EXPECT_EQ(f(X509_ASN_ENCODING, NULL, &r, out, &cb), 0); EXPECT_ERR(ERROR_MORE_DATA);
    EXPECT_EQ(cb, need);
    freecert(c);
}
TEST(mm_dlg_recipient_id_encode_rejects_other_choice) {
    if (t_is_wine()) { t_skip("emulator export is an aborting stub"); return; }
    EncodeRecipientID_pfn f = (EncodeRecipientID_pfn)t_proc_in("cryptdlg.dll", "EncodeRecipientID");
    REQUIRE(f); REQUIRE(U(CertCreateCertificateContext));
    PCCERT_CONTEXT c = CERT_A(); if (!c) { CHECK(0); return; }
    BYTE ser[1] = {0x2a}; RID r; build_rid(&r, c, ser, 1);
    for (DWORD ch = 1; ch < 4; ch++) {
        r.choice = ch; DWORD cb = 0;
        SET_ERR(0);
        EXPECT_EQ(f(X509_ASN_ENCODING, NULL, &r, NULL, &cb), 0); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    }
    freecert(c);
}
TEST(mm_dlg_recipient_id_round_trip) {
    if (t_is_wine()) { t_skip("emulator export is an aborting stub"); return; }
    EncodeRecipientID_pfn fe = (EncodeRecipientID_pfn)t_proc_in("cryptdlg.dll", "EncodeRecipientID");
    DecodeRecipientID_pfn fd = (DecodeRecipientID_pfn)t_proc_in("cryptdlg.dll", "DecodeRecipientID");
    REQUIRE(fe); REQUIRE(fd); REQUIRE(U(CertCreateCertificateContext));
    PCCERT_CONTEXT c = CERT_B(); if (!c) { CHECK(0); return; }
    BYTE ser[3] = {0x01, 0x02, 0x03}; RID r; build_rid(&r, c, ser, 3);
    BYTE enc[256]; DWORD cbe = sizeof enc;
    EXPECT_EQ(fe(X509_ASN_ENCODING, NULL, &r, enc, &cbe), 1);
    DWORD need = 0;
    SET_ERR(0);
    int rc = fd(X509_ASN_ENCODING, NULL, enc, cbe, 0, NULL, &need);
    /* the size probe reports success but leaves ERROR_MORE_DATA behind */
    EXPECT_EQ(rc, 1); EXPECT_ERR(ERROR_MORE_DATA);
    EXPECT_EQ(need, 3 + 0x28 + c->pCertInfo->Issuer.cbData);
    BYTE *out = (BYTE *)calloc(1, need + 16);
    DWORD cb = need - 1;
    SET_ERR(0);
    EXPECT_EQ(fd(X509_ASN_ENCODING, NULL, enc, cbe, 0, out, &cb), 0); EXPECT_ERR(ERROR_MORE_DATA);
    EXPECT_EQ(cb, need);
    cb = need;
    EXPECT_EQ(fd(X509_ASN_ENCODING, NULL, enc, cbe, 0, out, &cb), 1);
    RID *d = (RID *)out;
    EXPECT_EQ(d->choice, 0);
    EXPECT_EQ(d->issuer.cbData, c->pCertInfo->Issuer.cbData);
    CHECK(d->issuer.pbData == out + 0x28);
    CHECK(!memcmp(d->issuer.pbData, c->pCertInfo->Issuer.pbData, d->issuer.cbData));
    EXPECT_EQ(d->serial.cbData, 3);
    CHECK(d->serial.pbData == out + 0x28 + d->issuer.cbData);
    CHECK(!memcmp(d->serial.pbData, ser, 3));
    free(out); freecert(c);
}
TEST(mm_dlg_recipient_id_decode_garbage) {
    if (t_is_wine()) { t_skip("emulator export is an aborting stub"); return; }
    DecodeRecipientID_pfn fd = (DecodeRecipientID_pfn)t_proc_in("cryptdlg.dll", "DecodeRecipientID");
    REQUIRE(fd);
    static const BYTE bad[][4] = {{0x00,0x00,0x00,0x00},{0x30,0x05,0x01,0x01},{0x04,0x01,0x00,0x00},{0xff,0xff,0xff,0xff}};
    for (int i = 0; i < 4; i++) {
        BYTE out[64]; DWORD cb = sizeof out;
        SET_ERR(0);
        EXPECT_EQ(fd(X509_ASN_ENCODING, NULL, bad[i], 4, 0, out, &cb), 0);
        EXPECT_ERR(ERROR_NOT_ENOUGH_MEMORY);   /* every decode failure is reported as 8 */
    }
    /* a valid SEQUENCE OF with the wrong element count/shape also fails the same way */
    static const BYTE empty[] = {0x30, 0x00};
    BYTE out[64]; DWORD cb = sizeof out;
    SET_ERR(0);
    EXPECT_EQ(fd(X509_ASN_ENCODING, NULL, empty, 2, 0, out, &cb), 0);
    EXPECT_ERR(ERROR_NOT_ENOUGH_MEMORY);
}

/* ================= EncodeAttrSequence / DecodeAttrSequence ==================================== */
typedef struct { LPSTR oid; DWORD cValue; CRYPT_DATA_BLOB *rg; } ATTR;
typedef struct { DWORD cAttr; ATTR *rg; } ATTRSEQ;

static const BYTE kNull[] = {0x05, 0x00};
static const BYTE kAttrNullDer[] = {0x30,0x11, 0x30,0x0f, 0x06,0x09,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x09,0x03, 0x31,0x02,0x05,0x00};

TEST(mm_dlg_attr_sequence_encode_known_answer) {
    if (t_is_wine()) { t_skip("emulator export is an aborting stub"); return; }
    EncodeAttrSequence_pfn f = (EncodeAttrSequence_pfn)t_proc_in("cryptdlg.dll", "EncodeAttrSequence");
    REQUIRE(f);
    CRYPT_DATA_BLOB v = { 2, (BYTE *)kNull };
    ATTR a = { "1.2.840.113549.1.9.3", 1, &v };
    ATTRSEQ s = { 1, &a };
    DWORD cb = 0;
    EXPECT_EQ(f(X509_ASN_ENCODING, NULL, &s, NULL, &cb), 1);
    EXPECT_EQ(cb, sizeof kAttrNullDer);
    BYTE out[64]; cb = sizeof out;
    EXPECT_EQ(f(X509_ASN_ENCODING, NULL, &s, out, &cb), 1);
    EXPECT_EQ(cb, sizeof kAttrNullDer);
    CHECK(!memcmp(out, kAttrNullDer, sizeof kAttrNullDer));
}
TEST(mm_dlg_attr_sequence_encode_empty) {
    if (t_is_wine()) { t_skip("emulator export is an aborting stub"); return; }
    EncodeAttrSequence_pfn f = (EncodeAttrSequence_pfn)t_proc_in("cryptdlg.dll", "EncodeAttrSequence");
    REQUIRE(f);
    ATTRSEQ s = { 0, NULL };
    BYTE out[8]; DWORD cb = sizeof out;
    EXPECT_EQ(f(X509_ASN_ENCODING, NULL, &s, out, &cb), 1);
    EXPECT_EQ(cb, 2); CHECK(out[0] == 0x30 && out[1] == 0x00);
}
TEST(mm_dlg_attr_sequence_encode_count_limit) {
    if (t_is_wine()) { t_skip("emulator export is an aborting stub"); return; }
    EncodeAttrSequence_pfn f = (EncodeAttrSequence_pfn)t_proc_in("cryptdlg.dll", "EncodeAttrSequence");
    REQUIRE(f);
    ATTRSEQ s = { 0x100000, NULL };
    DWORD cb = 0;
    SET_ERR(0);
    EXPECT_EQ(f(X509_ASN_ENCODING, NULL, &s, NULL, &cb), 0); EXPECT_ERR(ERROR_ARITHMETIC_OVERFLOW);
    s.cAttr = 0xFFFFFFFF;
    SET_ERR(0);
    EXPECT_EQ(f(X509_ASN_ENCODING, NULL, &s, NULL, &cb), 0); EXPECT_ERR(ERROR_ARITHMETIC_OVERFLOW);
}
TEST(mm_dlg_attr_sequence_encode_small_buffer) {
    if (t_is_wine()) { t_skip("emulator export is an aborting stub"); return; }
    EncodeAttrSequence_pfn f = (EncodeAttrSequence_pfn)t_proc_in("cryptdlg.dll", "EncodeAttrSequence");
    REQUIRE(f);
    CRYPT_DATA_BLOB v = { 2, (BYTE *)kNull };
    ATTR a = { "1.2.840.113549.1.9.3", 1, &v };
    ATTRSEQ s = { 1, &a };
    BYTE out[64]; DWORD cb = sizeof kAttrNullDer - 1;
    SET_ERR(0);
    EXPECT_EQ(f(X509_ASN_ENCODING, NULL, &s, out, &cb), 0); EXPECT_ERR(ERROR_MORE_DATA);
    EXPECT_EQ(cb, sizeof kAttrNullDer);
}
TEST(mm_dlg_attr_sequence_encode_two_attributes) {
    if (t_is_wine()) { t_skip("emulator export is an aborting stub"); return; }
    EncodeAttrSequence_pfn f = (EncodeAttrSequence_pfn)t_proc_in("cryptdlg.dll", "EncodeAttrSequence");
    REQUIRE(f);
    CRYPT_DATA_BLOB v1 = { 2, (BYTE *)kNull }, v2[2] = { { 2, (BYTE *)kNull }, { 2, (BYTE *)kNull } };
    ATTR a[2] = { { "1.2.840.113549.1.9.3", 1, &v1 }, { "1.2.840.113549.1.9.4", 2, v2 } };
    ATTRSEQ s = { 2, a };
    BYTE out[128]; DWORD cb = sizeof out;
    EXPECT_EQ(f(X509_ASN_ENCODING, NULL, &s, out, &cb), 1);
    CHECK(out[0] == 0x30);
    EXPECT_EQ(out[1], cb - 2);
    CHECK(!memcmp(out + 2, kAttrNullDer + 2, 17));     /* first attribute identical to the single case */
    EXPECT_EQ(out[19], 0x30);
}
TEST(mm_dlg_attr_sequence_round_trip) {
    if (t_is_wine()) { t_skip("emulator export is an aborting stub"); return; }
    EncodeAttrSequence_pfn fe = (EncodeAttrSequence_pfn)t_proc_in("cryptdlg.dll", "EncodeAttrSequence");
    DecodeAttrSequence_pfn fd = (DecodeAttrSequence_pfn)t_proc_in("cryptdlg.dll", "DecodeAttrSequence");
    REQUIRE(fe); REQUIRE(fd);
    CRYPT_DATA_BLOB v = { 2, (BYTE *)kNull };
    ATTR a = { "1.2.840.113549.1.9.3", 1, &v };
    ATTRSEQ s = { 1, &a };
    BYTE enc[64]; DWORD cbe = sizeof enc;
    EXPECT_EQ(fe(X509_ASN_ENCODING, NULL, &s, enc, &cbe), 1);
    DWORD need = 0;
    EXPECT_EQ(fd(X509_ASN_ENCODING, NULL, enc, cbe, 0, NULL, &need), 1);
    CHECK(need >= 0x10 + 0x18);
    BYTE *out = (BYTE *)calloc(1, need + 64);
    DWORD cb = need - 1;
    SET_ERR(0);
    EXPECT_EQ(fd(X509_ASN_ENCODING, NULL, enc, cbe, 0, out, &cb), 0); EXPECT_ERR(ERROR_MORE_DATA);
    EXPECT_EQ(cb, need);
    cb = need;
    EXPECT_EQ(fd(X509_ASN_ENCODING, NULL, enc, cbe, 0, out, &cb), 1);
    ATTRSEQ *d = (ATTRSEQ *)out;
    EXPECT_EQ(d->cAttr, 1);
    CHECK(d->rg == (ATTR *)(out + 0x10));
    if (d->cAttr == 1 && d->rg == (ATTR *)(out + 0x10)) {
        EXPECT_STR(d->rg[0].oid, "1.2.840.113549.1.9.3");
        EXPECT_EQ(d->rg[0].cValue, 1);
        if (d->rg[0].cValue == 1) {
            EXPECT_EQ(d->rg[0].rg[0].cbData, 2);
            CHECK(!memcmp(d->rg[0].rg[0].pbData, kNull, 2));
        }
    }
    free(out);
}
TEST(mm_dlg_attr_sequence_decode_garbage) {
    if (t_is_wine()) { t_skip("emulator export is an aborting stub"); return; }
    DecodeAttrSequence_pfn fd = (DecodeAttrSequence_pfn)t_proc_in("cryptdlg.dll", "DecodeAttrSequence");
    REQUIRE(fd);
    static const BYTE bad[] = {0x30, 0x05, 0x01};
    DWORD cb = 0;
    SET_ERR(0);
    EXPECT_EQ(fd(X509_ASN_ENCODING, NULL, bad, sizeof bad, 0, NULL, &cb), 0);
    EXPECT_ERR(0x80093102);
    static const BYTE empty[] = {0x30, 0x00};
    cb = 0;
    EXPECT_EQ(fd(X509_ASN_ENCODING, NULL, empty, sizeof empty, 0, NULL, &cb), 1);
    EXPECT_EQ(cb, 0x10);
    BYTE out[0x10] = {0}; cb = 0x10;
    EXPECT_EQ(fd(X509_ASN_ENCODING, NULL, empty, sizeof empty, 0, out, &cb), 1);
    EXPECT_EQ(((ATTRSEQ *)out)->cAttr, 0);
}

/* ================= trust provider hooks ======================================================== */
typedef struct { BYTE raw[0x400]; } BIGBUF;
static void *fnslot(BYTE *pfns, int idx) { return *(void **)(pfns + idx * 8); }

TEST(mm_dlg_cert_trust_init_installs_final_policy) {
    if (t_is_wine()) { t_skip("emulator trust hooks are stubs"); return; }
    CertTrustInit_pfn init = (CertTrustInit_pfn)t_proc_in("cryptdlg.dll", "CertTrustInit");
    FARPROC fin = t_proc_in("cryptdlg.dll", "CertTrustFinalPolicy");
    REQUIRE(init); REQUIRE(fin);
    static CRYPT_PROVIDER_FUNCTIONS pfns; static CRYPT_PROVIDER_DATA pd;
    memset(&pfns, 0xAA, sizeof pfns); memset(&pd, 0, sizeof pd);
    pfns.cbStruct = 0x80;
    pd.cbStruct = 0xd0; pd.psPfns = &pfns;
    EXPECT_EQ(init(&pd), 0);
    CHECK(pfns.pfnObjectTrust == NULL);
    CHECK(pfns.pfnSignatureTrust == NULL);
    CHECK(pfns.pfnCertificateTrust == NULL);
    CHECK((FARPROC)pfns.pfnFinalPolicy == fin);
    CHECK(pfns.pfnCertCheckPolicy == NULL);
    CHECK(pfns.pfnTestFinalPolicy == NULL);
    CHECK(pfns.pfnCleanupPolicy == NULL);
    CHECK(pfns.cbStruct == 0x80);
    CHECK(pfns.pfnAlloc == (void *)(ULONG_PTR)0xAAAAAAAAAAAAAAAAull);   /* other slots untouched */
}
TEST(mm_dlg_cert_trust_init_size_checks) {
    if (t_is_wine()) { t_skip("emulator trust hooks are stubs"); return; }
    CertTrustInit_pfn init = (CertTrustInit_pfn)t_proc_in("cryptdlg.dll", "CertTrustInit");
    REQUIRE(init);
    static CRYPT_PROVIDER_FUNCTIONS pfns; static CRYPT_PROVIDER_DATA pd;
    memset(&pfns, 0xAA, sizeof pfns); memset(&pd, 0, sizeof pd);
    pd.psPfns = &pfns;
    pfns.cbStruct = 0x80; pd.cbStruct = 0xcf;
    EXPECT_EQ(init(&pd), 0x80070057);
    pd.cbStruct = 0;
    EXPECT_EQ(init(&pd), 0x80070057);
    pfns.cbStruct = 0x7f; pd.cbStruct = 0xd0;
    EXPECT_EQ(init(&pd), 0x80070057);
    pfns.cbStruct = 0;
    EXPECT_EQ(init(&pd), 0x80070057);
    CHECK(pfns.pfnFinalPolicy == (void *)(ULONG_PTR)0xAAAAAAAAAAAAAAAAull);   /* not modified on failure */
    pfns.cbStruct = 0x80; pd.cbStruct = 0x1000;
    EXPECT_EQ(init(&pd), 0);
    pfns.cbStruct = 0x400; pd.cbStruct = 0xd0;
    EXPECT_EQ(init(&pd), 0);
}
TEST(mm_dlg_cert_trust_final_policy_small_struct) {
    if (t_is_wine()) { t_skip("emulator trust hooks are stubs"); return; }
    CertTrustFinalPolicy_pfn f = (CertTrustFinalPolicy_pfn)t_proc_in("cryptdlg.dll", "CertTrustFinalPolicy");
    REQUIRE(f);
    static CRYPT_PROVIDER_DATA pd;
    memset(&pd, 0, sizeof pd);
    pd.cbStruct = 0xcf;
    EXPECT_EQ(f(&pd), 0x80070057);
    pd.cbStruct = 0;
    EXPECT_EQ(f(&pd), 0x80070057);
}
TEST(mm_dlg_cert_trust_cleanup_constant) {
    if (t_is_wine()) { t_skip("emulator trust hooks are stubs"); return; }
    CertTrustCleanup_pfn f = (CertTrustCleanup_pfn)t_proc_in("cryptdlg.dll", "CertTrustCleanup");
    REQUIRE(f);
    EXPECT_EQ(f(NULL), 0x800B010B);
    static CRYPT_PROVIDER_DATA pd;
    EXPECT_EQ(f(&pd), 0x800B010B);
}

/* ================= cryptui helpers ============================================================ */
TEST(mm_ui_free_property_pages_accepts_null) {
    if (t_is_wine()) { t_skip("emulator export is an aborting stub"); return; }
    CryptUIFreeCertificatePropertiesPagesW_pfn f = (CryptUIFreeCertificatePropertiesPagesW_pfn)t_proc_in("cryptui.dll", "CryptUIFreeCertificatePropertiesPagesW");
    REQUIRE(f);
    SET_ERR(0);
    EXPECT_EQ(f(NULL), 1);
    void *p = LocalAlloc(LPTR, 64);
    CHECK(p != NULL);
    EXPECT_EQ(f(p), 1);                    /* the free routine is LocalFree on the block */
}
TEST(mm_ui_free_signature_pages_accepts_null) {
    if (t_is_wine()) { t_skip("emulator export is an aborting stub"); return; }
    CryptUIFreeViewSignaturesPagesW_pfn f = (CryptUIFreeViewSignaturesPagesW_pfn)t_proc_in("cryptui.dll", "CryptUIFreeViewSignaturesPagesW");
    REQUIRE(f);
    EXPECT_EQ(f(NULL), 1);
    void *p = LocalAlloc(LPTR, 16);
    EXPECT_EQ(f(p), 1);
}
TEST(mm_ui_unknown_error_string) {
    GetUnknownErrorString_pfn f = (GetUnknownErrorString_pfn)t_proc_in("cryptui.dll", "GetUnknownErrorString");
    REQUIRE(f);
    WCHAR *s = NULL;
    EXPECT_EQ(f(&s, ERROR_FILE_NOT_FOUND), 1);
    CHECK(s != NULL);
    if (s) {
        WCHAR sys[256]; DWORD n = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, ERROR_FILE_NOT_FOUND, 0, sys, 256, NULL);
        CHECKF(n && !wcscmp(s, sys), "error 2 text \"%ls\" vs system text \"%ls\"", s, sys);   /* probed: same text as the system message */
        LocalFree(s);
    }
    s = NULL;
    EXPECT_EQ(f(&s, 0xDEADBEEF), 1);        /* unknown codes fall back to a resource string */
    CHECK(s != NULL && s[0] != 0);
    if (s) LocalFree(s);
}
TEST(mm_ui_format_eku_with_usages) {
    MyFormatEnhancedKeyUsageString_pfn f = (MyFormatEnhancedKeyUsageString_pfn)t_proc_in("cryptui.dll", "MyFormatEnhancedKeyUsageString");
    REQUIRE(f); REQUIRE(U(CertCreateCertificateContext));
    PCCERT_CONTEXT c = CERT_C(); if (!c) { CHECK(0); return; }
    WCHAR *s = NULL, *t = NULL;
    EXPECT_EQ(f(&s, c, 0, 0), 1);
    CHECK(s != NULL && s[0] != 0);
    EXPECT_EQ(f(&t, c, 0, 1), 1);
    CHECK(t != NULL && t[0] != 0);
    if (s && t) {
        CHECK(wcsstr(s, L", ") != NULL);     /* default separator */
        CHECK(wcschr(s, L'\n') == NULL);
        CHECK(wcschr(t, L'\n') != NULL);     /* multi-line variant */
        CHECK(wcsstr(t, L", ") == NULL);
        EXPECT_EQ(lstrlenW(s), lstrlenW(t) + 1);   /* ", " is one character longer than "\n" */
        if (mm_en_ui()) { EXPECT_WSTR(s, L"Server Authentication, Client Authentication"); EXPECT_WSTR(t, L"Server Authentication\nClient Authentication"); }
    }
    LocalFree(s); LocalFree(t);
    freecert(c);
}
TEST(mm_ui_format_eku_without_usages) {
    MyFormatEnhancedKeyUsageString_pfn f = (MyFormatEnhancedKeyUsageString_pfn)t_proc_in("cryptui.dll", "MyFormatEnhancedKeyUsageString");
    REQUIRE(f); REQUIRE(U(CertCreateCertificateContext));
    PCCERT_CONTEXT c = CERT_A(); if (!c) { CHECK(0); return; }
    WCHAR *s = NULL;
    EXPECT_EQ(f(&s, c, 0, 0), 1);
    CHECK(s != NULL && s[0] != 0);
    if (s) { if (mm_en_ui()) EXPECT_WSTR(s, L"<All>"); CHECK(wcschr(s, L'\n') == NULL); LocalFree(s); }
    /* property-only lookup finds nothing on a bare certificate: returns 0 and leaves the output untouched */
    WCHAR *p = (WCHAR *)7;
    EXPECT_EQ(f(&p, c, 1, 0), 0);
    CHECK(p == (WCHAR *)7);
    freecert(c);
}
TEST(mm_ui_format_eku_property_only_ignores_extension) {
    MyFormatEnhancedKeyUsageString_pfn f = (MyFormatEnhancedKeyUsageString_pfn)t_proc_in("cryptui.dll", "MyFormatEnhancedKeyUsageString");
    REQUIRE(f); REQUIRE(U(CertCreateCertificateContext));
    PCCERT_CONTEXT c = CERT_C(); if (!c) { CHECK(0); return; }
    WCHAR *ext = NULL, *prop = NULL;
    EXPECT_EQ(f(&ext, c, 0, 0), 1);
    prop = (WCHAR *)7;
    EXPECT_EQ(f(&prop, c, 1, 0), 0);       /* property only: the extension is not consulted, nothing is returned */
    CHECK(prop == (WCHAR *)7); prop = NULL;
    CHECK(ext != NULL && ext[0] != 0);
    LocalFree(ext); LocalFree(prop);
    freecert(c);
}

TEST(mm_ui_compare_certificate_null_is_zero) {
    CompareCertificate_pfn f = (CompareCertificate_pfn)t_proc_in("cryptui.dll", "CompareCertificate");
    REQUIRE(f); REQUIRE(U(CertCreateCertificateContext));
    PCCERT_CONTEXT c = CERT_A(); if (!c) { CHECK(0); return; }
    EXPECT_EQ(f(NULL, NULL, 2), 0);
    EXPECT_EQ(f(c, NULL, 2), 0);
    EXPECT_EQ(f(NULL, c, 2), 0);
    EXPECT_EQ(f(NULL, NULL, 0), 0);
    freecert(c);
}
TEST(mm_ui_compare_certificate_by_name) {
    CompareCertificate_pfn f = (CompareCertificate_pfn)t_proc_in("cryptui.dll", "CompareCertificate");
    REQUIRE(f); REQUIRE(U(CertCreateCertificateContext));
    PCCERT_CONTEXT a = CERT_A(), b = CERT_B();
    if (!a || !b) { CHECK(0); return; }
    /* flag 1 = issuer name, flag 2 = subject name (both self-signed here, so the same answer) */
    for (int fl = 1; fl <= 2; fl++) {
        EXPECT_EQ(f(a, a, fl), 0);
        EXPECT_EQ((int)f(a, b, fl), -1);
        EXPECT_EQ((int)f(b, a, fl), 1);
        EXPECT_EQ((int)f(a, b, fl | 0x20000), 1);       /* descending */
        EXPECT_EQ((int)f(b, a, fl | 0x20000), -1);
        EXPECT_EQ(f(b, b, fl | 0x20000), 0);
    }
    freecert(a); freecert(b);
}
TEST(mm_ui_compare_certificate_self_all_columns) {
    CompareCertificate_pfn f = (CompareCertificate_pfn)t_proc_in("cryptui.dll", "CompareCertificate");
    REQUIRE(f); REQUIRE(U(CertCreateCertificateContext));
    PCCERT_CONTEXT c = CERT_C(); if (!c) { CHECK(0); return; }
    static const int cols[] = {1, 2, 4, 8, 0x10};
    for (unsigned i = 0; i < 5; i++) { CHECKF((int)f(c, c, cols[i]) == 0, "column 0x%x", cols[i]); }
    freecert(c);
}
TEST(mm_ui_compare_certificate_unknown_column_is_equal) {
    CompareCertificate_pfn f = (CompareCertificate_pfn)t_proc_in("cryptui.dll", "CompareCertificate");
    REQUIRE(f); REQUIRE(U(CertCreateCertificateContext));
    PCCERT_CONTEXT a = CERT_A(), b = CERT_B();
    if (!a || !b) { CHECK(0); return; }
    EXPECT_EQ(f(a, b, 0), 0);
    EXPECT_EQ(f(a, b, 0x40), 0);
    EXPECT_EQ(f(a, b, 0x1000), 0);
    freecert(a); freecert(b);
}
TEST(mm_ui_compare_certificate_eku_column_orders) {
    CompareCertificate_pfn f = (CompareCertificate_pfn)t_proc_in("cryptui.dll", "CompareCertificate");
    REQUIRE(f); REQUIRE(U(CertCreateCertificateContext));
    PCCERT_CONTEXT a = CERT_A(), c = CERT_C();
    if (!a || !c) { CHECK(0); return; }
    int ab = (int)f(a, c, 8), ba = (int)f(c, a, 8);
    CHECK(ab != 0 && ab == -ba);           /* "all purposes" text vs listed purposes differ; order is antisymmetric */
    EXPECT_EQ((int)f(a, c, 8 | 0x20000), -ab);
    freecert(a); freecert(c);
}

/* CERT_SELECTUI_INPUT: hStore, prgpChain, cChain */
typedef struct { HCERTSTORE hStore; PCCERT_CHAIN_CONTEXT *prgpChain; DWORD cChain; } SELIN;
TEST(mm_ui_serialized_blob_null_arguments) {
    CertSelectionGetSerializedBlob_pfn f = (CertSelectionGetSerializedBlob_pfn)t_proc_in("cryptui.dll", "CertSelectionGetSerializedBlob");
    REQUIRE(f);
    SELIN in = {0}; void *out = (void *)7; ULONG cb = 9;
    EXPECT_EQ((unsigned)f(NULL, &out, &cb), 0x80070057u);
    EXPECT_EQ(f(&in, NULL, &cb), 0x80070057);
    EXPECT_EQ(f(&in, &out, NULL), 0x80070057);
    CHECK(out == (void *)7 && cb == 9);
}
TEST(mm_ui_serialized_blob_store_and_chain_conflict) {
    CertSelectionGetSerializedBlob_pfn f = (CertSelectionGetSerializedBlob_pfn)t_proc_in("cryptui.dll", "CertSelectionGetSerializedBlob");
    REQUIRE(f);
    SELIN in = {0}; void *out = (void *)7; ULONG cb = 9;
    in.hStore = (HCERTSTORE)(ULONG_PTR)0x1000; in.prgpChain = (PCCERT_CHAIN_CONTEXT *)(ULONG_PTR)0x2000; in.cChain = 1;
    EXPECT_EQ(f(&in, &out, &cb), 0x80070057);      /* rejected before either pointer is used */
    CHECK(out == (void *)7 && cb == 9);
}
TEST(mm_ui_serialized_blob_neither_store_nor_chain) {
    CertSelectionGetSerializedBlob_pfn f = (CertSelectionGetSerializedBlob_pfn)t_proc_in("cryptui.dll", "CertSelectionGetSerializedBlob");
    REQUIRE(f);
    SELIN in = {0}; void *out = (void *)7; ULONG cb = 9;
    EXPECT_EQ(f(&in, &out, &cb), 0);
    CHECK(out == NULL); EXPECT_EQ(cb, 0);
}
TEST(mm_ui_serialized_blob_memory_store) {
    CertSelectionGetSerializedBlob_pfn f = (CertSelectionGetSerializedBlob_pfn)t_proc_in("cryptui.dll", "CertSelectionGetSerializedBlob");
    REQUIRE(f); REQUIRE(U(CertOpenStore)); REQUIRE(U(CertAddCertificateContextToStore));
    HCERTSTORE st = U(CertOpenStore)(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
    CHECK(st != NULL); if (!st) return;
    PCCERT_CONTEXT a = CERT_A(), b = CERT_B();
    CHECK(U(CertAddCertificateContextToStore)(st, a, CERT_STORE_ADD_ALWAYS, NULL));
    CHECK(U(CertAddCertificateContextToStore)(st, b, CERT_STORE_ADD_ALWAYS, NULL));
    SELIN in = {0}; in.hStore = st;
    void *out = NULL; ULONG cb = 0;
    EXPECT_EQ(f(&in, &out, &cb), 0);
    CHECK(out != NULL && cb > 0);
    if (out && cb) {
        /* the blob is the selection-UI container, not a serialized store: that provider rejects it with
         * CRYPT_E_FILE_ERROR (probed on Win10). Both certificate encodings must be inside it verbatim. */
        EXPECT_EQ(cb, 820);
        CRYPT_DATA_BLOB blob = { cb, (BYTE *)out };
        SetLastError(0);
        HCERTSTORE rd = U(CertOpenStore)(CERT_STORE_PROV_SERIALIZED, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, 0, &blob);
        CHECK(rd == NULL); EXPECT_ERR(0x80092003);
        if (rd) U(CertCloseStore)(rd, 0);
        const unsigned char *ps[2] = { g_cert_a, g_cert_b }; size_t ns[2] = { sizeof g_cert_a, sizeof g_cert_b };
        for (int k = 0; k < 2; k++) {
            int found = 0;
            for (size_t o = 0; o + ns[k] <= cb; o++) if (!memcmp((unsigned char *)out + o, ps[k], ns[k])) { found = 1; break; }
            CHECKF(found, "certificate %d present in blob", k);
        }
        LocalFree(out);
    }
    U(CertCloseStore)(st, 0);
    freecert(a); freecert(b);
}
TEST(mm_ui_resolve_only_dialog_and_wizard_entry_points) {
    /* These raise UI, load wizard extensions or build chains with network side effects; only resolved. */
    static const char *n[] = {"CryptUIWizExport", "CryptUIWizImport", "CryptUIWizDigitalSign", "AddChainToStore",
        "CryptUIGetCertificatePropertiesPagesW", "CryptUIGetCertificatePropertiesPagesA",
        "CryptUIDlgViewCertificateW", "CryptUIDlgSelectCertificateFromStore", "CryptUIDlgCertMgr",
        "CryptUIWizFreeDigitalSignContext", "IsWizardExtensionAvailable"};
    if (!t_module("cryptui.dll") || t_is_wine()) { t_skip("cryptui.dll absent or emulated"); return; }
    for (unsigned i = 0; i < sizeof n / sizeof n[0]; i++) CHECKF(t_proc_in("cryptui.dll", n[i]) != NULL, "%s", n[i]);
}

