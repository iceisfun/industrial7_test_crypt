/* WVTAsn1*Encode / *Decode: the wintrust ASN.1 object functions behind CryptEncodeObject / CryptDecodeObject for the
 * SPC_* and CAT_* structure types.  Called directly (5 argument encode, 7 argument decode, same shape as the crypt32 entry
 * points), compared byte for byte with CryptEncodeObject and with fixed DER observed on Win10 22H2. */
#include "t.h"
#include <wincrypt.h>
#include <wintrust.h>

typedef BOOL (WINAPI *wvt_enc)(DWORD, LPCSTR, const void *, BYTE *, DWORD *);
typedef BOOL (WINAPI *wvt_dec)(DWORD, LPCSTR, const BYTE *, DWORD, DWORD, void *, DWORD *);

#define ENC X509_ASN_ENCODING
#define WVT_TRUNC_ERR 0x80093102   /* CRYPT_E_ASN1_EOD */
#define WVT_TAG_ERR 0x8009310b     /* CRYPT_E_ASN1_BADTAG */

static void hexcmp(const char *tag, const BYTE *got, DWORD cb, const char *want_hex) {
    size_t n = strlen(want_hex) / 2; char buf[1200]; DWORD i;
    for (i = 0; i < cb && i < 500; i++) sprintf(buf + 2 * i, "%02x", got[i]);
    buf[2 * i] = 0;
    t_check(cb == n && strcmp(buf, want_hex) == 0, __FILE__, __LINE__, tag, "got %lu bytes %s want %s", cb, buf, want_hex);
}

/* Encodes via the direct function and via CryptEncodeObject; both must give exactly want_hex.  Also the size query
 * protocol and the too-small buffer. */
static void enc_case(const char *fname, LPCSTR sto, const void *s, const char *want_hex) {
    char nm[96]; BYTE buf[1024], big[1024]; DWORD cb, cb2, ge; BOOL r;
    wvt_enc f;
    t_label("%s", fname);
    snprintf(nm, sizeof nm, "WVTAsn1%sEncode", fname);
    f = (wvt_enc)t_proc_in("wintrust.dll", nm);
    if (!t_require(f != NULL, __FILE__, __LINE__, nm)) return;
    size_t want = strlen(want_hex) / 2;

    cb = 0; r = T_CALL_ERR(&ge, f(ENC, sto, s, NULL, &cb));
    EXPECT_EQ(r, TRUE); EXPECT_EQ(cb, want);

    memset(buf, 0xAA, sizeof buf); cb = sizeof buf;
    r = T_CALL_ERR(&ge, f(ENC, sto, s, buf, &cb));
    EXPECT_EQ(r, TRUE);
    hexcmp("direct encode", buf, cb, want_hex);
    if (cb < sizeof buf) EXPECT_EQ(buf[cb], 0xAA);     /* no overrun */

    memset(big, 0xAA, sizeof big); cb2 = sizeof big;
    r = U(CryptEncodeObject)(ENC, sto, s, big, &cb2);
    EXPECT_EQ(r, TRUE);
    t_check(cb2 == cb && memcmp(big, buf, cb) == 0, __FILE__, __LINE__, "direct == CryptEncodeObject", "cb %lu vs %lu", cb, cb2);

    if (want > 1) {                                     /* one byte short */
        memset(buf, 0xAA, sizeof buf); cb = (DWORD)want - 1;
        r = T_CALL_ERR(&ge, f(ENC, sto, s, buf, &cb));
        EXPECT_EQ(r, FALSE); EXPECT_EQ(ge, ERROR_MORE_DATA); EXPECT_EQ(cb, want);
    }
}

TEST(wvt_encode_spc_link_url) {
    WCHAR url[] = L"http://example.invalid/a"; SPC_LINK l; memset(&l, 0, sizeof l);
    l.dwLinkChoice = SPC_URL_LINK_CHOICE; l.pwszUrl = url;
    enc_case("SpcLink", SPC_LINK_STRUCT, &l, "8018687474703a2f2f6578616d706c652e696e76616c69642f61");
}
TEST(wvt_encode_spc_link_file) {
    WCHAR fl[] = L"file.exe"; SPC_LINK l; memset(&l, 0, sizeof l);
    l.dwLinkChoice = SPC_FILE_LINK_CHOICE; l.pwszFile = fl;
    enc_case("SpcLink", SPC_LINK_STRUCT, &l, "a212801000660069006c0065002e006500780065");
}
TEST(wvt_encode_spc_sp_opus_info) {
    WCHAR url[] = L"http://example.invalid/a"; SPC_LINK l; SPC_SP_OPUS_INFO o; memset(&l, 0, sizeof l); memset(&o, 0, sizeof o);
    l.dwLinkChoice = SPC_URL_LINK_CHOICE; l.pwszUrl = url; o.pwszProgramName = L"Prog"; o.pMoreInfo = &l;
    enc_case("SpcSpOpusInfo", SPC_SP_OPUS_INFO_STRUCT, &o,
             "3028a00a800800500072006f0067a11a8018687474703a2f2f6578616d706c652e696e76616c69642f61");
}
TEST(wvt_encode_spc_sp_opus_info_empty) {
    SPC_SP_OPUS_INFO o; BYTE buf[64]; DWORD cb = sizeof buf; BOOL r; DWORD ge; wvt_enc f;
    f = (wvt_enc)t_proc_in("wintrust.dll", "WVTAsn1SpcSpOpusInfoEncode"); REQUIRE_NOTNULL(f);
    memset(&o, 0, sizeof o);
    r = T_CALL_ERR(&ge, f(ENC, SPC_SP_OPUS_INFO_STRUCT, &o, buf, &cb));
    EXPECT_EQ(r, TRUE); hexcmp("empty opus", buf, cb, "3000");
}
TEST(wvt_encode_spc_statement_type) {
    LPSTR oids[] = { "1.3.6.1.4.1.311.2.1.21" }; SPC_STATEMENT_TYPE st = { 1, oids };
    enc_case("SpcStatementType", SPC_STATEMENT_TYPE_STRUCT, &st, "300c060a2b060104018237020115");
}
TEST(wvt_encode_spc_financial_criteria) {
    SPC_FINANCIAL_CRITERIA fc = { TRUE, TRUE };
    enc_case("SpcFinancialCriteriaInfo", SPC_FINANCIAL_CRITERIA_STRUCT, &fc, "30060101ff0101ff");
}
TEST(wvt_encode_spc_financial_criteria_false) {
    SPC_FINANCIAL_CRITERIA fc = { FALSE, TRUE };
    enc_case("SpcFinancialCriteriaInfo", SPC_FINANCIAL_CRITERIA_STRUCT, &fc, "3006010100" "0101ff");
}
TEST(wvt_encode_spc_minimal_criteria) {
    DWORD mc = 1;
    enc_case("SpcMinimalCriteriaInfo", SPC_MINIMAL_CRITERIA_STRUCT, &mc, "0101ff");
}
TEST(wvt_encode_spc_pe_image_data) {
    WCHAR url[] = L"http://example.invalid/a"; SPC_LINK l; SPC_PE_IMAGE_DATA pe; BYTE fb[1] = { 0x80 };
    memset(&l, 0, sizeof l); memset(&pe, 0, sizeof pe);
    l.dwLinkChoice = SPC_URL_LINK_CHOICE; l.pwszUrl = url; pe.Flags.cbData = 1; pe.Flags.pbData = fb; pe.pFile = &l;
    enc_case("SpcPeImageData", SPC_PE_IMAGE_DATA_STRUCT, &pe, "301ca01a8018687474703a2f2f6578616d706c652e696e76616c69642f61");
}
TEST(wvt_encode_spc_siginfo) {
    SPC_SIGINFO si = { 1, { 0x11223344, 0x5566, 0x7788, { 1, 2, 3, 4, 5, 6, 7, 8 } }, 0, 0, 0, 0, 0 };
    enc_case("SpcSigInfo", SPC_SIGINFO_STRUCT, &si, "3024020101041044332211665588770102030405060708020100020100020100020100020100");
}
TEST(wvt_encode_cat_name_value) {
    BYTE v[3] = { 1, 2, 3 }; CAT_NAMEVALUE nv; memset(&nv, 0, sizeof nv);
    nv.pwszTag = L"Tag"; nv.fdwFlags = 0x10010001; nv.Value.cbData = 3; nv.Value.pbData = v;
    enc_case("CatNameValue", CAT_NAMEVALUE_STRUCT, &nv, "30131e060054006100670204100100010403010203");
}
TEST(wvt_encode_cat_member_info) {
    CAT_MEMBERINFO mi = { L"{C689AAB8-8E78-11D0-8C47-00C04FC295EE}", 200 };
    enc_case("CatMemberInfo", CAT_MEMBERINFO_STRUCT, &mi,
             "30521e4c007b00430036003800390041004100420038002d0038004500370038002d0031003100440030002d0038004300340037002d003000300043003000340046004300320039003500450045007d020200c8");
}
TEST(wvt_encode_spc_sp_agency_info) {
    WCHAR url[] = L"http://example.invalid/a"; SPC_LINK l; SPC_SP_AGENCY_INFO ag; memset(&l, 0, sizeof l); memset(&ag, 0, sizeof ag);
    l.dwLinkChoice = SPC_URL_LINK_CHOICE; l.pwszUrl = url; ag.pPolicyInformation = &l; ag.pwszPolicyDisplayText = L"txt";
    enc_case("SpcSpAgencyInfo", SPC_SP_AGENCY_INFO_STRUCT, &ag, "3026a01a8018687474703a2f2f6578616d706c652e696e76616c69642f61a1088006007400780074");
}
TEST(wvt_encode_spc_indirect_data_content) {
    BYTE dg[4] = { 9, 8, 7, 6 }; SPC_INDIRECT_DATA_CONTENT ic; memset(&ic, 0, sizeof ic);
    ic.Data.pszObjId = SPC_PE_IMAGE_DATA_OBJID; ic.DigestAlgorithm.pszObjId = "1.3.14.3.2.26"; ic.Digest.cbData = 4; ic.Digest.pbData = dg;
    enc_case("SpcIndirectDataContent", SPC_INDIRECT_DATA_CONTENT_STRUCT, &ic, "3021300c060a2b06010401823702010f3011300906052b0e03021a0500040409080706");
}

/* ---- decode: direct call must agree with CryptDecodeObject on the same DER ---- */
static void dec_case(const char *fname, LPCSTR sto, const char *hexin, DWORD want_cb) {
    char nm[96]; BYTE der[600], a[2048], b[2048]; DWORD n = (DWORD)strlen(hexin) / 2, i, cba = sizeof a, cbb = sizeof b, ge, q = 0; BOOL ra, rb; wvt_dec f;
    t_label("%s", fname);
    snprintf(nm, sizeof nm, "WVTAsn1%sDecode", fname);
    f = (wvt_dec)t_proc_in("wintrust.dll", nm);
    if (!t_require(f != NULL, __FILE__, __LINE__, nm)) return;
    for (i = 0; i < n; i++) { unsigned v; sscanf(hexin + 2 * i, "%2x", &v); der[i] = (BYTE)v; }
    memset(a, 0, sizeof a); memset(b, 0, sizeof b);
    ra = T_CALL_ERR(&ge, f(ENC, sto, der, n, 0, a, &cba));
    rb = U(CryptDecodeObject)(ENC, sto, der, n, 0, b, &cbb);
    EXPECT_EQ(ra, TRUE); EXPECT_EQ(rb, TRUE);
    EXPECT_EQ(cba, want_cb); EXPECT_EQ(cbb, want_cb);
    ra = T_CALL_ERR(&ge, f(ENC, sto, der, n, 0, NULL, &q));
    EXPECT_EQ(ra, TRUE); EXPECT_EQ(q, cbb);
}
TEST(wvt_decode_agrees_with_crypt32) {
    dec_case("SpcLink", SPC_LINK_STRUCT, "8018687474703a2f2f6578616d706c652e696e76616c69642f61", 96);
    dec_case("SpcSpOpusInfo", SPC_SP_OPUS_INFO_STRUCT, "3028a00a800800500072006f0067a11a8018687474703a2f2f6578616d706c652e696e76616c69642f61", 136);
    dec_case("SpcStatementType", SPC_STATEMENT_TYPE_STRUCT, "300c060a2b060104018237020115", 48);
    dec_case("SpcFinancialCriteriaInfo", SPC_FINANCIAL_CRITERIA_STRUCT, "30060101ff0101ff", 8);
    dec_case("SpcMinimalCriteriaInfo", SPC_MINIMAL_CRITERIA_STRUCT, "0101ff", 4);
    dec_case("SpcSigInfo", SPC_SIGINFO_STRUCT, "3024020101041044332211665588770102030405060708020100020100020100020100020100", 40);
    dec_case("CatNameValue", CAT_NAMEVALUE_STRUCT, "30131e060054006100670204100100010403010203", 48);
    dec_case("CatMemberInfo", CAT_MEMBERINFO_STRUCT, "30521e4c007b00430036003800390041004100420038002d0038004500370038002d0031003100440030002d0038004300340037002d003000300043003000340046004300320039003500450045007d020200c8", 96);
    dec_case("SpcSpAgencyInfo", SPC_SP_AGENCY_INFO_STRUCT, "3026a01a8018687474703a2f2f6578616d706c652e696e76616c69642f61a1088006007400780074", 136);
    dec_case("SpcIndirectDataContent", SPC_INDIRECT_DATA_CONTENT_STRUCT, "3021300c060a2b06010401823702010f3011300906052b0e03021a0500040409080706", 120);
    dec_case("SpcPeImageData", SPC_PE_IMAGE_DATA_STRUCT, "301ca01a8018687474703a2f2f6578616d706c652e696e76616c69642f61", 128);
}

/* Negative controls: truncated and corrupted DER fail identically through the direct entry and CryptDecodeObject. */
static void dec_bad(const char *fname, LPCSTR sto, const BYTE *der, DWORD n, DWORD want_err) {
    char nm[96]; BYTE a[1024]; DWORD cba = sizeof a, cbb = sizeof a, ge, ge2; wvt_dec f; BOOL ra, rb;
    t_label("%s", fname);
    snprintf(nm, sizeof nm, "WVTAsn1%sDecode", fname);
    f = (wvt_dec)t_proc_in("wintrust.dll", nm);
    if (!t_require(f != NULL, __FILE__, __LINE__, nm)) return;
    ra = T_CALL_ERR(&ge, f(ENC, sto, der, n, 0, a, &cba));
    rb = T_CALL_ERR(&ge2, U(CryptDecodeObject)(ENC, sto, der, n, 0, a, &cbb));
    EXPECT_EQ(ra, FALSE); EXPECT_EQ(rb, FALSE);
    EXPECT_EQ(ge, want_err); EXPECT_EQ(ge2, want_err);
}
TEST(wvt_decode_truncated_der) {
    static const BYTE link_trunc[] = { 0x80, 0x18, 0x68, 0x74, 0x74, 0x70 };      /* length 0x18, only 4 content bytes */
    static const BYTE seq_trunc[] = { 0x30, 0x06, 0x01, 0x01, 0xff };           /* financial criteria cut short */
    static const BYTE bad_tag[] = { 0x04, 0x00 };
    dec_bad("SpcLink", SPC_LINK_STRUCT, link_trunc, sizeof link_trunc, WVT_TRUNC_ERR);
    dec_bad("SpcFinancialCriteriaInfo", SPC_FINANCIAL_CRITERIA_STRUCT, seq_trunc, sizeof seq_trunc, WVT_TRUNC_ERR);
    dec_bad("SpcFinancialCriteriaInfo", SPC_FINANCIAL_CRITERIA_STRUCT, bad_tag, sizeof bad_tag, WVT_TAG_ERR);
}
