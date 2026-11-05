/* Authenticode (SPC_*) codecs exported by wintrust, logotype and QC statement extensions, and
 * dispatcher-level behaviour of CryptEncodeObjectEx / CryptDecodeObjectEx (allocators, flags, "#n" types). */
#include "kp.h"
#include <wintrust.h>

typedef BOOL (WINAPI *wv_enc_t)(DWORD, LPCSTR, const void *, BYTE *, DWORD *);
typedef BOOL (WINAPI *wv_dec_t)(DWORD, LPCSTR, const BYTE *, DWORD, DWORD, void *, DWORD *);

static wv_enc_t wv_e(const char *n) { return (wv_enc_t)t_proc_in("wintrust.dll", n); }
static wv_dec_t wv_d(const char *n) { return (wv_dec_t)t_proc_in("wintrust.dll", n); }

static int wv_is_stub(const char *enc) {       /* these exports exist only as aborting stubs in some emulators */
    return t_is_wine() && (strstr(enc, "MinimalCriteria") || strstr(enc, "SigInfo") || strstr(enc, "SpAgencyInfo") || strstr(enc, "StatementType"));
}
#define REQ_WV(enc, dec) do { REQUIRE(wv_e(enc)); REQUIRE(wv_d(dec)); if (wv_is_stub(enc)) { t_skip("export is an unimplemented stub in the emulator"); return; } kp_enc_type = X509_ASN_ENCODING; } while (0)

static void wv_check_enc(const char *file, int line, const char *fn, const void *info, const BYTE *want, size_t n) {
    DWORD cb = 0xCCCCCCCC; BYTE *buf; BOOL ok;
    wv_enc_t f = wv_e(fn);
    SetLastError(0xDEAD);
    ok = f(KP_ENC, NULL, info, NULL, &cb);
    t_check(ok && cb == n, file, line, "wv size query", "%s ok=%d cb=%lu want %zu err=0x%lx", fn, ok, (unsigned long)cb, n, GetLastError());
    if (!ok || cb != n) return;
    buf = (BYTE *)LocalAlloc(LPTR, n + 8);
    if (n > 0) {
        cb = (DWORD)n - 1; SetLastError(0xDEAD);
        ok = f(KP_ENC, NULL, info, buf, &cb);
        t_check(!ok && GetLastError() == ERROR_MORE_DATA && cb == n, file, line, "wv too small", "%s ok=%d err=0x%lx cb=%lu", fn, ok, GetLastError(), (unsigned long)cb);
    }
    memset(buf, 0xAA, n + 8); cb = (DWORD)n;
    ok = f(KP_ENC, NULL, info, buf, &cb);
    t_check(ok && cb == n && !memcmp(buf, want, n), file, line, "wv exact", "%s ok=%d cb=%lu", fn, ok, (unsigned long)cb);
    { size_t i; int bad = 0; for (i = n; i < n + 8; i++) if (buf[i] != 0xAA) bad = 1; t_check(!bad, file, line, "wv no overrun", NULL); }
    LocalFree(buf);
}
#define WV_ENC_EQ(fn, info, ...) wv_check_enc(__FILE__, __LINE__, fn, info, __VA_ARGS__)

static void wv_check_enc_fail(const char *file, int line, const char *fn, const void *info, DWORD err) {
    DWORD cb = 64; BYTE buf[256]; SetLastError(0xDEAD);
    BOOL ok = wv_e(fn)(KP_ENC, NULL, info, buf, &cb);
    t_check(!ok, file, line, "wv encode must fail", fn);
    if (err) t_check(GetLastError() == err, file, line, "wv last error", "got 0x%lx want 0x%lx", GetLastError(), (unsigned long)err);
    t_check(cb == 0, file, line, "wv size zeroed on failure", "cb=%lu", (unsigned long)cb);
}
#define WV_ENC_FAIL(fn, info, err) wv_check_enc_fail(__FILE__, __LINE__, fn, info, err)

/* decode via the wintrust export: size query, MORE_DATA, then real decode into LocalAlloc'd memory */
static void *wv_check_dec(const char *file, int line, const char *fn, const BYTE *der, size_t n, DWORD flags) {
    DWORD cb = 0xCCCCCCCC, cb2; BYTE *buf; BOOL ok;
    wv_dec_t f = wv_d(fn);
    SetLastError(0xDEAD);
    ok = f(KP_ENC, NULL, der, (DWORD)n, flags, NULL, &cb);
    t_check(ok && cb > 0 && cb != 0xCCCCCCCC, file, line, "wv decode size query", "%s ok=%d cb=%lu err=0x%lx", fn, ok, (unsigned long)cb, GetLastError());
    if (!ok) return NULL;
    buf = (BYTE *)LocalAlloc(LPTR, cb + 16);
    cb2 = 1; SetLastError(0xDEAD);
    ok = f(KP_ENC, NULL, der, (DWORD)n, flags, buf, &cb2);
    t_check(!ok && GetLastError() == ERROR_MORE_DATA && cb2 == cb, file, line, "wv decode too small", "%s ok=%d err=0x%lx cb2=%lu cb=%lu", fn, ok, GetLastError(), (unsigned long)cb2, (unsigned long)cb);
    cb2 = cb;
    ok = f(KP_ENC, NULL, der, (DWORD)n, flags, buf, &cb2);
    t_check(ok && cb2 <= cb, file, line, "wv decode", "%s ok=%d cb2=%lu cb=%lu err=0x%lx", fn, ok, (unsigned long)cb2, (unsigned long)cb, GetLastError());
    if (!ok) { LocalFree(buf); return NULL; }
    return buf;
}
#define WV_DEC(fn, ...) wv_check_dec_(__FILE__, __LINE__, fn, __VA_ARGS__)
#define wv_check_dec_(f, l, fn, p, n, fl) wv_check_dec(f, l, fn, p, n, fl)

static void wv_check_dec_fail(const char *file, int line, const char *fn, const BYTE *der, size_t n, DWORD err) {
    DWORD cb = 2048; BYTE buf[2048]; SetLastError(0xDEAD);
    BOOL ok = wv_d(fn)(KP_ENC, NULL, der, (DWORD)n, 0, buf, &cb);
    t_check(!ok, file, line, "wv decode must fail", fn);
    if (err == KP_E_TRUNC) t_check(GetLastError() == KP_E_EOD || GetLastError() == KP_E_CORRUPT, file, line, "wv decode last error (EOD or CORRUPT)", "got 0x%lx", GetLastError());
    else if (err) t_check(GetLastError() == err, file, line, "wv decode last error", "got 0x%lx want 0x%lx", GetLastError(), (unsigned long)err);
}
#define WV_DEC_FAILV(fn, err, ...) wv_check_dec_fail(__FILE__, __LINE__, fn, V(__VA_ARGS__), err)

static const BYTE url_a_der[] = {0x80,8,'h','t','t','p',':','/','/','a'};
static const BYTE file_x_link[] = {0xa2,4,0x80,2,0,'x'};

/* ---------------------------------------------------------------- SPC_LINK */
TEST(kpm_spc_link_url_encode) {
    REQ_WV("WVTAsn1SpcLinkEncode", "WVTAsn1SpcLinkDecode");
    SPC_LINK l; memset(&l, 0, sizeof l);
    l.dwLinkChoice = SPC_URL_LINK_CHOICE; l.pwszUrl = (LPWSTR)L"http://a";
    WV_ENC_EQ("WVTAsn1SpcLinkEncode", &l, url_a_der, sizeof url_a_der);
}
TEST(kpm_spc_link_file_encode) {
    REQ_WV("WVTAsn1SpcLinkEncode", "WVTAsn1SpcLinkDecode");
    SPC_LINK l; memset(&l, 0, sizeof l);
    l.dwLinkChoice = SPC_FILE_LINK_CHOICE; l.pwszFile = (LPWSTR)L"a.exe";
    WV_ENC_EQ("WVTAsn1SpcLinkEncode", &l, V(0xa2,0x0c,0x80,0x0a,0,'a',0,'.',0,'e',0,'x',0,'e'));
    l.pwszFile = (LPWSTR)L"x";
    WV_ENC_EQ("WVTAsn1SpcLinkEncode", &l, file_x_link, sizeof file_x_link);
    l.pwszFile = (LPWSTR)L"";
    WV_ENC_EQ("WVTAsn1SpcLinkEncode", &l, V(0xa2,2,0x80,0));
}
TEST(kpm_spc_link_moniker_encode) {
    REQ_WV("WVTAsn1SpcLinkEncode", "WVTAsn1SpcLinkDecode");
    SPC_LINK l; memset(&l, 0, sizeof l);
    l.dwLinkChoice = SPC_MONIKER_LINK_CHOICE;
    for (int i = 0; i < 16; i++) l.Moniker.ClassId[i] = (BYTE)i;
    l.Moniker.SerializedData.cbData = 2; l.Moniker.SerializedData.pbData = (BYTE *)"\xaa\xbb";
    WV_ENC_EQ("WVTAsn1SpcLinkEncode", &l, V(0xa1,0x16, 4,0x10,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 4,2,0xaa,0xbb));
}
TEST(kpm_spc_link_invalid_choice) {
    REQ_WV("WVTAsn1SpcLinkEncode", "WVTAsn1SpcLinkDecode");
    SPC_LINK l; memset(&l, 0, sizeof l);
    l.pwszUrl = (LPWSTR)L"x";
    l.dwLinkChoice = 0; WV_ENC_FAIL("WVTAsn1SpcLinkEncode", &l, KP_E_INVALIDARG);
    l.dwLinkChoice = 4; WV_ENC_FAIL("WVTAsn1SpcLinkEncode", &l, KP_E_INVALIDARG);
    l.dwLinkChoice = 0xffffffff; WV_ENC_FAIL("WVTAsn1SpcLinkEncode", &l, KP_E_INVALIDARG);
}
TEST(kpm_spc_link_url_must_be_ia5) {
    REQ_WV("WVTAsn1SpcLinkEncode", "WVTAsn1SpcLinkDecode");
    SPC_LINK l; memset(&l, 0, sizeof l);
    l.dwLinkChoice = SPC_URL_LINK_CHOICE; l.pwszUrl = (LPWSTR)L"http://\x00e9";
    DWORD cb = 0; SetLastError(0);
    BOOL ok = wv_e("WVTAsn1SpcLinkEncode")(KP_ENC, NULL, &l, NULL, &cb);
    t_note("non-ASCII URL: ok=%d err=0x%lx", ok, ok ? 0 : GetLastError());
}
TEST(kpm_spc_link_decode_url) {
    REQ_WV("WVTAsn1SpcLinkEncode", "WVTAsn1SpcLinkDecode");
    SPC_LINK *r = WV_DEC("WVTAsn1SpcLinkDecode", url_a_der, sizeof url_a_der, 0);
    if (r) { CHECK(r->dwLinkChoice == SPC_URL_LINK_CHOICE); CHECK(r->pwszUrl && !lstrcmpW(r->pwszUrl, L"http://a")); LocalFree(r); }
}
TEST(kpm_spc_link_decode_file) {
    REQ_WV("WVTAsn1SpcLinkEncode", "WVTAsn1SpcLinkDecode");
    SPC_LINK *r = WV_DEC("WVTAsn1SpcLinkDecode", file_x_link, sizeof file_x_link, 0);
    if (r) { CHECK(r->dwLinkChoice == SPC_FILE_LINK_CHOICE); CHECK(r->pwszFile && !lstrcmpW(r->pwszFile, L"x")); LocalFree(r); }
}
TEST(kpm_spc_link_decode_file_ascii_form) {
    REQ_WV("WVTAsn1SpcLinkEncode", "WVTAsn1SpcLinkDecode");
    /* SpcString ascii alternative [1] IA5String inside the file link */
    SPC_LINK *r = WV_DEC("WVTAsn1SpcLinkDecode", V(0xa2,4,0x81,2,'o','k'), 0);
    if (r) { CHECK(r->dwLinkChoice == SPC_FILE_LINK_CHOICE); CHECK(r->pwszFile && !lstrcmpW(r->pwszFile, L"ok")); LocalFree(r); }
}
TEST(kpm_spc_link_decode_moniker) {
    REQ_WV("WVTAsn1SpcLinkEncode", "WVTAsn1SpcLinkDecode");
    SPC_LINK *r = WV_DEC("WVTAsn1SpcLinkDecode", V(0xa1,0x16, 4,0x10,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 4,2,0xaa,0xbb), 0);
    if (r) {
        CHECK(r->dwLinkChoice == SPC_MONIKER_LINK_CHOICE);
        CHECK(r->Moniker.ClassId[0] == 0 && r->Moniker.ClassId[15] == 15);
        CHECK(r->Moniker.SerializedData.cbData == 2 && r->Moniker.SerializedData.pbData[0] == 0xaa);
        LocalFree(r);
    }
}
TEST(kpm_spc_link_decode_moniker_bad_class_id_length) {
    REQ_WV("WVTAsn1SpcLinkEncode", "WVTAsn1SpcLinkDecode");
    DWORD cb = 2048; BYTE buf[2048]; static const BYTE der[] = {0xa1,0x0a, 4,4,1,2,3,4, 4,2,0xaa,0xbb};
    SetLastError(0);
    CHECK(!wv_d("WVTAsn1SpcLinkDecode")(KP_ENC, NULL, der, sizeof der, 0, buf, &cb));
    EXPECT_ERR(CRYPT_E_BAD_ENCODE);
}
TEST(kpm_spc_link_decode_errors) {
    REQ_WV("WVTAsn1SpcLinkEncode", "WVTAsn1SpcLinkDecode");
    WV_DEC_FAILV("WVTAsn1SpcLinkDecode", 0, 0x30, 0);
    WV_DEC_FAILV("WVTAsn1SpcLinkDecode", KP_E_TRUNC, 0x80, 5, 'a');
    WV_DEC_FAILV("WVTAsn1SpcLinkDecode", 0, 0x83, 1, 'a');
}
TEST(kpm_spc_link_roundtrip_all) {
    REQ_WV("WVTAsn1SpcLinkEncode", "WVTAsn1SpcLinkDecode");
    SPC_LINK l; memset(&l, 0, sizeof l); BYTE buf[256]; DWORD cb;
    l.dwLinkChoice = SPC_FILE_LINK_CHOICE; l.pwszFile = (LPWSTR)L"\x20ac uro";
    cb = sizeof buf; CHECK(wv_e("WVTAsn1SpcLinkEncode")(KP_ENC, NULL, &l, buf, &cb));
    SPC_LINK *r = WV_DEC("WVTAsn1SpcLinkDecode", buf, cb, 0);
    if (r) { CHECK(r->dwLinkChoice == SPC_FILE_LINK_CHOICE && !lstrcmpW(r->pwszFile, L"\x20ac uro")); LocalFree(r); }
}

/* ---------------------------------------------------------------- SPC_SP_OPUS_INFO */
static const BYTE opus_name[] = {0xa0,0x0a,0x80,0x08,0,'P',0,'r',0,'o',0,'g'};
TEST(kpm_spc_opus_encode_empty) {
    REQ_WV("WVTAsn1SpcSpOpusInfoEncode", "WVTAsn1SpcSpOpusInfoDecode");
    SPC_SP_OPUS_INFO o; memset(&o, 0, sizeof o);
    WV_ENC_EQ("WVTAsn1SpcSpOpusInfoEncode", &o, V(0x30,0));
}
TEST(kpm_spc_opus_encode_name_only) {
    REQ_WV("WVTAsn1SpcSpOpusInfoEncode", "WVTAsn1SpcSpOpusInfoDecode");
    SPC_SP_OPUS_INFO o; memset(&o, 0, sizeof o); o.pwszProgramName = L"Prog";
    WV_ENC_EQ("WVTAsn1SpcSpOpusInfoEncode", &o, V(0x30,0x0c, 0xa0,0x0a,0x80,0x08,0,'P',0,'r',0,'o',0,'g'));
}
TEST(kpm_spc_opus_encode_name_and_more_info) {
    REQ_WV("WVTAsn1SpcSpOpusInfoEncode", "WVTAsn1SpcSpOpusInfoDecode");
    SPC_LINK url; memset(&url, 0, sizeof url); url.dwLinkChoice = SPC_URL_LINK_CHOICE; url.pwszUrl = (LPWSTR)L"http://a";
    SPC_SP_OPUS_INFO o; memset(&o, 0, sizeof o); o.pwszProgramName = L"Prog"; o.pMoreInfo = &url;
    WV_ENC_EQ("WVTAsn1SpcSpOpusInfoEncode", &o, V(0x30,0x18, 0xa0,0x0a,0x80,0x08,0,'P',0,'r',0,'o',0,'g', 0xa1,0x0a,0x80,8,'h','t','t','p',':','/','/','a'));
}
TEST(kpm_spc_opus_encode_publisher_file_link) {
    REQ_WV("WVTAsn1SpcSpOpusInfoEncode", "WVTAsn1SpcSpOpusInfoDecode");
    SPC_LINK f; memset(&f, 0, sizeof f); f.dwLinkChoice = SPC_FILE_LINK_CHOICE; f.pwszFile = (LPWSTR)L"x";
    SPC_SP_OPUS_INFO o; memset(&o, 0, sizeof o); o.pPublisherInfo = &f;
    WV_ENC_EQ("WVTAsn1SpcSpOpusInfoEncode", &o, V(0x30,8, 0xa2,6, 0xa2,4,0x80,2,0,'x'));
}
TEST(kpm_spc_opus_encode_all_three) {
    REQ_WV("WVTAsn1SpcSpOpusInfoEncode", "WVTAsn1SpcSpOpusInfoDecode");
    SPC_LINK url, f; memset(&url, 0, sizeof url); memset(&f, 0, sizeof f);
    url.dwLinkChoice = SPC_URL_LINK_CHOICE; url.pwszUrl = (LPWSTR)L"http://a";
    f.dwLinkChoice = SPC_FILE_LINK_CHOICE; f.pwszFile = (LPWSTR)L"x";
    SPC_SP_OPUS_INFO o = { L"Prog", &url, &f };
    WV_ENC_EQ("WVTAsn1SpcSpOpusInfoEncode", &o, V(0x30,0x20, 0xa0,0x0a,0x80,0x08,0,'P',0,'r',0,'o',0,'g', 0xa1,0x0a,0x80,8,'h','t','t','p',':','/','/','a', 0xa2,6,0xa2,4,0x80,2,0,'x'));
}
TEST(kpm_spc_opus_encode_bad_link_zeroes_size) {
    REQ_WV("WVTAsn1SpcSpOpusInfoEncode", "WVTAsn1SpcSpOpusInfoDecode");
    SPC_LINK bad; memset(&bad, 0, sizeof bad); bad.dwLinkChoice = 9;
    SPC_SP_OPUS_INFO o; memset(&o, 0, sizeof o); o.pMoreInfo = &bad;
    WV_ENC_FAIL("WVTAsn1SpcSpOpusInfoEncode", &o, KP_E_INVALIDARG);
}
TEST(kpm_spc_opus_decode_empty) {
    REQ_WV("WVTAsn1SpcSpOpusInfoEncode", "WVTAsn1SpcSpOpusInfoDecode");
    SPC_SP_OPUS_INFO *r = WV_DEC("WVTAsn1SpcSpOpusInfoDecode", V(0x30,0), 0);
    if (r) { CHECK(r->pwszProgramName == NULL && r->pMoreInfo == NULL && r->pPublisherInfo == NULL); LocalFree(r); }
}
TEST(kpm_spc_opus_decode_all) {
    REQ_WV("WVTAsn1SpcSpOpusInfoEncode", "WVTAsn1SpcSpOpusInfoDecode");
    SPC_SP_OPUS_INFO *r = WV_DEC("WVTAsn1SpcSpOpusInfoDecode", V(0x30,0x20, 0xa0,0x0a,0x80,0x08,0,'P',0,'r',0,'o',0,'g', 0xa1,0x0a,0x80,8,'h','t','t','p',':','/','/','a', 0xa2,6,0xa2,4,0x80,2,0,'x'), 0);
    if (r) {
        CHECK(r->pwszProgramName && !lstrcmpW(r->pwszProgramName, L"Prog"));
        CHECK(r->pMoreInfo && r->pMoreInfo->dwLinkChoice == SPC_URL_LINK_CHOICE && !lstrcmpW(r->pMoreInfo->pwszUrl, L"http://a"));
        CHECK(r->pPublisherInfo && r->pPublisherInfo->dwLinkChoice == SPC_FILE_LINK_CHOICE && !lstrcmpW(r->pPublisherInfo->pwszFile, L"x"));
        LocalFree(r);
    }
}
TEST(kpm_spc_opus_decode_ascii_program_name) {
    REQ_WV("WVTAsn1SpcSpOpusInfoEncode", "WVTAsn1SpcSpOpusInfoDecode");
    SPC_SP_OPUS_INFO *r = WV_DEC("WVTAsn1SpcSpOpusInfoDecode", V(0x30,6, 0xa0,4,0x81,2,'o','k'), 0);
    if (r) { CHECK(r->pwszProgramName && !lstrcmpW(r->pwszProgramName, L"ok")); LocalFree(r); }
}
TEST(kpm_spc_opus_decode_errors) {
    REQ_WV("WVTAsn1SpcSpOpusInfoEncode", "WVTAsn1SpcSpOpusInfoDecode");
    WV_DEC_FAILV("WVTAsn1SpcSpOpusInfoDecode", KP_E_BADTAG, 0x31, 0);
    WV_DEC_FAILV("WVTAsn1SpcSpOpusInfoDecode", KP_E_BADTAG, 2, 1, 1);
    WV_DEC_FAILV("WVTAsn1SpcSpOpusInfoDecode", KP_E_TRUNC, 0x30, 8, 0xa0, 6);
}
TEST(kpm_spc_opus_via_crypt32_by_oid) {
    REQ_WV("WVTAsn1SpcSpOpusInfoEncode", "WVTAsn1SpcSpOpusInfoDecode");
    SPC_SP_OPUS_INFO o; memset(&o, 0, sizeof o); o.pwszProgramName = L"Prog";
    DWORD cb = 0; BYTE *e = kp_enc_alloc(SPC_SP_OPUS_INFO_OBJID, &o, 0, &cb);
    if (!e) { t_note("CryptEncodeObjectEx(SPC_SP_OPUS_INFO_OBJID): err=0x%lx (needs the default OID registrations)", GetLastError()); return; }
    CHECK(cb == 14 && !memcmp(e, "\x30\x0c\xa0\x0a\x80\x08\x00P\x00r\x00o\x00g", 14));
    SPC_SP_OPUS_INFO *r = kp_dec_alloc(SPC_SP_OPUS_INFO_OBJID, e, cb, 0, NULL);
    CHECK(r && r->pwszProgramName && !lstrcmpW(r->pwszProgramName, L"Prog"));
    kp_free(r); kp_free(e);
}
TEST(kpm_spc_opus_via_crypt32_by_number) {
    REQ_WV("WVTAsn1SpcSpOpusInfoEncode", "WVTAsn1SpcSpOpusInfoDecode");
    SPC_SP_OPUS_INFO o; memset(&o, 0, sizeof o);
    DWORD cb = 0; BYTE *e = kp_enc_alloc(SPC_SP_OPUS_INFO_STRUCT, &o, 0, &cb);
    t_note("SPC_SP_OPUS_INFO_STRUCT (2007) via CryptEncodeObjectEx: %s err=0x%lx", e ? "ok" : "failed", e ? 0 : GetLastError());
    kp_free(e);
}

/* ---------------------------------------------------------------- SPC_PE_IMAGE_DATA */
TEST(kpm_spc_pe_image_encode) {
    REQ_WV("WVTAsn1SpcPeImageDataEncode", "WVTAsn1SpcPeImageDataDecode");
    SPC_PE_IMAGE_DATA d; memset(&d, 0, sizeof d);
    WV_ENC_EQ("WVTAsn1SpcPeImageDataEncode", &d, V(0x30,0));                         /* flags default + no file: empty sequence */
    SPC_LINK f; memset(&f, 0, sizeof f); f.dwLinkChoice = SPC_FILE_LINK_CHOICE; f.pwszFile = (LPWSTR)L"x";
    d.pFile = &f;
    WV_ENC_EQ("WVTAsn1SpcPeImageDataEncode", &d, V(0x30,8, 0xa0,6, 0xa2,4,0x80,2,0,'x'));
    BYTE fl = 0x80; d.Flags.cbData = 1; d.Flags.pbData = &fl; d.Flags.cUnusedBits = 7;
    WV_ENC_EQ("WVTAsn1SpcPeImageDataEncode", &d, V(0x30,0x0c, 3,2,7,0x80, 0xa0,6, 0xa2,4,0x80,2,0,'x'));
    d.pFile = NULL;
    WV_ENC_EQ("WVTAsn1SpcPeImageDataEncode", &d, V(0x30,4, 3,2,7,0x80));
}
TEST(kpm_spc_pe_image_flags_length_in_bits) {
    REQ_WV("WVTAsn1SpcPeImageDataEncode", "WVTAsn1SpcPeImageDataDecode");
    SPC_PE_IMAGE_DATA d; memset(&d, 0, sizeof d);
    BYTE fl[2] = { 0xff, 0xf0 }; d.Flags.cbData = 2; d.Flags.pbData = fl; d.Flags.cUnusedBits = 4;
    WV_ENC_EQ("WVTAsn1SpcPeImageDataEncode", &d, V(0x30,5, 3,3,4,0xff,0xf0));
    BYTE z = 0; d.Flags.cbData = 1; d.Flags.pbData = &z; d.Flags.cUnusedBits = 0;
    WV_ENC_EQ("WVTAsn1SpcPeImageDataEncode", &d, V(0x30,4, 3,2,0,0));
}
TEST(kpm_spc_pe_image_decode) {
    REQ_WV("WVTAsn1SpcPeImageDataEncode", "WVTAsn1SpcPeImageDataDecode");
    SPC_PE_IMAGE_DATA *r = WV_DEC("WVTAsn1SpcPeImageDataDecode", V(0x30,0x0c, 3,2,7,0x80, 0xa0,6, 0xa2,4,0x80,2,0,'x'), 0);
    if (r) {
        CHECK(r->Flags.cbData == 1 && r->Flags.cUnusedBits == 7 && r->Flags.pbData[0] == 0x80);
        CHECK(r->pFile && r->pFile->dwLinkChoice == SPC_FILE_LINK_CHOICE && !lstrcmpW(r->pFile->pwszFile, L"x"));
        LocalFree(r);
    }
    r = WV_DEC("WVTAsn1SpcPeImageDataDecode", V(0x30,0), 0);
    if (r) { CHECK(r->Flags.cbData == 0 && r->pFile == NULL); LocalFree(r); }
}
TEST(kpm_spc_pe_image_decode_errors) {
    REQ_WV("WVTAsn1SpcPeImageDataEncode", "WVTAsn1SpcPeImageDataDecode");
    WV_DEC_FAILV("WVTAsn1SpcPeImageDataDecode", KP_E_BADTAG, 0x31, 0);
    WV_DEC_FAILV("WVTAsn1SpcPeImageDataDecode", KP_E_TRUNC, 0x30, 6, 3);
}

/* ---------------------------------------------------------------- SPC_INDIRECT_DATA_CONTENT */
TEST(kpm_spc_indirect_data_encode) {
    REQ_WV("WVTAsn1SpcIndirectDataContentEncode", "WVTAsn1SpcIndirectDataContentDecode");
    SPC_INDIRECT_DATA_CONTENT c; memset(&c, 0, sizeof c);
    c.Data.pszObjId = (LPSTR)SPC_PE_IMAGE_DATA_OBJID; c.Data.Value.cbData = 2; c.Data.Value.pbData = (BYTE *)"\x30\x00";
    c.DigestAlgorithm.pszObjId = (LPSTR)szOID_OIWSEC_sha1;
    c.Digest.cbData = 4; c.Digest.pbData = (BYTE *)"\x01\x02\x03\x04";
    WV_ENC_EQ("WVTAsn1SpcIndirectDataContentEncode", &c, V(0x30,0x23,
        0x30,0x0e, 6,0x0a,0x2b,6,1,4,1,0x82,0x37,2,1,0x0f, 0x30,0,
        0x30,0x11, 0x30,9,6,5,0x2b,0x0e,3,2,0x1a,5,0, 4,4,1,2,3,4));
}
TEST(kpm_spc_indirect_data_encode_without_value) {
    REQ_WV("WVTAsn1SpcIndirectDataContentEncode", "WVTAsn1SpcIndirectDataContentDecode");
    SPC_INDIRECT_DATA_CONTENT c; memset(&c, 0, sizeof c);
    c.Data.pszObjId = (LPSTR)SPC_PE_IMAGE_DATA_OBJID;
    c.DigestAlgorithm.pszObjId = (LPSTR)szOID_OIWSEC_sha1;
    c.Digest.cbData = 4; c.Digest.pbData = (BYTE *)"\x01\x02\x03\x04";
    WV_ENC_EQ("WVTAsn1SpcIndirectDataContentEncode", &c, V(0x30,0x21,
        0x30,0x0c, 6,0x0a,0x2b,6,1,4,1,0x82,0x37,2,1,0x0f,
        0x30,0x11, 0x30,9,6,5,0x2b,0x0e,3,2,0x1a,5,0, 4,4,1,2,3,4));
}
TEST(kpm_spc_indirect_data_explicit_algorithm_params) {
    REQ_WV("WVTAsn1SpcIndirectDataContentEncode", "WVTAsn1SpcIndirectDataContentDecode");
    SPC_INDIRECT_DATA_CONTENT c; memset(&c, 0, sizeof c);
    c.Data.pszObjId = (LPSTR)"1.2.3";
    c.DigestAlgorithm.pszObjId = (LPSTR)"1.2.4"; c.DigestAlgorithm.Parameters.cbData = 3; c.DigestAlgorithm.Parameters.pbData = (BYTE *)"\x04\x01\x09";
    WV_ENC_EQ("WVTAsn1SpcIndirectDataContentEncode", &c, V(0x30,0x13, 0x30,4,6,2,0x2a,3, 0x30,0x0b, 0x30,7,6,2,0x2a,4,4,1,9, 4,0));
}
TEST(kpm_spc_indirect_data_bad_oid) {
    REQ_WV("WVTAsn1SpcIndirectDataContentEncode", "WVTAsn1SpcIndirectDataContentDecode");
    SPC_INDIRECT_DATA_CONTENT c; memset(&c, 0, sizeof c);
    c.Data.pszObjId = (LPSTR)"oops"; c.DigestAlgorithm.pszObjId = (LPSTR)szOID_OIWSEC_sha1;
    WV_ENC_FAIL("WVTAsn1SpcIndirectDataContentEncode", &c, 0);
}
TEST(kpm_spc_indirect_data_decode) {
    REQ_WV("WVTAsn1SpcIndirectDataContentEncode", "WVTAsn1SpcIndirectDataContentDecode");
    SPC_INDIRECT_DATA_CONTENT *r = WV_DEC("WVTAsn1SpcIndirectDataContentDecode", V(0x30,0x23,
        0x30,0x0e, 6,0x0a,0x2b,6,1,4,1,0x82,0x37,2,1,0x0f, 0x30,0,
        0x30,0x11, 0x30,9,6,5,0x2b,0x0e,3,2,0x1a,5,0, 4,4,1,2,3,4), 0);
    if (r) {
        EXPECT_STR(r->Data.pszObjId, SPC_PE_IMAGE_DATA_OBJID);
        BLOB_IS(r->Data.Value, 0x30, 0);
        EXPECT_STR(r->DigestAlgorithm.pszObjId, szOID_OIWSEC_sha1);
        BLOB_IS(r->DigestAlgorithm.Parameters, 5, 0);
        BLOB_IS(r->Digest, 1, 2, 3, 4);
        LocalFree(r);
    }
}
TEST(kpm_spc_indirect_data_decode_nocopy_digest_aliases_input) {
    REQ_WV("WVTAsn1SpcIndirectDataContentEncode", "WVTAsn1SpcIndirectDataContentDecode");
    static const BYTE der[] = {0x30,0x21, 0x30,0x0c, 6,0x0a,0x2b,6,1,4,1,0x82,0x37,2,1,0x0f, 0x30,0x11, 0x30,9,6,5,0x2b,0x0e,3,2,0x1a,5,0, 4,4,1,2,3,4};
    DWORD cb = 0;
    CHECK(wv_d("WVTAsn1SpcIndirectDataContentDecode")(KP_ENC, NULL, der, sizeof der, CRYPT_DECODE_NOCOPY_FLAG, NULL, &cb));
    BYTE buf[512]; DWORD cb2 = sizeof buf;
    CHECK(wv_d("WVTAsn1SpcIndirectDataContentDecode")(KP_ENC, NULL, der, sizeof der, CRYPT_DECODE_NOCOPY_FLAG, buf, &cb2));
    SPC_INDIRECT_DATA_CONTENT *r = (SPC_INDIRECT_DATA_CONTENT *)buf;
    CHECK(r->Digest.cbData == 4 && r->Digest.pbData >= der && r->Digest.pbData < der + sizeof der);
}
TEST(kpm_spc_indirect_data_decode_errors) {
    REQ_WV("WVTAsn1SpcIndirectDataContentEncode", "WVTAsn1SpcIndirectDataContentDecode");
    WV_DEC_FAILV("WVTAsn1SpcIndirectDataContentDecode", KP_E_BADTAG, 2, 1, 1);
    WV_DEC_FAILV("WVTAsn1SpcIndirectDataContentDecode", 0, 0x30, 0);
    WV_DEC_FAILV("WVTAsn1SpcIndirectDataContentDecode", KP_E_TRUNC, 0x30, 0x23, 0x30, 0x0e, 6);
}

/* ---------------------------------------------------------------- SPC_STATEMENT_TYPE, SPC_FINANCIAL/MINIMAL_CRITERIA */
TEST(kpm_spc_statement_type_encode_decode) {
    REQ_WV("WVTAsn1SpcStatementTypeEncode", "WVTAsn1SpcStatementTypeDecode");
    LPSTR ids[2] = { (LPSTR)"1.2.3", (LPSTR)"1.2.4" };
    SPC_STATEMENT_TYPE s = { 2, ids };
    WV_ENC_EQ("WVTAsn1SpcStatementTypeEncode", &s, V(0x30,8, 6,2,0x2a,3, 6,2,0x2a,4));
    s.cKeyPurposeId = 0;
    WV_ENC_EQ("WVTAsn1SpcStatementTypeEncode", &s, V(0x30,0));
    SPC_STATEMENT_TYPE *r = WV_DEC("WVTAsn1SpcStatementTypeDecode", V(0x30,8, 6,2,0x2a,3, 6,2,0x2a,4), 0);
    if (r) { CHECK(r->cKeyPurposeId == 2); if (r->cKeyPurposeId == 2) { EXPECT_STR(r->rgpszKeyPurposeId[0], "1.2.3"); EXPECT_STR(r->rgpszKeyPurposeId[1], "1.2.4"); } LocalFree(r); }
}
TEST(kpm_spc_statement_type_known_purposes) {
    REQ_WV("WVTAsn1SpcStatementTypeEncode", "WVTAsn1SpcStatementTypeDecode");
    LPSTR ids[1] = { (LPSTR)SPC_COMMERCIAL_SP_KEY_PURPOSE_OBJID };
    SPC_STATEMENT_TYPE s = { 1, ids };
    WV_ENC_EQ("WVTAsn1SpcStatementTypeEncode", &s, V(0x30,12, 6,10,0x2b,6,1,4,1,0x82,0x37,2,1,0x16));
    ids[0] = (LPSTR)SPC_INDIVIDUAL_SP_KEY_PURPOSE_OBJID;
    WV_ENC_EQ("WVTAsn1SpcStatementTypeEncode", &s, V(0x30,12, 6,10,0x2b,6,1,4,1,0x82,0x37,2,1,0x15));
}
TEST(kpm_spc_statement_type_bad_oid) {
    REQ_WV("WVTAsn1SpcStatementTypeEncode", "WVTAsn1SpcStatementTypeDecode");
    LPSTR ids[1] = { (LPSTR)"x.y" };
    SPC_STATEMENT_TYPE s = { 1, ids };
    WV_ENC_FAIL("WVTAsn1SpcStatementTypeEncode", &s, 0);
}
TEST(kpm_spc_statement_type_decode_errors) {
    REQ_WV("WVTAsn1SpcStatementTypeEncode", "WVTAsn1SpcStatementTypeDecode");
    WV_DEC_FAILV("WVTAsn1SpcStatementTypeDecode", KP_E_BADTAG, 0x31, 0);
    WV_DEC_FAILV("WVTAsn1SpcStatementTypeDecode", KP_E_BADTAG, 0x30, 3, 2, 1, 1);
}
TEST(kpm_spc_financial_criteria) {
    REQ_WV("WVTAsn1SpcFinancialCriteriaInfoEncode", "WVTAsn1SpcFinancialCriteriaInfoDecode");
    SPC_FINANCIAL_CRITERIA c = { TRUE, FALSE };
    WV_ENC_EQ("WVTAsn1SpcFinancialCriteriaInfoEncode", &c, V(0x30,6, 1,1,0xff, 1,1,0));
    c.fFinancialInfoAvailable = FALSE; c.fMeetsCriteria = TRUE;
    WV_ENC_EQ("WVTAsn1SpcFinancialCriteriaInfoEncode", &c, V(0x30,6, 1,1,0, 1,1,0xff));
    c.fFinancialInfoAvailable = 7; c.fMeetsCriteria = 0x100;      /* any non-zero BOOL: only the low byte is looked at */
    DWORD cb = 0; wv_e("WVTAsn1SpcFinancialCriteriaInfoEncode")(KP_ENC, NULL, &c, NULL, &cb);
    t_note("non-canonical BOOL values encode to %lu bytes", cb);
}
TEST(kpm_spc_financial_criteria_decode) {
    REQ_WV("WVTAsn1SpcFinancialCriteriaInfoEncode", "WVTAsn1SpcFinancialCriteriaInfoDecode");
    SPC_FINANCIAL_CRITERIA *r = WV_DEC("WVTAsn1SpcFinancialCriteriaInfoDecode", V(0x30,6, 1,1,0xff, 1,1,0), 0);
    if (r) { CHECK(r->fFinancialInfoAvailable == TRUE && r->fMeetsCriteria == FALSE); LocalFree(r); }
    WV_DEC_FAILV("WVTAsn1SpcFinancialCriteriaInfoDecode", KP_E_BADTAG, 2, 1, 1);
    WV_DEC_FAILV("WVTAsn1SpcFinancialCriteriaInfoDecode", KP_E_BADTAG, 0x30, 6, 2, 1, 1, 2, 1, 1);
}
TEST(kpm_spc_minimal_criteria) {
    REQ_WV("WVTAsn1SpcMinimalCriteriaInfoEncode", "WVTAsn1SpcMinimalCriteriaInfoDecode");
    BOOL b = TRUE;
    WV_ENC_EQ("WVTAsn1SpcMinimalCriteriaInfoEncode", &b, V(1,1,0xff));
    b = FALSE;
    WV_ENC_EQ("WVTAsn1SpcMinimalCriteriaInfoEncode", &b, V(1,1,0));
    BOOL *r = WV_DEC("WVTAsn1SpcMinimalCriteriaInfoDecode", V(1,1,0xff), 0);
    if (r) { CHECK(*r == TRUE); LocalFree(r); }
    WV_DEC_FAILV("WVTAsn1SpcMinimalCriteriaInfoDecode", KP_E_BADTAG, 2, 1, 1);
}

/* ---------------------------------------------------------------- SPC_SP_AGENCY_INFO */
TEST(kpm_spc_agency_info_encode_decode) {
    REQ_WV("WVTAsn1SpcSpAgencyInfoEncode", "WVTAsn1SpcSpAgencyInfoDecode");
    SPC_SP_AGENCY_INFO a; memset(&a, 0, sizeof a);
    DWORD cb = 0;
    CHECK(wv_e("WVTAsn1SpcSpAgencyInfoEncode")(KP_ENC, NULL, &a, NULL, &cb));
    BYTE buf[64]; CHECK(cb <= sizeof buf);
    if (cb <= sizeof buf) {
        CHECK(wv_e("WVTAsn1SpcSpAgencyInfoEncode")(KP_ENC, NULL, &a, buf, &cb));
        CHECK(cb == 2 && buf[0] == 0x30 && buf[1] == 0);
    }
    SPC_LINK url; memset(&url, 0, sizeof url); url.dwLinkChoice = SPC_URL_LINK_CHOICE; url.pwszUrl = (LPWSTR)L"http://a";
    a.pPolicyInformation = &url; a.pwszPolicyDisplayText = L"Hi";
    cb = sizeof buf; CHECK(wv_e("WVTAsn1SpcSpAgencyInfoEncode")(KP_ENC, NULL, &a, buf, &cb));
    SPC_SP_AGENCY_INFO *r = WV_DEC("WVTAsn1SpcSpAgencyInfoDecode", buf, cb, 0);
    if (r) {
        CHECK(r->pPolicyInformation && r->pPolicyInformation->dwLinkChoice == SPC_URL_LINK_CHOICE);
        CHECK(r->pwszPolicyDisplayText && !lstrcmpW(r->pwszPolicyDisplayText, L"Hi"));
        CHECK(r->pLogoImage == NULL && r->pLogoLink == NULL);
        LocalFree(r);
    }
}

/* ---------------------------------------------------------------- QC statements, logotypes */
TEST(kpm_qc_statements_by_oid) {
    REQ_CRYPT32();
    CERT_QC_STATEMENT st[2];
    st[0].pszStatementId = (LPSTR)szOID_QC_EU_COMPLIANCE; st[0].StatementInfo.cbData = 0; st[0].StatementInfo.pbData = NULL;
    st[1].pszStatementId = (LPSTR)"1.2.3"; st[1].StatementInfo.cbData = 3; st[1].StatementInfo.pbData = (BYTE *)"\x02\x01\x07";
    CERT_QC_STATEMENTS_EXT_INFO q = { 2, st };
    DWORD cb = 0; BYTE *e = kp_enc_alloc(szOID_QC_STATEMENTS_EXT, &q, 0, &cb);
    if (!e) { t_note("szOID_QC_STATEMENTS_EXT encode: err=0x%lx", GetLastError()); return; }
    /* SEQUENCE OF SEQUENCE { statementId OID, statementInfo ANY OPTIONAL }: absent info is omitted */
    static const BYTE want[] = {0x30,0x13, 0x30,7,6,5,0x04,0x00,0x8e,0x46,0x01, 0x30,8,6,2,0x2a,3,2,1,7};
    CHECK(cb == sizeof want && !memcmp(e, want, cb));
    CERT_QC_STATEMENTS_EXT_INFO *r = kp_dec_alloc(szOID_QC_STATEMENTS_EXT, e, cb, 0, NULL);
    CHECK(r && r->cStatement == 2);
    if (r && r->cStatement == 2) { EXPECT_STR(r->rgStatement[0].pszStatementId, szOID_QC_EU_COMPLIANCE); CHECK(r->rgStatement[0].StatementInfo.cbData == 0); BLOB_IS(r->rgStatement[1].StatementInfo, 2,1,7); }
    kp_free(r); kp_free(e);
}
TEST(kpm_qc_statements_empty) {
    REQ_CRYPT32();
    CERT_QC_STATEMENTS_EXT_INFO q = { 0, NULL };
    DWORD cb = 0; BYTE *e = kp_enc_alloc(szOID_QC_STATEMENTS_EXT, &q, 0, &cb);
    if (!e) { t_note("szOID_QC_STATEMENTS_EXT encode: err=0x%lx", GetLastError()); return; }
    CHECK(cb == 2 && e[0] == 0x30 && e[1] == 0);
    kp_free(e);
}
TEST(kpm_qc_statements_numeric_type_is_smime_codec) {
    REQ_CRYPT32();
    /* X509_QC_STATEMENTS_EXT and PKCS_SMIME_CAPABILITIES share the value 42 */
    CHECK((ULONG_PTR)X509_QC_STATEMENTS_EXT == (ULONG_PTR)PKCS_SMIME_CAPABILITIES);
    CERT_QC_STATEMENT st = { (LPSTR)"1.2.3", { 0, NULL } };
    CERT_QC_STATEMENTS_EXT_INFO q = { 1, &st };
    ENC_EQ(X509_QC_STATEMENTS_EXT, &q, V(0x30,6, 0x30,4,6,2,0x2a,3));
}

static const BYTE sha1_hash[4] = {1,2,3,4};
static void fill_hashed_url(CERT_HASHED_URL *h) {
    memset(h, 0, sizeof *h);
    h->HashAlgorithm.pszObjId = (LPSTR)szOID_OIWSEC_sha1;
    h->Hash.cbData = 4; h->Hash.pbData = (BYTE *)sha1_hash;
    h->pwszUrl = (LPWSTR)L"http://a";
}
TEST(kpm_logotype_indirect_subject_logo) {
    REQ_TYPE(X509_LOGOTYPE_EXT);
    CERT_HASHED_URL hu; fill_hashed_url(&hu);
    CERT_LOGOTYPE_REFERENCE ref = { 1, &hu };
    CERT_LOGOTYPE_INFO info; memset(&info, 0, sizeof info);
    info.dwLogotypeInfoChoice = CERT_LOGOTYPE_INDIRECT_INFO_CHOICE; info.pLogotypeIndirectInfo = &ref;
    CERT_LOGOTYPE_EXT_INFO ext; memset(&ext, 0, sizeof ext); ext.pSubjectLogo = &info;
    DWORD cb = 0; BYTE *e = kp_enc_alloc(X509_LOGOTYPE_EXT, &ext, 0, &cb);
    CHECK(e != NULL);
    if (!e) return;
    /* LogotypeExtn { subjectLogo [2] EXPLICIT LogotypeInfo }, LogotypeInfo.indirect = [1] LogotypeReference */
    CHECK(cb > 8 && e[0] == 0x30 && e[2] == 0xa2 && e[4] == 0xa1);
    static const BYTE hash_part[] = {0x30,0x11, 0x30,9,6,5,0x2b,0x0e,3,2,0x1a,5,0, 4,4,1,2,3,4};
    CHECK(cb >= 10 + sizeof hash_part);
    int found = 0; for (DWORD i = 0; i + sizeof hash_part <= cb; i++) if (!memcmp(e + i, hash_part, sizeof hash_part)) found = 1;
    CHECK(found);
    CERT_LOGOTYPE_EXT_INFO *r = kp_dec_alloc(X509_LOGOTYPE_EXT, e, cb, 0, NULL);
    CHECK(r != NULL);
    if (r) {
        CHECK(r->cCommunityLogo == 0 && r->pIssuerLogo == NULL && r->cOtherLogo == 0);
        CHECK(r->pSubjectLogo && r->pSubjectLogo->dwLogotypeInfoChoice == CERT_LOGOTYPE_INDIRECT_INFO_CHOICE);
        if (r->pSubjectLogo && r->pSubjectLogo->dwLogotypeInfoChoice == CERT_LOGOTYPE_INDIRECT_INFO_CHOICE) {
            CERT_LOGOTYPE_REFERENCE *rr = r->pSubjectLogo->pLogotypeIndirectInfo;
            CHECK(rr && rr->cHashedUrl == 1);
            if (rr && rr->cHashedUrl == 1) { EXPECT_STR(rr->rgHashedUrl[0].HashAlgorithm.pszObjId, szOID_OIWSEC_sha1); BLOB_IS(rr->rgHashedUrl[0].Hash, 1,2,3,4); CHECK(!lstrcmpW(rr->rgHashedUrl[0].pwszUrl, L"http://a")); }
        }
        kp_free(r);
    }
    kp_free(e);
}
TEST(kpm_logotype_empty_extension) {
    REQ_TYPE(X509_LOGOTYPE_EXT);
    CERT_LOGOTYPE_EXT_INFO ext; memset(&ext, 0, sizeof ext);
    ENC_EQ(X509_LOGOTYPE_EXT, &ext, V(0x30,0));
}
TEST(kpm_logotype_community_and_issuer) {
    REQ_TYPE(X509_LOGOTYPE_EXT);
    CERT_HASHED_URL hu; fill_hashed_url(&hu);
    CERT_LOGOTYPE_REFERENCE ref = { 1, &hu };
    CERT_LOGOTYPE_INFO info; memset(&info, 0, sizeof info);
    info.dwLogotypeInfoChoice = CERT_LOGOTYPE_INDIRECT_INFO_CHOICE; info.pLogotypeIndirectInfo = &ref;
    CERT_LOGOTYPE_EXT_INFO ext; memset(&ext, 0, sizeof ext);
    ext.cCommunityLogo = 1; ext.rgCommunityLogo = &info; ext.pIssuerLogo = &info;
    DWORD cb = 0; BYTE *e = kp_enc_alloc(szOID_LOGOTYPE_EXT, &ext, 0, &cb);
    CHECK(e != NULL);
    if (!e) return;
    CHECK(e[0] == 0x30 && e[2] == 0xa0);                        /* communityLogos [0] first */
    CERT_LOGOTYPE_EXT_INFO *r = kp_dec_alloc(szOID_LOGOTYPE_EXT, e, cb, 0, NULL);
    CHECK(r && r->cCommunityLogo == 1 && r->pIssuerLogo && r->pSubjectLogo == NULL);
    kp_free(r); kp_free(e);
}
TEST(kpm_logotype_decode_errors) {
    REQ_TYPE(X509_LOGOTYPE_EXT);
    DEC_FAILV(X509_LOGOTYPE_EXT, KP_E_BADTAG, 2, 1, 1);
    DEC_FAILV(X509_LOGOTYPE_EXT, KP_E_BADTAG, 0x30, 2, 0xa5, 0);
}

/* ---------------------------------------------------------------- dispatcher behaviour */
static int g_alloc_calls, g_free_calls; static void *g_last_alloc;
static void *WINAPI cnt_alloc(size_t n) { g_alloc_calls++; g_last_alloc = LocalAlloc(LPTR, n); return g_last_alloc; }
static void WINAPI cnt_free(void *p) { g_free_calls++; LocalFree(p); }

TEST(kpm_encode_custom_allocator_used_for_alloc_flag) {
    REQ_CRYPT32();
    CRYPT_ENCODE_PARA para; memset(&para, 0, sizeof para);
    para.cbSize = sizeof para; para.pfnAlloc = cnt_alloc; para.pfnFree = cnt_free;
    int v = 5; BYTE *out = NULL; DWORD cb = 0; g_alloc_calls = g_free_calls = 0; g_last_alloc = NULL;
    CHECK(U(CryptEncodeObjectEx)(KP_ENC, X509_INTEGER, &v, CRYPT_ENCODE_ALLOC_FLAG, &para, &out, &cb));
    EXPECT_EQ(g_alloc_calls, 1); CHECK(out == (BYTE *)g_last_alloc); EXPECT_EQ(cb, 3);
    if (out) { CHECK(out[0] == 2 && out[2] == 5); para.pfnFree(out); }
}
TEST(kpm_encode_custom_allocator_ignored_without_alloc_flag) {
    REQ_CRYPT32();
    CRYPT_ENCODE_PARA para; memset(&para, 0, sizeof para);
    para.cbSize = sizeof para; para.pfnAlloc = cnt_alloc; para.pfnFree = cnt_free;
    int v = 5; BYTE buf[8]; DWORD cb = sizeof buf; g_alloc_calls = 0;
    CHECK(U(CryptEncodeObjectEx)(KP_ENC, X509_INTEGER, &v, 0, &para, buf, &cb));
    EXPECT_EQ(g_alloc_calls, 0);
}
TEST(kpm_encode_para_too_small_means_default_allocator) {
    REQ_CRYPT32();
    CRYPT_ENCODE_PARA para; memset(&para, 0, sizeof para);
    para.cbSize = 15; para.pfnAlloc = cnt_alloc; para.pfnFree = cnt_free;     /* cbSize must be >= 16 to cover pfnAlloc */
    int v = 5; BYTE *out = NULL; DWORD cb = 0; g_alloc_calls = 0;
    CHECK(U(CryptEncodeObjectEx)(KP_ENC, X509_INTEGER, &v, CRYPT_ENCODE_ALLOC_FLAG, &para, &out, &cb));
    t_note("encode para cbSize=15: custom allocator calls=%d", g_alloc_calls);
    if (out && g_alloc_calls == 0) LocalFree(out);
}
TEST(kpm_encode_para_exact_cbsize_16_uses_allocator) {
    REQ_CRYPT32();
    CRYPT_ENCODE_PARA para; memset(&para, 0, sizeof para);
    para.cbSize = 16; para.pfnAlloc = cnt_alloc; para.pfnFree = NULL;
    int v = 5; BYTE *out = NULL; DWORD cb = 0; g_alloc_calls = 0;
    CHECK(U(CryptEncodeObjectEx)(KP_ENC, X509_INTEGER, &v, CRYPT_ENCODE_ALLOC_FLAG, &para, &out, &cb));
    EXPECT_EQ(g_alloc_calls, 1);
    if (out) LocalFree(out);
}
TEST(kpm_decode_para_too_small_means_default_allocator) {
    REQ_CRYPT32();
    CRYPT_DECODE_PARA para; memset(&para, 0, sizeof para);
    para.cbSize = 8; para.pfnAlloc = cnt_alloc; para.pfnFree = cnt_free;
    static const BYTE der[] = {2,1,9}; void *out = NULL; DWORD cb = 0; g_alloc_calls = 0;
    CHECK(U(CryptDecodeObjectEx)(KP_ENC, X509_INTEGER, der, 3, CRYPT_DECODE_ALLOC_FLAG, &para, &out, &cb));
    t_note("decode para cbSize=8: custom allocator calls=%d", g_alloc_calls);
    if (out && g_alloc_calls == 0) LocalFree(out);
}
TEST(kpm_decode_custom_allocator_used_for_alloc_flag) {
    REQ_CRYPT32();
    CRYPT_DECODE_PARA para; memset(&para, 0, sizeof para);
    para.cbSize = sizeof para; para.pfnAlloc = cnt_alloc; para.pfnFree = cnt_free;
    static const BYTE der[] = {2,1,9}; void *out = NULL; DWORD cb = 0; g_alloc_calls = 0; g_last_alloc = NULL;
    CHECK(U(CryptDecodeObjectEx)(KP_ENC, X509_INTEGER, der, 3, CRYPT_DECODE_ALLOC_FLAG, &para, &out, &cb));
    EXPECT_EQ(g_alloc_calls, 1); CHECK(out == g_last_alloc);
    if (out) { CHECK(*(int *)out == 9); para.pfnFree(out); }
}
TEST(kpm_decode_failure_does_not_call_allocator_result) {
    REQ_CRYPT32();
    CRYPT_DECODE_PARA para; memset(&para, 0, sizeof para);
    para.cbSize = sizeof para; para.pfnAlloc = cnt_alloc; para.pfnFree = cnt_free;
    static const BYTE der[] = {4,1,9}; void *out = (void *)(ULONG_PTR)1; DWORD cb = 5; g_alloc_calls = 0;
    CHECK(!U(CryptDecodeObjectEx)(KP_ENC, X509_INTEGER, der, 3, CRYPT_DECODE_ALLOC_FLAG, &para, &out, &cb));
    t_note("decode failure with ALLOC: out=%p cb=%lu allocs=%d", out, (unsigned long)cb, g_alloc_calls);
}
TEST(kpm_encode_alloc_flag_failure_leaves_null_and_zero) {
    REQ_CRYPT32();
    int v = 1; BYTE *out = (BYTE *)(ULONG_PTR)1; DWORD cb = 9;
    CHECK(!U(CryptEncodeObjectEx)(KP_ENC, "9.9.9.9.9", &v, CRYPT_ENCODE_ALLOC_FLAG, NULL, &out, &cb));
    t_note("unknown oid with ALLOC: out=%p cb=%lu", out, (unsigned long)cb);
}
TEST(kpm_unknown_flag_bits_ignored_by_asn1_codecs) {
    REQ_CRYPT32();
    /* these codecs only look at the ALLOC bit; everything else in dwFlags is passed through unused */
    static const DWORD fl[] = { 0x2, 0x4, 0x8, 0x10, 0x40000000, 0x20000, 0x40000 };
    int v = 300;
    for (unsigned i = 0; i < sizeof fl / sizeof fl[0]; i++) {
        BYTE buf[8]; DWORD cb = sizeof buf;
        BOOL ok = U(CryptEncodeObjectEx)(KP_ENC, X509_INTEGER, &v, fl[i], NULL, buf, &cb);
        CHECKF(ok && cb == 4 && buf[0] == 2 && buf[2] == 1 && buf[3] == 0x2c, "flag 0x%lx", (unsigned long)fl[i]);
        int out = 0; cb = sizeof out;
        ok = U(CryptDecodeObjectEx)(KP_ENC, X509_INTEGER, buf, 4, fl[i], NULL, &out, &cb);
        CHECKF(ok && out == 300, "decode flag 0x%lx", (unsigned long)fl[i]);
    }
}
TEST(kpm_decode_object_non_ex_matches_ex) {
    REQ_CRYPT32();
    static const BYTE der[] = {2,2,1,0x2c}; int a = 0, b = 0; DWORD ca = sizeof a, cb = sizeof b;
    CHECK(U(CryptDecodeObject)(KP_ENC, X509_INTEGER, der, 4, 0, &a, &ca));
    CHECK(U(CryptDecodeObjectEx)(KP_ENC, X509_INTEGER, der, 4, 0, NULL, &b, &cb));
    CHECK(a == 300 && b == 300 && ca == cb);
}
TEST(kpm_decode_object_non_ex_size_protocol) {
    REQ_CRYPT32();
    static const BYTE der[] = {2,1,7}; int a = 0; DWORD ca = 0;
    CHECK(U(CryptDecodeObject)(KP_ENC, X509_INTEGER, der, 3, 0, NULL, &ca));
    EXPECT_EQ(ca, sizeof(int));
    ca = 1; SET_ERR(0);
    CHECK(!U(CryptDecodeObject)(KP_ENC, X509_INTEGER, der, 3, 0, &a, &ca));
    EXPECT_ERR(ERROR_MORE_DATA); EXPECT_EQ(ca, sizeof(int));
}
TEST(kpm_decode_object_non_ex_rejects_alloc_flag_semantics) {
    REQ_CRYPT32();
    /* CryptDecodeObject (non Ex) forwards dwFlags; with ALLOC the output slot is a pointer */
    static const BYTE der[] = {2,1,7}; void *out = NULL; DWORD cb = 0;
    BOOL ok = U(CryptDecodeObject)(KP_ENC, X509_INTEGER, der, 3, CRYPT_DECODE_ALLOC_FLAG, &out, &cb);
    t_note("CryptDecodeObject with ALLOC_FLAG: ok=%d out=%p", ok, out);
    if (ok && out) LocalFree(out);
}
TEST(kpm_hash_prefixed_type_decode_matches_numeric) {
    REQ_CRYPT32();
    if (t_is_wine()) { t_skip("emulator lacks #nnn struct types"); return; }
    static const BYTE der[] = {2,2,1,0x2c};
    int a = 0, b = 0; DWORD ca = sizeof a, cb = sizeof b;
    CHECK(U(CryptDecodeObjectEx)(KP_ENC, "#27", der, 4, 0, NULL, &a, &ca));
    CHECK(U(CryptDecodeObjectEx)(KP_ENC, X509_INTEGER, der, 4, 0, NULL, &b, &cb));
    CHECK(a == 300 && b == 300 && ca == cb);
    BYTE big[64]; cb = sizeof big;
    CHECK(U(CryptDecodeObjectEx)(KP_ENC, "#28", (const BYTE[]){2,1,5}, 3, 0, NULL, big, &cb));
}
TEST(kpm_hash_prefixed_type_garbage_numbers) {
    REQ_CRYPT32();
    BYTE buf[16]; DWORD cb = sizeof buf; static const BYTE der[] = {2,1,1};
    SET_ERR(0);
    BOOL ok = U(CryptDecodeObjectEx)(KP_ENC, "#", der, 3, 0, NULL, buf, &cb);
    t_note("\"#\" struct type: ok=%d err=0x%lx", ok, ok ? 0 : GetLastError());
    cb = sizeof buf; SET_ERR(0);
    ok = U(CryptDecodeObjectEx)(KP_ENC, "#abc", der, 3, 0, NULL, buf, &cb);
    t_note("\"#abc\" struct type: ok=%d err=0x%lx", ok, ok ? 0 : GetLastError());
    cb = sizeof buf; SET_ERR(0);
    ok = U(CryptDecodeObjectEx)(KP_ENC, "#99999", der, 3, 0, NULL, buf, &cb);
    CHECK(!ok);
    t_note("\"#99999\" struct type: err=0x%lx", GetLastError());
}
TEST(kpm_encode_null_size_pointer_not_probed) {
    REQ_CRYPT32();
    t_note("NULL pcbEncoded is not exercised: it is a caller bug, not DLL logic");
}
TEST(kpm_encoded_size_query_independent_of_input_size_value) {
    REQ_CRYPT32();
    int v = 5; DWORD cb = 12345;
    CHECK(U(CryptEncodeObjectEx)(KP_ENC, X509_INTEGER, &v, 0, NULL, NULL, &cb));
    EXPECT_EQ(cb, 3);
}
TEST(kpm_encode_more_data_reports_size_not_partial) {
    REQ_CRYPT32();
    int v = 0x12345678; BYTE buf[8]; memset(buf, 0x55, sizeof buf); DWORD cb = 2; SET_ERR(0);
    CHECK(!U(CryptEncodeObjectEx)(KP_ENC, X509_INTEGER, &v, 0, NULL, buf, &cb));
    EXPECT_ERR(ERROR_MORE_DATA); EXPECT_EQ(cb, 6);
    t_note("buffer after MORE_DATA: %02x %02x %02x", buf[0], buf[1], buf[2]);
}
TEST(kpm_encode_zero_buffer_size_with_buffer) {
    REQ_CRYPT32();
    int v = 5; BYTE buf[8]; DWORD cb = 0; SET_ERR(0);
    CHECK(!U(CryptEncodeObjectEx)(KP_ENC, X509_INTEGER, &v, 0, NULL, buf, &cb));
    EXPECT_ERR(ERROR_MORE_DATA); EXPECT_EQ(cb, 3);
}
TEST(kpm_decode_zero_buffer_size_with_buffer) {
    REQ_CRYPT32();
    static const BYTE der[] = {2,1,7}; int out = 0; DWORD cb = 0; SET_ERR(0);
    CHECK(!U(CryptDecodeObjectEx)(KP_ENC, X509_INTEGER, der, 3, 0, NULL, &out, &cb));
    EXPECT_ERR(ERROR_MORE_DATA); EXPECT_EQ(cb, sizeof(int));
}
TEST(kpm_decode_trailing_data_note) {
    REQ_CRYPT32();
    static const BYTE der[] = {0x30,0,0xff,0xff}; DWORD cb = 0; SET_ERR(0);
    BOOL ok = U(CryptDecodeObjectEx)(KP_ENC, X509_SEQUENCE_OF_ANY, der, 4, 0, NULL, NULL, &cb);
    t_note("SEQUENCE OF ANY with two trailing bytes: ok=%d err=0x%lx", ok, ok ? 0 : GetLastError());
}
