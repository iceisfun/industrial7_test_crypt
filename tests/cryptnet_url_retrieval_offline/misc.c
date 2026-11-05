#include "cnet.h"
/* Time-valid objects, host-name parsing, IRI conversion, revocation/CTL helpers, exports of cryptnet.dll. */

#define SENTINEL ((LPVOID)(ULONG_PTR)0x1234500)
#define CN(name) ((__typeof__(&name))t_proc_in("cryptnet.dll", #name))
#define NO_WINE(why) do { if (t_is_wine()) { t_skip("%s", why); return; } } while (0)

UDECL(BOOL, I_CryptNetGetHostNameFromUrl, (LPCWSTR url, int cch, LPWSTR out));
UDECL(int,  I_CryptConvertIriToAsciiOrUnicode, (int toUnicode, LPCWSTR iri, DWORD *pcch, LPWSTR out));
UDECL(int,  I_CryptConvertIriToAsciiOrUnicodeWithFlags, (DWORD flags, LPCWSTR iri, DWORD *pcch, LPWSTR out));
UDECL(int,  I_CryptNetGetConnectivity, (void));
UDECL(BOOL, I_CryptNetFlushOfflineUrl, (int *pcEntries));
UDECL(BOOL, CertDllVerifyRevocation, (DWORD enc, DWORD revType, DWORD cContext, PVOID rgpv[], DWORD flags, PCERT_REVOCATION_PARA para, PCERT_REVOCATION_STATUS st));
UDECL(BOOL, CertDllVerifyCTLUsage, (DWORD enc, DWORD subjType, void *subj, PCTL_USAGE usage, DWORD flags, PCTL_VERIFY_USAGE_PARA para, PCTL_VERIFY_USAGE_STATUS st));

#define PIN(name) ((name##_pfn)t_proc_in("cryptnet.dll", #name))

/* ---- exports ------------------------------------------------------------- */
TEST(cnmisc_exports_resolve) {
    static const char *names[] = {
        "CertDllVerifyCTLUsage", "CertDllVerifyRevocation", "CryptCancelAsyncRetrieval", "CryptFlushTimeValidObject",
        "CryptGetObjectUrl", "CryptGetTimeValidObject", "CryptInstallCancelRetrieval", "CryptRetrieveObjectByUrlA",
        "CryptRetrieveObjectByUrlW", "CryptUninstallCancelRetrieval", "DllRegisterServer", "DllUnregisterServer",
        "I_CryptConvertIriToAsciiOrUnicode", "I_CryptConvertIriToAsciiOrUnicodeWithFlags", "I_CryptNetAutoFlush",
        "I_CryptNetEnumUrlCacheEntry", "I_CryptNetFlushOfflineUrl", "I_CryptNetGetConnectivity",
        "I_CryptNetGetHostNameFromUrl", "I_CryptNetGetUserDsStoreUrl", "I_CryptNetSetUrlCacheFlushInfo",
        "I_CryptNetSetUrlCachePreFetchInfo", "LdapProvOpenStore" };
    HMODULE m = t_module("cryptnet.dll");
    REQUIRE(m);
    for (size_t i = 0; i < sizeof names / sizeof *names; i++) {
        FARPROC p = t_proc_in("cryptnet.dll", names[i]);
        CHECKF(p != NULL, "%s", names[i]);
        if (p) {
            /* an export resolves into the module image */
            CHECKF((BYTE *)p > (BYTE *)m && (BYTE *)p < (BYTE *)m + 0x200000, "%s outside image", names[i]);
        }
    }
}
TEST(cnmisc_exports_by_ordinal) {
    static const struct { unsigned ord; const char *name; } rows[] = {
        { 1, "CertDllVerifyCTLUsage" }, { 2, "CertDllVerifyRevocation" }, { 3, "I_CryptConvertIriToAsciiOrUnicode" },
        { 4, "I_CryptConvertIriToAsciiOrUnicodeWithFlags" }, { 5, "LdapProvOpenStore" }, { 6, "CryptCancelAsyncRetrieval" },
        { 7, "CryptFlushTimeValidObject" }, { 8, "CryptGetObjectUrl" }, { 9, "CryptGetTimeValidObject" },
        { 10, "CryptInstallCancelRetrieval" }, { 11, "CryptRetrieveObjectByUrlA" }, { 12, "CryptRetrieveObjectByUrlW" },
        { 13, "CryptUninstallCancelRetrieval" }, { 16, "I_CryptNetAutoFlush" }, { 17, "I_CryptNetEnumUrlCacheEntry" },
        { 18, "I_CryptNetFlushOfflineUrl" }, { 19, "I_CryptNetGetConnectivity" }, { 20, "I_CryptNetGetHostNameFromUrl" },
        { 21, "I_CryptNetGetUserDsStoreUrl" } };
    REQUIRE(t_module("cryptnet.dll"));
    if (t_is_wine()) { t_skip("ordinal numbering differs in the emulator"); return; }
    for (size_t i = 0; i < sizeof rows / sizeof *rows; i++) {
        FARPROC a = t_proc_ord("cryptnet.dll", rows[i].ord), b = t_proc_in("cryptnet.dll", rows[i].name);
        CHECKF(a != NULL && a == b, "ordinal %u / %s", rows[i].ord, rows[i].name);
    }
}
TEST(cnmisc_forwarders_none) {
    /* the retrieval API lives in cryptnet itself: no forwarding to crypt32 */
    HMODULE m = t_module("cryptnet.dll"); REQUIRE(m);
    FARPROC p = t_proc_in("cryptnet.dll", "CryptRetrieveObjectByUrlW");
    REQUIRE(p);
    HMODULE owner = NULL;
    GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)p, &owner);
    CHECK(owner == m);
}
TEST(cnmisc_getprocaddress_negative) {
    HMODULE m = t_module("cryptnet.dll"); REQUIRE(m);
    SET_ERR(0);
    CHECK(GetProcAddress(m, "CryptRetrieveObjectByUrl") == NULL);   /* only the A/W names exist */
    EXPECT_ERR(ERROR_PROC_NOT_FOUND);
    SET_ERR(0);
    CHECK(GetProcAddress(m, "cryptretrieveobjectbyurlw") == NULL);  /* export names are case sensitive */
    EXPECT_ERR(ERROR_PROC_NOT_FOUND);
    SET_ERR(0);
    CHECK(GetProcAddress(m, "I_CryptNetNoSuchThing") == NULL);
    EXPECT_ERR(ERROR_PROC_NOT_FOUND);
}

/* ---- I_CryptNetGetHostNameFromUrl ------------------------------------------ */
static BOOL host(const WCHAR *url, int cch, WCHAR *out) { return PIN(I_CryptNetGetHostNameFromUrl)(url, cch, out); }

TEST(cnhost_vectors) {
    REQUIRE(PIN(I_CryptNetGetHostNameFromUrl));
    NO_WINE("host-name helper differs in the emulator");
    static const struct { const WCHAR *url, *host; } rows[] = {
        { L"http://www.example.test/path", L"www.example.test" },
        { L"http://www.example.test", L"www.example.test" },
        { L"http://www.example.test/", L"www.example.test" },
        { L"https://a.b.example.test:8443/x/y?z=1#f", L"a.b.example.test" },
        { L"ldap://dc1.example.test/CN=CA?cACertificate?base", L"dc1.example.test" },
        { L"ldap://dc1.example.test:389/CN=CA", L"dc1.example.test" },
        { L"http://xn--bcher-kva.example/x", L"xn--bcher-kva.example" },
        { L"http://localhost/x", L"localhost" },
        { L"http://127.0.0.1:8080/x", L"127.0.0.1" },
        { L"ftp://ftp.example.test/pub", L"ftp.example.test" },
        { L"http://a/", L"a" },
    };
    for (size_t i = 0; i < sizeof rows / sizeof *rows; i++) {
        WCHAR buf[260]; wmemset(buf, 0x7777, 260); SET_ERR(0);
        BOOL ok = host(rows[i].url, 260, buf);
        CHECKF(ok, "%ls err=0x%lx", rows[i].url, GetLastError());
        if (ok) CHECKF(!wcscmp(buf, rows[i].host), "%ls -> %ls", rows[i].url, buf);
    }
}
TEST(cnhost_leading_spaces) {
    REQUIRE(PIN(I_CryptNetGetHostNameFromUrl));
    NO_WINE("host-name helper differs in the emulator");
    WCHAR buf[260];
    CHECK(host(L"   http://sp.example.test/x", 260, buf));
    CHECK(!wcscmp(buf, L"sp.example.test"));
    BOOL okt = host(L" \t", 260, buf);   /* tab is not trimmed; shlwapi decides */
    t_note("tab-only url: ok=%d", okt);
}
TEST(cnhost_zero_buffer) {
    REQUIRE(PIN(I_CryptNetGetHostNameFromUrl));
    NO_WINE("host-name helper differs in the emulator");
    WCHAR buf[4] = { 0x7777, 0x7777, 0x7777, 0x7777 };
    SET_ERR(0);
    CHECK(!host(L"http://www.example.test/", 0, buf));
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    CHECK(buf[0] == 0x7777);   /* untouched */
    SET_ERR(0);
    CHECK(!host(L"http://www.example.test/", 0, NULL));
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
    CHECK(!host(L"", 0, NULL));
}
TEST(cnhost_output_cleared_first) {
    REQUIRE(PIN(I_CryptNetGetHostNameFromUrl));
    NO_WINE("host-name helper differs in the emulator");
    WCHAR buf[260]; wmemset(buf, 0x7777, 260);
    BOOL ok = host(L"file:///C:/dir/x.cer", 260, buf);
    t_note("file:///C:/... host: ok=%d err=0x%lx", ok, ok ? 0 : GetLastError());
    if (!ok) CHECK(buf[0] == 0);
    wmemset(buf, 0x7777, 260);
    ok = host(L"no-scheme.example.test/path", 260, buf);
    t_note("no scheme: ok=%d err=0x%lx", ok, ok ? 0 : GetLastError());
    CHECK(buf[0] == 0 || ok);
    wmemset(buf, 0x7777, 260);
    ok = host(L"", 260, buf);
    if (!ok) CHECK(buf[0] == 0);
}
TEST(cnhost_buffer_boundaries) {
    REQUIRE(PIN(I_CryptNetGetHostNameFromUrl));
    NO_WINE("host-name helper differs in the emulator");
    /* the helper passes cch-1 on to the part extractor: observe where the boundary falls */
    const WCHAR *url = L"http://www.example.test/x";   /* host is 16 characters */
    int firstok = -1;
    for (int cch = 1; cch <= 24; cch++) {
        WCHAR buf[32]; wmemset(buf, 0x7777, 32); SET_ERR(0);
        BOOL ok = host(url, cch, buf);
        if (ok && firstok < 0) firstok = cch;
        if (!ok) CHECKF(buf[0] == 0, "cch=%d buffer not cleared", cch);
        if (ok) CHECKF(!wcscmp(buf, L"www.example.test"), "cch=%d -> %ls", cch, buf);
        CHECKF(ok == (firstok >= 0), "cch=%d success is not monotonic", cch);
    }
    t_note("smallest cch that succeeds for a 16-character host: %d", firstok);
    CHECK(firstok >= 17 && firstok <= 19);
}
TEST(cnhost_userinfo_and_port_notes) {
    REQUIRE(PIN(I_CryptNetGetHostNameFromUrl));
    NO_WINE("host-name helper differs in the emulator");
    static const WCHAR *urls[] = { L"http://user:pw@h.example.test/", L"http://user@h.example.test:81/" };
    for (int i = 0; i < 2; i++) {
        WCHAR buf[260];
        BOOL ok = host(urls[i], 260, buf);
        t_note("%ls -> ok=%d '%ls'", urls[i], ok, ok ? buf : L"-");
    }
}
TEST(cnhost_case_and_ip) {
    REQUIRE(PIN(I_CryptNetGetHostNameFromUrl));
    NO_WINE("host-name helper differs in the emulator");
    WCHAR buf[260];
    CHECK(host(L"HTTP://MiXeD.Example.TEST/", 260, buf));
    t_note("mixed-case host returned as: %ls", buf);
    CHECK(!_wcsicmp(buf, L"mixed.example.test"));
    BOOL ok = host(L"http://[::1]:80/x", 260, buf);
    t_note("ipv6 literal host: ok=%d value=%ls", ok, ok ? buf : L"-");
}

/* ---- I_CryptConvertIriToAsciiOrUnicode(+WithFlags) --------------------------- */
static int iri(int toUni, const WCHAR *in, DWORD *cch, WCHAR *out) { return PIN(I_CryptConvertIriToAsciiOrUnicode)(toUni, in, cch, out); }
static int iriF(DWORD fl, const WCHAR *in, DWORD *cch, WCHAR *out) { return PIN(I_CryptConvertIriToAsciiOrUnicodeWithFlags)(fl, in, cch, out); }
#define F_UNICODE 0x20000
#define F_ASCII   0x2000000
#define F_ESCAPE  0x40000
#define F_UNESC   0x4000000

static const WCHAR IRI_BUCHER[]  = L"http://b\x00fc" L"cher.example/";
static const WCHAR PUNY_BUCHER[] = L"http://xn--bcher-kva.example/";

TEST(cniri_to_ascii) {
    REQUIRE(PIN(I_CryptConvertIriToAsciiOrUnicode));
    NO_WINE("IRI helper differs in the emulator");
    WCHAR out[300]; DWORD n = 300; SET_ERR(0);
    int r = iri(0, IRI_BUCHER, &n, out);
    CHECKF(r == 1, "err=0x%lx", GetLastError());
    if (r == 1) CHECKF(!wcscmp(out, PUNY_BUCHER), "got %ls", out);
}
TEST(cniri_to_unicode) {
    REQUIRE(PIN(I_CryptConvertIriToAsciiOrUnicode));
    NO_WINE("IRI helper differs in the emulator");
    WCHAR out[300]; DWORD n = 300; SET_ERR(0);
    int r = iri(1, PUNY_BUCHER, &n, out);
    CHECKF(r == 1, "err=0x%lx", GetLastError());
    if (r == 1) CHECKF(!wcscmp(out, IRI_BUCHER), "got %ls", out);
}
TEST(cniri_ascii_passthrough) {
    REQUIRE(PIN(I_CryptConvertIriToAsciiOrUnicode));
    NO_WINE("IRI helper differs in the emulator");
    static const WCHAR *urls[] = { L"http://www.example.test/path?q=1", L"https://a.example.test:8443/", L"ldap://dc.example.test/CN=CA?cACertificate?base", L"http://www.example.test" };
    for (int to = 0; to < 2; to++)
        for (size_t i = 0; i < 4; i++) {
            WCHAR out[300]; DWORD n = 300; SET_ERR(0);
            int r = iri(to, urls[i], &n, out);
            CHECKF(r == 1, "to=%d %ls err=0x%lx", to, urls[i], GetLastError());
            if (r == 1) CHECKF(!wcscmp(out, urls[i]), "to=%d %ls -> %ls", to, urls[i], out);
        }
}
TEST(cniri_idn_table) {
    REQUIRE(PIN(I_CryptConvertIriToAsciiOrUnicode));
    NO_WINE("IRI helper differs in the emulator");
    static const struct { const WCHAR *uni, *ascii; } rows[] = {
        { L"http://b\x00fc" L"cher.example/x", L"http://xn--bcher-kva.example/x" },
        { L"http://m\x00fc" L"nchen.example.test/", L"http://xn--mnchen-3ya.example.test/" },
        { L"http://caf\x00e9.example/", L"http://xn--caf-dma.example/" },
        { L"http://\x00fc" L"ber.example/", L"http://xn--ber-goa.example/" },
        { L"https://r\x00e9sum\x00e9.example:8443/a?b=c", L"https://xn--rsum-bpad.example:8443/a?b=c" },
        { L"http://\x4f8b\x3048.example/", L"http://xn--r8jz45g.example/" },
    };
    for (size_t i = 0; i < sizeof rows / sizeof *rows; i++) {
        WCHAR out[300]; DWORD n = 300; SET_ERR(0);
        int r = iri(0, rows[i].uni, &n, out);
        CHECKF(r == 1, "row %zu err=0x%lx", i, GetLastError());
        if (r == 1) CHECKF(!wcscmp(out, rows[i].ascii), "row %zu: got %ls", i, out);
        n = 300; SET_ERR(0);
        r = iri(1, rows[i].ascii, &n, out);
        CHECKF(r == 1, "row %zu back err=0x%lx", i, GetLastError());
        if (r == 1) CHECKF(!wcscmp(out, rows[i].uni), "row %zu back: got %ls", i, out);
    }
}
TEST(cniri_with_flags_equivalence) {
    REQUIRE(PIN(I_CryptConvertIriToAsciiOrUnicodeWithFlags));
    NO_WINE("IRI helper differs in the emulator");
    WCHAR a[300], b[300]; DWORD n = 300, m = 300;
    CHECK(iriF(F_ASCII, IRI_BUCHER, &n, a) == 1);
    CHECK(iri(0, IRI_BUCHER, &m, b) == 1);
    CHECK(!wcscmp(a, b));
    CHECK(!wcscmp(a, PUNY_BUCHER));
    n = m = 300;
    CHECK(iriF(F_UNICODE, PUNY_BUCHER, &n, a) == 1);
    CHECK(iri(1, PUNY_BUCHER, &m, b) == 1);
    CHECK(!wcscmp(a, b));
    CHECK(!wcscmp(a, IRI_BUCHER));
}
TEST(cniri_flags_zero_is_copy) {
    REQUIRE(PIN(I_CryptConvertIriToAsciiOrUnicodeWithFlags));
    NO_WINE("IRI helper differs in the emulator");
    /* neither conversion flag: the host is left alone */
    WCHAR out[300]; DWORD n = 300; SET_ERR(0);
    int r = iriF(0, IRI_BUCHER, &n, out);
    CHECKF(r == 1, "err=0x%lx", GetLastError());
    if (r == 1) CHECK(!wcscmp(out, IRI_BUCHER));
    n = 300;
    r = iriF(0, PUNY_BUCHER, &n, out);
    CHECK(r == 1);
    if (r == 1) CHECK(!wcscmp(out, PUNY_BUCHER));
}
TEST(cniri_buffer_protocol) {
    REQUIRE(PIN(I_CryptConvertIriToAsciiOrUnicode));
    NO_WINE("IRI helper differs in the emulator");
    const WCHAR *in = L"http://www.example.test/";   /* 24 characters, 25 with the terminator */
    WCHAR out[64]; DWORD n;
    /* size query */
    n = 0; SET_ERR(0);
    CHECK(iri(0, in, &n, NULL) == 0);
    EXPECT_ERR(NTE_BAD_LEN);
    EXPECT_EQ(n, 25);
    /* too small by one */
    wmemset(out, 0x7777, 64); n = 24; SET_ERR(0);
    CHECK(iri(0, in, &n, out) == 0);
    EXPECT_ERR(NTE_BAD_LEN);
    EXPECT_EQ(n, 25);
    CHECK(out[0] == 0x7777);
    /* exact */
    n = 25; SET_ERR(0);
    CHECK(iri(0, in, &n, out) == 1);
    CHECK(!wcscmp(out, in));
    EXPECT_EQ(n, 25);
    /* tiny */
    for (DWORD cap = 0; cap < 25; cap++) {
        n = cap; SET_ERR(0);
        CHECKF(iri(0, in, &n, out) == 0, "cap %lu", cap);
        EXPECT_ERR(NTE_BAD_LEN);
        CHECKF(n == 25, "cap %lu -> %lu", cap, n);
    }
}
TEST(cniri_buffer_protocol_unicode) {
    REQUIRE(PIN(I_CryptConvertIriToAsciiOrUnicode));
    NO_WINE("IRI helper differs in the emulator");
    WCHAR out[64]; DWORD n = 0; SET_ERR(0);
    /* "http://xn--bcher-kva.example/" is 29 characters; the Unicode form is 22 */
    CHECK(iri(1, PUNY_BUCHER, &n, NULL) == 0);
    EXPECT_ERR(NTE_BAD_LEN);
    t_note("unicode size query for the puny URL asks for %lu characters", n);
    n = 64;
    CHECK(iri(1, PUNY_BUCHER, &n, out) == 1);
    n = (DWORD)(wcslen(IRI_BUCHER) + 1);
    CHECK(iri(1, PUNY_BUCHER, &n, out) == 1);
    CHECK(!wcscmp(out, IRI_BUCHER));
    n = (DWORD)wcslen(IRI_BUCHER);
    SET_ERR(0);
    CHECK(iri(1, PUNY_BUCHER, &n, out) == 0);
    EXPECT_ERR(NTE_BAD_LEN);
}
TEST(cniri_ascii_needs_expanded_room) {
    REQUIRE(PIN(I_CryptConvertIriToAsciiOrUnicode));
    NO_WINE("IRI helper differs in the emulator");
    /* the punycode form is longer than the IRI */
    WCHAR out[64]; DWORD n = (DWORD)wcslen(IRI_BUCHER) + 1; SET_ERR(0);
    CHECK(iri(0, IRI_BUCHER, &n, out) == 0);
    EXPECT_ERR(NTE_BAD_LEN);
    EXPECT_EQ(n, wcslen(PUNY_BUCHER) + 1);
    n = (DWORD)wcslen(PUNY_BUCHER) + 1;
    CHECK(iri(0, IRI_BUCHER, &n, out) == 1);
    CHECK(!wcscmp(out, PUNY_BUCHER));
}
TEST(cniri_scheme_too_long) {
    REQUIRE(PIN(I_CryptConvertIriToAsciiOrUnicode));
    NO_WINE("IRI helper differs in the emulator");
    WCHAR out[300]; DWORD n = 300; SET_ERR(0);
    CHECK(iri(0, L"abcdefghijklmnopqrstuvwxyz0123456789://host/x", &n, out) == 0);
    EXPECT_ERR(ERROR_INVALID_PARAMETER);
}
TEST(cniri_no_scheme_gets_host_only) {
    REQUIRE(PIN(I_CryptConvertIriToAsciiOrUnicode));
    NO_WINE("IRI helper differs in the emulator");
    WCHAR out[300]; DWORD n = 300; SET_ERR(0);
    int r = iri(0, L"b\x00fc" L"cher.example/x", &n, out);
    t_note("scheme-less IRI: r=%d err=0x%lx out=%ls n=%lu", r, r ? 0 : GetLastError(), r ? out : L"-", n);
    if (r == 1) CHECK(!wcscmp(out, L"xn--bcher-kva.example/x"));
}
TEST(cniri_escape_flag) {
    REQUIRE(PIN(I_CryptConvertIriToAsciiOrUnicodeWithFlags));
    NO_WINE("IRI helper differs in the emulator");
    WCHAR out[300]; DWORD n = 300; SET_ERR(0);
    int r = iriF(F_ASCII | F_ESCAPE, L"http://www.example.test/a b", &n, out);
    t_note("escape flag: r=%d err=0x%lx out=%ls n=%lu", r, r ? 0 : GetLastError(), r ? out : L"-", n);
    if (r == 1) { CHECK(!wcschr(out, L' ')); CHECK(wcsstr(out, L"a%20b") != NULL); }
}
TEST(cniri_unescape_flag) {
    REQUIRE(PIN(I_CryptConvertIriToAsciiOrUnicodeWithFlags));
    NO_WINE("IRI helper differs in the emulator");
    WCHAR out[300]; DWORD n = 300; SET_ERR(0);
    int r = iriF(F_ASCII | F_UNESC, L"http://www.example.test/a%20b", &n, out);
    t_note("unescape flag: r=%d err=0x%lx out=%ls", r, r ? 0 : GetLastError(), r ? out : L"-");
    n = 300; SET_ERR(0);
    r = iriF(F_ASCII | F_UNESC, L"http://b%C3%BCcher.example/", &n, out);
    t_note("unescape+idn: r=%d err=0x%lx out=%ls", r, r ? 0 : GetLastError(), r ? out : L"-");
}
TEST(cniri_ldap_url) {
    REQUIRE(PIN(I_CryptConvertIriToAsciiOrUnicode));
    NO_WINE("IRI helper differs in the emulator");
    WCHAR out[300]; DWORD n = 300; SET_ERR(0);
    int r = iri(0, L"ldap://ldap.example.test/CN=CA?cACertificate?base", &n, out);
    CHECKF(r == 1, "err=0x%lx", GetLastError());
    t_note("ldap url -> %ls", r ? out : L"-");
}
TEST(cniri_repeatable) {
    REQUIRE(PIN(I_CryptConvertIriToAsciiOrUnicode));
    NO_WINE("IRI helper differs in the emulator");
    for (int i = 0; i < 200; i++) {
        WCHAR out[300]; DWORD n = 300;
        if (iri(0, IRI_BUCHER, &n, out) != 1 || wcscmp(out, PUNY_BUCHER)) { CHECKF(0, "iteration %d", i); break; }
    }
}

/* ---- time-valid objects ---------------------------------------------------------- */
static PCCERT_CONTEXT mk(const unsigned char *p, size_t n) { return U(CertCreateCertificateContext)(X509_ASN_ENCODING, p, (DWORD)n); }

TEST(cntv_unknown_oid_get) {
    REQUIRE(U(CryptGetTimeValidObject));
    NO_WINE("time-valid helpers differ in the emulator");
    PCCERT_CONTEXT a = mk(v_cert_a, sizeof v_cert_a); REQUIRE(a);
    static const size_t ids[] = { 0x10, 99, 0xFFFF };
    for (size_t i = 0; i < 3; i++) {
        LPVOID obj = SENTINEL; SET_ERR(0);
        BOOL ok = U(CryptGetTimeValidObject)((LPCSTR)ids[i], (LPVOID)a, a, NULL, CRYPT_CACHE_ONLY_RETRIEVAL, 0, &obj, NULL, NULL);
        CHECKF(!ok, "oid %zu succeeded", ids[i]);
        CHECKF(obj == SENTINEL, "oid %zu touched the output", ids[i]);
        t_note("time-valid oid %zu: error 0x%lx", ids[i], GetLastError());
    }
    U(CertFreeCertificateContext)(a);
}
TEST(cntv_crl_from_cert_cache_only_miss) {
    REQUIRE(U(CryptGetTimeValidObject));
    NO_WINE("time-valid helpers differ in the emulator");
    PCCERT_CONTEXT a = mk(v_cert_a, sizeof v_cert_a), b = mk(v_cert_b, sizeof v_cert_b); REQUIRE(a && b);
    PCCERT_CONTEXT subj[2] = { a, b };
    for (int i = 0; i < 2; i++) {
        LPVOID obj = SENTINEL; SET_ERR(0);
        /* cache only: nothing leaves the machine; the cache has no CRL for these URLs */
        BOOL ok = U(CryptGetTimeValidObject)(TIME_VALID_OID_GET_CRL_FROM_CERT, (LPVOID)subj[i], a, NULL, CRYPT_CACHE_ONLY_RETRIEVAL, 0, &obj, NULL, NULL);
        CHECKF(!ok, "cert %d: cache hit", i);
        DWORD e = GetLastError();
        t_note("crl-from-cert (%s) cache-only: error 0x%lx obj=%p", i ? "no CDP" : "with CDP", e, obj);
        if (ok && obj) U(CertFreeCRLContext)(obj);
    }
    U(CertFreeCertificateContext)(a); U(CertFreeCertificateContext)(b);
}
TEST(cntv_freshest_crl_cache_only_miss) {
    REQUIRE(U(CryptGetTimeValidObject));
    NO_WINE("time-valid helpers differ in the emulator");
    PCCERT_CONTEXT a = mk(v_cert_a, sizeof v_cert_a); REQUIRE(a);
    LPVOID obj = SENTINEL; SET_ERR(0);
    BOOL ok = U(CryptGetTimeValidObject)(TIME_VALID_OID_GET_FRESHEST_CRL_FROM_CERT, (LPVOID)a, a, NULL, CRYPT_CACHE_ONLY_RETRIEVAL, 0, &obj, NULL, NULL);
    CHECK(!ok);
    t_note("freshest-crl-from-cert cache-only: error 0x%lx obj=%p", GetLastError(), obj);
    if (ok && obj) U(CertFreeCRLContext)(obj);
    U(CertFreeCertificateContext)(a);
}
TEST(cntv_crl_cache_only_miss) {
    REQUIRE(U(CryptGetTimeValidObject));
    NO_WINE("time-valid helpers differ in the emulator");
    PCCERT_CONTEXT a = mk(v_cert_a, sizeof v_cert_a); REQUIRE(a);
    PCCRL_CONTEXT crl = U(CertCreateCRLContext)(X509_ASN_ENCODING, v_crl_a, sizeof v_crl_a); REQUIRE(crl);
    LPVOID obj = SENTINEL; SET_ERR(0);
    BOOL ok = U(CryptGetTimeValidObject)(TIME_VALID_OID_GET_CRL, (LPVOID)crl, a, NULL, CRYPT_CACHE_ONLY_RETRIEVAL, 0, &obj, NULL, NULL);
    CHECK(!ok);
    t_note("crl refresh cache-only: error 0x%lx obj=%p", GetLastError(), obj);
    if (ok && obj) U(CertFreeCRLContext)(obj);
    U(CertFreeCRLContext)(crl); U(CertFreeCertificateContext)(a);
}
TEST(cntv_with_valid_for_time) {
    REQUIRE(U(CryptGetTimeValidObject));
    NO_WINE("time-valid helpers differ in the emulator");
    PCCERT_CONTEXT a = mk(v_cert_a, sizeof v_cert_a); REQUIRE(a);
    SYSTEMTIME st = { 2030, 1, 0, 1, 0, 0, 0, 0 }; FILETIME ft; SystemTimeToFileTime(&st, &ft);
    LPVOID obj = SENTINEL; SET_ERR(0);
    BOOL ok = U(CryptGetTimeValidObject)(TIME_VALID_OID_GET_CRL_FROM_CERT, (LPVOID)a, a, &ft, CRYPT_CACHE_ONLY_RETRIEVAL, 0, &obj, NULL, NULL);
    CHECK(!ok);
    t_note("explicit validity time, cache-only: error 0x%lx", GetLastError());
    if (ok && obj) U(CertFreeCRLContext)(obj);
    /* extra info block with a last-sync pointer */
    FILETIME sync = { 0x1111, 0x2222 }, maxage = { 0x3333, 0x4444 };
    CRYPT_GET_TIME_VALID_OBJECT_EXTRA_INFO ex; memset(&ex, 0, sizeof ex);
    ex.cbSize = sizeof ex; ex.pLastSyncTime = &sync; ex.pMaxAgeTime = &maxage;
    obj = SENTINEL; SET_ERR(0);
    ok = U(CryptGetTimeValidObject)(TIME_VALID_OID_GET_CRL_FROM_CERT, (LPVOID)a, a, NULL, CRYPT_CACHE_ONLY_RETRIEVAL, 0, &obj, NULL, &ex);
    CHECK(!ok);
    t_note("extra info after miss: lastsync=%08lx%08lx maxage=%08lx%08lx", sync.dwHighDateTime, sync.dwLowDateTime, maxage.dwHighDateTime, maxage.dwLowDateTime);
    if (ok && obj) U(CertFreeCRLContext)(obj);
    U(CertFreeCertificateContext)(a);
}
TEST(cntv_flush_unknown_oid) {
    REQUIRE(U(CryptFlushTimeValidObject));
    NO_WINE("time-valid helpers differ in the emulator");
    static const size_t ids[] = { 0x10, 99, 0xFFFF };
    for (size_t i = 0; i < 3; i++) {
        SET_ERR(0);
        BOOL ok = U(CryptFlushTimeValidObject)((LPCSTR)ids[i], NULL, NULL, 0, NULL);
        CHECKF(!ok, "oid %zu succeeded", ids[i]);
        t_note("flush oid %zu: error 0x%lx", ids[i], GetLastError());
    }
}
TEST(cntv_flush_crl_from_cert) {
    REQUIRE(U(CryptFlushTimeValidObject));
    NO_WINE("time-valid helpers differ in the emulator");
    PCCERT_CONTEXT a = mk(v_cert_a, sizeof v_cert_a); REQUIRE(a);
    SET_ERR(0);
    BOOL ok = U(CryptFlushTimeValidObject)(TIME_VALID_OID_FLUSH_CRL_FROM_CERT, (LPVOID)a, a, 0, NULL);
    t_note("flush crl-from-cert (empty cache): ok=%d err=0x%lx", ok, ok ? 0 : GetLastError());
    SET_ERR(0);
    ok = U(CryptFlushTimeValidObject)(TIME_VALID_OID_FLUSH_FRESHEST_CRL_FROM_CERT, (LPVOID)a, a, 0, NULL);
    t_note("flush freshest-crl-from-cert (empty cache): ok=%d err=0x%lx", ok, ok ? 0 : GetLastError());
    U(CertFreeCertificateContext)(a);
}

/* ---- offline URL cache and connectivity ---------------------------------------------- */
TEST(cnnet_flush_offline_url_twice) {
    REQUIRE(PIN(I_CryptNetFlushOfflineUrl));
    NO_WINE("offline-url helpers differ in the emulator");
    int n = 0x77;
    (void)PIN(I_CryptNetFlushOfflineUrl)(&n);          /* drain whatever earlier tests left */
    n = 0x77;
    BOOL ok = PIN(I_CryptNetFlushOfflineUrl)(&n);
    CHECK(!ok);
    EXPECT_EQ(n, 0);
}
TEST(cnnet_offline_check_populates_cache) {
    REQUIRE(PIN(I_CryptNetFlushOfflineUrl));
    REQUIRE(U(CryptRetrieveObjectByUrlW));
    NO_WINE("offline-url helpers differ in the emulator");
    int n = 0; (void)PIN(I_CryptNetFlushOfflineUrl)(&n);
    char path[MAX_PATH]; WCHAR u[1200];
    t_tmpfile(path, sizeof path, "offline_missing.cer");
    cn_url_w(path, u, 1200);
    LPVOID obj = SENTINEL; SET_ERR(0);
    BOOL ok = cn_retrieve_w(u, CONTEXT_OID_CERTIFICATE, CRYPT_OFFLINE_CHECK_RETRIEVAL, 0, &obj, NULL);
    CHECK(!ok);
    DWORD e1 = GetLastError();
    obj = SENTINEL; SET_ERR(0);
    ok = cn_retrieve_w(u, CONTEXT_OID_CERTIFICATE, CRYPT_OFFLINE_CHECK_RETRIEVAL, 0, &obj, NULL);
    CHECK(!ok);
    t_note("offline-check miss twice: first 0x%lx second 0x%lx", e1, GetLastError());
    n = 0x77;
    ok = PIN(I_CryptNetFlushOfflineUrl)(&n);
    t_note("flush after failed offline-check retrievals: ok=%d count=%d", ok, n);
    CHECK((ok != 0) == (n != 0));
    n = 0x77;
    CHECK(!PIN(I_CryptNetFlushOfflineUrl)(&n));
    EXPECT_EQ(n, 0);
}
TEST(cnnet_get_connectivity) {
    REQUIRE(PIN(I_CryptNetGetConnectivity));
    NO_WINE("connectivity helper differs in the emulator");
    int r1 = PIN(I_CryptNetGetConnectivity)();
    int r2 = PIN(I_CryptNetGetConnectivity)();
    t_note("connectivity: %d then %d", r1, r2);
    CHECK(r1 == 0 || r1 == 1);
}
TEST(cnnet_resolve_only) {
    /* signatures are not public: only check that the entry points exist and are distinct */
    FARPROC p[] = { t_proc_in("cryptnet.dll", "I_CryptNetAutoFlush"), t_proc_in("cryptnet.dll", "I_CryptNetEnumUrlCacheEntry"),
        t_proc_in("cryptnet.dll", "I_CryptNetSetUrlCacheFlushInfo"), t_proc_in("cryptnet.dll", "I_CryptNetSetUrlCachePreFetchInfo"),
        t_proc_in("cryptnet.dll", "I_CryptNetGetUserDsStoreUrl"), t_proc_in("cryptnet.dll", "LdapProvOpenStore") };
    for (int i = 0; i < 6; i++) {
        CHECK(p[i] != NULL);
        for (int j = i + 1; j < 6; j++) CHECK(p[i] != p[j]);
    }
}

/* ---- CertDllVerifyRevocation ------------------------------------------------------------ */
TEST(cnrev_zero_contexts) {
    REQUIRE(PIN(CertDllVerifyRevocation));
    NO_WINE("revocation provider differs in the emulator");
    PCCERT_CONTEXT a = mk(v_cert_a, sizeof v_cert_a); REQUIRE(a);
    PVOID ctx[1] = { (PVOID)a };
    CERT_REVOCATION_STATUS st; memset(&st, 0x55, sizeof st); st.cbSize = sizeof st;
    SET_ERR(0);
    BOOL ok = PIN(CertDllVerifyRevocation)(X509_ASN_ENCODING, CERT_CONTEXT_REVOCATION_TYPE, 0, ctx, 0, NULL, &st);
    CHECK(!ok);
    EXPECT_ERR(ERR_INVALIDARG);
    EXPECT_EQ(st.cbSize, sizeof st);
    EXPECT_EQ(st.dwIndex, 0);
    EXPECT_EQ(st.dwError, ERR_INVALIDARG);
    EXPECT_EQ(st.dwReason, 0);
    /* zero contexts is rejected before the type is looked at */
    memset(&st, 0x55, sizeof st); st.cbSize = sizeof st;
    SET_ERR(0);
    ok = PIN(CertDllVerifyRevocation)(0, 99, 0, ctx, 0, NULL, &st);
    CHECK(!ok);
    EXPECT_ERR(ERR_INVALIDARG);
    EXPECT_EQ(st.dwError, ERR_INVALIDARG);
    U(CertFreeCertificateContext)(a);
}
TEST(cnrev_unsupported_type_or_encoding) {
    REQUIRE(PIN(CertDllVerifyRevocation));
    NO_WINE("revocation provider differs in the emulator");
    PCCERT_CONTEXT a = mk(v_cert_a, sizeof v_cert_a); REQUIRE(a);
    PVOID ctx[1] = { (PVOID)a };
    static const struct { DWORD enc, type; const char *n; } rows[] = {
        { 0, 1, "enc 0" }, { 2, 1, "enc 2" }, { 0x10000, 1, "pkcs7 only" }, { 1, 0, "type 0" }, { 1, 2, "type 2" }, { 1, 3, "type 3" }, { 1, 0xFF, "type 255" } };
    for (size_t i = 0; i < sizeof rows / sizeof *rows; i++) {
        CERT_REVOCATION_STATUS st; memset(&st, 0x55, sizeof st); st.cbSize = sizeof st;
        SET_ERR(0);
        BOOL ok = PIN(CertDllVerifyRevocation)(rows[i].enc, rows[i].type, 1, ctx, 0, NULL, &st);
        CHECKF(!ok, "%s succeeded", rows[i].n);
        DWORD e = GetLastError();
        CHECKF(e == ERR_NO_REVCHECK, "%s: error 0x%lx", rows[i].n, e);
        CHECKF(st.dwError == ERR_NO_REVCHECK, "%s: status error 0x%lx", rows[i].n, st.dwError);
        CHECKF(st.dwIndex == 0, "%s: index %lu", rows[i].n, st.dwIndex);
    }
    U(CertFreeCertificateContext)(a);
}

/* ---- CertDllVerifyCTLUsage --------------------------------------------------------------- */
TEST(cnctl_empty_store_has_no_ctl) {
    REQUIRE(PIN(CertDllVerifyCTLUsage));
    NO_WINE("CTL usage provider differs in the emulator");
    HCERTSTORE s = U(CertOpenStore)(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL); REQUIRE(s);
    CTL_ANY_SUBJECT_INFO subj; memset(&subj, 0, sizeof subj);
    CTL_VERIFY_USAGE_PARA para; memset(&para, 0, sizeof para);
    para.cbSize = sizeof para; para.cCtlStore = 1; para.rghCtlStore = &s;
    CTL_VERIFY_USAGE_STATUS st; memset(&st, 0x55, sizeof st); st.cbSize = sizeof st;
    PCCTL_CONTEXT ctl = NULL; st.ppCtl = &ctl;
    SET_ERR(0);
    BOOL ok = PIN(CertDllVerifyCTLUsage)(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, CTL_ANY_SUBJECT_TYPE, &subj, NULL, 0, &para, &st);
    CHECK(!ok);
    EXPECT_ERR(0x80092028);   /* CRYPT_E_NO_VERIFY_USAGE_CTL */
    EXPECT_EQ(st.dwError, 0x80092028);
    CHECK(ctl == NULL);
    U(CertCloseStore)(s, 0);
}
TEST(cnctl_untrusted_signed_ctl) {
    REQUIRE(PIN(CertDllVerifyCTLUsage));
    NO_WINE("CTL usage provider differs in the emulator");
    HCERTSTORE s = U(CertOpenStore)(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL); REQUIRE(s);
    BOOL added = U(CertAddEncodedCTLToStore)(s, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, v_ctl_signed, sizeof v_ctl_signed, CERT_STORE_ADD_ALWAYS, NULL);
    CHECK(added);
    CTL_ANY_SUBJECT_INFO subj; memset(&subj, 0, sizeof subj);
    CTL_VERIFY_USAGE_PARA para; memset(&para, 0, sizeof para);
    para.cbSize = sizeof para; para.cCtlStore = 1; para.rghCtlStore = &s;
    CTL_VERIFY_USAGE_STATUS st; memset(&st, 0, sizeof st); st.cbSize = sizeof st;
    SET_ERR(0);
    BOOL ok = PIN(CertDllVerifyCTLUsage)(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, CTL_ANY_SUBJECT_TYPE, &subj, NULL, 0, &para, &st);
    CHECK(!ok);
    DWORD e = GetLastError();
    t_note("untrusted signed CTL: error 0x%lx status.dwError 0x%lx", e, st.dwError);
    CHECK(e == st.dwError);
    CHECK(e != 0);
    U(CertCloseStore)(s, 0);
}
