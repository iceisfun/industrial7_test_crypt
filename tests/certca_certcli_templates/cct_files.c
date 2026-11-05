/* certcli file codec helpers (EncodeToFileW / DecodeFileW) and the certificate name / filter helpers. */
#include "cct.h"
#include "cct_certs.inc"

static void freel(void *p) { if (p) LocalFree(p); }

static void tpath(WCHAR *out, size_t cap, const char *leaf)
{
    char a[MAX_PATH];
    t_tmpfile(a, sizeof a, leaf);
    MultiByteToWideChar(CP_ACP, 0, a, -1, out, (int)cap);
}

static int slurp(const WCHAR *path, BYTE *buf, DWORD cap, DWORD *got)
{
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    BOOL ok = ReadFile(h, buf, cap, got, NULL);
    CloseHandle(h);
    return ok;
}

static int spit(const WCHAR *path, const void *d, DWORD n)
{
    HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    DWORD w = 0; BOOL ok = WriteFile(h, d, n, &w, NULL);
    CloseHandle(h);
    return ok && w == n;
}

static const BYTE k_pat[100] = {
    0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,
    40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,
    80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99 };

/* ---- EncodeToFileW ------------------------------------------------------------ */
TEST(cct_encfile_binary_exact_bytes)
{
    REQUIRE(CCLI(EncodeToFileW));
    WCHAR p[MAX_PATH]; tpath(p, MAX_PATH, "enc_bin.dat");
    HRESULT hr = CCLI(EncodeToFileW)(p, k_pat, 100, 2);
    CHECK(hr == 0);
    BYTE got[200]; DWORD n = 0;
    CHECK(slurp(p, got, sizeof got, &n));
    CHECK(n == 100 && !memcmp(got, k_pat, 100));
    DeleteFileW(p);
}

TEST(cct_encfile_existing_file_not_overwritten)
{
    REQUIRE(CCLI(EncodeToFileW));
    WCHAR p[MAX_PATH]; tpath(p, MAX_PATH, "enc_exist.dat");
    CHECK(spit(p, "old", 3));
    HRESULT hr = CCLI(EncodeToFileW)(p, k_pat, 10, 2);
    CHECK(hr == (HRESULT)0x80070050);          /* HRESULT_FROM_WIN32(ERROR_FILE_EXISTS): created with CREATE_NEW */
    BYTE got[16]; DWORD n = 0;
    CHECK(slurp(p, got, sizeof got, &n) && n == 3 && !memcmp(got, "old", 3));
    DeleteFileW(p);
}

TEST(cct_encfile_overwrite_flag_0x100)
{
    REQUIRE(CCLI(EncodeToFileW));
    WCHAR p[MAX_PATH]; tpath(p, MAX_PATH, "enc_over.dat");
    CHECK(spit(p, "old old old", 11));
    HRESULT hr = CCLI(EncodeToFileW)(p, k_pat, 10, 2 | 0x100);
    CHECK(hr == 0);
    BYTE got[32]; DWORD n = 0;
    CHECK(slurp(p, got, sizeof got, &n) && n == 10 && !memcmp(got, k_pat, 10));
    DeleteFileW(p);
    /* with the overwrite flag a missing file is simply created */
    hr = CCLI(EncodeToFileW)(p, k_pat, 4, 2 | 0x100);
    CHECK(hr == 0);
    CHECK(slurp(p, got, sizeof got, &n) && n == 4);
    DeleteFileW(p);
}

TEST(cct_encfile_inconsistent_binary_flags_rejected)
{
    REQUIRE(CCLI(EncodeToFileW));
    WCHAR p[MAX_PATH]; tpath(p, MAX_PATH, "enc_badflag.dat");
    HRESULT hr = CCLI(EncodeToFileW)(p, k_pat, 4, 0x1002);
    CHECK(hr == E_BADARG);
    CHECK(GetFileAttributesW(p) == INVALID_FILE_ATTRIBUTES);
}

TEST(cct_encfile_base64_ansi_text)
{
    REQUIRE(CCLI(EncodeToFileW));
    WCHAR p[MAX_PATH]; tpath(p, MAX_PATH, "enc_b64.txt");
    static const BYTE d[3] = { 1, 2, 3 };
    CHECK(CCLI(EncodeToFileW)(p, d, 3, CRYPT_STRING_BASE64) == 0);
    BYTE got[64]; DWORD n = 0;
    CHECK(slurp(p, got, sizeof got, &n));
    CHECK(n == 6 && !memcmp(got, "AQID\r\n", 6));
    DeleteFileW(p);
}

TEST(cct_encfile_base64_header_text)
{
    REQUIRE(CCLI(EncodeToFileW));
    WCHAR p[MAX_PATH]; tpath(p, MAX_PATH, "enc_hdr.pem");
    static const BYTE d[3] = { 1, 2, 3 };
    CHECK(CCLI(EncodeToFileW)(p, d, 3, CRYPT_STRING_BASE64HEADER) == 0);
    static const char want[] = "-----BEGIN CERTIFICATE-----\r\nAQID\r\n-----END CERTIFICATE-----\r\n";
    BYTE got[128]; DWORD n = 0;
    CHECK(slurp(p, got, sizeof got, &n));
    CHECK(n == sizeof want - 1 && !memcmp(got, want, n));
    DeleteFileW(p);
}

TEST(cct_encfile_unicode_flag_writes_bom_and_utf16)
{
    REQUIRE(CCLI(EncodeToFileW));
    WCHAR p[MAX_PATH]; tpath(p, MAX_PATH, "enc_w.txt");
    static const BYTE d[3] = { 1, 2, 3 };
    CHECK(CCLI(EncodeToFileW)(p, d, 3, CRYPT_STRING_BASE64 | 0x200) == 0);
    BYTE got[64]; DWORD n = 0;
    CHECK(slurp(p, got, sizeof got, &n));
    static const BYTE want[] = { 0xff, 0xfe, 'A', 0, 'Q', 0, 'I', 0, 'D', 0, '\r', 0, '\n', 0 };
    CHECK(n == sizeof want && !memcmp(got, want, n));
    DeleteFileW(p);
}

TEST(cct_encfile_missing_directory)
{
    REQUIRE(CCLI(EncodeToFileW));
    WCHAR p[MAX_PATH]; tpath(p, MAX_PATH, "no_such_dir_cryptt\\f.dat");
    HRESULT hr = CCLI(EncodeToFileW)(p, k_pat, 4, 2);
    CHECK(hr == (HRESULT)0x80070003);          /* ERROR_PATH_NOT_FOUND */
    hr = CCLI(EncodeToFileW)(p, k_pat, 4, 2 | 0x100);
    CHECK(hr == (HRESULT)0x80070003);
}

TEST(cct_encfile_bad_format_fails_without_file)
{
    REQUIRE(CCLI(EncodeToFileW));
    WCHAR p[MAX_PATH]; tpath(p, MAX_PATH, "enc_badfmt.dat");
    HRESULT hr = CCLI(EncodeToFileW)(p, k_pat, 4, 0x7f);
    CHECK(FAILED(hr));
    CHECK(GetFileAttributesW(p) == INVALID_FILE_ATTRIBUTES);
}

/* ---- DecodeFileW --------------------------------------------------------------- */
TEST(cct_decfile_missing_file)
{
    REQUIRE(CCLI(DecodeFileW));
    WCHAR p[MAX_PATH]; tpath(p, MAX_PATH, "dec_missing.dat");
    BYTE *b = (BYTE *)(ULONG_PTR)1; DWORD cb = 5;
    HRESULT hr = CCLI(DecodeFileW)(p, &b, &cb, 2);
    CHECK(hr == HR_NOT_FOUND_FILE);
    CHECK(b == (BYTE *)(ULONG_PTR)1); CHECK(cb == 5);
}

TEST(cct_decfile_directory_rejected)
{
    REQUIRE(CCLI(DecodeFileW));
    WCHAR p[MAX_PATH];
    MultiByteToWideChar(CP_ACP, 0, t_tmpdir(), -1, p, MAX_PATH);
    BYTE *b = NULL; DWORD cb = 0;
    HRESULT hr = CCLI(DecodeFileW)(p, &b, &cb, 2);
    CHECK(FAILED(hr));
    t_note("DecodeFileW(directory) -> 0x%lx", (long)hr);
    CHECK(b == NULL);
}

TEST(cct_decfile_empty_file_invalid_data)
{
    REQUIRE(CCLI(DecodeFileW));
    WCHAR p[MAX_PATH]; tpath(p, MAX_PATH, "dec_empty.dat");
    CHECK(spit(p, "", 0));
    BYTE *b = NULL; DWORD cb = 0;
    HRESULT hr = CCLI(DecodeFileW)(p, &b, &cb, 2);
    CHECK(hr == (HRESULT)0x8007000D);
    CHECK(b == NULL);
    DeleteFileW(p);
}

TEST(cct_decfile_binary_raw)
{
    REQUIRE(CCLI(DecodeFileW));
    WCHAR p[MAX_PATH]; tpath(p, MAX_PATH, "dec_raw.dat");
    CHECK(spit(p, k_pat, 100));
    BYTE *b = NULL; DWORD cb = 0;
    HRESULT hr = CCLI(DecodeFileW)(p, &b, &cb, 2);
    CHECK(hr == 0); CHECK(cb == 100);
    if (b) { CHECK(!memcmp(b, k_pat, 100)); freel(b); }
    DeleteFileW(p);
}

TEST(cct_decfile_base64_text)
{
    REQUIRE(CCLI(DecodeFileW));
    WCHAR p[MAX_PATH]; tpath(p, MAX_PATH, "dec_b64.txt");
    CHECK(spit(p, "AQID\r\n", 6));
    BYTE *b = NULL; DWORD cb = 0;
    HRESULT hr = CCLI(DecodeFileW)(p, &b, &cb, CRYPT_STRING_BASE64);
    CHECK(hr == 0); CHECK(cb == 3);
    if (b) { CHECK(!memcmp(b, "\x01\x02\x03", 3)); freel(b); }
    DeleteFileW(p);
}

TEST(cct_decfile_pem_text_any)
{
    REQUIRE(CCLI(DecodeFileW));
    WCHAR p[MAX_PATH]; tpath(p, MAX_PATH, "dec_pem.txt");
    static const char pem[] = "-----BEGIN CERTIFICATE-----\r\nAQID\r\n-----END CERTIFICATE-----\r\n";
    CHECK(spit(p, pem, sizeof pem - 1));
    BYTE *b = NULL; DWORD cb = 0;
    HRESULT hr = CCLI(DecodeFileW)(p, &b, &cb, CRYPT_STRING_BASE64HEADER);
    CHECK(hr == 0); CHECK(cb == 3);
    freel(b); b = NULL; cb = 0;
    hr = CCLI(DecodeFileW)(p, &b, &cb, CRYPT_STRING_BASE64_ANY);
    CHECK(hr == 0); CHECK(cb == 3);
    freel(b);
    DeleteFileW(p);
}

TEST(cct_decfile_garbage_as_base64_fails)
{
    REQUIRE(CCLI(DecodeFileW));
    WCHAR p[MAX_PATH]; tpath(p, MAX_PATH, "dec_garbage.txt");
    CHECK(spit(p, "!!!! not base64 !!!!", 20));
    BYTE *b = (BYTE *)(ULONG_PTR)1; DWORD cb = 0;
    HRESULT hr = CCLI(DecodeFileW)(p, &b, &cb, CRYPT_STRING_BASE64);
    CHECK(FAILED(hr)); t_note("garbage base64 file -> 0x%lx", (long)hr);
    CHECK(b == (BYTE *)(ULONG_PTR)1);
    DeleteFileW(p);
}

TEST(cct_decfile_roundtrip_formats)
{
    REQUIRE(CCLI(EncodeToFileW)); REQUIRE(CCLI(DecodeFileW));
    static const DWORD fmts[] = { 2, CRYPT_STRING_BASE64, CRYPT_STRING_BASE64HEADER };
    for (int i = 0; i < 3; i++) {
        WCHAR p[MAX_PATH]; char leaf[32]; wsprintfA(leaf, "rt_%d.dat", i);
        tpath(p, MAX_PATH, leaf);
        HRESULT hr = CCLI(EncodeToFileW)(p, k_pat, 100, fmts[i]);
        CHECKF(hr == 0, "fmt %lu enc 0x%lx", fmts[i], (long)hr);
        BYTE *b = NULL; DWORD cb = 0;
        hr = CCLI(DecodeFileW)(p, &b, &cb, fmts[i]);
        CHECKF(hr == 0 && cb == 100 && b && !memcmp(b, k_pat, 100), "fmt %lu dec 0x%lx cb=%lu", fmts[i], (long)hr, cb);
        freel(b);
        DeleteFileW(p);
    }
}

TEST(cct_decfile_roundtrip_hex_formats_observed)
{
    REQUIRE(CCLI(EncodeToFileW)); REQUIRE(CCLI(DecodeFileW));
    static const DWORD fmts[] = { CRYPT_STRING_HEX, CRYPT_STRING_HEXRAW, CRYPT_STRING_HEXASCII, CRYPT_STRING_HEXADDR, CRYPT_STRING_BASE64 | 0x200 };
    for (int i = 0; i < 5; i++) {
        WCHAR p[MAX_PATH]; char leaf[32]; wsprintfA(leaf, "rth_%d.dat", i);
        tpath(p, MAX_PATH, leaf);
        HRESULT hr = CCLI(EncodeToFileW)(p, k_pat, 100, fmts[i]);
        BYTE *b = NULL; DWORD cb = 0;
        HRESULT hr2 = hr == 0 ? CCLI(DecodeFileW)(p, &b, &cb, fmts[i] & 0xff) : hr;
        t_note("format 0x%lx: encode 0x%lx decode 0x%lx cb=%lu equal=%d", fmts[i], (long)hr, (long)hr2, cb, b && cb == 100 && !memcmp(b, k_pat, 100));
        freel(b);
        DeleteFileW(p);
    }
}

/* ---- CCGetCertNameList ----------------------------------------------------------- */
static PCCERT_CONTEXT mkcert(const BYTE *der, DWORD n)
{
    return U(CertCreateCertificateContext)(X509_ASN_ENCODING, der, n);
}

static void free_names(LPWSTR *a) { CCLI(CCFreeStringArray)(a); }

TEST(cct_namelist_dns_names)
{
    REQUIRE(U(CertCreateCertificateContext)); REQUIRE(CCLI(CCGetCertNameList)); REQUIRE(CCLI(CCFreeStringArray));
    PCCERT_CONTEXT c = mkcert(g_certSan, sizeof g_certSan);
    CHECK(c != NULL); if (!c) return;
    DWORD n = 99; LPWSTR *a = (LPWSTR *)(ULONG_PTR)1;
    HRESULT hr = CCLI(CCGetCertNameList)(c, CERT_ALT_NAME_DNS_NAME, 0, &n, &a);
    CHECK(hr == 0); CHECK(n == 2);
    if (hr == 0 && a && n == 2) {
        CHECK(a[0] && !lstrcmpW(a[0], L"a.example.test"));
        CHECK(a[1] && !lstrcmpW(a[1], L"b.example.test"));
        CHECK(a[2] == NULL);              /* NULL terminated */
    }
    if (hr == 0) free_names(a);
    U(CertFreeCertificateContext)(c);
}

TEST(cct_namelist_all_supported_choices_in_order)
{
    REQUIRE(U(CertCreateCertificateContext)); REQUIRE(CCLI(CCGetCertNameList));
    PCCERT_CONTEXT c = mkcert(g_certSan, sizeof g_certSan);
    CHECK(c != NULL); if (!c) return;
    DWORD n = 0; LPWSTR *a = NULL;
    HRESULT hr = CCLI(CCGetCertNameList)(c, 0, 0, &n, &a);
    CHECK(hr == 0); CHECK(n == 4);
    if (hr == 0 && a && n == 4) {
        CHECK(!lstrcmpW(a[0], L"a.example.test"));
        CHECK(!lstrcmpW(a[1], L"b.example.test"));
        CHECK(!lstrcmpW(a[2], L"x@example.test"));
        CHECK(!lstrcmpW(a[3], L"http://u.example.test/"));
        CHECK(a[4] == NULL);
    }
    if (hr == 0) free_names(a);
    U(CertFreeCertificateContext)(c);
}

TEST(cct_namelist_rfc822_and_url_choices)
{
    REQUIRE(U(CertCreateCertificateContext)); REQUIRE(CCLI(CCGetCertNameList));
    PCCERT_CONTEXT c = mkcert(g_certSan, sizeof g_certSan);
    CHECK(c != NULL); if (!c) return;
    DWORD n = 0; LPWSTR *a = NULL;
    HRESULT hr = CCLI(CCGetCertNameList)(c, CERT_ALT_NAME_RFC822_NAME, 0, &n, &a);
    CHECK(hr == 0); CHECK(n == 1);
    if (hr == 0 && a && n == 1) CHECK(!lstrcmpW(a[0], L"x@example.test"));
    if (hr == 0) free_names(a);
    n = 0; a = NULL;
    hr = CCLI(CCGetCertNameList)(c, CERT_ALT_NAME_URL, 0, &n, &a);
    CHECK(hr == 0); CHECK(n == 1);
    if (hr == 0 && a && n == 1) CHECK(!lstrcmpW(a[0], L"http://u.example.test/"));
    if (hr == 0) free_names(a);
    U(CertFreeCertificateContext)(c);
}

TEST(cct_namelist_absent_choice_is_not_found)
{
    REQUIRE(U(CertCreateCertificateContext)); REQUIRE(CCLI(CCGetCertNameList));
    PCCERT_CONTEXT c = mkcert(g_certSan, sizeof g_certSan);
    CHECK(c != NULL); if (!c) return;
    DWORD n = 55; LPWSTR *a = (LPWSTR *)(ULONG_PTR)1;
    HRESULT hr = CCLI(CCGetCertNameList)(c, CERT_ALT_NAME_IP_ADDRESS, 0, &n, &a);
    CHECK(hr == HR_CRYPT_E_NOT_FOUND);
    CHECK(n == 0); CHECK(a == NULL);        /* outputs are cleared first */
    n = 55; a = (LPWSTR *)(ULONG_PTR)1;
    hr = CCLI(CCGetCertNameList)(c, CERT_ALT_NAME_REGISTERED_ID, 0, &n, &a);
    CHECK(hr == HR_CRYPT_E_NOT_FOUND);
    U(CertFreeCertificateContext)(c);
}

TEST(cct_namelist_unsupported_choice_x400_is_skipped)
{
    REQUIRE(U(CertCreateCertificateContext)); REQUIRE(CCLI(CCGetCertNameList));
    PCCERT_CONTEXT c = mkcert(g_certSan, sizeof g_certSan);
    CHECK(c != NULL); if (!c) return;
    DWORD n = 0; LPWSTR *a = NULL;
    HRESULT hr = CCLI(CCGetCertNameList)(c, CERT_ALT_NAME_X400_ADDRESS, 0, &n, &a);
    CHECK(hr == HR_CRYPT_E_NOT_FOUND);
    U(CertFreeCertificateContext)(c);
}

TEST(cct_namelist_no_san_extension)
{
    REQUIRE(U(CertCreateCertificateContext)); REQUIRE(CCLI(CCGetCertNameList));
    PCCERT_CONTEXT c = mkcert(g_certNoSan, sizeof g_certNoSan);
    CHECK(c != NULL); if (!c) return;
    DWORD n = 55; LPWSTR *a = (LPWSTR *)(ULONG_PTR)1;
    HRESULT hr = CCLI(CCGetCertNameList)(c, CERT_ALT_NAME_IP_ADDRESS, 0, &n, &a);
    CHECK(hr == HR_CRYPT_E_NOT_FOUND); CHECK(n == 0); CHECK(a == NULL);
    hr = CCLI(CCGetCertNameList)(c, CERT_ALT_NAME_URL, 0, &n, &a);
    CHECK(hr == HR_CRYPT_E_NOT_FOUND);
    /* choices 2 and 3 fall back to the subject name string (e-mail / DNS name attribute) */
    n = 0; a = NULL;
    hr = CCLI(CCGetCertNameList)(c, CERT_ALT_NAME_DNS_NAME, 0, &n, &a);
    t_note("no SAN, DNS choice: hr=0x%lx n=%lu first=%ls", (long)hr, n, (hr == 0 && a && a[0]) ? a[0] : L"-");
    if (hr == 0) free_names(a);
    n = 0; a = NULL;
    hr = CCLI(CCGetCertNameList)(c, CERT_ALT_NAME_RFC822_NAME, 0, &n, &a);
    t_note("no SAN, e-mail choice: hr=0x%lx n=%lu", (long)hr, n);
    if (hr == 0) free_names(a);
    U(CertFreeCertificateContext)(c);
}

TEST(cct_freestringarray_null_is_noop)
{
    REQUIRE(CCLI(CCFreeStringArray));
    CCLI(CCFreeStringArray)(NULL);
    CHECK(1);
}

TEST(cct_freestringarray_frees_zero_terminated_list)
{
    REQUIRE(CCLI(CCFreeStringArray));
    LPWSTR *arr = (LPWSTR *)LocalAlloc(LPTR, 4 * sizeof(LPWSTR));
    CHECK(arr != NULL); if (!arr) return;
    for (int i = 0; i < 3; i++) { arr[i] = (LPWSTR)LocalAlloc(LPTR, 32); lstrcpyW(arr[i], L"secret"); }
    arr[3] = NULL;
    CCLI(CCFreeStringArray)(arr);        /* must free each string and the array without faulting */
    CHECK(1);
}

/* ---- CCFindCertificate* on an in-memory store ---------------------------------------- */
static HCERTSTORE mem_store_with(int sanCert, int noSanCert)
{
    HCERTSTORE s = U(CertOpenStore)(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, NULL);
    if (!s) return NULL;
    if (sanCert) {
        PCCERT_CONTEXT c = mkcert(g_certSan, sizeof g_certSan);
        if (c) { U(CertAddCertificateContextToStore)(s, c, CERT_STORE_ADD_ALWAYS, NULL); U(CertFreeCertificateContext)(c); }
    }
    if (noSanCert) {
        PCCERT_CONTEXT c = mkcert(g_certNoSan, sizeof g_certNoSan);
        if (c) { U(CertAddCertificateContextToStore)(s, c, CERT_STORE_ADD_ALWAYS, NULL); U(CertFreeCertificateContext)(c); }
    }
    return s;
}

TEST(cct_findcert_empty_store_not_found)
{
    REQUIRE(U(CertOpenStore)); REQUIRE(CCLI(CCFindCertificateFromFilter));
    HCERTSTORE s = mem_store_with(0, 0);
    CHECK(s != NULL); if (!s) return;
    CCFindCertificateFromFilter_pfn fn = CCLI(CCFindCertificateFromFilter);
    SET_ERR(0);
    PCCERT_CONTEXT c = fn(s, NULL, NULL);
    DWORD e = GetLastError();
    CHECK(c == NULL);
    CHECKF(e == (DWORD)HR_CRYPT_E_NOT_FOUND, "last error 0x%lx", e);
    U(CertCloseStore)(s, 0);
}

TEST(cct_findcert_enumerates_all_without_filter)
{
    REQUIRE(U(CertOpenStore)); REQUIRE(CCLI(CCFindCertificateFromFilter));
    HCERTSTORE s = mem_store_with(1, 1);
    CHECK(s != NULL); if (!s) return;
    CCFindCertificateFromFilter_pfn fn = CCLI(CCFindCertificateFromFilter);
    PCCERT_CONTEXT c1 = fn(s, NULL, NULL);
    CHECK(c1 != NULL);
    PCCERT_CONTEXT c2 = c1 ? fn(s, NULL, c1) : NULL;   /* the previous context is released by the call */
    CHECK(c2 != NULL);
    SET_ERR(0);
    PCCERT_CONTEXT c3 = c2 ? fn(s, NULL, c2) : NULL;
    DWORD e = GetLastError();
    CHECK(c3 == NULL);
    CHECKF(e == (DWORD)HR_CRYPT_E_NOT_FOUND, "last error 0x%lx", e);
    U(CertCloseStore)(s, 0);
}

TEST(cct_findcert_distinct_results)
{
    REQUIRE(U(CertOpenStore)); REQUIRE(CCLI(CCFindCertificateFromFilter));
    HCERTSTORE s = mem_store_with(1, 1);
    CHECK(s != NULL); if (!s) return;
    CCFindCertificateFromFilter_pfn fn = CCLI(CCFindCertificateFromFilter);
    PCCERT_CONTEXT c1 = fn(s, NULL, NULL);
    CHECK(c1 != NULL); if (!c1) { U(CertCloseStore)(s, 0); return; }
    BYTE h1[20]; DWORD n1 = 20;
    U(CryptHashCertificate)(0, CALG_SHA1, 0, c1->pbCertEncoded, c1->cbCertEncoded, h1, &n1);
    PCCERT_CONTEXT dup = U(CertDuplicateCertificateContext)(c1);
    PCCERT_CONTEXT c2 = fn(s, NULL, c1);
    CHECK(c2 != NULL);
    if (c2) {
        BYTE h2[20]; DWORD n2 = 20;
        U(CryptHashCertificate)(0, CALG_SHA1, 0, c2->pbCertEncoded, c2->cbCertEncoded, h2, &n2);
        CHECK(memcmp(h1, h2, 20) != 0);
        U(CertFreeCertificateContext)(c2);
    }
    if (dup) U(CertFreeCertificateContext)(dup);
    U(CertCloseStore)(s, 0);
}

TEST(cct_findcert_build_filter_null_text)
{
    REQUIRE(CCLI(CCFindCertificateBuildFilter)); REQUIRE(CCLI(CCFindCertificateFreeFilter));
    void *f = NULL;
    HRESULT hr = CCLI(CCFindCertificateBuildFilter)(NULL, &f);
    CHECK(hr == 0); CHECK(f != NULL);
    CCLI(CCFindCertificateFreeFilter)(f);
}

TEST(cct_findcert_free_filter_null)
{
    REQUIRE(CCLI(CCFindCertificateFreeFilter));
    CCLI(CCFindCertificateFreeFilter)(NULL);
    CHECK(1);
}

TEST(cct_findcert_empty_filter_matches_observed)
{
    REQUIRE(U(CertOpenStore)); REQUIRE(CCLI(CCFindCertificateBuildFilter)); REQUIRE(CCLI(CCFindCertificateFromFilter));
    HCERTSTORE s = mem_store_with(1, 1);
    CHECK(s != NULL); if (!s) return;
    void *f = NULL;
    CHECK(CCLI(CCFindCertificateBuildFilter)(NULL, &f) == 0);
    PCCERT_CONTEXT c = CCLI(CCFindCertificateFromFilter)(s, f, NULL);
    t_note("empty filter first match: %p err=0x%lx", (void *)c, GetLastError());
    if (c) U(CertFreeCertificateContext)(c);
    if (f) CCLI(CCFindCertificateFreeFilter)(f);
    U(CertCloseStore)(s, 0);
}

TEST(cct_findcert_filter_text_variants_observed)
{
    REQUIRE(CCLI(CCFindCertificateBuildFilter)); REQUIRE(CCLI(CCFindCertificateFreeFilter));
    static const WCHAR *txt[] = { L"cryptt san test", L"CN=cryptt san test", L"template=SomeTemplate", L"serial=01", L"thumbprint=00", L"subject=cryptt", L"bogus=x" };
    for (int i = 0; i < 7; i++) {
        void *f = NULL;
        HRESULT hr = CCLI(CCFindCertificateBuildFilter)(txt[i], &f);
        t_note("BuildFilter(\"%ls\") -> 0x%lx filter=%p", txt[i], (long)hr, f);
        if (hr == 0) CHECK(f != NULL);
        if (f) CCLI(CCFindCertificateFreeFilter)(f);
    }
}
