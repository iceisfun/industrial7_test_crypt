#include "gap0.h"
/* RFC 3161 time-stamp client helpers in crypt32. No request is ever sent: CryptRetrieveTimeStamp is only
 * driven through its argument validation. */

TEST(gap0_ts_exports) {
    if (t_is_wine()) { t_skip("exports absent in the emulator"); return; }
    CHECK(t_proc_in("crypt32.dll", "CryptRetrieveTimeStamp") != NULL);
    CHECK(t_proc_in("crypt32.dll", "CryptVerifyTimeStampSignature") != NULL);
}

/* ---- CryptRetrieveTimeStamp -------------------------------------------- */
static const BYTE g_in[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };

TEST(gap0_ts_retrieve_invalid_arguments) {
    REQUIRE(U(CryptRetrieveTimeStamp));
    static const WCHAR url[] = L"file:///cryptt_gap0_never_contacted";
    PCRYPT_TIMESTAMP_CONTEXT ctx;
    struct { const WCHAR *url; DWORD fl; const char *hid; const BYTE *d; DWORD cb; int nullctx; const char *why; } t[] = {
        { NULL, 0, szOID_NIST_sha256, g_in, 8, 0, "NULL url" },
        { L"",  0, szOID_NIST_sha256, g_in, 8, 0, "empty url" },
        { url,  0, NULL,              g_in, 8, 0, "NULL hash oid" },
        { url,  0, "",                g_in, 8, 0, "empty hash oid" },
        { url,  0, szOID_NIST_sha256, NULL, 8, 0, "NULL data" },
        { url,  0, szOID_NIST_sha256, g_in, 0, 0, "cb 0" },
        { url,  0, szOID_NIST_sha256, g_in, 0x20000000, 0, "cb above 0x1fffffff" },
        { url,  0, szOID_NIST_sha256, g_in, 0xFFFFFFFF, 0, "cb 0xffffffff" },
        { url,  0, szOID_NIST_sha256, g_in, 8, 1, "NULL ppTsContext" },
        { url,  TIMESTAMP_DONT_HASH_DATA, szOID_NIST_sha256, g_in, 0, 0, "DONT_HASH with cb 0" },
        { NULL, TIMESTAMP_DONT_HASH_DATA, szOID_NIST_sha256, g_in, 8, 0, "DONT_HASH with NULL url" },
        { url,  TIMESTAMP_VERIFY_CONTEXT_SIGNATURE, NULL, g_in, 8, 0, "VERIFY flag with NULL oid" },
    };
    for (unsigned i = 0; i < sizeof t / sizeof *t; i++) {
        ctx = (PCRYPT_TIMESTAMP_CONTEXT)(ULONG_PTR)0x10;
        SET_ERR(0);
        BOOL r = U(CryptRetrieveTimeStamp)(t[i].url, t[i].fl, 0, t[i].hid, NULL, t[i].d, t[i].cb,
                                           t[i].nullctx ? NULL : &ctx, NULL, NULL);
        CHECKF(r == FALSE, "%s", t[i].why);
        EXPECT_ERR(ERROR_INVALID_PARAMETER);
        if (!t[i].nullctx) CHECKF(ctx == (PCRYPT_TIMESTAMP_CONTEXT)(ULONG_PTR)0x10, "%s: ppTsContext written", t[i].why);
    }
}

TEST(gap0_ts_retrieve_unknown_hash_oid) {
    REQUIRE(U(CryptRetrieveTimeStamp));
    static const WCHAR url[] = L"file:///cryptt_gap0_never_contacted";
    /* Not a hash algorithm OID (or not an OID at all): rejected before any request is built. */
    const char *oids[] = { "1.2.3.4.5.6.7", szOID_RSA_RSA, "2.16.840.1.101.3.4.2", "0.0" };
    for (unsigned i = 0; i < sizeof oids / sizeof *oids; i++) {
        PCRYPT_TIMESTAMP_CONTEXT ctx = NULL;
        SET_ERR(0);
        BOOL r = U(CryptRetrieveTimeStamp)(url, 0, 0, oids[i], NULL, g_in, 8, &ctx, NULL, NULL);
        CHECKF(r == FALSE, "oid %s", oids[i]);
        EXPECT_ERR(G0_NTE_BAD_ALGID);
        CHECK(ctx == NULL);
    }
}

TEST(gap0_ts_retrieve_unknown_hash_oid_with_flags) {
    REQUIRE(U(CryptRetrieveTimeStamp));
    static const WCHAR url[] = L"file:///cryptt_gap0_never_contacted";
    DWORD fl[] = { 0, TIMESTAMP_DONT_HASH_DATA, TIMESTAMP_VERIFY_CONTEXT_SIGNATURE, TIMESTAMP_NO_AUTH_RETRIEVAL };
    for (unsigned i = 0; i < 4; i++) {
        PCRYPT_TIMESTAMP_CONTEXT ctx = NULL;
        CRYPT_TIMESTAMP_PARA para; memset(&para, 0, sizeof para);
        para.pszTSAPolicyId = "1.2.3.4.1"; para.fRequestCerts = TRUE;
        SET_ERR(0);
        BOOL r = U(CryptRetrieveTimeStamp)(url, fl[i], 0, "1.2.3.4.5.6.7", &para, g_in, 8, &ctx, NULL, NULL);
        CHECKF(r == FALSE, "flags 0x%lx", fl[i]);
        EXPECT_ERR(G0_NTE_BAD_ALGID);
    }
}

/* ---- CryptVerifyTimeStampSignature -------------------------------------- */
TEST(gap0_ts_verify_invalid_arguments) {
    REQUIRE(U(CryptVerifyTimeStampSignature));
    PCRYPT_TIMESTAMP_CONTEXT ctx;
    struct { const BYTE *tok; DWORD cbtok; const BYTE *d; DWORD cbd; int nullctx; const char *why; } t[] = {
        { NULL, 100, NULL, 0, 0, "NULL token" },
        { gap0_ts_token, 0, NULL, 0, 0, "cbToken 0" },
        { gap0_ts_token, 0x20000000, NULL, 0, 0, "cbToken above 0x1fffffff" },
        { gap0_ts_token, 0xFFFFFFFF, NULL, 0, 0, "cbToken 0xffffffff" },
        { gap0_ts_token, sizeof gap0_ts_token, gap0_ts_data, 0x20000000, 0, "cbData above 0x1fffffff" },
        { gap0_ts_token, sizeof gap0_ts_token, NULL, 0x20000000, 0, "cbData big with NULL data" },
        { gap0_ts_token, sizeof gap0_ts_token, NULL, 0, 1, "NULL ppTsContext" },
    };
    for (unsigned i = 0; i < sizeof t / sizeof *t; i++) {
        ctx = (PCRYPT_TIMESTAMP_CONTEXT)(ULONG_PTR)0x10;
        PCCERT_CONTEXT signer = (PCCERT_CONTEXT)(ULONG_PTR)0x20;
        HCERTSTORE st = (HCERTSTORE)(ULONG_PTR)0x30;
        SET_ERR(0);
        BOOL r = U(CryptVerifyTimeStampSignature)(t[i].tok, t[i].cbtok, t[i].d, t[i].cbd, NULL,
                                                  t[i].nullctx ? NULL : &ctx, &signer, &st);
        CHECKF(r == FALSE, "%s", t[i].why);
        EXPECT_ERR(ERROR_INVALID_PARAMETER);
        /* Rejected before any output is initialised. */
        if (!t[i].nullctx) CHECKF(ctx == (PCRYPT_TIMESTAMP_CONTEXT)(ULONG_PTR)0x10, "%s: ctx written", t[i].why);
        CHECKF(signer == (PCCERT_CONTEXT)(ULONG_PTR)0x20, "%s: signer written", t[i].why);
        CHECKF(st == (HCERTSTORE)(ULONG_PTR)0x30, "%s: store written", t[i].why);
    }
}

TEST(gap0_ts_verify_garbage_token_clears_outputs) {
    REQUIRE(U(CryptVerifyTimeStampSignature));
    static const BYTE junk[] = { 0x30, 0x03, 0x02, 0x01, 0x05 };
    static const BYTE one[] = { 0x30 };
    static const BYTE zeros[16] = { 0 };
    struct { const BYTE *p; DWORD cb; } t[] = { { junk, sizeof junk }, { one, 1 }, { zeros, sizeof zeros } };
    for (unsigned i = 0; i < 3; i++) {
        PCRYPT_TIMESTAMP_CONTEXT ctx = (PCRYPT_TIMESTAMP_CONTEXT)(ULONG_PTR)0x10;
        PCCERT_CONTEXT signer = (PCCERT_CONTEXT)(ULONG_PTR)0x20;
        HCERTSTORE st = (HCERTSTORE)(ULONG_PTR)0x30;
        SET_ERR(0);
        BOOL r = U(CryptVerifyTimeStampSignature)(t[i].p, t[i].cb, NULL, 0, NULL, &ctx, &signer, &st);
        DWORD e = GetLastError();
        CHECKF(r == FALSE, "row %u", i);
        CHECKF(e != 0, "row %u: no last error", i);
        t_note("garbage token row %u: err=0x%lx", i, e);
        /* Past the argument checks the context and signer outputs are reset; the store output is only set on success. */
        CHECKF(ctx == NULL, "row %u: ctx not cleared", i);
        CHECKF(signer == NULL, "row %u: signer not cleared", i);
        CHECKF(st == (HCERTSTORE)(ULONG_PTR)0x30, "row %u: store written", i);
    }
}

TEST(gap0_ts_verify_non_timestamp_signed_message) {
    REQUIRE(U(CryptVerifyTimeStampSignature));
    /* A valid CMS SignedData whose inner content type is id-data, not id-ct-TSTInfo. */
    PCRYPT_TIMESTAMP_CONTEXT ctx = (PCRYPT_TIMESTAMP_CONTEXT)(ULONG_PTR)0x10;
    PCCERT_CONTEXT signer = (PCCERT_CONTEXT)(ULONG_PTR)0x20;
    SET_ERR(0);
    BOOL r = U(CryptVerifyTimeStampSignature)(gap0_cms_data_signed, sizeof gap0_cms_data_signed, NULL, 0, NULL, &ctx, &signer, NULL);
    CHECK(r == FALSE); EXPECT_ERR(G0_CRYPT_E_INVALID_MSG_TYPE);
    CHECK(ctx == NULL); CHECK(signer == NULL);
}

static void g0_free_ts(PCRYPT_TIMESTAMP_CONTEXT ctx, PCCERT_CONTEXT signer, HCERTSTORE st) {
    if (ctx) U(CryptMemFree)(ctx);
    if (signer) U(CertFreeCertificateContext)(signer);
    if (st) U(CertCloseStore)(st, 0);
}

TEST(gap0_ts_verify_valid_token) {
    REQUIRE(U(CryptVerifyTimeStampSignature)); REQUIRE(U(CryptMemFree));
    PCRYPT_TIMESTAMP_CONTEXT ctx = NULL; PCCERT_CONTEXT signer = NULL; HCERTSTORE st = NULL;
    SET_ERR(0);
    BOOL r = U(CryptVerifyTimeStampSignature)(gap0_ts_token, sizeof gap0_ts_token, gap0_ts_data, sizeof gap0_ts_data, NULL, &ctx, &signer, &st);
    if (!r) {
        t_note("valid token rejected: err=0x%lx", GetLastError());
        CHECK(ctx == NULL && signer == NULL);
        return;
    }
    CHECK(ctx != NULL); CHECK(signer != NULL); CHECK(st != NULL);
    if (ctx) {
        EXPECT_EQ(ctx->cbEncoded, sizeof gap0_ts_token);
        CHECK(ctx->pbEncoded && !memcmp(ctx->pbEncoded, gap0_ts_token, sizeof gap0_ts_token));
        PCRYPT_TIMESTAMP_INFO ti = ctx->pTimeStamp;
        CHECK(ti != NULL);
        if (ti) {
            EXPECT_EQ(ti->dwVersion, 1);
            CHECK(ti->pszTSAPolicyId && !strcmp(ti->pszTSAPolicyId, "1.2.3.4.1"));
            CHECK(ti->HashAlgorithm.pszObjId && !strcmp(ti->HashAlgorithm.pszObjId, szOID_NIST_sha256));
            EXPECT_EQ(ti->HashedMessage.cbData, 32);
            CHECK(ti->HashedMessage.cbData == 32 && !memcmp(ti->HashedMessage.pbData, gap0_ts_sha256, 32));
            /* serial 0x0A1B2C3E, stored little endian */
            EXPECT_EQ(ti->SerialNumber.cbData, 4);
            if (ti->SerialNumber.cbData == 4) {
                static const BYTE ser[4] = { 0x3E, 0x2C, 0x1B, 0x0A };
                CHECK(!memcmp(ti->SerialNumber.pbData, ser, 4));
            }
            SYSTEMTIME s; CHECK(FileTimeToSystemTime(&ti->ftTime, &s));
            CHECK(s.wYear >= 2026 && s.wYear <= 2027);
            CHECK(ti->pvAccuracy != NULL);
            if (ti->pvAccuracy) EXPECT_EQ(ti->pvAccuracy->dwSeconds, 1);
            CHECK(ti->fOrdering == TRUE);
            EXPECT_EQ(ti->Nonce.cbData, 0);
            CHECK(ti->Tsa.cbData > 0);
            EXPECT_EQ(ti->cExtension, 0);
        }
    }
    if (signer) {
        char nm[128] = "";
        U(CertGetNameStringA)(signer, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, nm, sizeof nm);
        EXPECT_STR(nm, "cryptt gap0 TSA");
    }
    g0_free_ts(ctx, signer, st);
}

TEST(gap0_ts_verify_valid_token_optional_outputs) {
    REQUIRE(U(CryptVerifyTimeStampSignature)); REQUIRE(U(CryptMemFree));
    PCRYPT_TIMESTAMP_CONTEXT ctx = NULL;
    SET_ERR(0);
    /* Signer and store outputs are optional; data may be omitted (no imprint comparison). */
    BOOL r = U(CryptVerifyTimeStampSignature)(gap0_ts_token, sizeof gap0_ts_token, NULL, 0, NULL, &ctx, NULL, NULL);
    if (!r) { t_note("token rejected without data: err=0x%lx", GetLastError()); return; }
    CHECK(ctx != NULL && ctx->pTimeStamp != NULL);
    g0_free_ts(ctx, NULL, NULL);
}

TEST(gap0_ts_verify_wrong_data) {
    REQUIRE(U(CryptVerifyTimeStampSignature)); REQUIRE(U(CryptMemFree));
    PCRYPT_TIMESTAMP_CONTEXT ok = NULL;
    BOOL good = U(CryptVerifyTimeStampSignature)(gap0_ts_token, sizeof gap0_ts_token, gap0_ts_data, sizeof gap0_ts_data, NULL, &ok, NULL, NULL);
    if (!good) { t_skip("valid token not accepted here"); return; }
    g0_free_ts(ok, NULL, NULL);
    BYTE bad[sizeof gap0_ts_data]; memcpy(bad, gap0_ts_data, sizeof bad); bad[0] ^= 1;
    PCRYPT_TIMESTAMP_CONTEXT ctx = (PCRYPT_TIMESTAMP_CONTEXT)(ULONG_PTR)0x10;
    PCCERT_CONTEXT signer = (PCCERT_CONTEXT)(ULONG_PTR)0x20;
    SET_ERR(0);
    BOOL r = U(CryptVerifyTimeStampSignature)(gap0_ts_token, sizeof gap0_ts_token, bad, sizeof bad, NULL, &ctx, &signer, NULL);
    DWORD e = GetLastError();
    CHECK(r == FALSE);
    t_note("flipped data bit: err=0x%lx", e);
    CHECK(ctx == NULL); CHECK(signer == NULL);
    /* One byte short and one byte long are also different imprints. */
    ctx = NULL;
    CHECK(!U(CryptVerifyTimeStampSignature)(gap0_ts_token, sizeof gap0_ts_token, gap0_ts_data, sizeof gap0_ts_data - 1, NULL, &ctx, NULL, NULL));
    BYTE longer[sizeof gap0_ts_data + 1]; memcpy(longer, gap0_ts_data, sizeof gap0_ts_data); longer[sizeof gap0_ts_data] = 0;
    CHECK(!U(CryptVerifyTimeStampSignature)(gap0_ts_token, sizeof gap0_ts_token, longer, sizeof longer, NULL, &ctx, NULL, NULL));
}

TEST(gap0_ts_verify_truncated_or_tampered_token) {
    REQUIRE(U(CryptVerifyTimeStampSignature)); REQUIRE(U(CryptMemFree));
    PCRYPT_TIMESTAMP_CONTEXT ok = NULL;
    BOOL good = U(CryptVerifyTimeStampSignature)(gap0_ts_token, sizeof gap0_ts_token, gap0_ts_data, sizeof gap0_ts_data, NULL, &ok, NULL, NULL);
    if (!good) { t_skip("valid token not accepted here"); return; }
    g0_free_ts(ok, NULL, NULL);
    static BYTE tok[sizeof gap0_ts_token];
    DWORD cuts[] = { sizeof tok - 1, sizeof tok - 16, sizeof tok / 2, 8 };
    for (unsigned i = 0; i < 4; i++) {
        PCRYPT_TIMESTAMP_CONTEXT ctx = NULL;
        SET_ERR(0);
        BOOL r = U(CryptVerifyTimeStampSignature)(gap0_ts_token, cuts[i], NULL, 0, NULL, &ctx, NULL, NULL);
        CHECKF(r == FALSE, "truncated to %lu", cuts[i]);
        CHECK(ctx == NULL);
    }
    /* Flip a bit in the last byte (inside the signature value). */
    memcpy(tok, gap0_ts_token, sizeof tok); tok[sizeof tok - 1] ^= 0x01;
    PCRYPT_TIMESTAMP_CONTEXT ctx = NULL;
    SET_ERR(0);
    BOOL r = U(CryptVerifyTimeStampSignature)(tok, sizeof tok, NULL, 0, NULL, &ctx, NULL, NULL);
    CHECK(r == FALSE); CHECK(GetLastError() != 0);
    t_note("tampered signature: err=0x%lx", GetLastError());
    /* Flip a bit inside the signed TSTInfo (the data it covers). */
    memcpy(tok, gap0_ts_token, sizeof tok);
    for (unsigned i = 0; i + 4 < sizeof tok; i++) if (!memcmp(tok + i, gap0_ts_sha256, 4)) { tok[i + 1] ^= 0x80; break; }
    ctx = NULL;
    r = U(CryptVerifyTimeStampSignature)(tok, sizeof tok, NULL, 0, NULL, &ctx, NULL, NULL);
    CHECK(r == FALSE);
    t_note("tampered imprint: err=0x%lx", GetLastError());
}
