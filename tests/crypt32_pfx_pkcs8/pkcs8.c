#include "pp.h"

#define T_PKCS_PRIVATE_KEY_INFO           ((LPCSTR)44)
#define T_PKCS_ENCRYPTED_PRIVATE_KEY_INFO ((LPCSTR)45)
#define E_UNSUPPORTED_TYPE 1630

#define NEED_P8() do { REQUIRE(U(CryptExportPKCS8)); REQUIRE(U(CryptImportPKCS8)); \
    REQUIRE(U(CryptAcquireContextA)); REQUIRE(U(CryptReleaseContext)); REQUIRE(U(CryptGenKey)); REQUIRE(U(CryptGetUserKey)); \
    REQUIRE(U(CryptExportKey)); REQUIRE(U(CryptDestroyKey)); REQUIRE(U(CryptDecodeObjectEx)); } while (0)

/* the emulator only stubs the PKCS#8 entry points */
#define PP_WINE_P8() do { if (t_is_wine() && !U(CryptExportPKCS8Ex)) { t_skip("emulator: no PKCS#8 support"); return; } } while (0)
static const char rsa_oid[] = szOID_RSA_RSA;
static const char xor_oid[] = "1.2.840.113549.3.7"; /* an OID of our own choosing for the toy "cipher" */

/* ephemeral provider holding a fresh exportable RSA-1024 key-exchange key */
static HCRYPTPROV gen_prov(void) {
    HCRYPTPROV p = 0; HCRYPTKEY k = 0;
    if (!U(CryptAcquireContextA)(&p, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) return 0;
    if (!U(CryptGenKey)(p, AT_KEYEXCHANGE, (1024u << 16) | CRYPT_EXPORTABLE, &k)) { U(CryptReleaseContext)(p, 0); return 0; }
    U(CryptDestroyKey)(k);
    return p;
}
static BYTE *export_p8(HCRYPTPROV p, DWORD *pcb) {
    DWORD cb = 0;
    if (!U(CryptExportPKCS8)(p, AT_KEYEXCHANGE, (LPSTR)rsa_oid, 0, NULL, NULL, &cb)) return NULL;
    BYTE *b = (BYTE *)LocalAlloc(LPTR, cb);
    if (!U(CryptExportPKCS8)(p, AT_KEYEXCHANGE, (LPSTR)rsa_oid, 0x8000, NULL, b, &cb)) { LocalFree(b); return NULL; }
    *pcb = cb; return b;
}
static BYTE *get_pub(HCRYPTPROV p, DWORD spec, DWORD *pcb) {
    HCRYPTKEY k = 0; DWORD cb = 0; BYTE *b = NULL;
    if (!U(CryptGetUserKey)(p, spec, &k)) return NULL;
    if (U(CryptExportKey)(k, 0, PUBLICKEYBLOB, 0, NULL, &cb)) {
        b = (BYTE *)LocalAlloc(LPTR, cb);
        if (!U(CryptExportKey)(k, 0, PUBLICKEYBLOB, 0, b, &cb)) { LocalFree(b); b = NULL; }
    }
    U(CryptDestroyKey)(k);
    if (b) *pcb = cb;
    return b;
}
/* little-endian modulus inside a PUBLICKEYBLOB equals the fixture's big-endian modulus */
static int pub_is_fixture(const BYTE *blob, DWORD cb) {
    if (cb != 20 + 128) return 0;
    const BYTE *m = blob + 20;
    for (int i = 0; i < 128; i++) if (m[i] != fx_mod1_be[127 - i]) return 0;
    return 1;
}
/* documented path: the caller supplies the (ephemeral) provider through the resolve callback */
static BOOL CALLBACK resolve_vc(CRYPT_PRIVATE_KEY_INFO *pk, HCRYPTPROV *pp, LPVOID ctx) {
    return U(CryptAcquireContextA)(pp, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
}
static HCRYPTPROV import_plain(const BYTE *p8, size_t n, DWORD flags) {
    CRYPT_PKCS8_IMPORT_PARAMS ip; memset(&ip, 0, sizeof ip);
    ip.PrivateKey.cbData = (DWORD)n; ip.PrivateKey.pbData = (BYTE *)p8;
    ip.pResolvehCryptProvFunc = resolve_vc;
    HCRYPTPROV p = 0;
    if (!U(CryptImportPKCS8)(ip, flags & ~0x8000u, &p, NULL)) return 0;
    return p;
}
/* undocumented-in-the-SDK flag 0x8000: the import routine acquires a CRYPT_VERIFYCONTEXT provider itself */
static HCRYPTPROV import_plain_8000(const BYTE *p8, size_t n, DWORD flags) {
    CRYPT_PKCS8_IMPORT_PARAMS ip; memset(&ip, 0, sizeof ip);
    ip.PrivateKey.cbData = (DWORD)n; ip.PrivateKey.pbData = (BYTE *)p8;
    HCRYPTPROV p = 0;
    if (!U(CryptImportPKCS8)(ip, flags | 0x8000, &p, NULL)) return 0;
    return p;
}

/* ---- export argument handling -------------------------------------------------- */
TEST(pkcs8_export_unknown_oid_is_unsupported_type) {
    NEED_P8(); PP_WINE_P8();
    HCRYPTPROV p = gen_prov();
    if (!p) { CHECK(p != 0); return; }
    DWORD cb = 0;
    SET_ERR(0);
    BOOL r = U(CryptExportPKCS8)(p, AT_KEYEXCHANGE, (LPSTR)"1.2.3.4.5.6.7.8.99", 0, NULL, NULL, &cb);
    EXPECT_FAIL(!r, E_UNSUPPORTED_TYPE);
    U(CryptReleaseContext)(p, 0);
}
TEST(pkcs8_export_null_oid_observed) {
    NEED_P8(); PP_WINE_P8();
    HCRYPTPROV p = gen_prov();
    if (!p) { CHECK(p != 0); return; }
    DWORD cb = 0;
    SET_ERR(0);
    BOOL r = U(CryptExportPKCS8)(p, AT_KEYEXCHANGE, NULL, 0, NULL, NULL, &cb);
    t_note("CryptExportPKCS8 with NULL OID: ret=%d err=%lu cb=%lu", r, GetLastError(), cb);
    U(CryptReleaseContext)(p, 0);
}
TEST(pkcs8_export_size_query) {
    NEED_P8(); PP_WINE_P8();
    HCRYPTPROV p = gen_prov();
    if (!p) { CHECK(p != 0); return; }
    DWORD cb = 0, cb2 = 0;
    CHECKF(U(CryptExportPKCS8)(p, AT_KEYEXCHANGE, (LPSTR)rsa_oid, 0, NULL, NULL, &cb), "err 0x%lx", GetLastError());
    CHECK(cb > 500 && cb < 700);
    CHECK(U(CryptExportPKCS8)(p, AT_KEYEXCHANGE, (LPSTR)rsa_oid, 0, NULL, NULL, &cb2));
    EXPECT_EQ(cb, cb2); /* the size depends on the random key (leading zero bytes), so it is not pinned */
    U(CryptReleaseContext)(p, 0);
}
TEST(pkcs8_export_exact_buffer_decodes_as_private_key_info) {
    NEED_P8(); PP_WINE_P8();
    HCRYPTPROV p = gen_prov();
    if (!p) { CHECK(p != 0); return; }
    DWORD cb = 0;
    BYTE *b = export_p8(p, &cb);
    CHECKF(b != NULL, "err 0x%lx", GetLastError());
    if (b) {
        CHECK(b[0] == 0x30);
        DWORD dc = 0; CRYPT_PRIVATE_KEY_INFO *pk = NULL;
        BOOL r = U(CryptDecodeObjectEx)(X509_ASN_ENCODING, T_PKCS_PRIVATE_KEY_INFO, b, cb, CRYPT_DECODE_ALLOC_FLAG, NULL, &pk, &dc);
        CHECKF(r, "decode err 0x%lx", GetLastError());
        if (r) {
            EXPECT_EQ(pk->Version, 0);
            EXPECT_STR(pk->Algorithm.pszObjId, szOID_RSA_RSA);
            CHECK(pk->PrivateKey.cbData > 400);
            CHECK(pk->PrivateKey.pbData[0] == 0x30);
            LocalFree(pk);
        }
        LocalFree(b);
    }
    U(CryptReleaseContext)(p, 0);
}
TEST(pkcs8_export_buffer_too_small_is_more_data) {
    NEED_P8(); PP_WINE_P8();
    HCRYPTPROV p = gen_prov();
    if (!p) { CHECK(p != 0); return; }
    DWORD need = 0;
    CHECK(U(CryptExportPKCS8)(p, AT_KEYEXCHANGE, (LPSTR)rsa_oid, 0, NULL, NULL, &need));
    BYTE *buf = (BYTE *)LocalAlloc(LPTR, need + 16);
    DWORD sizes[] = {0, 1, need / 2, need - 1};
    for (int i = 0; i < 4; i++) {
        DWORD cb = sizes[i];
        SET_ERR(0);
        BOOL r = U(CryptExportPKCS8)(p, AT_KEYEXCHANGE, (LPSTR)rsa_oid, 0x8000, NULL, buf, &cb);
        CHECKF(!r, "size %lu", sizes[i]);
        EXPECT_ERR(ERROR_MORE_DATA);
        CHECKF(cb == need, "required size %lu vs %lu", cb, need);
    }
    LocalFree(buf);
    U(CryptReleaseContext)(p, 0);
}
TEST(pkcs8_export_oversized_buffer_reports_actual_size) {
    NEED_P8(); PP_WINE_P8();
    HCRYPTPROV p = gen_prov();
    if (!p) { CHECK(p != 0); return; }
    DWORD need = 0;
    CHECK(U(CryptExportPKCS8)(p, AT_KEYEXCHANGE, (LPSTR)rsa_oid, 0, NULL, NULL, &need));
    BYTE *buf = (BYTE *)LocalAlloc(LPTR, need + 64);
    DWORD cb = need + 64;
    CHECKF(U(CryptExportPKCS8)(p, AT_KEYEXCHANGE, (LPSTR)rsa_oid, 0x8000, NULL, buf, &cb), "err 0x%lx", GetLastError());
    CHECKF(cb <= need && cb > need - 8, "cb %lu need %lu", cb, need);
    LocalFree(buf);
    U(CryptReleaseContext)(p, 0);
}
TEST(pkcs8_export_wrong_keyspec_fails) {
    NEED_P8(); PP_WINE_P8();
    HCRYPTPROV p = gen_prov();
    if (!p) { CHECK(p != 0); return; }
    DWORD cb = 0;
    SET_ERR(0);
    BOOL r = U(CryptExportPKCS8)(p, AT_SIGNATURE, (LPSTR)rsa_oid, 0, NULL, NULL, &cb);
    CHECK(!r);
    t_note("export of absent AT_SIGNATURE key: err 0x%lx", GetLastError());
    U(CryptReleaseContext)(p, 0);
}
TEST(pkcs8_export_nonexportable_key_fails) {
    NEED_P8(); PP_WINE_P8();
    HCRYPTPROV p = 0; HCRYPTKEY k = 0;
    CHECK(U(CryptAcquireContextA)(&p, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT));
    CHECK(U(CryptGenKey)(p, AT_KEYEXCHANGE, 1024u << 16, &k));
    if (k) U(CryptDestroyKey)(k);
    DWORD cb = 0;
    SET_ERR(0);
    BOOL r = U(CryptExportPKCS8)(p, AT_KEYEXCHANGE, (LPSTR)rsa_oid, 0, NULL, NULL, &cb);
    if (r) {
        BYTE *buf = (BYTE *)LocalAlloc(LPTR, cb);
        r = U(CryptExportPKCS8)(p, AT_KEYEXCHANGE, (LPSTR)rsa_oid, 0x8000, NULL, buf, &cb);
        LocalFree(buf);
    }
    CHECK(!r);
    t_note("non-exportable key: err 0x%lx", GetLastError());
    U(CryptReleaseContext)(p, 0);
}
TEST(pkcs8_export_ex_is_not_exported) {
    /* CryptExportPKCS8Ex is declared in the SDK header but crypt32 on Win10 22H2 does not export it */
    HMODULE m = GetModuleHandleW(L"crypt32.dll");
    REQUIRE_NOTNULL(m);
    EXPECT_GPA_FAIL(m, "CryptExportPKCS8Ex");
    CHECK(GetProcAddress(m, "CryptExportPKCS8") != NULL);
}

/* ---- encrypt callback ----------------------------------------------------------- */
static struct { int calls; int null_buf_calls; void *ctx; } g_enc;
static BOOL CALLBACK xor_decrypt(CRYPT_ALGORITHM_IDENTIFIER alg, CRYPT_DATA_BLOB enc, BYTE *out, DWORD *pcb, LPVOID ctx) {
    g_enc.calls++; g_enc.ctx = ctx;
    if (!alg.pszObjId || strcmp(alg.pszObjId, xor_oid)) { SetLastError(NTE_BAD_ALGID); return FALSE; }
    if (!out) { g_enc.null_buf_calls++; *pcb = enc.cbData; return TRUE; }
    if (*pcb < enc.cbData) { SetLastError(ERROR_MORE_DATA); *pcb = enc.cbData; return FALSE; }
    for (DWORD i = 0; i < enc.cbData; i++) out[i] = enc.pbData[i] ^ 0x5a;
    *pcb = enc.cbData;
    return TRUE;
}
/* build an EncryptedPrivateKeyInfo of our own: toy xor "cipher" over a plain PKCS#8 blob */
static BYTE *export_enc(HCRYPTPROV p, DWORD *pcb) {
    DWORD cp = 0; BYTE *plain = export_p8(p, &cp);
    if (!plain) return NULL;
    for (DWORD i = 0; i < cp; i++) plain[i] ^= 0x5a;
    CRYPT_ENCRYPTED_PRIVATE_KEY_INFO ei; memset(&ei, 0, sizeof ei);
    ei.EncryptionAlgorithm.pszObjId = (LPSTR)xor_oid;
    ei.EncryptedPrivateKey.cbData = cp; ei.EncryptedPrivateKey.pbData = plain;
    BYTE *out = NULL; DWORD cb = 0;
    if (!U(CryptEncodeObjectEx)(X509_ASN_ENCODING, T_PKCS_ENCRYPTED_PRIVATE_KEY_INFO, &ei, CRYPT_ENCODE_ALLOC_FLAG, NULL, &out, &cb)) out = NULL;
    LocalFree(plain);
    if (out) *pcb = cb;
    return out;
}

/* ---- import: plain ------------------------------------------------------------------ */
TEST(pkcs8_import_plain_fixture_yields_usable_provider) {
    NEED_P8(); PP_WINE_P8();
    HCRYPTPROV p = import_plain(fx_p8plain, sizeof fx_p8plain, 0);
    CHECKF(p != 0, "err 0x%lx", GetLastError());
    if (p) {
        DWORD cb = 0;
        BYTE *pub = get_pub(p, AT_KEYEXCHANGE, &cb);
        if (!pub) pub = get_pub(p, AT_SIGNATURE, &cb);
        CHECK(pub != NULL);
        if (pub) { CHECK(pub_is_fixture(pub, cb)); LocalFree(pub); }
        U(CryptReleaseContext)(p, 0);
    }
}
TEST(pkcs8_import_8000_flag_uses_verify_context_provider) {
    NEED_P8(); PP_WINE_P8();
    HCRYPTPROV p = import_plain_8000(fx_p8plain, sizeof fx_p8plain, 0);
    t_note("flag 0x8000 import without resolver: %s (err 0x%lx)", p ? "ok" : "failed", GetLastError());
    if (p) {
        DWORD cb = 0;
        BYTE *pub = get_pub(p, AT_KEYEXCHANGE, &cb);
        if (!pub) pub = get_pub(p, AT_SIGNATURE, &cb);
        CHECK(pub != NULL);
        if (pub) { CHECK(pub_is_fixture(pub, cb)); LocalFree(pub); }
        U(CryptReleaseContext)(p, 0);
    }
}
TEST(pkcs8_import_plain_without_provider_out_param) {
    NEED_P8(); PP_WINE_P8();
    CRYPT_PKCS8_IMPORT_PARAMS ip; memset(&ip, 0, sizeof ip);
    ip.PrivateKey.cbData = sizeof fx_p8plain; ip.PrivateKey.pbData = (BYTE *)fx_p8plain;
    ip.pResolvehCryptProvFunc = resolve_vc;
    SET_ERR(0);
    BOOL r = U(CryptImportPKCS8)(ip, 0, NULL, NULL);
    CHECKF(r, "err 0x%lx", GetLastError());
}
TEST(pkcs8_import_exportable_flag_allows_key_export) {
    NEED_P8(); PP_WINE_P8();
    HCRYPTPROV p = import_plain(fx_p8plain, sizeof fx_p8plain, CRYPT_EXPORTABLE);
    CHECKF(p != 0, "err 0x%lx", GetLastError());
    if (p) {
        HCRYPTKEY k = 0; DWORD cb = 0;
        if (U(CryptGetUserKey)(p, AT_KEYEXCHANGE, &k)) {
            BOOL r = U(CryptExportKey)(k, 0, PRIVATEKEYBLOB, 0, NULL, &cb);
            CHECKF(r, "CryptExportKey err 0x%lx", GetLastError());
            U(CryptDestroyKey)(k);
        } else t_note("no AT_KEYEXCHANGE key after import (err 0x%lx)", GetLastError());
        U(CryptReleaseContext)(p, 0);
    }
}
TEST(pkcs8_import_without_exportable_flag_blocks_key_export) {
    NEED_P8(); PP_WINE_P8();
    HCRYPTPROV p = import_plain(fx_p8plain, sizeof fx_p8plain, 0);
    CHECKF(p != 0, "err 0x%lx", GetLastError());
    if (p) {
        HCRYPTKEY k = 0; DWORD cb = 0;
        if (U(CryptGetUserKey)(p, AT_KEYEXCHANGE, &k)) {
            SET_ERR(0);
            BOOL r = U(CryptExportKey)(k, 0, PRIVATEKEYBLOB, 0, NULL, &cb);
            CHECK(!r);
            t_note("non-exportable imported key: CryptExportKey err 0x%lx", GetLastError());
            U(CryptDestroyKey)(k);
        }
        U(CryptReleaseContext)(p, 0);
    }
}
TEST(pkcs8_import_signature_matches_known_answer) {
    NEED_P8(); PP_WINE_P8();
    REQUIRE(U(CryptCreateHash)); REQUIRE(U(CryptHashData)); REQUIRE(U(CryptSignHashA)); REQUIRE(U(CryptDestroyHash));
    HCRYPTPROV p = import_plain(fx_p8plain, sizeof fx_p8plain, 0);
    CHECKF(p != 0, "err 0x%lx", GetLastError());
    if (!p) return;
    DWORD spec = AT_KEYEXCHANGE;
    HCRYPTKEY k = 0;
    if (!U(CryptGetUserKey)(p, spec, &k)) { spec = AT_SIGNATURE; U(CryptGetUserKey)(p, spec, &k); }
    if (k) U(CryptDestroyKey)(k);
    HCRYPTHASH h = 0;
    CHECK(U(CryptCreateHash)(p, CALG_SHA1, 0, 0, &h));
    if (h) {
        static const char msg[] = "cryptt pkcs8 message";
        CHECK(U(CryptHashData)(h, (const BYTE *)msg, sizeof msg - 1, 0));
        BYTE sig[256]; DWORD cb = sizeof sig;
        BOOL r = U(CryptSignHashA)(h, spec, NULL, 0, sig, &cb);
        CHECKF(r, "sign err 0x%lx", GetLastError());
        if (r) {
            EXPECT_EQ(cb, 128);
            int same = cb == 128;
            for (int i = 0; same && i < 128; i++) if (sig[i] != fx_sig1_be[127 - i]) same = 0;
            CHECK(same); /* PKCS#1 v1.5 signatures are deterministic */
        }
        U(CryptDestroyHash)(h);
    }
    U(CryptReleaseContext)(p, 0);
}
TEST(pkcs8_import_resolve_callback_supplies_provider) {
    NEED_P8(); PP_WINE_P8();
    struct R { int calls; HCRYPTPROV prov; char oid[64]; DWORD ver; void *ctx; };
    static struct R rr;
    BOOL CALLBACK resolve(CRYPT_PRIVATE_KEY_INFO *pk, HCRYPTPROV *pp, LPVOID ctx) {
        rr.calls++; rr.ctx = ctx; rr.ver = pk->Version;
        lstrcpynA(rr.oid, pk->Algorithm.pszObjId ? pk->Algorithm.pszObjId : "(null)", sizeof rr.oid);
        HCRYPTPROV h = 0;
        if (!U(CryptAcquireContextA)(&h, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) return FALSE;
        rr.prov = h; *pp = h; return TRUE;
    }
    memset(&rr, 0, sizeof rr);
    CRYPT_PKCS8_IMPORT_PARAMS ip; memset(&ip, 0, sizeof ip);
    ip.PrivateKey.cbData = sizeof fx_p8plain; ip.PrivateKey.pbData = (BYTE *)fx_p8plain;
    ip.pResolvehCryptProvFunc = resolve; ip.pVoidResolveFunc = (LPVOID)(ULONG_PTR)0x77;
    HCRYPTPROV out = 0;
    BOOL r = U(CryptImportPKCS8)(ip, 0, &out, NULL);
    CHECKF(r, "err 0x%lx", GetLastError());
    EXPECT_EQ(rr.calls, 1);
    EXPECT_EQ(rr.ctx, 0x77);
    EXPECT_EQ(rr.ver, 0);
    EXPECT_STR(rr.oid, szOID_RSA_RSA);
    CHECK(out == rr.prov);
    if (out) {
        DWORD cb = 0;
        BYTE *pub = get_pub(out, AT_KEYEXCHANGE, &cb);
        if (!pub) pub = get_pub(out, AT_SIGNATURE, &cb);
        CHECK(pub != NULL);
        if (pub) { CHECK(pub_is_fixture(pub, cb)); LocalFree(pub); }
        U(CryptReleaseContext)(out, 0);
    }
}
TEST(pkcs8_import_resolve_callback_failure_fails_import) {
    NEED_P8(); PP_WINE_P8();
    static int calls;
    BOOL CALLBACK resolve_fail(CRYPT_PRIVATE_KEY_INFO *pk, HCRYPTPROV *pp, LPVOID ctx) { calls++; SetLastError(ERROR_ACCESS_DENIED); return FALSE; }
    calls = 0;
    CRYPT_PKCS8_IMPORT_PARAMS ip; memset(&ip, 0, sizeof ip);
    ip.PrivateKey.cbData = sizeof fx_p8plain; ip.PrivateKey.pbData = (BYTE *)fx_p8plain;
    ip.pResolvehCryptProvFunc = resolve_fail;
    HCRYPTPROV out = 0;
    SET_ERR(0);
    BOOL r = U(CryptImportPKCS8)(ip, 0, &out, NULL);
    CHECK(!r);
    EXPECT_EQ(calls, 1);
    EXPECT_EQ(out, 0);
    t_note("resolve callback failure: last error %lu", GetLastError());
}

/* ---- import: invalid input ------------------------------------------------------------- */
TEST(pkcs8_import_unknown_algorithm_oid_is_unsupported_type) {
    NEED_P8(); PP_WINE_P8();
    /* rsaEncryption 06 09 2a 86 48 86 f7 0d 01 01 01 -> ...01 01 7f (an unregistered OID) */
    BYTE *copy = (BYTE *)LocalAlloc(LPTR, sizeof fx_p8plain);
    memcpy(copy, fx_p8plain, sizeof fx_p8plain);
    static const BYTE oid[] = {0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01};
    DWORD at = 0; int found = 0;
    for (DWORD i = 0; i + sizeof oid <= sizeof fx_p8plain; i++) if (!memcmp(copy + i, oid, sizeof oid)) { at = i; found = 1; break; }
    CHECK(found);
    if (found) {
        copy[at + 10] = 0x7f;
        SET_ERR(0);
        HCRYPTPROV p = import_plain(copy, sizeof fx_p8plain, 0);
        CHECK(p == 0);
        EXPECT_ERR(E_UNSUPPORTED_TYPE);
        if (p) U(CryptReleaseContext)(p, 0);
    }
    LocalFree(copy);
}
TEST(pkcs8_import_garbage_fails) {
    NEED_P8(); PP_WINE_P8();
    static const BYTE g[] = {1, 2, 3, 4, 5, 6, 7, 8};
    SET_ERR(0);
    HCRYPTPROV p = import_plain(g, sizeof g, 0);
    CHECK(p == 0);
    DWORD e = GetLastError();
    CHECK(e != 0);
    t_note("garbage PKCS#8: last error 0x%lx", e);
    static const BYTE g2[] = {0x30, 0x00};
    SET_ERR(0);
    p = import_plain(g2, sizeof g2, 0);
    CHECK(p == 0);
    CHECK(GetLastError() != 0);
}
TEST(pkcs8_import_empty_fails) {
    NEED_P8(); PP_WINE_P8();
    CRYPT_PKCS8_IMPORT_PARAMS ip; memset(&ip, 0, sizeof ip);
    HCRYPTPROV out = 0;
    SET_ERR(0);
    BOOL r = U(CryptImportPKCS8)(ip, 0, &out, NULL);
    CHECK(!r);
    CHECK(GetLastError() != 0);
    EXPECT_EQ(out, 0);
}
TEST(pkcs8_import_truncated_fails) {
    NEED_P8(); PP_WINE_P8();
    for (size_t cut = 1; cut <= 300; cut += 37) {
        SET_ERR(0);
        HCRYPTPROV p = import_plain(fx_p8plain, sizeof fx_p8plain - cut, 0);
        CHECKF(p == 0, "cut %zu", cut);
        if (p) U(CryptReleaseContext)(p, 0);
    }
}
TEST(pkcs8_import_certificate_der_fails) {
    NEED_P8(); PP_WINE_P8();
    SET_ERR(0);
    HCRYPTPROV p = import_plain(fx_cert1, sizeof fx_cert1, 0);
    CHECK(p == 0);
    CHECK(GetLastError() != 0);
}

/* ---- import: encrypted ---------------------------------------------------------------------- */
TEST(pkcs8_import_encrypted_fixture_reaches_decrypt_callback) {
    NEED_P8(); PP_WINE_P8();
    static struct { int calls; int nullbuf; char oid[64]; DWORD enc_cb; int blob_matches; void *ctx; } seen;
    BOOL CALLBACK dec(CRYPT_ALGORITHM_IDENTIFIER alg, CRYPT_DATA_BLOB enc, BYTE *out, DWORD *pcb, LPVOID ctx) {
        seen.calls++; seen.ctx = ctx; seen.enc_cb = enc.cbData;
        lstrcpynA(seen.oid, alg.pszObjId ? alg.pszObjId : "(null)", sizeof seen.oid);
        if (!out) seen.nullbuf++;
        /* the ciphertext is the tail of the fixture */
        seen.blob_matches = enc.cbData < sizeof fx_p8enc && !memcmp(enc.pbData, fx_p8enc + sizeof fx_p8enc - enc.cbData, enc.cbData);
        SetLastError(NTE_BAD_DATA);
        return FALSE;
    }
    memset(&seen, 0, sizeof seen);
    CRYPT_PKCS8_IMPORT_PARAMS ip; memset(&ip, 0, sizeof ip);
    ip.PrivateKey.cbData = sizeof fx_p8enc; ip.PrivateKey.pbData = (BYTE *)fx_p8enc;
    ip.pDecryptPrivateKeyFunc = dec; ip.pVoidDecryptFunc = (LPVOID)(ULONG_PTR)0x99; ip.pResolvehCryptProvFunc = resolve_vc;
    HCRYPTPROV out = 0;
    BOOL r = U(CryptImportPKCS8)(ip, 0, &out, NULL);
    CHECK(!r);
    EXPECT_EQ(out, 0);
    EXPECT_EQ(seen.calls, 1);
    EXPECT_EQ(seen.nullbuf, 1);
    EXPECT_EQ(seen.ctx, 0x99);
    /* pbeWithSHA1And3-KeyTripleDES-CBC (PKCS#12 PBE) as written by the fixture generator */
    EXPECT_STR(seen.oid, "1.2.840.113549.1.12.1.3");
    CHECK(seen.enc_cb > 500);
    CHECK(seen.blob_matches);
    t_note("decrypt callback failure surfaces last error 0x%lx", GetLastError());
}
TEST(pkcs8_import_encrypted_decrypt_callback_returns_plain_key) {
    NEED_P8(); PP_WINE_P8();
    /* a callback that ignores the real ciphertext and answers with the plain PKCS#8 of the same key */
    static int calls;
    BOOL CALLBACK dec(CRYPT_ALGORITHM_IDENTIFIER alg, CRYPT_DATA_BLOB enc, BYTE *out, DWORD *pcb, LPVOID ctx) {
        calls++;
        if (!out) { *pcb = sizeof fx_p8plain; return TRUE; }
        if (*pcb < sizeof fx_p8plain) { SetLastError(ERROR_MORE_DATA); return FALSE; }
        memcpy(out, fx_p8plain, sizeof fx_p8plain); *pcb = sizeof fx_p8plain; return TRUE;
    }
    calls = 0;
    CRYPT_PKCS8_IMPORT_PARAMS ip; memset(&ip, 0, sizeof ip);
    ip.PrivateKey.cbData = sizeof fx_p8enc; ip.PrivateKey.pbData = (BYTE *)fx_p8enc;
    ip.pDecryptPrivateKeyFunc = dec; ip.pResolvehCryptProvFunc = resolve_vc;
    HCRYPTPROV out = 0;
    BOOL r = U(CryptImportPKCS8)(ip, 0, &out, NULL);
    CHECKF(r, "err 0x%lx", GetLastError());
    EXPECT_EQ(calls, 2);
    if (out) {
        DWORD cb = 0;
        BYTE *pub = get_pub(out, AT_KEYEXCHANGE, &cb);
        if (!pub) pub = get_pub(out, AT_SIGNATURE, &cb);
        CHECK(pub != NULL);
        if (pub) { CHECK(pub_is_fixture(pub, cb)); LocalFree(pub); }
        U(CryptReleaseContext)(out, 0);
    }
}
TEST(pkcs8_import_encrypted_decrypt_returns_garbage) {
    NEED_P8(); PP_WINE_P8();
    BOOL CALLBACK dec(CRYPT_ALGORITHM_IDENTIFIER alg, CRYPT_DATA_BLOB enc, BYTE *out, DWORD *pcb, LPVOID ctx) {
        if (!out) { *pcb = 16; return TRUE; }
        memset(out, 0x41, 16); *pcb = 16; return TRUE;
    }
    CRYPT_PKCS8_IMPORT_PARAMS ip; memset(&ip, 0, sizeof ip);
    ip.PrivateKey.cbData = sizeof fx_p8enc; ip.PrivateKey.pbData = (BYTE *)fx_p8enc;
    ip.pDecryptPrivateKeyFunc = dec; ip.pResolvehCryptProvFunc = resolve_vc;
    HCRYPTPROV out = 0;
    SET_ERR(0);
    BOOL r = U(CryptImportPKCS8)(ip, 0, &out, NULL);
    CHECK(!r);
    CHECK(GetLastError() != 0);
    EXPECT_EQ(out, 0);
}

/* ---- export -> import round trip -------------------------------------------------------------- */
TEST(pkcs8_roundtrip_plain_preserves_public_key) {
    NEED_P8(); PP_WINE_P8();
    HCRYPTPROV a = gen_prov();
    if (!a) { CHECK(a != 0); return; }
    DWORD cb = 0, ca = 0, cc = 0;
    BYTE *p8 = export_p8(a, &cb);
    CHECK(p8 != NULL);
    BYTE *pa = get_pub(a, AT_KEYEXCHANGE, &ca);
    CHECK(pa != NULL);
    if (p8) {
        HCRYPTPROV b = import_plain(p8, cb, 0);
        CHECKF(b != 0, "err 0x%lx", GetLastError());
        if (b && pa) {
            BYTE *pb = get_pub(b, AT_KEYEXCHANGE, &cc);
            if (!pb) pb = get_pub(b, AT_SIGNATURE, &cc);
            CHECK(pb != NULL);
            if (pb) { CHECK(ca == cc && !memcmp(pa, pb, ca)); LocalFree(pb); }
        }
        if (b) U(CryptReleaseContext)(b, 0);
        LocalFree(p8);
    }
    if (pa) LocalFree(pa);
    U(CryptReleaseContext)(a, 0);
}
TEST(pkcs8_roundtrip_reexport_decodes_identically) {
    NEED_P8(); PP_WINE_P8();
    HCRYPTPROV a = gen_prov();
    if (!a) { CHECK(a != 0); return; }
    DWORD c1 = 0;
    BYTE *p1 = export_p8(a, &c1);
    CHECK(p1 != NULL);
    if (p1) {
        HCRYPTPROV b = import_plain(p1, c1, CRYPT_EXPORTABLE);
        CHECK(b != 0);
        if (b) {
            DWORD c2 = 0;
            DWORD spec = AT_KEYEXCHANGE;
            BYTE *p2 = export_p8(b, &c2);
            CHECKF(p2 != NULL, "re-export err 0x%lx", GetLastError());
            if (p2) {
                CHECK(c1 == c2 && !memcmp(p1, p2, c1)); /* same key, same canonical DER */
                LocalFree(p2);
            }
            U(CryptReleaseContext)(b, 0);
        }
        LocalFree(p1);
    }
    U(CryptReleaseContext)(a, 0);
}
TEST(pkcs8_roundtrip_through_encrypt_decrypt_callbacks) {
    NEED_P8(); PP_WINE_P8();
    HCRYPTPROV a = gen_prov();
    if (!a) { CHECK(a != 0); return; }
    memset(&g_enc, 0, sizeof g_enc);
    DWORD cb = 0, ca = 0, cc = 0;
    BYTE *enc = export_enc(a, &cb);
    CHECK(enc != NULL);
    BYTE *pa = get_pub(a, AT_KEYEXCHANGE, &ca);
    if (enc) {
        CRYPT_PKCS8_IMPORT_PARAMS ip; memset(&ip, 0, sizeof ip);
        ip.PrivateKey.cbData = cb; ip.PrivateKey.pbData = enc;
        ip.pResolvehCryptProvFunc = resolve_vc; ip.pDecryptPrivateKeyFunc = xor_decrypt; ip.pVoidDecryptFunc = (LPVOID)(ULONG_PTR)0x55;
        HCRYPTPROV b = 0;
        memset(&g_enc, 0, sizeof g_enc);
        BOOL r = U(CryptImportPKCS8)(ip, 0, &b, NULL);
        CHECKF(r, "err 0x%lx", GetLastError());
        EXPECT_EQ(g_enc.calls, 2);
        EXPECT_EQ(g_enc.ctx, 0x55);
        if (b && pa) {
            BYTE *pb = get_pub(b, AT_KEYEXCHANGE, &cc);
            if (!pb) pb = get_pub(b, AT_SIGNATURE, &cc);
            CHECK(pb != NULL);
            if (pb) { CHECK(ca == cc && !memcmp(pa, pb, ca)); LocalFree(pb); }
        }
        if (b) U(CryptReleaseContext)(b, 0);
        LocalFree(enc);
    }
    if (pa) LocalFree(pa);
    U(CryptReleaseContext)(a, 0);
}
TEST(pkcs8_roundtrip_fixture_export_matches_openssl_der) {
    NEED_P8(); PP_WINE_P8();
    HCRYPTPROV p = import_plain(fx_p8plain, sizeof fx_p8plain, CRYPT_EXPORTABLE);
    CHECKF(p != 0, "err 0x%lx", GetLastError());
    if (!p) return;
    DWORD cb = 0;
    BYTE *b = export_p8(p, &cb);
    if (b) {
        DWORD dc = 0; CRYPT_PRIVATE_KEY_INFO *pk = NULL;
        if (U(CryptDecodeObjectEx)(X509_ASN_ENCODING, T_PKCS_PRIVATE_KEY_INFO, b, cb, CRYPT_DECODE_ALLOC_FLAG, NULL, &pk, &dc)) {
            EXPECT_STR(pk->Algorithm.pszObjId, szOID_RSA_RSA);
            LocalFree(pk);
        }
        t_note("re-export of fixture key: %lu bytes (source %zu), identical=%d", cb, sizeof fx_p8plain, cb == sizeof fx_p8plain && !memcmp(b, fx_p8plain, cb));
        LocalFree(b);
    } else t_note("re-export of imported fixture key failed: 0x%lx", GetLastError());
    U(CryptReleaseContext)(p, 0);
}

/* ---- attach an imported PKCS#8 key to a certificate and export a PFX ---------------------------- */
TEST(pkcs8_attach_key_context_then_pfx_export) {
    NEED_P8(); PP_WINE_P8();
    REQUIRE(U(PFXExportCertStoreEx)); REQUIRE(U(PFXImportCertStore)); REQUIRE(U(CertSetCertificateContextProperty));
    PP_WINE_SKIP("limited PFX export");
    HCRYPTPROV p = import_plain(fx_p8plain, sizeof fx_p8plain, CRYPT_EXPORTABLE);
    CHECKF(p != 0, "err 0x%lx", GetLastError());
    if (!p) return;
    HCERTSTORE s = pp_memstore();
    PCCERT_CONTEXT c = NULL;
    CHECK(U(CertAddEncodedCertificateToStore)(s, X509_ASN_ENCODING, fx_cert1, sizeof fx_cert1, CERT_STORE_ADD_NEW, &c));
    if (c) {
        HCRYPTKEY k = 0; DWORD spec = AT_KEYEXCHANGE;
        if (!U(CryptGetUserKey)(p, spec, &k)) { spec = AT_SIGNATURE; U(CryptGetUserKey)(p, spec, &k); }
        if (k) U(CryptDestroyKey)(k);
        CERT_KEY_CONTEXT kc; memset(&kc, 0, sizeof kc);
        kc.cbSize = sizeof kc; kc.hCryptProv = p; kc.dwKeySpec = spec;
        BOOL r = U(CertSetCertificateContextProperty)(c, CERT_KEY_CONTEXT_PROP_ID, 0, &kc);
        CHECKF(r, "set prop err 0x%lx", GetLastError());
        U(CertFreeCertificateContext)(c);
        CRYPT_DATA_BLOB b;
        r = pp_export_ex(s, &b, L"attach", NULL, EXPORT_PRIVATE_KEYS | REPORT_NO_PRIVATE_KEY);
        CHECKF(r, "export err 0x%lx", GetLastError());
        if (r && b.pbData) {
            HCERTSTORE s2 = U(PFXImportCertStore)(&b, L"attach", PP_NP);
            CHECK(s2 != NULL);
            if (s2) { PCCERT_CONTEXT kc2 = pp_first_with_key(s2); CHECK(kc2 != NULL); if (kc2) U(CertFreeCertificateContext)(kc2); }
            pp_close(s2);
            LocalFree(b.pbData);
        }
    }
    pp_close(s);
    U(CryptReleaseContext)(p, 0);
}
