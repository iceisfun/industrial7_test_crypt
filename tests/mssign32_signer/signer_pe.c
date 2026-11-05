/* Signing a hand-built minimal PE with SignerSign* using an in-memory key (key context attached to the
 * certificate, no persisted container) and verifying the result with crypt32 / wintrust.
 * Expectations rely on Authenticode semantics and on the decompiled signer: certificate table appended at the end of
 * the image, PKCS#7 SignedData with SPC_INDIRECT_DATA content, re-signing replaces the signature. */
#include "mssfix.h"

#define NEED_FIX(f) FX f; do { if (t_is_wine()) { t_skip("mssign32 stubs under Wine"); return; } \
    if (!UN(SignerSignEx) || !UN(SignerSign) || !UN(SignerSignEx2) || !UN(SignerSignEx3) || !UN(SignerFreeSignerContext)) { t_skip("missing signer exports"); return; } \
    if (!fx_open(&f, FX_A, 1) || !fx_cert_attach(&f)) { fx_close(&f); t_skip("cannot build signing fixture (RSA_AES key context)"); return; } } while (0)

static const char *OID_SHA1 = "1.3.14.3.2.26", *OID_SHA256 = "2.16.840.1.101.3.4.2.1",
                  *OID_SHA384 = "2.16.840.1.101.3.4.2.2", *OID_SHA512 = "2.16.840.1.101.3.4.2.3";

/* Sign a fresh PE; on failure notes the HRESULT and skips. */
static int fresh_signed(FX *f, char *path, size_t cap, const char *leaf, DWORD alg) {
    fx_pe_new(path, cap, leaf);
    SET_ERR(0);
    HRESULT hr = fx_sign(f, path, alg, 0, NULL);
    if (hr != 0) { t_note("fixture signing failed: 0x%08lx", (DWORD)hr); return 0; }
    return 1;
}
#define SIGN_OR_FAIL(f, path, leaf, alg) do { if (!fresh_signed(&f, path, sizeof path, leaf, alg)) { CHECKF(0, "SignerSignEx failed"); fx_close(&f); DeleteFileA(path); return; } } while (0)

static void cleanup(FX *f, const char *path) { fx_close(f); DeleteFileA(path); }

TEST(mssigner_pe_sign_sha1_succeeds) {
    NEED_FIX(f);
    char p[MAX_PATH]; fx_pe_new(p, sizeof p, "a.exe");
    SET_ERR(0);
    HRESULT hr = fx_sign(&f, p, CALG_SHA1, 0, NULL);
    EXPECT_EQ((DWORD)hr, 0);
    cleanup(&f, p);
}
TEST(mssigner_pe_signed_file_layout) {
    NEED_FIX(f);
    char p[MAX_PATH]; SIGN_OR_FAIL(f, p, "layout.exe", CALG_SHA1);
    DWORD n = 0; BYTE *b = fx_read_file(p, &n);
    CHECK(b != NULL && n > FX_PE_SIZE);
    if (b && n > FX_PE_SIZE) {
        DWORD off, size;
        CHECK(fx_pe_secdir(b, n, &off, &size));
        EXPECT_EQ(off, FX_PE_SIZE);            /* appended right after the last section */
        CHECK(size > 8 && off + size <= n);
        EXPECT_EQ(off % 8, 0);
        if (off + 8 <= n) {
            DWORD len; WORD rev, type;
            memcpy(&len, b + off, 4); memcpy(&rev, b + off + 4, 2); memcpy(&type, b + off + 6, 2);
            EXPECT_EQ(rev, 0x0200);            /* WIN_CERT_REVISION_2_0 */
            EXPECT_EQ(type, 0x0002);           /* WIN_CERT_TYPE_PKCS_SIGNED_DATA */
            CHECK(len > 8 && len <= size && size - len < 8);
            CHECK(b[off + 8] == 0x30);         /* DER SEQUENCE (ContentInfo) */
        }
        EXPECT_EQ(off + size, n);
    }
    free(b); cleanup(&f, p);
}
TEST(mssigner_pe_signing_changes_only_checksum_and_directory) {
    NEED_FIX(f);
    char p[MAX_PATH]; SIGN_OR_FAIL(f, p, "diff.exe", CALG_SHA1);
    BYTE orig[FX_PE_SIZE]; fx_pe_image(orig);
    DWORD n = 0; BYTE *b = fx_read_file(p, &n);
    CHECK(b != NULL && n > FX_PE_SIZE);
    if (b && n > FX_PE_SIZE) {
        DWORD nt = ((IMAGE_DOS_HEADER *)orig)->e_lfanew;
        DWORD chk = nt + 4 + 20 + 64, sec = nt + 4 + 20 + 0x70 + 32;
        for (DWORD i = 0; i < FX_PE_SIZE; i++) {
            if ((i >= chk && i < chk + 4) || (i >= sec && i < sec + 8)) continue;
            if (b[i] != orig[i]) { CHECKF(0, "byte 0x%lx changed %02x -> %02x", i, orig[i], b[i]); break; }
        }
        DWORD csum; memcpy(&csum, b + chk, 4);
        t_note("PE checksum after signing: 0x%08lx", csum);
    }
    free(b); cleanup(&f, p);
}
TEST(mssigner_pe_signature_embedded_pkcs7) {
    NEED_FIX(f);
    char p[MAX_PATH]; SIGN_OR_FAIL(f, p, "q.exe", CALG_SHA1);
    HCERTSTORE st = NULL; HCRYPTMSG m = fx_query_pe(p, &st);
    CHECK(m != NULL);
    if (m) {
        EXPECT_EQ(fx_signer_count(m), 1);
        DWORD type = 0, cb = sizeof type;
        CHECK(U(CryptMsgGetParam)(m, CMSG_TYPE_PARAM, 0, &type, &cb));
        EXPECT_EQ(type, CMSG_SIGNED);
        char oid[64] = ""; cb = sizeof oid;
        CHECK(U(CryptMsgGetParam)(m, CMSG_INNER_CONTENT_TYPE_PARAM, 0, oid, &cb));
        EXPECT_STR(oid, "1.3.6.1.4.1.311.2.1.4");          /* SPC_INDIRECT_DATA_OBJID */
        char *d = fx_signer_digest_oid(m);
        CHECK(d != NULL);
        if (d) { EXPECT_STR(d, OID_SHA1); free(d); }
        U(CryptMsgClose)(m);
    }
    if (st) U(CertCloseStore)(st, 0);
    cleanup(&f, p);
}
TEST(mssigner_pe_embedded_store_has_signing_cert) {
    NEED_FIX(f);
    char p[MAX_PATH]; SIGN_OR_FAIL(f, p, "store.exe", CALG_SHA1);
    HCERTSTORE st = NULL; HCRYPTMSG m = fx_query_pe(p, &st);
    CHECK(m != NULL && st != NULL);
    if (st) {
        DWORD cb; const BYTE *der = fx_cert_der(FX_A, &cb);
        PCCERT_CONTEXT c = NULL; int found = 0, count = 0;
        while ((c = U(CertEnumCertificatesInStore)(st, c)) != NULL) {
            count++;
            if (c->cbCertEncoded == cb && !memcmp(c->pbCertEncoded, der, cb)) found = 1;
        }
        CHECK(found);
        t_note("certificates embedded in the signature: %d", count);
    }
    if (m) U(CryptMsgClose)(m);
    if (st) U(CertCloseStore)(st, 0);
    cleanup(&f, p);
}
TEST(mssigner_pe_signer_info_references_signing_cert) {
    NEED_FIX(f);
    char p[MAX_PATH]; SIGN_OR_FAIL(f, p, "si.exe", CALG_SHA1);
    HCERTSTORE st = NULL; HCRYPTMSG m = fx_query_pe(p, &st);
    CHECK(m != NULL);
    if (m) {
        DWORD cb = 0;
        CHECK(U(CryptMsgGetParam)(m, CMSG_SIGNER_INFO_PARAM, 0, NULL, &cb));
        CMSG_SIGNER_INFO *si = malloc(cb);
        CHECK(U(CryptMsgGetParam)(m, CMSG_SIGNER_INFO_PARAM, 0, si, &cb));
        PCERT_INFO ci = f.cert->pCertInfo;
        CHECK(si->Issuer.cbData == ci->Issuer.cbData && !memcmp(si->Issuer.pbData, ci->Issuer.pbData, ci->Issuer.cbData));
        CHECK(si->SerialNumber.cbData == ci->SerialNumber.cbData && !memcmp(si->SerialNumber.pbData, ci->SerialNumber.pbData, ci->SerialNumber.cbData));
        /* the signature verifies against the certificate */
        CHECK(U(CryptMsgControl)(m, 0, CMSG_CTRL_VERIFY_SIGNATURE, f.cert->pCertInfo));
        free(si); U(CryptMsgClose)(m);
    }
    if (st) U(CertCloseStore)(st, 0);
    cleanup(&f, p);
}
static int blob_contains(const BYTE *h, DWORD hn, const BYTE *n, DWORD nn) {
    for (DWORD i = 0; i + nn <= hn; i++) if (!memcmp(h + i, n, nn)) return 1;
    return 0;
}
static void check_digest_in_content(const char *path, LPCWSTR bcalg, DWORD alg_len_expected) {
    DWORD n = 0; BYTE *b = fx_read_file(path, &n);
    BYTE h[64]; DWORD hl = 0;
    CHECK(b && fx_pe_authhash(b, n, bcalg, h, &hl));
    EXPECT_EQ(hl, alg_len_expected);
    HCRYPTMSG m = fx_query_pe(path, NULL);
    CHECK(m != NULL);
    if (m && hl) {
        DWORD cb = 0;
        CHECK(U(CryptMsgGetParam)(m, CMSG_CONTENT_PARAM, 0, NULL, &cb));
        BYTE *c = malloc(cb);
        CHECK(U(CryptMsgGetParam)(m, CMSG_CONTENT_PARAM, 0, c, &cb));
        CHECK(blob_contains(c, cb, h, hl));     /* SpcIndirectDataContent carries the Authenticode image digest */
        free(c);
    }
    if (m) U(CryptMsgClose)(m);
    free(b);
}
TEST(mssigner_pe_sha1_authenticode_digest_in_content) {
    NEED_FIX(f);
    char p[MAX_PATH]; SIGN_OR_FAIL(f, p, "d1.exe", CALG_SHA1);
    check_digest_in_content(p, BCRYPT_SHA1_ALGORITHM, 20);
    cleanup(&f, p);
}
TEST(mssigner_pe_sha256_authenticode_digest_in_content) {
    NEED_FIX(f);
    char p[MAX_PATH]; SIGN_OR_FAIL(f, p, "d256.exe", CALG_SHA_256);
    check_digest_in_content(p, BCRYPT_SHA256_ALGORITHM, 32);
    HCRYPTMSG m = fx_query_pe(p, NULL);
    if (m) { char *d = fx_signer_digest_oid(m); CHECK(d && !strcmp(d, OID_SHA256)); free(d); U(CryptMsgClose)(m); }
    cleanup(&f, p);
}
TEST(mssigner_pe_sha384_and_sha512) {
    NEED_FIX(f);
    static const struct { DWORD alg; const char *oid; LPCWSTR bc; DWORD len; } t[] = {
        { 0x800d, "2.16.840.1.101.3.4.2.2", BCRYPT_SHA384_ALGORITHM, 48 },
        { 0x800e, "2.16.840.1.101.3.4.2.3", BCRYPT_SHA512_ALGORITHM, 64 },
    };
    for (int i = 0; i < 2; i++) {
        char p[MAX_PATH]; fx_pe_new(p, sizeof p, "dx.exe");
        HRESULT hr = fx_sign(&f, p, t[i].alg, 0, NULL);
        CHECKF(hr == 0, "alg 0x%lx: 0x%08lx", t[i].alg, (DWORD)hr);
        if (hr == 0) {
            HCRYPTMSG m = fx_query_pe(p, NULL);
            CHECK(m != NULL);
            if (m) { char *d = fx_signer_digest_oid(m); CHECK(d && !strcmp(d, t[i].oid)); free(d); U(CryptMsgClose)(m); }
            check_digest_in_content(p, t[i].bc, t[i].len);
        }
        DeleteFileA(p);
    }
    fx_close(&f);
}
TEST(mssigner_pe_wintrust_untrusted_root) {
    NEED_FIX(f);
    char p[MAX_PATH]; SIGN_OR_FAIL(f, p, "wvt.exe", CALG_SHA_256);
    HRESULT hr = fx_verify_trust(p);
    EXPECT_EQ((DWORD)hr, 0x800B0109u);        /* CERT_E_UNTRUSTEDROOT: self-signed, not in a trusted root store */
    cleanup(&f, p);
}
TEST(mssigner_pe_wintrust_detects_tampering) {
    NEED_FIX(f);
    char p[MAX_PATH]; SIGN_OR_FAIL(f, p, "tamper.exe", CALG_SHA1);
    DWORD n = 0; BYTE *b = fx_read_file(p, &n);
    CHECK(b != NULL);
    if (b) {
        b[0x201] ^= 0xFF;                      /* code byte covered by the Authenticode digest */
        CHECK(fx_write_file(p, b, n));
        HRESULT hr = fx_verify_trust(p);
        EXPECT_EQ((DWORD)hr, 0x80096010u);     /* TRUST_E_BAD_DIGEST */
        free(b);
    }
    cleanup(&f, p);
}
TEST(mssigner_pe_resign_replaces_signature) {
    NEED_FIX(f);
    char p[MAX_PATH]; SIGN_OR_FAIL(f, p, "re.exe", CALG_SHA1);
    DWORD n1 = 0; BYTE *b1 = fx_read_file(p, &n1);
    HRESULT hr = fx_sign(&f, p, CALG_SHA_256, 0, NULL);
    EXPECT_EQ((DWORD)hr, 0);
    DWORD n2 = 0; BYTE *b2 = fx_read_file(p, &n2);
    CHECK(b1 && b2);
    if (b1 && b2) {
        DWORD o1, s1, o2, s2;
        fx_pe_secdir(b1, n1, &o1, &s1); fx_pe_secdir(b2, n2, &o2, &s2);
        EXPECT_EQ(o2, FX_PE_SIZE);
        EXPECT_EQ(o2 + s2, n2);               /* a single certificate table entry, nothing left over */
        CHECK(memcmp(b1 + o1, b2 + o2, s1 < s2 ? s1 : s2) != 0);
        CHECK(n2 < n1 + 0x800);               /* replaced, not accumulated */
    }
    HCRYPTMSG m = fx_query_pe(p, NULL);
    CHECK(m != NULL);
    if (m) {
        EXPECT_EQ(fx_signer_count(m), 1);
        char *d = fx_signer_digest_oid(m);
        CHECK(d && !strcmp(d, OID_SHA256));
        free(d); U(CryptMsgClose)(m);
    }
    free(b1); free(b2); cleanup(&f, p);
}
TEST(mssigner_pe_resign_same_algorithm_keeps_one_signature) {
    NEED_FIX(f);
    char p[MAX_PATH]; SIGN_OR_FAIL(f, p, "re2.exe", CALG_SHA1);
    for (int i = 0; i < 3; i++) EXPECT_EQ((DWORD)fx_sign(&f, p, CALG_SHA1, 0, NULL), 0);
    DWORD n = 0; BYTE *b = fx_read_file(p, &n);
    DWORD o, s;
    if (b && fx_pe_secdir(b, n, &o, &s)) { EXPECT_EQ(o, FX_PE_SIZE); EXPECT_EQ(o + s, n); }
    free(b);
    HCRYPTMSG m = fx_query_pe(p, NULL);
    CHECK(m != NULL);
    if (m) { EXPECT_EQ(fx_signer_count(m), 1); U(CryptMsgClose)(m); }
    cleanup(&f, p);
}
TEST(mssigner_pe_all_entry_points_sign) {
    NEED_FIX(f);
    for (int v = 0; v < 4; v++) {
        char p[MAX_PATH]; fx_pe_new(p, sizeof p, "ep.exe");
        LPWSTR wp = fx_w(p);
        DWORD idx = 0;
        SG_FILE fi = { sizeof fi, wp, NULL };
        SG_SUBJECT sub = { sizeof sub, &idx, SG_SUBJECT_FILE, &fi };
        SG_CERTSTORE cs = { sizeof cs, f.cert, 0, NULL };
        SG_CERT cert = { sizeof cert, SG_CERT_STORE, &cs, NULL };
        SG_SIGINFO si = { sizeof si, CALG_SHA_256, SG_NO_ATTR, NULL, NULL, NULL };
        SG_CTX *ctx = NULL; HRESULT hr;
        switch (v) {
        case 0: hr = UN(SignerSign)(&sub, &cert, &si, NULL, NULL, NULL, NULL); break;
        case 1: hr = UN(SignerSignEx)(0, &sub, &cert, &si, NULL, NULL, NULL, NULL, &ctx); break;
        case 2: hr = UN(SignerSignEx2)(0, &sub, &cert, &si, NULL, 0, NULL, NULL, NULL, NULL, &ctx, NULL, NULL); break;
        default: hr = UN(SignerSignEx3)(0, &sub, &cert, &si, NULL, 0, NULL, NULL, NULL, NULL, &ctx, NULL, NULL, NULL); break;
        }
        CHECKF(hr == 0, "variant %d: 0x%08lx", v, (DWORD)hr);
        HCRYPTMSG m = fx_query_pe(p, NULL);
        CHECKF(m != NULL, "variant %d: no embedded signature", v);
        if (m) {
            EXPECT_EQ(fx_signer_count(m), 1);
            char *d = fx_signer_digest_oid(m);
            CHECK(d && !strcmp(d, OID_SHA256));
            free(d); U(CryptMsgClose)(m);
        }
        if (ctx) UN(SignerFreeSignerContext)(ctx);
        free(wp); DeleteFileA(p);
    }
    fx_close(&f);
}
TEST(mssigner_pe_signer_context_returned) {
    NEED_FIX(f);
    char p[MAX_PATH]; fx_pe_new(p, sizeof p, "ctx.exe");
    SG_CTX *ctx = (SG_CTX *)(ULONG_PTR)1;
    HRESULT hr = fx_sign(&f, p, CALG_SHA1, 0, &ctx);
    EXPECT_EQ((DWORD)hr, 0);
    CHECK(ctx != NULL && ctx != (SG_CTX *)(ULONG_PTR)1);
    if (hr == 0 && ctx && ctx != (SG_CTX *)(ULONG_PTR)1) {
        EXPECT_EQ(ctx->cbSize, 16);
        CHECK(ctx->cbBlob > 8 && ctx->pbBlob != NULL);
        if (ctx->pbBlob && ctx->cbBlob > 8) {
            CHECK(ctx->pbBlob[0] == 0x30);
            DWORD enc = 0, ct = 0, fmt = 0; HCERTSTORE st = NULL; HCRYPTMSG m = NULL;
            CRYPT_DATA_BLOB blob = { ctx->cbBlob, ctx->pbBlob };
            BOOL ok = U(CryptQueryObject)(CERT_QUERY_OBJECT_BLOB, &blob, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
                                          CERT_QUERY_FORMAT_FLAG_BINARY, 0, &enc, &ct, &fmt, &st, &m, NULL);
            CHECK(ok);
            if (ok) { EXPECT_EQ(ct, CERT_QUERY_CONTENT_PKCS7_SIGNED); EXPECT_EQ(fx_signer_count(m), 1); }
            if (m) U(CryptMsgClose)(m);
            if (st) U(CertCloseStore)(st, 0);
            /* the blob is the signature stored in the file */
            DWORD n = 0; BYTE *b = fx_read_file(p, &n); DWORD o, s;
            if (b && fx_pe_secdir(b, n, &o, &s) && o + 8 + ctx->cbBlob <= n)
                t_note("context blob equals the stored signature: %d", !memcmp(b + o + 8, ctx->pbBlob, ctx->cbBlob));
            free(b);
        }
        EXPECT_EQ((DWORD)UN(SignerFreeSignerContext)(ctx), 0);
    }
    cleanup(&f, p);
}
TEST(mssigner_pe_authcode_attributes) {
    NEED_FIX(f);
    char p[MAX_PATH]; fx_pe_new(p, sizeof p, "ac.exe");
    LPWSTR wp = fx_w(p);
    DWORD idx = 0;
    SG_FILE fi = { sizeof fi, wp, NULL };
    SG_SUBJECT sub = { sizeof sub, &idx, SG_SUBJECT_FILE, &fi };
    SG_CERTSTORE cs = { sizeof cs, f.cert, 0, NULL };
    SG_CERT cert = { sizeof cert, SG_CERT_STORE, &cs, NULL };
    SG_AUTHCODE ac = { sizeof ac, 1, 0, L"cryptt product", L"http://127.0.0.1/info" };
    SG_SIGINFO si = { sizeof si, CALG_SHA1, SG_AUTHCODE_ATTR, &ac, NULL, NULL };
    HRESULT hr = UN(SignerSignEx)(0, &sub, &cert, &si, NULL, NULL, NULL, NULL, NULL);
    EXPECT_EQ((DWORD)hr, 0);
    HCRYPTMSG m = hr == 0 ? fx_query_pe(p, NULL) : NULL;
    CHECK(m != NULL || hr != 0);
    if (m) {
        DWORD cb = 0;
        CHECK(U(CryptMsgGetParam)(m, CMSG_SIGNER_INFO_PARAM, 0, NULL, &cb));
        CMSG_SIGNER_INFO *s = malloc(cb);
        CHECK(U(CryptMsgGetParam)(m, CMSG_SIGNER_INFO_PARAM, 0, s, &cb));
        int opus = 0, stmt = 0, ctype = 0, mdig = 0;
        for (DWORD i = 0; i < s->AuthAttrs.cAttr; i++) {
            const char *o = s->AuthAttrs.rgAttr[i].pszObjId;
            if (!strcmp(o, "1.3.6.1.4.1.311.2.1.12")) {          /* SPC_SP_OPUS_INFO */
                opus = 1;
                const BYTE *pb = s->AuthAttrs.rgAttr[i].rgValue[0].pbData; DWORD nb = s->AuthAttrs.rgAttr[i].rgValue[0].cbData;
                BYTE nm[64]; int k = 0;
                for (const WCHAR *w = L"cryptt product"; *w; w++) { nm[k++] = (BYTE)(*w >> 8); nm[k++] = (BYTE)*w; }
                CHECK(blob_contains(pb, nb, nm, k));               /* BMPString (UCS-2 big endian) */
                CHECK(blob_contains(pb, nb, (const BYTE *)"http://127.0.0.1/info", 21));   /* IA5 URL */
            }
            if (!strcmp(o, "1.3.6.1.4.1.311.2.1.11")) stmt = 1;    /* SPC_STATEMENT_TYPE */
            if (!strcmp(o, "1.2.840.113549.1.9.3")) ctype = 1;
            if (!strcmp(o, "1.2.840.113549.1.9.4")) mdig = 1;
        }
        CHECK(opus); CHECK(stmt); CHECK(ctype); CHECK(mdig);
        free(s); U(CryptMsgClose)(m);
    }
    free(wp); cleanup(&f, p);
}
TEST(mssigner_pe_no_attr_has_no_opus_info) {
    NEED_FIX(f);
    char p[MAX_PATH]; SIGN_OR_FAIL(f, p, "noattr.exe", CALG_SHA1);
    HCRYPTMSG m = fx_query_pe(p, NULL);
    CHECK(m != NULL);
    if (m) {
        DWORD cb = 0;
        CHECK(U(CryptMsgGetParam)(m, CMSG_SIGNER_INFO_PARAM, 0, NULL, &cb));
        CMSG_SIGNER_INFO *s = malloc(cb);
        CHECK(U(CryptMsgGetParam)(m, CMSG_SIGNER_INFO_PARAM, 0, s, &cb));
        int opus = 0;
        for (DWORD i = 0; i < s->AuthAttrs.cAttr; i++)
            if (!strcmp(s->AuthAttrs.rgAttr[i].pszObjId, "1.3.6.1.4.1.311.2.1.12")) opus = 1;
        t_note("SIGNER_NO_ATTR: %lu authenticated attributes, SPC_SP_OPUS_INFO present=%d", s->AuthAttrs.cAttr, opus);
        free(s); U(CryptMsgClose)(m);
    }
    cleanup(&f, p);
}
TEST(mssigner_pe_hfile_subject_is_not_closed) {
    NEED_FIX(f);
    char p[MAX_PATH]; fx_pe_new(p, sizeof p, "hf.exe");
    LPWSTR wp = fx_w(p);
    HANDLE h = CreateFileA(p, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    CHECK(h != INVALID_HANDLE_VALUE);
    DWORD idx = 0;
    SG_FILE fi = { sizeof fi, wp, h };
    SG_SUBJECT sub = { sizeof sub, &idx, SG_SUBJECT_FILE, &fi };
    SG_CERTSTORE cs = { sizeof cs, f.cert, 0, NULL };
    SG_CERT cert = { sizeof cert, SG_CERT_STORE, &cs, NULL };
    SG_SIGINFO si = { sizeof si, CALG_SHA1, SG_NO_ATTR, NULL, NULL, NULL };
    HRESULT hr = UN(SignerSignEx)(0, &sub, &cert, &si, NULL, NULL, NULL, NULL, NULL);
    EXPECT_EQ((DWORD)hr, 0);
    DWORD sz = GetFileSize(h, NULL);        /* the caller's handle is still open and valid */
    CHECK(sz != INVALID_FILE_SIZE && sz > FX_PE_SIZE);
    CloseHandle(h);
    CHECK(fx_query_pe(p, NULL) != NULL);
    free(wp); cleanup(&f, p);
}

/* ---- failing targets: the file is never modified ---- */
static BYTE *snapshot(const char *p, DWORD *n) { return fx_read_file(p, n); }
static void expect_unchanged(const char *p, const BYTE *before, DWORD n) {
    DWORD m = 0; BYTE *a = fx_read_file(p, &m);
    CHECK(a != NULL && m == n && !memcmp(a, before, n));
    free(a);
}
TEST(mssigner_pe_missing_target_file) {
    NEED_FIX(f);
    char p[MAX_PATH]; t_tmpfile(p, sizeof p, "does_not_exist.exe");
    HRESULT hr = fx_sign(&f, p, CALG_SHA1, 0, NULL);
    EXPECT_EQ((DWORD)hr, HR_FILE_NOT_FOUND);
    fx_close(&f);
}
TEST(mssigner_pe_missing_directory) {
    NEED_FIX(f);
    HRESULT hr = fx_sign(&f, "C:\\cryptt_nonexistent_dir_xyz\\a.exe", CALG_SHA1, 0, NULL);
    EXPECT_EQ((DWORD)hr, 0x80070003u);                 /* ERROR_PATH_NOT_FOUND */
    fx_close(&f);
}
TEST(mssigner_pe_target_is_directory) {
    NEED_FIX(f);
    char d[MAX_PATH]; t_tmpfile(d, sizeof d, "adir");
    CreateDirectoryA(d, NULL);
    HRESULT hr = fx_sign(&f, d, CALG_SHA1, 0, NULL);
    EXPECT_EQ((DWORD)hr, 0x80070005u);                 /* opening a directory for write without backup semantics */
    RemoveDirectoryA(d);
    fx_close(&f);
}
TEST(mssigner_pe_readonly_target) {
    NEED_FIX(f);
    char p[MAX_PATH]; fx_pe_new(p, sizeof p, "ro.exe");
    SetFileAttributesA(p, FILE_ATTRIBUTE_READONLY);
    DWORD n = 0; BYTE *b = snapshot(p, &n);
    HRESULT hr = fx_sign(&f, p, CALG_SHA1, 0, NULL);
    EXPECT_EQ((DWORD)hr, 0x80070005u);
    SetFileAttributesA(p, FILE_ATTRIBUTE_NORMAL);
    if (b) expect_unchanged(p, b, n);
    free(b); cleanup(&f, p);
}
TEST(mssigner_pe_sharing_violation) {
    NEED_FIX(f);
    char p[MAX_PATH]; fx_pe_new(p, sizeof p, "busy.exe");
    HANDLE h = CreateFileA(p, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);   /* exclusive */
    CHECK(h != INVALID_HANDLE_VALUE);
    HRESULT hr = fx_sign(&f, p, CALG_SHA1, 0, NULL);
    EXPECT_EQ((DWORD)hr, 0x80070020u);                 /* ERROR_SHARING_VIOLATION */
    CloseHandle(h);
    cleanup(&f, p);
}
TEST(mssigner_pe_unsupported_file_types) {
    NEED_FIX(f);
    static const struct { const char *name; const char *data; DWORD n; } t[] = {
        { "text", "this is not a portable executable\r\n", 34 },
        { "empty", "", 0 },
        { "mz only", "MZ", 2 },
        { "short mz", "MZ\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16 },
    };
    for (int i = 0; i < 4; i++) {
        char p[MAX_PATH]; t_tmpfile(p, sizeof p, "other.bin");
        CHECK(fx_write_file(p, t[i].data, t[i].n));
        HRESULT hr = fx_sign(&f, p, CALG_SHA1, 0, NULL);
        CHECKF(hr < 0, "%s: unexpectedly 0x%08lx", t[i].name, (DWORD)hr);
        t_note("signing a %s file: 0x%08lx", t[i].name, (DWORD)hr);
        DWORD n = 0; BYTE *b = fx_read_file(p, &n);
        CHECKF(b && n == t[i].n && !memcmp(b, t[i].data, n), "%s modified", t[i].name);
        free(b); DeleteFileA(p);
    }
    fx_close(&f);
}
TEST(mssigner_pe_unknown_hash_algorithm) {
    NEED_FIX(f);
    char p[MAX_PATH]; fx_pe_new(p, sizeof p, "alg.exe");
    DWORD n = 0; BYTE *b = snapshot(p, &n);
    static const DWORD bad[] = { 0xFFFF, 0x1234, 0x7FFF };
    for (int i = 0; i < 3; i++) {
        HRESULT hr = fx_sign(&f, p, bad[i], 0, NULL);
        CHECKF((DWORD)hr == 0x80091002u, "alg 0x%lx: 0x%08lx", bad[i], (DWORD)hr);   /* CRYPT_E_UNKNOWN_ALGO */
    }
    if (b) expect_unchanged(p, b, n);
    free(b); cleanup(&f, p);
}
TEST(mssigner_pe_failed_sign_clears_context) {
    NEED_FIX(f);
    char p[MAX_PATH]; t_tmpfile(p, sizeof p, "gone.exe");
    SG_CTX *ctx = (SG_CTX *)(ULONG_PTR)0x1000;
    HRESULT hr = fx_sign(&f, p, CALG_SHA1, 0, &ctx);
    EXPECT_EQ((DWORD)hr, HR_FILE_NOT_FOUND);
    CHECK(ctx == NULL);
    fx_close(&f);
}

/* ---- time stamping with an unusable service: error codes only, file untouched ---- */
static void ts_expect_failure(FX *f, const char *leaf, const wchar_t *url, DWORD flags, const char *oid) {
    char p[MAX_PATH]; SIGN_OR_FAIL((*f), p, leaf, CALG_SHA1);
    DWORD n = 0; BYTE *b = snapshot(p, &n);
    LPWSTR wp = fx_w(p);
    DWORD idx = 0;
    SG_FILE fi = { sizeof fi, wp, NULL };
    SG_SUBJECT sub = { sizeof sub, &idx, SG_SUBJECT_FILE, &fi };
    HRESULT hr = UN(SignerTimeStampEx3)(flags, 0, &sub, url, oid, NULL, NULL, NULL, NULL, NULL);
    CHECKF(hr < 0, "flags %lu url %ls: 0x%08lx", flags, url, (DWORD)hr);
    t_note("time stamp flags=%lu url=%ls -> 0x%08lx", flags, url, (DWORD)hr);
    if (b) expect_unchanged(p, b, n);
    free(b); free(wp); cleanup(f, p);
}
TEST(mssigner_pe_timestamp_closed_localhost_port_authenticode) {
    NEED_FIX(f);
    if (!UN(SignerTimeStampEx3)) { fx_close(&f); t_skip("no SignerTimeStampEx3"); return; }
    ts_expect_failure(&f, "ts1.exe", L"http://127.0.0.1:1/ts", 1, NULL);
}
TEST(mssigner_pe_timestamp_closed_localhost_port_rfc3161) {
    NEED_FIX(f);
    if (!UN(SignerTimeStampEx3)) { fx_close(&f); t_skip("no SignerTimeStampEx3"); return; }
    ts_expect_failure(&f, "ts2.exe", L"http://127.0.0.1:1/ts", 2, OID_SHA256);
}
TEST(mssigner_pe_timestamp_invalid_url) {
    NEED_FIX(f);
    if (!UN(SignerTimeStampEx3)) { fx_close(&f); t_skip("no SignerTimeStampEx3"); return; }
    ts_expect_failure(&f, "ts3.exe", L"this is not a url", 1, NULL);
}
TEST(mssigner_pe_timestamp_unsigned_file) {
    NEED_FIX(f);
    if (!UN(SignerTimeStamp)) { fx_close(&f); t_skip("no SignerTimeStamp"); return; }
    char p[MAX_PATH]; fx_pe_new(p, sizeof p, "tsu.exe");
    DWORD n = 0; BYTE *b = snapshot(p, &n);
    LPWSTR wp = fx_w(p);
    DWORD idx = 0;
    SG_FILE fi = { sizeof fi, wp, NULL };
    SG_SUBJECT sub = { sizeof sub, &idx, SG_SUBJECT_FILE, &fi };
    HRESULT hr = UN(SignerTimeStamp)(&sub, L"http://127.0.0.1:1/ts", NULL, NULL);
    CHECK(hr < 0);
    t_note("time stamping an unsigned file: 0x%08lx", (DWORD)hr);
    if (b) expect_unchanged(p, b, n);
    free(b); free(wp); cleanup(&f, p);
}
TEST(mssigner_pe_add_timestamp_response_garbage) {
    NEED_FIX(f);
    if (!UN(SignerAddTimeStampResponse)) { fx_close(&f); t_skip("no SignerAddTimeStampResponse"); return; }
    char p[MAX_PATH]; SIGN_OR_FAIL(f, p, "resp.exe", CALG_SHA1);
    DWORD n = 0; BYTE *b = snapshot(p, &n);
    LPWSTR wp = fx_w(p);
    DWORD idx = 0;
    SG_FILE fi = { sizeof fi, wp, NULL };
    SG_SUBJECT sub = { sizeof sub, &idx, SG_SUBJECT_FILE, &fi };
    BYTE junk[32]; memset(junk, 0x41, sizeof junk);
    HRESULT hr = UN(SignerAddTimeStampResponse)(&sub, junk, sizeof junk, NULL);
    CHECK(hr < 0);
    t_note("garbage time stamp response: 0x%08lx", (DWORD)hr);
    if (b) expect_unchanged(p, b, n);
    free(b); free(wp); cleanup(&f, p);
}
TEST(mssigner_pe_create_timestamp_request_on_signed_file) {
    NEED_FIX(f);
    if (!UN(SignerCreateTimeStampRequest)) { fx_close(&f); t_skip("no SignerCreateTimeStampRequest"); return; }
    char p[MAX_PATH]; SIGN_OR_FAIL(f, p, "req.exe", CALG_SHA1);
    LPWSTR wp = fx_w(p);
    DWORD idx = 0;
    SG_FILE fi = { sizeof fi, wp, NULL };
    SG_SUBJECT sub = { sizeof sub, &idx, SG_SUBJECT_FILE, &fi };
    DWORD cb = 0;
    HRESULT hr = UN(SignerCreateTimeStampRequest)(&sub, NULL, NULL, NULL, &cb);
    t_note("SignerCreateTimeStampRequest size query: hr=0x%08lx cb=%lu", (DWORD)hr, cb);
    if (hr == 0) CHECK(cb > 0);
    free(wp); cleanup(&f, p);
}
TEST(mssigner_pe_append_signature_flag_note) {
    NEED_FIX(f);
    char p[MAX_PATH]; SIGN_OR_FAIL(f, p, "app.exe", CALG_SHA1);
    LPWSTR wp = fx_w(p);
    DWORD idx = 1;
    SG_FILE fi = { sizeof fi, wp, NULL };
    SG_SUBJECT sub = { sizeof sub, &idx, SG_SUBJECT_FILE, &fi };
    SG_CERTSTORE cs = { sizeof cs, f.cert, 0, NULL };
    SG_CERT cert = { sizeof cert, SG_CERT_STORE, &cs, NULL };
    SG_SIGINFO si = { sizeof si, CALG_SHA_256, SG_NO_ATTR, NULL, NULL, NULL };
    HRESULT hr = UN(SignerSignEx3)(0x1000, &sub, &cert, &si, NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    DWORD n = 0; BYTE *b = fx_read_file(p, &n); DWORD o = 0, s = 0, entries = 0;
    if (b && fx_pe_secdir(b, n, &o, &s)) {
        DWORD pos = o;
        while (pos + 8 <= o + s) { DWORD len; memcpy(&len, b + pos, 4); entries++; if (len < 8) break; pos += (len + 7) & ~7u; }
    }
    t_note("append signature (flag 0x1000, SHA-256 after SHA-1): hr=0x%08lx certificate table entries=%lu index=%lu", (DWORD)hr, entries, idx);
    free(b); free(wp); cleanup(&f, p);
}
