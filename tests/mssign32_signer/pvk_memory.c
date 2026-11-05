/* mssign32 Pvk* private-key helpers, memory flavours (PVK image in a buffer).
 * Layout of a PVK image: 24-byte header
 *   +0 magic 0xB0B5F11E  +4 reserved(0)  +8 keytype  +12 encrypt(0/1/2)  +16 saltlen(<=0x1000)  +20 keylen(1..0x1000)
 * followed by saltlen salt bytes and keylen bytes of PRIVATEKEYBLOB.
 * Only unencrypted images are used: the password of an encrypted image is obtained through a modal
 * dialog (no programmatic password parameter), which is out of scope for this non-UI area. */
#include "mssfix.h"

#define P_LOAD_W  UN(PvkPrivateKeyLoadFromMemory)
#define P_LOAD_A  UN(PvkPrivateKeyLoadFromMemoryA)

static int have_key(HCRYPTPROV h, DWORD spec) {
    HCRYPTKEY k = 0;
    if (!U(CryptGetUserKey)(h, spec, &k)) return 0;
    U(CryptDestroyKey)(k);
    return 1;
}
/* sign SHA-1("abc") with the user key `spec` of h; compare with the known answer for key A */
static int sig_matches_A(HCRYPTPROV h, DWORD spec) {
    HCRYPTHASH hh = 0; BYTE sig[512]; DWORD cb = sizeof sig, kcb; int ok = 0;
    const BYTE *kat = fx_sig_sha1_abc(&kcb);
    if (!U(CryptCreateHash)(h, CALG_SHA1, 0, 0, &hh)) return 0;
    if (U(CryptHashData)(hh, (const BYTE *)"abc", 3, 0) && U(CryptSignHashW)(hh, spec, NULL, 0, sig, &cb))
        ok = (cb == kcb && !memcmp(sig, kat, kcb));
    U(CryptDestroyHash)(hh);
    return ok;
}
static int ctx_empty(FX *f) {
    if (!fx_open_empty(f)) { t_skip("cannot open an RSA_AES context"); return 0; }
    return 1;
}
#define NEED_FX(f) FX f; if (!ctx_empty(&f)) return; 

TEST(mssigner_pvkmem_load_keyx_w) {
    PvkPrivateKeyLoadFromMemory_pfn fn = P_LOAD_W; REQUIRE(fn);
    NEED_FX(f)
    BYTE pvk[2048]; DWORD n = fx_pvk(FX_A, 1, 0, 0, pvk, sizeof pvk);
    DWORD spec = 0;
    SET_ERR(0);
    BOOL r = fn(f.hProv, pvk, n, NULL, NULL, 0, &spec);
    CHECK(r);
    EXPECT_EQ(spec, 1);
    CHECK(have_key(f.hProv, AT_KEYEXCHANGE));
    CHECK(sig_matches_A(f.hProv, AT_KEYEXCHANGE));
    fx_close(&f);
}
/* The ANSI flavours of the Pvk loaders convert the key-name argument (the fifth parameter) with MultiByteToWideChar and
 * return FALSE at once when it is NULL: no parameter is looked at, the key-type out value keeps its old value and the
 * header is never read. Any non-NULL key name sends this Win10 build into a fault or a heap corruption (0xC0000005 /
 * 0xC0000374, every path including the valid one), so the corpus only pins the NULL-name behaviour and never passes a
 * name to an ANSI flavour. */
TEST(mssigner_pvkmem_a_form_null_name_fails) {
    PvkPrivateKeyLoadFromMemoryA_pfn fn = P_LOAD_A; REQUIRE(fn);
    NEED_FX(f)
    BYTE pvk[2048], bad[2048];
    DWORD n = fx_pvk(FX_A, 1, 0, 0, pvk, sizeof pvk);
    memcpy(bad, pvk, n); fx_pvk_hdr(bad, 0xB0B5F11E, 9, 1, 0, 0, n - 24);
    static const BYTE text[34] = "this is not a private key file...";
    struct { const char *what; const BYTE *p; DWORD cb; DWORD spec_in; } t[] = {
        { "valid keyx image", pvk, n, 0 },
        { "valid image, key type mismatch", pvk, n, 2 },
        { "bad header", bad, n, 5 },
        { "text", text, sizeof text, 7 },
        { "short", pvk, 10, 3 },
    };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        DWORD spec = t[i].spec_in;
        BOOL r = fn(f.hProv, (PBYTE)t[i].p, t[i].cb, NULL, NULL, 0, &spec);
        CHECKF(!r, "%s", t[i].what);
        CHECKF(spec == t[i].spec_in, "%s: key type changed to %lu", t[i].what, spec);
        CHECKF(!have_key(f.hProv, AT_KEYEXCHANGE), "%s: key imported", t[i].what);
    }
    fx_close(&f);
}
TEST(mssigner_pvkmem_load_signature_key) {
    PvkPrivateKeyLoadFromMemory_pfn fn = P_LOAD_W; REQUIRE(fn);
    NEED_FX(f)
    BYTE pvk[2048]; DWORD n = fx_pvk(FX_A, 2, 0, 0, pvk, sizeof pvk);
    DWORD spec = 0;
    BOOL r = fn(f.hProv, pvk, n, NULL, NULL, 0, &spec);
    CHECK(r);
    EXPECT_EQ(spec, 2);
    CHECK(have_key(f.hProv, AT_SIGNATURE));
    CHECK(sig_matches_A(f.hProv, AT_SIGNATURE));
    fx_close(&f);
}
TEST(mssigner_pvkmem_load_null_keyspec_pointer) {
    PvkPrivateKeyLoadFromMemory_pfn fn = P_LOAD_W; REQUIRE(fn);
    NEED_FX(f)
    BYTE pvk[2048]; DWORD n = fx_pvk(FX_A, 1, 0, 0, pvk, sizeof pvk);
    CHECK(fn(f.hProv, pvk, n, NULL, NULL, 0, NULL));
    CHECK(have_key(f.hProv, AT_KEYEXCHANGE));
    fx_close(&f);
}
TEST(mssigner_pvkmem_load_keyspec_in_match) {
    PvkPrivateKeyLoadFromMemory_pfn fn = P_LOAD_W; REQUIRE(fn);
    NEED_FX(f)
    BYTE pvk[2048]; DWORD n = fx_pvk(FX_A, 1, 0, 0, pvk, sizeof pvk);
    DWORD spec = 1;
    CHECK(fn(f.hProv, pvk, n, NULL, NULL, 0, &spec));
    EXPECT_EQ(spec, 1);
    fx_close(&f);
}
TEST(mssigner_pvkmem_load_keyspec_in_mismatch_w) {
    PvkPrivateKeyLoadFromMemory_pfn fn = P_LOAD_W; REQUIRE(fn);
    NEED_FX(f)
    BYTE pvk[2048]; DWORD n = fx_pvk(FX_A, 1, 0, 0, pvk, sizeof pvk);
    DWORD spec = 2;   /* caller wants a signature key, the file holds a key exchange key */
    SET_ERR(0);
    BOOL r = fn(f.hProv, pvk, n, NULL, NULL, 0, &spec);
    CHECK(!r); EXPECT_ERR(PVK_E_WRONGTYPE);
    EXPECT_EQ(spec, 1);                 /* out value is the key type found in the header */
    CHECK(!have_key(f.hProv, AT_KEYEXCHANGE)); /* nothing was imported */
    fx_close(&f);
}
TEST(mssigner_pvkmem_load_header_keytype_not_validated) {
    /* the header key type is copied to the caller without validation; the blob's own algid decides the slot */
    PvkPrivateKeyLoadFromMemory_pfn fn = P_LOAD_W; REQUIRE(fn);
    NEED_FX(f)
    BYTE pvk[2048]; DWORD n = fx_pvk(FX_A, 1, 0, 0, pvk, sizeof pvk);
    fx_pvk_hdr(pvk, 0xB0B5F11E, 0, 7, 0, 0, n - 24);
    DWORD spec = 0;
    BOOL r = fn(f.hProv, pvk, n, NULL, NULL, 0, &spec);
    CHECK(r);
    EXPECT_EQ(spec, 7);
    CHECK(have_key(f.hProv, AT_KEYEXCHANGE));
    fx_close(&f);
}
TEST(mssigner_pvkmem_load_salt_ignored_when_unencrypted) {
    PvkPrivateKeyLoadFromMemory_pfn fn = P_LOAD_W; REQUIRE(fn);
    NEED_FX(f)
    BYTE pvk[2300]; DWORD n = fx_pvk(FX_A, 1, 0, 16, pvk, sizeof pvk);
    DWORD spec = 0;
    BOOL r = fn(f.hProv, pvk, n, NULL, NULL, 0, &spec);
    CHECK(r);
    EXPECT_EQ(spec, 1);
    CHECK(sig_matches_A(f.hProv, AT_KEYEXCHANGE));
    fx_close(&f);
}
TEST(mssigner_pvkmem_load_trailing_bytes_ignored) {
    PvkPrivateKeyLoadFromMemory_pfn fn = P_LOAD_W; REQUIRE(fn);
    NEED_FX(f)
    BYTE pvk[2300]; DWORD n = fx_pvk(FX_A, 1, 0, 0, pvk, sizeof pvk);
    memset(pvk + n, 0xEE, 64);
    DWORD spec = 0;
    CHECK(fn(f.hProv, pvk, n + 64, NULL, NULL, 0, &spec));
    EXPECT_EQ(spec, 1);
    fx_close(&f);
}
TEST(mssigner_pvkmem_load_second_key_B) {
    PvkPrivateKeyLoadFromMemory_pfn fn = P_LOAD_W; REQUIRE(fn);
    NEED_FX(f)
    BYTE pvk[2048]; DWORD n = fx_pvk(FX_B, 1, 0, 0, pvk, sizeof pvk);
    DWORD spec = 0;
    CHECK(fn(f.hProv, pvk, n, NULL, NULL, 0, &spec));
    EXPECT_EQ(spec, 1);
    CHECK(have_key(f.hProv, AT_KEYEXCHANGE));
    CHECK(!sig_matches_A(f.hProv, AT_KEYEXCHANGE));   /* different key -> different signature */
    fx_close(&f);
}
TEST(mssigner_pvkmem_load_exportable_flag) {
    /* dwFlags is passed straight to CryptImportKey: CRYPT_EXPORTABLE makes the key exportable */
    PvkPrivateKeyLoadFromMemory_pfn fn = P_LOAD_W; REQUIRE(fn);
    NEED_FX(f)
    BYTE pvk[2048], exp[2048]; DWORD n = fx_pvk(FX_A, 1, 0, 0, pvk, sizeof pvk), spec = 0;
    CHECK(fn(f.hProv, pvk, n, NULL, NULL, CRYPT_EXPORTABLE, &spec));
    HCRYPTKEY k = 0; DWORD cb = sizeof exp;
    CHECK(U(CryptGetUserKey)(f.hProv, AT_KEYEXCHANGE, &k));
    if (k) {
        BOOL e = U(CryptExportKey)(k, 0, PRIVATEKEYBLOB, 0, exp, &cb);
        CHECK(e);
        if (e) {
            BYTE ref[2048]; DWORD rn = fx_keyblob(FX_A, 1, ref, sizeof ref);
            EXPECT_EQ(cb, rn);
            CHECK(cb >= 20 + 256 && !memcmp(exp, ref, 20 + 256));   /* header + public part */
        }
        U(CryptDestroyKey)(k);
    }
    fx_close(&f);
}
TEST(mssigner_pvkmem_load_not_exportable_by_default) {
    PvkPrivateKeyLoadFromMemory_pfn fn = P_LOAD_W; REQUIRE(fn);
    NEED_FX(f)
    BYTE pvk[2048], exp[2048]; DWORD n = fx_pvk(FX_A, 1, 0, 0, pvk, sizeof pvk), spec = 0;
    CHECK(fn(f.hProv, pvk, n, NULL, NULL, 0, &spec));
    HCRYPTKEY k = 0; DWORD cb = sizeof exp;
    CHECK(U(CryptGetUserKey)(f.hProv, AT_KEYEXCHANGE, &k));
    if (k) {
        SET_ERR(0);
        BOOL e = U(CryptExportKey)(k, 0, PRIVATEKEYBLOB, 0, exp, &cb);
        CHECK(!e);
        if (!e) t_note("export of a non-exportable imported key fails with 0x%08lx", GetLastError());
        U(CryptDestroyKey)(k);
    }
    fx_close(&f);
}

/* ---- malformed images: every one fails with PVK_E_BADFILE and zeroes the key type ---- */
typedef struct { const char *name; DWORD magic, reserved, keytype, enc, salt, keylen; int trunc; } BADHDR;
static const BADHDR bad[] = {
    { "reserved=1",        0xB0B5F11E, 1, 1, 0, 0, 0, 0 },
    { "reserved=ffffffff", 0xB0B5F11E, 0xFFFFFFFF, 1, 0, 0, 0, 0 },
    { "salt=0x1001",       0xB0B5F11E, 0, 1, 0, 0x1001, 0, 0 },
    { "salt=ffffffff",     0xB0B5F11E, 0, 1, 0, 0xFFFFFFFF, 0, 0 },
    { "keylen=0",          0xB0B5F11E, 0, 1, 0, 0, 1, 0 },   /* keylen overwritten with 0 below */
    { "keylen=0x1001",     0xB0B5F11E, 0, 1, 0, 0, 0x1001, 0 },
    { "keylen=ffffffff",   0xB0B5F11E, 0, 1, 0, 0, 0xFFFFFFFF, 0 },
    { "enc=3",             0xB0B5F11E, 0, 1, 3, 0, 0, 0 },
    { "enc=ffffffff",      0xB0B5F11E, 0, 1, 0xFFFFFFFF, 0, 0, 0 },
    { "keylen larger than data", 0xB0B5F11E, 0, 1, 0, 0, 0x1000, 0 },
    { "short by one byte", 0xB0B5F11E, 0, 1, 0, 0, 0, 1 },
    { "short by half",     0xB0B5F11E, 0, 1, 0, 0, 0, 300 },
    { "header only",       0xB0B5F11E, 0, 1, 0, 0, 0, 1 << 20 },
};
static void run_bad(PvkPrivateKeyLoadFromMemory_pfn fn) {
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        const BADHDR *b = &bad[i];
        FX f; if (!ctx_empty(&f)) return;
        BYTE pvk[2300]; DWORD n = fx_pvk(FX_A, 1, 0, 0, pvk, sizeof pvk);
        DWORD kl = n - 24;
        DWORD keylen = b->keylen ? b->keylen : kl;
        if (!strcmp(b->name, "keylen=0")) keylen = 0;
        if (!strcmp(b->name, "enc=3") || !strcmp(b->name, "enc=ffffffff")) { /* keep data consistent */ }
        fx_pvk_hdr(pvk, b->magic, b->reserved, b->keytype, b->enc, b->salt, keylen);
        DWORD use = n;
        if (b->trunc == 1 && !strcmp(b->name, "header only")) use = 24;
        else if (b->trunc == 1) use = n - 1;
        else if (b->trunc == 300) use = n / 2;
        else if (b->trunc == 1 << 20) use = 24;
        DWORD spec = 1;
        SET_ERR(0);
        BOOL r = fn(f.hProv, pvk, use, NULL, NULL, 0, &spec);
        DWORD e = GetLastError();
        CHECKF(!r, "%s: unexpectedly succeeded", b->name);
        CHECKF(e == PVK_E_BADFILE, "%s: last error 0x%08lx", b->name, e);
        CHECKF(spec == 0, "%s: key type left at %lu", b->name, spec);
        CHECKF(!have_key(f.hProv, AT_KEYEXCHANGE), "%s: key imported", b->name);
        fx_close(&f);
    }
}
TEST(mssigner_pvkmem_bad_header_table_w) {
    PvkPrivateKeyLoadFromMemory_pfn fn = P_LOAD_W; REQUIRE(fn);
    run_bad(fn);
}
TEST(mssigner_pvkmem_buffer_shorter_than_header) {
    PvkPrivateKeyLoadFromMemory_pfn fn = P_LOAD_W; REQUIRE(fn);
    NEED_FX(f)
    BYTE pvk[2048]; DWORD n = fx_pvk(FX_A, 1, 0, 0, pvk, sizeof pvk);
    static const DWORD lens[] = { 0, 1, 4, 12, 23 };
    for (int i = 0; i < 5; i++) {
        DWORD spec = 1;
        SET_ERR(0);
        BOOL r = fn(f.hProv, pvk, lens[i], NULL, NULL, 0, &spec);
        CHECKF(!r, "len %lu", lens[i]);
        EXPECT_ERR(PVK_E_BADFILE);
        CHECKF(spec == 0, "len %lu spec %lu", lens[i], spec);
    }
    DWORD spec = 1;
    SET_ERR(0);
    CHECK(!fn(f.hProv, NULL, 0, NULL, NULL, 0, &spec));   /* NULL buffer is never dereferenced when cb < 24 */
    EXPECT_ERR(PVK_E_BADFILE);
    fx_close(&f);
}
TEST(mssigner_pvkmem_bad_header_null_keyspec_pointer) {
    PvkPrivateKeyLoadFromMemory_pfn fn = P_LOAD_W; REQUIRE(fn);
    NEED_FX(f)
    BYTE pvk[2048]; DWORD n = fx_pvk(FX_A, 1, 0, 0, pvk, sizeof pvk);
    fx_pvk_hdr(pvk, 0xB0B5F11E, 5, 1, 0, 0, n - 24);
    SET_ERR(0);
    CHECK(!fn(f.hProv, pvk, n, NULL, NULL, 0, NULL));
    EXPECT_ERR(PVK_E_BADFILE);
    fx_close(&f);
}
TEST(mssigner_pvkmem_load_wrong_magic_large_is_bad_file) {
    /* an image whose magic is not the PVK magic is handed to the legacy structured-storage loader,
     * which rejects anything larger than 0x4000 bytes with the same error */
    PvkPrivateKeyLoadFromMemory_pfn fn = P_LOAD_W; REQUIRE(fn);
    NEED_FX(f)
    BYTE *big = calloc(1, 0x4001);
    fx_pvk_hdr(big, 0xDEADBEEF, 0, 1, 0, 0, 100);
    DWORD spec = 1;
    SET_ERR(0);
    CHECK(!fn(f.hProv, big, 0x4001, NULL, NULL, 0, &spec));
    EXPECT_ERR(PVK_E_BADFILE);
    EXPECT_EQ(spec, 0);
    free(big);
    fx_close(&f);
}
TEST(mssigner_pvkmem_load_wrong_magic_small_fails) {
    PvkPrivateKeyLoadFromMemory_pfn fn = P_LOAD_W; REQUIRE(fn);
    NEED_FX(f)
    BYTE buf[64]; memset(buf, 0x41, sizeof buf);
    DWORD spec = 1;
    SET_ERR(0);
    BOOL r = fn(f.hProv, buf, sizeof buf, NULL, NULL, 0, &spec);
    DWORD e = GetLastError();
    CHECK(!r);
    t_note("garbage image of 64 bytes: last error 0x%08lx", e);
    CHECK(e != 0);
    EXPECT_EQ(spec, 0);
    CHECK(!have_key(f.hProv, AT_KEYEXCHANGE));
    fx_close(&f);
}
TEST(mssigner_pvkmem_load_invalid_provider_handle) {
    PvkPrivateKeyLoadFromMemory_pfn fn = P_LOAD_W; REQUIRE(fn);
    BYTE pvk[2048]; DWORD n = fx_pvk(FX_A, 1, 0, 0, pvk, sizeof pvk);
    DWORD spec = 0;
    SET_ERR(0);
    BOOL r = fn(0, pvk, n, NULL, NULL, 0, &spec);
    CHECK(!r);
    t_note("hProv=0: last error 0x%08lx, key type out=%lu", GetLastError(), spec);
}
TEST(mssigner_pvkmem_load_header_only_keylen_ok_but_zero_data) {
    /* keylen=1 passes header validation, the one-byte body fails inside CryptImportKey */
    PvkPrivateKeyLoadFromMemory_pfn fn = P_LOAD_W; REQUIRE(fn);
    NEED_FX(f)
    BYTE pvk[25]; fx_pvk_hdr(pvk, 0xB0B5F11E, 0, 1, 0, 0, 1); pvk[24] = 0;
    DWORD spec = 0;
    CHECK(!fn(f.hProv, pvk, 25, NULL, NULL, 0, &spec));
    CHECK(!have_key(f.hProv, AT_KEYEXCHANGE));
    fx_close(&f);
}
TEST(mssigner_pvkmem_load_corrupt_blob_rejected) {
    PvkPrivateKeyLoadFromMemory_pfn fn = P_LOAD_W; REQUIRE(fn);
    NEED_FX(f)
    BYTE pvk[2048]; DWORD n = fx_pvk(FX_A, 1, 0, 0, pvk, sizeof pvk);
    pvk[24 + 8] = 'X';        /* RSAPUBKEY magic no longer RSA2 */
    DWORD spec = 0;
    SET_ERR(0);
    CHECK(!fn(f.hProv, pvk, n, NULL, NULL, 0, &spec));
    EXPECT_ERR(NTE_BAD_DATA);
    CHECK(!have_key(f.hProv, AT_KEYEXCHANGE));
    fx_close(&f);
}
TEST(mssigner_pvkmem_load_public_blob_type_succeeds_without_user_key) {
    /* BLOBHEADER.bType = PUBLICKEYBLOB: CryptImportKey accepts the blob as a public key, so the loader reports success
     * (with the header key type) although no user key appears in the container. */
    PvkPrivateKeyLoadFromMemory_pfn fn = P_LOAD_W; REQUIRE(fn);
    NEED_FX(f)
    BYTE pvk[2048]; DWORD n = fx_pvk(FX_A, 1, 0, 0, pvk, sizeof pvk);
    pvk[24] = 0x06;
    DWORD spec = 0;
    CHECK(fn(f.hProv, pvk, n, NULL, NULL, 0, &spec));
    EXPECT_EQ(spec, 1);
    CHECK(!have_key(f.hProv, AT_KEYEXCHANGE));
    fx_close(&f);
}
/* ---- SaveToMemory: only the NULL-buffer form is exercised (a real write prompts for a password) ---- */
TEST(mssigner_pvkmem_save_no_key_fails) {
    PvkPrivateKeySaveToMemory_pfn fn = UN(PvkPrivateKeySaveToMemory); REQUIRE(fn);
    NEED_FX(f)
    DWORD cb = 77;
    SET_ERR(0);
    BOOL r = fn(f.hProv, AT_KEYEXCHANGE, NULL, NULL, 0, NULL, &cb);
    CHECK(!r);
    EXPECT_EQ(cb, 0);
    t_note("size query on a context without a key: last error 0x%08lx", GetLastError());
    cb = 77;
    CHECK(!fn(f.hProv, 3, NULL, NULL, 0, NULL, &cb));   /* invalid key spec */
    EXPECT_EQ(cb, 0);
    fx_close(&f);
}
TEST(mssigner_pvkmem_save_size_query_note) {
    PvkPrivateKeySaveToMemory_pfn fn = UN(PvkPrivateKeySaveToMemory); REQUIRE(fn);
    PvkPrivateKeySaveToMemoryA_pfn fa = UN(PvkPrivateKeySaveToMemoryA); REQUIRE(fa);
    FX f;
    if (!fx_open(&f, FX_A, 1)) { t_skip("no key context"); return; }
    /* the key must be exportable for a save: re-import with CRYPT_EXPORTABLE through the loader */
    PvkPrivateKeyLoadFromMemory_pfn ld = P_LOAD_W; REQUIRE(ld);
    BYTE pvk[2048]; DWORD n = fx_pvk(FX_A, 1, 0, 0, pvk, sizeof pvk), spec = 0;
    ld(f.hProv, pvk, n, NULL, NULL, CRYPT_EXPORTABLE, &spec);
    DWORD cw = 0, ca = 0;
    SET_ERR(0);
    BOOL rw = fn(f.hProv, AT_KEYEXCHANGE, NULL, NULL, 0, NULL, &cw);
    DWORD ew = GetLastError();
    BOOL ra = fa(f.hProv, AT_KEYEXCHANGE, NULL, NULL, 0, NULL, &ca);
    t_note("PvkPrivateKeySaveToMemory(NULL buffer): ret=%d cb=%lu err=0x%08lx; A form ret=%d cb=%lu", rw, cw, ew, ra, ca);
    EXPECT_EQ(rw, ra);
    EXPECT_EQ(cw, ca);
    if (rw) {
        /* header(24) + salt(16) + PRIVATEKEYBLOB(1172 for 2048 bit) when the size query reports success */
        t_note("expected 24+16+1172=1212 for a protected image, got %lu", cw);
    }
    fx_close(&f);
}

/* ---- AcquireContextFromMemory: creates a uniquely named temporary container, deleted by Release ---- */
static int tmpname_ok_w(LPCWSTR s) {
    if (!s || lstrlenW(s) != 38 || wcsncmp(s, L"TmpKey", 6)) return 0;
    for (int i = 6; i < 38; i++) if (!((s[i] >= L'0' && s[i] <= L'9') || (s[i] >= L'A' && s[i] <= L'F'))) return 0;
    return 1;
}
static int tmpname_ok_a(const char *s) {
    if (!s || strlen(s) != 38 || strncmp(s, "TmpKey", 6)) return 0;
    for (int i = 6; i < 38; i++) if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'A' && s[i] <= 'F'))) return 0;
    return 1;
}
TEST(mssigner_pvkmem_acquire_context_w) {
    PvkPrivateKeyAcquireContextFromMemory_pfn fn = UN(PvkPrivateKeyAcquireContextFromMemory); REQUIRE(fn);
    PvkPrivateKeyReleaseContext_pfn rel = UN(PvkPrivateKeyReleaseContext); REQUIRE(rel);
    BYTE pvk[2048]; DWORD n = fx_pvk(FX_A, 1, 0, 0, pvk, sizeof pvk), spec = 0;
    HCRYPTPROV h = 0x1234; LPWSTR tmp = (LPWSTR)(ULONG_PTR)0x1;
    SET_ERR(0);
    BOOL r = fn(MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, pvk, n, NULL, NULL, &spec, &h, &tmp);
    CHECK(r);
    if (!r) { t_note("last error 0x%08lx", GetLastError()); return; }
    CHECK(h != 0 && h != 0x1234);
    CHECK(tmpname_ok_w(tmp));
    EXPECT_EQ(spec, 1);
    CHECK(have_key(h, AT_KEYEXCHANGE));
    CHECK(sig_matches_A(h, AT_KEYEXCHANGE));
    WCHAR name[64]; lstrcpynW(name, tmp, 64);
    CHECK(rel(h, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, tmp));
    /* the temporary container is gone */
    HCRYPTPROV h2 = 0;
    SET_ERR(0);
    BOOL o = U(CryptAcquireContextW)(&h2, name, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, 0);
    CHECK(!o);
    EXPECT_ERR(NTE_BAD_KEYSET);
    if (o) U(CryptReleaseContext)(h2, 0);
}
TEST(mssigner_pvkmem_acquire_context_a_null_name_fails) {
    PvkPrivateKeyAcquireContextFromMemoryA_pfn fn = UN(PvkPrivateKeyAcquireContextFromMemoryA); REQUIRE(fn);
    BYTE pvk[2048]; DWORD n = fx_pvk(FX_A, 2, 0, 0, pvk, sizeof pvk), spec = 9;
    HCRYPTPROV h = 0x1234; LPSTR tmp = (LPSTR)(ULONG_PTR)0x1;
    BOOL r = fn(MS_ENH_RSA_AES_PROV_A, PROV_RSA_AES, pvk, n, NULL, NULL, &spec, &h, &tmp);
    CHECK(!r);                                  /* see the note on the ANSI flavours above */
    EXPECT_EQ(h, 0);
    CHECK(tmp == NULL);
    EXPECT_EQ(spec, 9);                         /* untouched */
}
TEST(mssigner_pvkmem_acquire_context_names_unique) {
    PvkPrivateKeyAcquireContextFromMemory_pfn fn = UN(PvkPrivateKeyAcquireContextFromMemory); REQUIRE(fn);
    PvkPrivateKeyReleaseContext_pfn rel = UN(PvkPrivateKeyReleaseContext); REQUIRE(rel);
    BYTE pvk[2048]; DWORD n = fx_pvk(FX_B, 1, 0, 0, pvk, sizeof pvk), s1 = 0, s2 = 0;
    HCRYPTPROV h1 = 0, h2 = 0; LPWSTR t1 = NULL, t2 = NULL;
    BOOL r1 = fn(MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, pvk, n, NULL, NULL, &s1, &h1, &t1);
    BOOL r2 = fn(MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, pvk, n, NULL, NULL, &s2, &h2, &t2);
    CHECK(r1); CHECK(r2);
    if (r1 && r2) { CHECK(h1 != h2); CHECK(lstrcmpW(t1, t2) != 0); }
    if (r1) rel(h1, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, t1);
    if (r2) rel(h2, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, t2);
}
TEST(mssigner_pvkmem_acquire_context_bad_image_clears_outputs) {
    PvkPrivateKeyAcquireContextFromMemory_pfn fn = UN(PvkPrivateKeyAcquireContextFromMemory); REQUIRE(fn);
    BYTE pvk[2048]; DWORD n = fx_pvk(FX_A, 1, 0, 0, pvk, sizeof pvk), spec = 5;
    fx_pvk_hdr(pvk, 0xB0B5F11E, 9, 1, 0, 0, n - 24);
    HCRYPTPROV h = 0x1234; LPWSTR tmp = (LPWSTR)(ULONG_PTR)0x1;
    BOOL r = fn(MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, pvk, n, NULL, NULL, &spec, &h, &tmp);
    CHECK(!r);
    EXPECT_EQ(h, 0);
    CHECK(tmp == NULL);
    EXPECT_EQ(spec, 0);
}
TEST(mssigner_pvkmem_acquire_context_keyspec_mismatch_cleans_up) {
    PvkPrivateKeyAcquireContextFromMemory_pfn fn = UN(PvkPrivateKeyAcquireContextFromMemory); REQUIRE(fn);
    BYTE pvk[2048]; DWORD n = fx_pvk(FX_A, 1, 0, 0, pvk, sizeof pvk), spec = 2;
    HCRYPTPROV h = 0x1234; LPWSTR tmp = (LPWSTR)(ULONG_PTR)0x1;
    BOOL r = fn(MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, pvk, n, NULL, NULL, &spec, &h, &tmp);
    CHECK(!r);
    EXPECT_EQ(h, 0);
    CHECK(tmp == NULL);
    EXPECT_EQ(spec, 1);
}
TEST(mssigner_pvkmem_acquire_context_bad_provider) {
    PvkPrivateKeyAcquireContextFromMemory_pfn fn = UN(PvkPrivateKeyAcquireContextFromMemory); REQUIRE(fn);
    BYTE pvk[2048]; DWORD n = fx_pvk(FX_A, 1, 0, 0, pvk, sizeof pvk), spec = 0;
    HCRYPTPROV h = 0x1234; LPWSTR tmp = (LPWSTR)(ULONG_PTR)0x1;
    BOOL r = fn(L"cryptt no such provider", PROV_RSA_AES, pvk, n, NULL, NULL, &spec, &h, &tmp);
    CHECK(!r);
    EXPECT_EQ(h, 0);
    CHECK(tmp == NULL);
}
TEST(mssigner_pvkmem_release_context_noop) {
    PvkPrivateKeyReleaseContext_pfn rel = UN(PvkPrivateKeyReleaseContext); REQUIRE(rel);
    PvkPrivateKeyReleaseContextA_pfn rela = UN(PvkPrivateKeyReleaseContextA); REQUIRE(rela);
    SET_ERR(0);
    EXPECT_EQ(rel(0, NULL, 0, NULL), 1);
    EXPECT_EQ(rela(0, NULL, 0, NULL), 1);
}
TEST(mssigner_pvkmem_release_context_plain_handle) {
    PvkPrivateKeyReleaseContext_pfn rel = UN(PvkPrivateKeyReleaseContext); REQUIRE(rel);
    HCRYPTPROV h = 0;
    CHECK(U(CryptAcquireContextW)(&h, NULL, MS_ENH_RSA_AES_PROV_W, PROV_RSA_AES, CRYPT_VERIFYCONTEXT));
    if (!h) return;
    CHECK(U(CryptContextAddRef)(h, NULL, 0));
    EXPECT_EQ(rel(h, NULL, 0, NULL), 1);              /* drops one reference only */
    BYTE rnd[8];
    CHECK(U(CryptGenRandom)(h, 8, rnd));              /* still usable */
    CHECK(U(CryptReleaseContext)(h, 0));
}
