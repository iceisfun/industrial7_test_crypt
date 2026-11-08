/* ncrypt.dll SSL provider interface (Ssl*): handle validation, argument order, reference counting and
 * buffer ownership of the Ssl provider layer. No handshake, no network, no TLS traffic; only the provider
 * object ("Microsoft SSL Protocol Provider") is opened and queried.
 * Expectations marked "decomp:" come from the Windows 10 22H2 (19041) ncrypt.dll decompilation
 * (sslprot.c) and are pending confirmation on a real machine; provider-content facts are t_note only. */
#include "t.h"

#define NTE_BAD_HANDLE   0x80090026u
#define NTE_BAD_PARAM    0x80090027u
#define STATUS_BAD_HANDLE 0xc0000008u
#define PROV_MAGIC       0x44444441u
#define PROV_SIZE        0x178u

typedef LONG (WINAPI *p_open)(ULONG_PTR *, LPCWSTR, DWORD);
typedef LONG (WINAPI *p_free_obj)(ULONG_PTR);
typedef LONG (WINAPI *p_free_buf)(void *);
typedef LONG (WINAPI *p_incdec)(ULONG_PTR);
typedef LONG (WINAPI *p_enum_cs)(ULONG_PTR, ULONG_PTR, void **, void **, DWORD);
typedef LONG (WINAPI *p_ecc)(ULONG_PTR, DWORD *, void **);
typedef LONG (WINAPI *p_getprop)(ULONG_PTR, LPCWSTR, void **, DWORD *, void **, DWORD);
typedef LONG (WINAPI *p_prf)(ULONG_PTR, DWORD, DWORD, DWORD, void *);
typedef LONG (WINAPI *p_lookup_info)(ULONG_PTR, DWORD, void *, void *, void *, DWORD);
typedef LONG (WINAPI *p_lookup_len)(ULONG_PTR, DWORD, DWORD, DWORD, void *, DWORD, DWORD);

static const WCHAR PROV[] = L"Microsoft SSL Protocol Provider";
/* The area guard (t_probe_ncrypt_ssl) skips every test here when the Ssl* provider exports are stubs. */
static void __attribute__((constructor)) ssl_guard(void) { t_set_guard(t_probe_ncrypt_ssl); }
#define NEED_SSL() do { } while (0)
#define F(type, name) type name = (type)t_proc_in("ncrypt.dll", #name)

static ULONG_PTR open_prov(void) {
    F(p_open, SslOpenProvider); ULONG_PTR h = 0;
    if (!SslOpenProvider) return 0;
    if (!t_require(SslOpenProvider(&h, PROV, 0) == 0 && h != 0, __FILE__, __LINE__, "SslOpenProvider")) return 0;
    return h;
}
static void close_prov(ULONG_PTR h) { F(p_free_obj, SslFreeObject); if (h && SslFreeObject) SslFreeObject(h); }
static DWORD refcnt(ULONG_PTR h) { return ((DWORD *)h)[4]; }

/* decomp: ValidateSslProvHandle accepts only size >= 0x178, magic 0x44444441, word[3] == 0 and rejects before
 * touching anything else, so forged buffers with a bad header are safe to pass. */
TEST(ssl_forged_handle_rejected) {
    NEED_SSL();
    F(p_getprop, SslGetProviderProperty); F(p_ecc, SslEnumEccCurves); F(p_enum_cs, SslEnumCipherSuites);
    F(p_prf, SslGetCipherSuitePRFHashAlgorithm); F(p_lookup_info, SslLookupCipherSuiteInfo);
    F(p_lookup_len, SslLookupCipherLengths);
    static DWORD fake[0x60]; DWORD n = 0; void *p = NULL, *q = NULL; DWORD cb = 0; char buf[0x40] = {0};
    int i;
    REQUIRE_NOTNULL(SslGetProviderProperty); REQUIRE_NOTNULL(SslEnumEccCurves); REQUIRE_NOTNULL(SslEnumCipherSuites);
    REQUIRE_NOTNULL(SslGetCipherSuitePRFHashAlgorithm); REQUIRE_NOTNULL(SslLookupCipherSuiteInfo);
    REQUIRE_NOTNULL(SslLookupCipherLengths);
    for (i = 0; i < 4; i++) {
        memset(fake, 0, sizeof fake);
        fake[0] = PROV_SIZE; fake[1] = PROV_MAGIC;
        t_label("variant %d", i);
        if (i == 0) fake[1] = 0x44444442;      /* key-object magic is not a provider */
        if (i == 1) fake[0] = PROV_SIZE - 1;   /* too small */
        if (i == 2) fake[3] = 1;               /* closed/invalid flag word */
        if (i == 3) fake[1] = 0;               /* no magic */
        EXPECT_EQ(SslGetProviderProperty((ULONG_PTR)fake, L"x", &p, &cb, NULL, 0), NTE_BAD_HANDLE);
        EXPECT_EQ(SslEnumEccCurves((ULONG_PTR)fake, &n, &p), NTE_BAD_HANDLE);
        EXPECT_EQ(SslEnumCipherSuites((ULONG_PTR)fake, 0, &p, &q, 0), NTE_BAD_HANDLE);
        EXPECT_EQ(SslGetCipherSuitePRFHashAlgorithm((ULONG_PTR)fake, 0, 0, 0, buf), NTE_BAD_HANDLE);
        EXPECT_EQ(SslLookupCipherSuiteInfo((ULONG_PTR)fake, 0, buf, buf, buf, 0), NTE_BAD_HANDLE);
        EXPECT_EQ(SslLookupCipherLengths((ULONG_PTR)fake, 0, 0, 0, buf, 0x20, 0), NTE_BAD_HANDLE);
    }
}

/* decomp: the handle check precedes every argument check, so a bad handle wins over NULL out pointers. */
TEST(ssl_bad_handle_wins_over_bad_args) {
    NEED_SSL();
    F(p_ecc, SslEnumEccCurves); F(p_prf, SslGetCipherSuitePRFHashAlgorithm);
    F(p_enum_cs, SslEnumCipherSuites); F(p_lookup_len, SslLookupCipherLengths);
    REQUIRE_NOTNULL(SslEnumEccCurves); REQUIRE_NOTNULL(SslGetCipherSuitePRFHashAlgorithm);
    REQUIRE_NOTNULL(SslEnumCipherSuites); REQUIRE_NOTNULL(SslLookupCipherLengths);
    EXPECT_EQ(SslEnumEccCurves(0, NULL, NULL), NTE_BAD_HANDLE);
    EXPECT_EQ(SslGetCipherSuitePRFHashAlgorithm(0, 0, 0, 0, NULL), NTE_BAD_HANDLE);
    EXPECT_EQ(SslEnumCipherSuites(0, 0, NULL, NULL, 0), NTE_BAD_HANDLE);
    EXPECT_EQ(SslLookupCipherLengths(0, 0, 0, 0, NULL, 0, 0), NTE_BAD_HANDLE);
}

/* decomp: with a valid handle, NULL output pointers give NTE_INVALID_PARAMETER. */
TEST(ssl_valid_handle_null_args) {
    NEED_SSL();
    F(p_ecc, SslEnumEccCurves); F(p_prf, SslGetCipherSuitePRFHashAlgorithm);
    F(p_enum_cs, SslEnumCipherSuites); F(p_getprop, SslGetProviderProperty); F(p_lookup_len, SslLookupCipherLengths);
    ULONG_PTR h; DWORD n = 7, cb = 0; void *p = (void *)1, *q = NULL; char buf[0x20] = {0};
    REQUIRE_NOTNULL(SslEnumEccCurves); REQUIRE_NOTNULL(SslGetCipherSuitePRFHashAlgorithm);
    REQUIRE_NOTNULL(SslEnumCipherSuites); REQUIRE_NOTNULL(SslGetProviderProperty); REQUIRE_NOTNULL(SslLookupCipherLengths);
    h = open_prov(); REQUIRE(h);
    EXPECT_EQ(SslEnumEccCurves(h, NULL, &p), NTE_BAD_PARAM);
    EXPECT_EQ(SslEnumEccCurves(h, &n, NULL), NTE_BAD_PARAM);
    EXPECT_EQ(SslGetCipherSuitePRFHashAlgorithm(h, 0, 0, 0, NULL), NTE_BAD_PARAM);
    EXPECT_EQ(SslEnumCipherSuites(h, 0, NULL, &q, 0), NTE_BAD_PARAM);
    EXPECT_EQ(SslEnumCipherSuites(h, 0, &p, NULL, 0), NTE_BAD_PARAM);
    EXPECT_EQ(SslGetProviderProperty(h, L"x", NULL, &cb, NULL, 0), NTE_BAD_PARAM);
    EXPECT_EQ(SslGetProviderProperty(h, L"x", &p, NULL, NULL, 0), NTE_BAD_PARAM);
    EXPECT_EQ(SslLookupCipherLengths(h, 0, 0, 0, NULL, 0x20, 0), NTE_BAD_PARAM);
    EXPECT_EQ(SslLookupCipherLengths(h, 0, 0, 0, buf, 0x13, 0), NTE_BAD_PARAM);   /* output struct smaller than 0x14 */
    close_prov(h);
}

/* decomp: property names of 0x41 or more characters are rejected before the provider is called. */
TEST(ssl_getprop_name_length_limit) {
    NEED_SSL();
    F(p_getprop, SslGetProviderProperty);
    ULONG_PTR h; WCHAR name[0x60]; void *p = NULL; DWORD cb = 0; int i;
    REQUIRE_NOTNULL(SslGetProviderProperty);
    h = open_prov(); REQUIRE(h);
    for (i = 0; i < 0x50; i++) name[i] = L'A';
    name[0x41] = 0;
    EXPECT_EQ(SslGetProviderProperty(h, name, &p, &cb, NULL, 0), NTE_BAD_PARAM);
    name[0x40] = 0;
    {   /* 0x40 characters passes the length gate; the provider decides, so only record */
        LONG r = SslGetProviderProperty(h, name, &p, &cb, NULL, 0);
        EXPECT_NE((DWORD)r, NTE_BAD_HANDLE);
        t_note("64-char unknown property -> 0x%08lx", (unsigned long)r);
        if (r == 0 && p) { F(p_free_buf, SslFreeBuffer); if (SslFreeBuffer) SslFreeBuffer(p); }
    }
    close_prov(h);
}

/* decomp: handle word[0]=0x178, word[1]=magic, word[3]=0, word[4]=reference count starting at 1;
 * Increment/Decrement adjust word[4] atomically. */
TEST(ssl_provider_refcount_layout) {
    NEED_SSL();
    F(p_incdec, SslIncrementProviderReferenceCount); F(p_incdec, SslDecrementProviderReferenceCount);
    ULONG_PTR h;
    REQUIRE_NOTNULL(SslIncrementProviderReferenceCount); REQUIRE_NOTNULL(SslDecrementProviderReferenceCount);
    h = open_prov(); REQUIRE(h);
    EXPECT_EQ(((DWORD *)h)[0], PROV_SIZE);
    EXPECT_EQ(((DWORD *)h)[1], PROV_MAGIC);
    EXPECT_EQ(((DWORD *)h)[3], 0);
    EXPECT_EQ(refcnt(h), 1);
    EXPECT_EQ(SslIncrementProviderReferenceCount(h), 0);
    EXPECT_EQ(refcnt(h), 2);
    EXPECT_EQ(SslIncrementProviderReferenceCount(h), 0);
    EXPECT_EQ(refcnt(h), 3);
    EXPECT_EQ(SslDecrementProviderReferenceCount(h), 0);
    EXPECT_EQ(SslDecrementProviderReferenceCount(h), 0);
    EXPECT_EQ(refcnt(h), 1);
    close_prov(h);
}

/* decomp: Increment/Decrement return raw STATUS_INVALID_HANDLE (no NTE normalisation) for bad handles. */
TEST(ssl_refcount_bad_handles) {
    NEED_SSL();
    F(p_incdec, SslIncrementProviderReferenceCount); F(p_incdec, SslDecrementProviderReferenceCount);
    static DWORD fake[0x60];
    REQUIRE_NOTNULL(SslIncrementProviderReferenceCount); REQUIRE_NOTNULL(SslDecrementProviderReferenceCount);
    memset(fake, 0, sizeof fake);
    fake[0] = PROV_SIZE; fake[1] = 0x44444442;
    EXPECT_EQ(SslIncrementProviderReferenceCount(0), STATUS_BAD_HANDLE);
    EXPECT_EQ(SslIncrementProviderReferenceCount((ULONG_PTR)fake), STATUS_BAD_HANDLE);
    EXPECT_EQ(SslDecrementProviderReferenceCount((ULONG_PTR)fake), STATUS_BAD_HANDLE);
    fake[0] = PROV_SIZE - 1; fake[1] = PROV_MAGIC;
    EXPECT_EQ(SslDecrementProviderReferenceCount((ULONG_PTR)fake), STATUS_BAD_HANDLE);
    EXPECT_EQ(fake[4], 0);   /* untouched */
}

/* decomp: SslOpenProvider rejects non-zero flags and a NULL output; *phProvider is untouched on failure;
 * a NULL provider name selects the default "Microsoft SSL Protocol Provider". */
TEST(ssl_open_provider_args) {
    NEED_SSL();
    F(p_open, SslOpenProvider); F(p_free_obj, SslFreeObject);
    ULONG_PTR h = 0x1234, h2 = 0;
    REQUIRE_NOTNULL(SslOpenProvider); REQUIRE_NOTNULL(SslFreeObject);
    EXPECT_EQ(SslOpenProvider(&h, PROV, 1), NTE_BAD_PARAM);
    EXPECT_EQ(h, 0x1234);
    EXPECT_EQ(SslOpenProvider(&h, PROV, 0x80000000), NTE_BAD_PARAM);
    EXPECT_EQ(h, 0x1234);
    EXPECT_EQ(SslOpenProvider(&h2, NULL, 0), 0);
    EXPECT_NE(h2, 0);
    if (h2) {
        EXPECT_EQ(((DWORD *)h2)[1], PROV_MAGIC);
        EXPECT_EQ(SslFreeObject(h2), 0);
    }
}

/* Each open is an independent object with its own count; free of one does not invalidate the other. */
TEST(ssl_two_handles_independent) {
    NEED_SSL();
    F(p_incdec, SslIncrementProviderReferenceCount); F(p_ecc, SslEnumEccCurves);
    ULONG_PTR a, b; DWORD n = 0; void *p = NULL; LONG r;
    REQUIRE_NOTNULL(SslIncrementProviderReferenceCount); REQUIRE_NOTNULL(SslEnumEccCurves);
    a = open_prov(); REQUIRE(a); b = open_prov();
    if (!b) { close_prov(a); return; }
    EXPECT_NE(a, b);
    EXPECT_EQ(SslIncrementProviderReferenceCount(a), 0);
    EXPECT_EQ(refcnt(a), 2);
    EXPECT_EQ(refcnt(b), 1);
    close_prov(a);                      /* drops one of two references on a */
    r = SslEnumEccCurves(b, &n, &p);
    t_note("SslEnumEccCurves -> 0x%08lx count=%lu", (unsigned long)r, (unsigned long)n);
    if (r == 0 && p) { F(p_free_buf, SslFreeBuffer); if (SslFreeBuffer) SslFreeBuffer(p); }
    close_prov(b);
}

/* decomp: outputs of Enum* calls are tracked in a provider buffer list and each takes one provider
 * reference that SslFreeBuffer releases; after freeing everything the count is back to 1. */
TEST(ssl_enum_buffers_hold_references) {
    NEED_SSL();
    F(p_enum_cs, SslEnumCipherSuites); F(p_ecc, SslEnumEccCurves); F(p_free_buf, SslFreeBuffer);
    ULONG_PTR h; void *cs = NULL, *st = NULL, *curves = NULL; DWORD n = 0; LONG r;
    REQUIRE_NOTNULL(SslEnumCipherSuites); REQUIRE_NOTNULL(SslEnumEccCurves); REQUIRE_NOTNULL(SslFreeBuffer);
    h = open_prov(); REQUIRE(h);
    r = SslEnumCipherSuites(h, 0, &cs, &st, 0);
    EXPECT_EQ(r, 0);
    if (r == 0) {
        EXPECT_NE(refcnt(h), 1);
        SslFreeBuffer(cs);
        SslFreeBuffer(st);
    }
    EXPECT_EQ(refcnt(h), 1);
    r = SslEnumEccCurves(h, &n, &curves);
    if (r == 0) {
        EXPECT_NE(refcnt(h), 1);
        SslFreeBuffer(curves);
        EXPECT_EQ(refcnt(h), 1);
    } else t_note("SslEnumEccCurves -> 0x%08lx", (unsigned long)r);
    close_prov(h);
}

/* Walk the whole cipher suite enumeration with the returned state pointer; it must terminate and
 * every step must hand back an owned buffer. */
TEST(ssl_enum_cipher_suites_walk) {
    NEED_SSL();
    F(p_enum_cs, SslEnumCipherSuites); F(p_free_buf, SslFreeBuffer);
    ULONG_PTR h; void *cs = NULL, *st = NULL; LONG r = 0; int n = 0;
    REQUIRE_NOTNULL(SslEnumCipherSuites); REQUIRE_NOTNULL(SslFreeBuffer);
    h = open_prov(); REQUIRE(h);
    while (n < 4096) {
        void *cur = NULL;
        r = SslEnumCipherSuites(h, 0, &cur, &st, 0);
        if (r != 0) break;
        n++;
        SslFreeBuffer(cur);
    }
    EXPECT_NE(n, 4096);                 /* terminated */
    EXPECT_NE(n, 0);
    t_note("cipher suites enumerated: %d, terminal status 0x%08lx", n, (unsigned long)r);
    if (st) SslFreeBuffer(st);
    EXPECT_EQ(refcnt(h), 1);
    close_prov(h);
}

/* decomp: SslEnumProtocolProviders: NULL count or list -> NTE_INVALID_PARAMETER; non-zero flags are
 * handled by a different branch; the list is released through SslFreeBuffer. */
TEST(ssl_enum_protocol_providers_args) {
    NEED_SSL();
    typedef LONG (WINAPI *p_ep)(DWORD *, void **, DWORD);
    F(p_ep, SslEnumProtocolProviders); F(p_free_buf, SslFreeBuffer);
    DWORD n = 5; void *l = NULL; LONG r;
    REQUIRE_NOTNULL(SslEnumProtocolProviders); REQUIRE_NOTNULL(SslFreeBuffer);
    EXPECT_EQ(SslEnumProtocolProviders(NULL, &l, 0), NTE_BAD_PARAM);
    EXPECT_EQ(SslEnumProtocolProviders(&n, NULL, 0), NTE_BAD_PARAM);
    EXPECT_EQ(n, 5);
    r = SslEnumProtocolProviders(&n, &l, 0);
    EXPECT_EQ(r, 0);
    EXPECT_NE(n, 0);
    if (l) SslFreeBuffer(l);
    n = 5; l = NULL;
    r = SslEnumProtocolProviders(&n, &l, 1);
    t_note("SslEnumProtocolProviders flags=1 -> 0x%08lx n=%lu", (unsigned long)r, (unsigned long)n);
    if (r == 0 && l) SslFreeBuffer(l);
}

/* SslFreeBuffer of a pointer that is not tracked is a plain heap free (NULL is a no-op returning 0). */
TEST(ssl_free_buffer_null) {
    NEED_SSL();
    F(p_free_buf, SslFreeBuffer);
    REQUIRE_NOTNULL(SslFreeBuffer);
    EXPECT_EQ(SslFreeBuffer(NULL), 0);
}
