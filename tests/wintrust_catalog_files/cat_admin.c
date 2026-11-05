/* Catalog admin context, file hashing (CryptCATAdminCalcHashFromFileHandle 1/2/3) and the read-only
 * catalog lookups.  Nothing here writes to the system catalog database. */
#include "cat_common.h"
#include "vectors.h"

#define NO_WINE() do { if (t_is_wine()) { t_skip("Wine differs from Windows here (context layout, buffer protocol, catalog database)"); return; } } while (0)
#define NEED() do { REQUIRE(U(CryptCATAdminAcquireContext)); REQUIRE(U(CryptCATAdminReleaseContext)); \
                    REQUIRE(U(CryptCATAdminCalcHashFromFileHandle)); } while (0)
#define NTE_BAD_ALGID_ ((DWORD)0x80090008)

/* ---- independent reference hashes (FIPS 180-4) ------------------------- */
typedef struct { DWORD h[8]; unsigned long long len; BYTE buf[64]; int n; int is256; } SHA;
static DWORD rol(DWORD x, int n) { return (x << n) | (x >> (32 - n)); }
static DWORD ror(DWORD x, int n) { return (x >> n) | (x << (32 - n)); }
static const DWORD K256[64] = {
 0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
 0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
 0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
 0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2 };
static void sha_block(SHA *s, const BYTE *p)
{
    DWORD w[80], a, b, c, d, e, f, g, h, t1, t2; int i;
    for (i = 0; i < 16; i++) w[i] = ((DWORD)p[4*i] << 24) | (p[4*i+1] << 16) | (p[4*i+2] << 8) | p[4*i+3];
    if (!s->is256) {
        for (i = 16; i < 80; i++) w[i] = rol(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
        a = s->h[0]; b = s->h[1]; c = s->h[2]; d = s->h[3]; e = s->h[4];
        for (i = 0; i < 80; i++) {
            DWORD k, fn;
            if (i < 20) { fn = (b & c) | (~b & d); k = 0x5a827999; }
            else if (i < 40) { fn = b ^ c ^ d; k = 0x6ed9eba1; }
            else if (i < 60) { fn = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdc; }
            else { fn = b ^ c ^ d; k = 0xca62c1d6; }
            t1 = rol(a, 5) + fn + e + k + w[i]; e = d; d = c; c = rol(b, 30); b = a; a = t1;
        }
        s->h[0] += a; s->h[1] += b; s->h[2] += c; s->h[3] += d; s->h[4] += e;
    } else {
        for (i = 16; i < 64; i++) {
            DWORD s0 = ror(w[i-15], 7) ^ ror(w[i-15], 18) ^ (w[i-15] >> 3), s1 = ror(w[i-2], 17) ^ ror(w[i-2], 19) ^ (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        a = s->h[0]; b = s->h[1]; c = s->h[2]; d = s->h[3]; e = s->h[4]; f = s->h[5]; g = s->h[6]; h = s->h[7];
        for (i = 0; i < 64; i++) {
            t1 = h + (ror(e, 6) ^ ror(e, 11) ^ ror(e, 25)) + ((e & f) ^ (~e & g)) + K256[i] + w[i];
            t2 = (ror(a, 2) ^ ror(a, 13) ^ ror(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
            h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        }
        s->h[0] += a; s->h[1] += b; s->h[2] += c; s->h[3] += d; s->h[4] += e; s->h[5] += f; s->h[6] += g; s->h[7] += h;
    }
}
static void sha_init(SHA *s, int is256)
{
    static const DWORD i1[8] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0, 0, 0, 0 };
    static const DWORD i2[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
    memset(s, 0, sizeof *s); memcpy(s->h, is256 ? i2 : i1, sizeof s->h); s->is256 = is256;
}
static void sha_upd(SHA *s, const void *d, size_t n)
{
    const BYTE *p = d;
    s->len += n;
    while (n) {
        size_t c = 64 - s->n; if (c > n) c = n;
        memcpy(s->buf + s->n, p, c); s->n += (int)c; p += c; n -= c;
        if (s->n == 64) { sha_block(s, s->buf); s->n = 0; }
    }
}
static void sha_fin(SHA *s, BYTE *out)
{
    unsigned long long bits = s->len * 8; BYTE pad[72] = { 0x80 }; int i, padn = (s->n < 56) ? 56 - s->n : 120 - s->n, words = s->is256 ? 8 : 5;
    BYTE lenb[8];
    for (i = 0; i < 8; i++) lenb[i] = (BYTE)(bits >> (56 - 8 * i));
    sha_upd(s, pad, padn); sha_upd(s, lenb, 8);
    for (i = 0; i < words; i++) { out[4*i] = (BYTE)(s->h[i] >> 24); out[4*i+1] = (BYTE)(s->h[i] >> 16); out[4*i+2] = (BYTE)(s->h[i] >> 8); out[4*i+3] = (BYTE)s->h[i]; }
}
static void sha_of(int is256, const void *d, size_t n, BYTE *out) { SHA s; sha_init(&s, is256); sha_upd(&s, d, n); sha_fin(&s, out); }

/* Authenticode image digest of an in-memory PE file, per the published algorithm. Returns 0 if not a PE. */
static int pe_digest(const BYTE *f, size_t n, int is256, BYTE *out)
{
    DWORD e, opt, chk, dd, soh, certoff = 0, certsz = 0; WORD nsec, osz; SHA s; DWORD end, i;
    struct { DWORD ptr, size; } secs[96], tmp;
    if (n < 0x200 || f[0] != 'M' || f[1] != 'Z') return 0;
    memcpy(&e, f + 0x3c, 4);
    if (e + 0x108 > n || memcmp(f + e, "PE\0\0", 4)) return 0;
    opt = e + 24; memcpy(&nsec, f + e + 6, 2); memcpy(&osz, f + e + 20, 2);
    if (nsec > 96 || f[opt] != 0x0b || f[opt + 1] != 0x02) return 0;   /* PE32+ only */
    chk = opt + 64; dd = opt + 112 + 4 * 8; memcpy(&soh, f + opt + 60, 4);
    memcpy(&certoff, f + dd, 4); memcpy(&certsz, f + dd + 4, 4);
    sha_init(&s, is256);
    sha_upd(&s, f, chk); sha_upd(&s, f + chk + 4, dd - chk - 4); sha_upd(&s, f + dd + 8, soh - dd - 8);
    for (i = 0; i < nsec; i++) { DWORD sh = opt + osz + 40 * i; memcpy(&secs[i].size, f + sh + 16, 4); memcpy(&secs[i].ptr, f + sh + 20, 4); }
    for (i = 1; i < nsec; i++) for (DWORD j = i; j > 0 && secs[j].ptr < secs[j - 1].ptr; j--) { tmp = secs[j]; secs[j] = secs[j - 1]; secs[j - 1] = tmp; }
    end = soh;
    for (i = 0; i < nsec; i++) { if (secs[i].size && secs[i].ptr + secs[i].size <= n) sha_upd(&s, f + secs[i].ptr, secs[i].size); end = secs[i].ptr + secs[i].size; }
    {
        size_t lim = certsz ? certoff : n;
        if (lim > end && lim <= n) sha_upd(&s, f + end, lim - end);
    }
    sha_fin(&s, out);
    return 1;
}
static BYTE *read_all(const char *path, size_t *n)
{
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
    DWORD sz, got = 0; BYTE *b;
    if (h == INVALID_HANDLE_VALUE) return NULL;
    sz = GetFileSize(h, NULL);
    b = malloc(sz ? sz : 1);
    if (b && !ReadFile(h, b, sz, &got, NULL)) got = 0;
    CloseHandle(h);
    *n = got;
    return b;
}

static HANDLE open_read(const WCHAR *p) { return ropen(p); }
static void mkflat(BYTE *b, size_t n) { size_t i; for (i = 0; i < n; i++) b[i] = (BYTE)((i * 31 + 7) & 255); }

/* Hash helpers: rewind first, so the result never depends on where an earlier call left the file pointer. */
static BOOL H1(HANDLE f, DWORD *cb, BYTE *b) { SetFilePointer(f, 0, NULL, FILE_BEGIN); return U(CryptCATAdminCalcHashFromFileHandle)(f, cb, b, 0); }
static BOOL H2(HCATADMIN c, HANDLE f, DWORD *cb, BYTE *b) { SetFilePointer(f, 0, NULL, FILE_BEGIN); return U(CryptCATAdminCalcHashFromFileHandle2)(c, f, cb, b, 0); }
static BOOL H3(HCATADMIN c, HANDLE f, DWORD *cb, BYTE *b, DWORD fl) { SetFilePointer(f, 0, NULL, FILE_BEGIN); return UN(CryptCATAdminCalcHashFromFileHandle3)(c, f, cb, b, fl); }

TEST(wtadm_selfcheck_reference_hashes)
{
    BYTE d[32], big[70000]; size_t i;
    sha_of(0, flat_a, sizeof flat_a, d); CHECK(!memcmp(d, flat_a_sha1, 20));
    sha_of(1, flat_a, sizeof flat_a, d); CHECK(!memcmp(d, flat_a_sha256, 32));
    sha_of(0, flat_c, sizeof flat_c, d); CHECK(!memcmp(d, flat_c_sha1, 20));
    for (i = 0; i < sizeof big; i++) big[i] = (BYTE)((i * 7 + 3) & 255);
    sha_of(0, big, sizeof big, d); CHECK(!memcmp(d, flat_b_sha1, 20));
    sha_of(1, big, sizeof big, d); CHECK(!memcmp(d, flat_b_sha256, 32));
    CHECK(pe_digest(pe_base, sizeof pe_base, 0, d) && !memcmp(d, pe_base_sha1, 20));
    CHECK(pe_digest(pe_trail, sizeof pe_trail, 1, d) && !memcmp(d, pe_trail_sha256, 32));
    CHECK(pe_digest(pe_chk, sizeof pe_chk, 0, d) && !memcmp(d, pe_base_sha1, 20));
}

/* ---------------------------------------------------------------- acquire / release */
TEST(wtadm_acquire_invalid_parameters)
{
    HCATADMIN h = (HCATADMIN)(ULONG_PTR)0x1234;
    NEED();
    SET_ERR(0); CHECK(!U(CryptCATAdminAcquireContext)(NULL, NULL, 0)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!U(CryptCATAdminAcquireContext)(&h, NULL, 1)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    CHECK(h == (HCATADMIN)(ULONG_PTR)0x1234);   /* untouched when the parameters are rejected */
    SET_ERR(0); CHECK(!U(CryptCATAdminAcquireContext)(&h, NULL, 0x80000000)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}

TEST(wtadm_acquire_default_subsystem)
{
    HCATADMIN h = NULL;
    NO_WINE(); NEED();
    SET_ERR(0);
    CHECK(U(CryptCATAdminAcquireContext)(&h, NULL, 0));
    REQUIRE(h != NULL);
    EXPECT_EQ(*(DWORD *)h, 0xb8);   /* the context object starts with its own size */
    CHECK(U(CryptCATAdminReleaseContext)(h, 0));
}

TEST(wtadm_acquire_twice_gives_distinct_contexts)
{
    HCATADMIN a = NULL, b = NULL;
    NEED();
    CHECK(U(CryptCATAdminAcquireContext)(&a, NULL, 0));
    CHECK(U(CryptCATAdminAcquireContext)(&b, NULL, 0));
    REQUIRE(a && b);
    CHECK(a != b);
    CHECK(U(CryptCATAdminReleaseContext)(a, 0));
    CHECK(U(CryptCATAdminReleaseContext)(b, 0));
}

TEST(wtadm_release_invalid)
{
    NEED();
    SET_ERR(0); CHECK(!U(CryptCATAdminReleaseContext)(NULL, 0)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}

TEST(wtadm_release_ignores_flags)
{
    HCATADMIN h = NULL;
    NEED();
    CHECK(U(CryptCATAdminAcquireContext)(&h, NULL, 0));
    REQUIRE(h);
    CHECK(U(CryptCATAdminReleaseContext)(h, 0xffff));
}

TEST(wtadm_acquire2_algorithms)
{
    static const struct { const WCHAR *alg; DWORD hashlen; } ok[] = {
        { L"SHA1", 20 }, { L"sha1", 20 }, { L"Sha1", 20 }, { L"SHA256", 32 }, { L"sha256", 32 }, { L"Sha256", 32 }, { NULL, 20 },
    };
    size_t i;
    NO_WINE(); NEED(); REQUIRE(U(CryptCATAdminAcquireContext2)); REQUIRE(U(CryptCATAdminCalcHashFromFileHandle2));
    for (i = 0; i < sizeof ok / sizeof *ok; i++) {
        HCATADMIN h = NULL; WCHAR p[MAX_PATH]; HANDLE f; DWORD cb = 0;
        wpath(p, "acq2.dat"); put_file(p, flat_a, sizeof flat_a);
        SET_ERR(0);
        CHECKF(U(CryptCATAdminAcquireContext2)(&h, NULL, ok[i].alg, NULL, 0), "row %zu err %lu", i, GetLastError());
        if (!h) continue;
        f = open_read(p); REQUIRE(f != INVALID_HANDLE_VALUE);
        SET_ERR(0);
        CHECKF(U(CryptCATAdminCalcHashFromFileHandle2)(h, f, &cb, NULL, 0), "row %zu", i);
        CHECKF(cb == ok[i].hashlen, "row %zu: hash length %lu want %lu", i, cb, ok[i].hashlen);
        CloseHandle(f);
        CHECK(U(CryptCATAdminReleaseContext)(h, 0));
        DeleteFileW(p);
    }
}

TEST(wtadm_acquire2_unsupported_algorithms)
{
    static const WCHAR *bad[] = { L"MD5", L"SHA384", L"SHA512", L"MD2", L"", L"SHA-1", L"SHA2", L"1.3.14.3.2.26", L" SHA1" };
    size_t i;
    NO_WINE(); NEED(); REQUIRE(U(CryptCATAdminAcquireContext2));
    for (i = 0; i < sizeof bad / sizeof *bad; i++) {
        HCATADMIN h = (HCATADMIN)(ULONG_PTR)0x4321;
        SET_ERR(0);
        CHECKF(!U(CryptCATAdminAcquireContext2)(&h, NULL, bad[i], NULL, 0), "row %zu (%ls) was accepted", i, bad[i]);
        EXPECT_ERR(NTE_BAD_ALGID_);
        CHECKF(h == NULL, "row %zu: output handle %p, expected NULL", i, h);   /* cleared before the algorithm is checked */
    }
}

TEST(wtadm_acquire2_invalid_parameters)
{
    HCATADMIN h = (HCATADMIN)(ULONG_PTR)0x4321;
    NEED(); REQUIRE(U(CryptCATAdminAcquireContext2));
    SET_ERR(0); CHECK(!U(CryptCATAdminAcquireContext2)(NULL, NULL, L"SHA1", NULL, 0)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!U(CryptCATAdminAcquireContext2)(&h, NULL, L"SHA1", NULL, 1)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    CHECK(h == (HCATADMIN)(ULONG_PTR)0x4321);
    SET_ERR(0); CHECK(!U(CryptCATAdminAcquireContext2)(&h, NULL, NULL, NULL, 2)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}

TEST(wtadm_acquire2_context_signature)
{
    HCATADMIN h = NULL;
    NO_WINE(); NEED(); REQUIRE(U(CryptCATAdminAcquireContext2));
    CHECK(U(CryptCATAdminAcquireContext2)(&h, NULL, L"SHA256", NULL, 0));
    REQUIRE(h);
    EXPECT_EQ(*(DWORD *)h, 0xb8);
    CHECK(U(CryptCATAdminReleaseContext)(h, 0));
}

/* ---------------------------------------------------------------- hashing: parameters */
TEST(wtadm_hash_invalid_parameters)
{
    WCHAR p[MAX_PATH]; HANDLE f; DWORD cb = 0; BYTE b[64];
    NO_WINE(); NEED(); wpath(p, "hp.dat"); put_file(p, flat_a, sizeof flat_a);
    f = open_read(p); REQUIRE(f != INVALID_HANDLE_VALUE);
    SET_ERR(0); CHECK(!U(CryptCATAdminCalcHashFromFileHandle)(NULL, NULL, NULL, 0)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!H1(NULL, &cb, b)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!H1(INVH, &cb, b)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!U(CryptCATAdminCalcHashFromFileHandle)(f, NULL, b, 0)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!U(CryptCATAdminCalcHashFromFileHandle)(f, NULL, NULL, 0)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    cb = 64;
    SET_ERR(0); CHECK(!U(CryptCATAdminCalcHashFromFileHandle)(f, &cb, b, 1)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!U(CryptCATAdminCalcHashFromFileHandle)(f, &cb, b, 0x80000000)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!U(CryptCATAdminCalcHashFromFileHandle)(f, &cb, NULL, 2)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    EXPECT_EQ(cb, 64);   /* rejected calls leave the size alone */
    CloseHandle(f); DeleteFileW(p);
}

TEST(wtadm_hash2_invalid_parameters)
{
    WCHAR p[MAX_PATH]; HANDLE f; DWORD cb = 64; BYTE b[64]; HCATADMIN ctx = NULL;
    NO_WINE(); NEED(); REQUIRE(U(CryptCATAdminCalcHashFromFileHandle2)); REQUIRE(U(CryptCATAdminAcquireContext2));
    wpath(p, "hp2.dat"); put_file(p, flat_a, sizeof flat_a);
    f = open_read(p); REQUIRE(f != INVALID_HANDLE_VALUE);
    CHECK(U(CryptCATAdminAcquireContext2)(&ctx, NULL, L"SHA1", NULL, 0)); REQUIRE(ctx);
    SET_ERR(0); CHECK(!H2(NULL, f, &cb, b)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!H2(ctx, NULL, &cb, b)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!H2(ctx, INVH, &cb, b)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!U(CryptCATAdminCalcHashFromFileHandle2)(ctx, f, NULL, b, 0)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!U(CryptCATAdminCalcHashFromFileHandle2)(ctx, f, &cb, b, 1)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!U(CryptCATAdminCalcHashFromFileHandle2)(ctx, NULL, NULL, NULL, 0)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    CHECK(U(CryptCATAdminReleaseContext)(ctx, 0));
    CloseHandle(f); DeleteFileW(p);
}

TEST(wtadm_hash3_invalid_parameters)
{
    WCHAR p[MAX_PATH]; HANDLE f; DWORD cb = 64; BYTE b[64]; HCATADMIN ctx = NULL;
    NEED(); REQUIRE(UN(CryptCATAdminCalcHashFromFileHandle3)); REQUIRE(U(CryptCATAdminAcquireContext2));
    wpath(p, "hp3.dat"); put_file(p, flat_a, sizeof flat_a);
    f = open_read(p); REQUIRE(f != INVALID_HANDLE_VALUE);
    CHECK(U(CryptCATAdminAcquireContext2)(&ctx, NULL, L"SHA1", NULL, 0)); REQUIRE(ctx);
    SET_ERR(0); CHECK(!H3(NULL, f, &cb, b, 0)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!H3(ctx, NULL, &cb, b, 0)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!UN(CryptCATAdminCalcHashFromFileHandle3)(ctx, f, NULL, b, 0)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!H3(ctx, f, &cb, b, 2)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!H3(ctx, f, &cb, b, 0xffffffff)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    cb = 64;
    CHECK(H3(ctx, f, &cb, b, 0));
    EXPECT_EQ(cb, 20);
    cb = 64;
    CHECK(H3(ctx, f, &cb, b, 1));
    EXPECT_EQ(cb, 20);
    CHECK(U(CryptCATAdminReleaseContext)(ctx, 0));
    CloseHandle(f); DeleteFileW(p);
}

/* ---------------------------------------------------------------- hashing: buffer protocol */
TEST(wtadm_hash_size_query)
{
    WCHAR p[MAX_PATH]; HANDLE f; DWORD cb;
    NO_WINE(); NEED(); wpath(p, "sq.dat"); put_file(p, flat_a, sizeof flat_a);
    f = open_read(p); REQUIRE(f != INVALID_HANDLE_VALUE);
    cb = 0;
    SET_ERR(0);
    CHECK(H1(f, &cb, NULL));   /* a size query succeeds ... */
    EXPECT_EQ(cb, 20);
    EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);                            /* ... and leaves 122 behind */
    cb = 19;
    SET_ERR(0);
    CHECK(H1(f, &cb, NULL));
    EXPECT_EQ(cb, 20);
    EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
    cb = 1000;
    SET_ERR(0xdead);
    CHECK(H1(f, &cb, NULL));
    EXPECT_EQ(cb, 20);
    t_note("GLE after a size query with a large enough cb: %lu (0xdead = untouched)", GetLastError());
    CloseHandle(f); DeleteFileW(p);
}

TEST(wtadm_hash_buffer_too_small)
{
    WCHAR p[MAX_PATH]; HANDLE f; DWORD cb; BYTE b[64];
    NO_WINE(); NEED(); wpath(p, "bs.dat"); put_file(p, flat_a, sizeof flat_a);
    f = open_read(p); REQUIRE(f != INVALID_HANDLE_VALUE);
    memset(b, 0xcc, sizeof b);
    cb = 19;
    SET_ERR(0);
    CHECK(!H1(f, &cb, b));
    EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(cb, 20);
    EXPECT_EQ(b[0], 0xcc);   /* nothing written */
    cb = 0;
    SET_ERR(0);
    CHECK(!H1(f, &cb, b));
    EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
    EXPECT_EQ(cb, 20);
    CloseHandle(f); DeleteFileW(p);
}

TEST(wtadm_hash_exact_and_larger_buffer)
{
    WCHAR p[MAX_PATH]; HANDLE f; DWORD cb; BYTE b[64];
    NEED(); wpath(p, "eb.dat"); put_file(p, flat_a, sizeof flat_a);
    f = open_read(p); REQUIRE(f != INVALID_HANDLE_VALUE);
    memset(b, 0xcc, sizeof b);
    cb = 20;
    SET_ERR(0);
    CHECK(H1(f, &cb, b));
    EXPECT_EQ(cb, 20);
    CHECK(!memcmp(b, flat_a_sha1, 20));
    EXPECT_EQ(b[20], 0xcc);
    memset(b, 0xcc, sizeof b);
    cb = 64;
    CHECK(H1(f, &cb, b));
    EXPECT_EQ(cb, 20);   /* the length is updated to the real hash size */
    CHECK(!memcmp(b, flat_a_sha1, 20));
    EXPECT_EQ(b[20], 0xcc);
    CloseHandle(f); DeleteFileW(p);
}

TEST(wtadm_hash_sha256_buffer_protocol)
{
    WCHAR p[MAX_PATH]; HANDLE f; DWORD cb; BYTE b[64]; HCATADMIN ctx = NULL;
    NO_WINE(); NEED(); REQUIRE(U(CryptCATAdminAcquireContext2)); REQUIRE(U(CryptCATAdminCalcHashFromFileHandle2));
    wpath(p, "bs256.dat"); put_file(p, flat_a, sizeof flat_a);
    f = open_read(p); REQUIRE(f != INVALID_HANDLE_VALUE);
    CHECK(U(CryptCATAdminAcquireContext2)(&ctx, NULL, L"SHA256", NULL, 0)); REQUIRE(ctx);
    cb = 0; SET_ERR(0);
    CHECK(U(CryptCATAdminCalcHashFromFileHandle2)(ctx, f, &cb, NULL, 0));
    EXPECT_EQ(cb, 32); EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
    cb = 31; SET_ERR(0);
    CHECK(!H2(ctx, f, &cb, b));
    EXPECT_EQ(cb, 32); EXPECT_ERR(ERROR_INSUFFICIENT_BUFFER);
    cb = 32;
    CHECK(H2(ctx, f, &cb, b));
    EXPECT_EQ(cb, 32);
    CHECK(!memcmp(b, flat_a_sha256, 32));
    CHECK(U(CryptCATAdminReleaseContext)(ctx, 0));
    CloseHandle(f); DeleteFileW(p);
}

/* ---------------------------------------------------------------- hashing: values */
TEST(wtadm_hash_flat_vectors_all_entry_points)
{
    static const struct { const BYTE *data; size_t n; const BYTE *s1, *s256; } t[] = {
        { flat_a, sizeof flat_a, flat_a_sha1, flat_a_sha256 }, { flat_c, sizeof flat_c, flat_c_sha1, flat_c_sha256 },
    };
    size_t i;
    NEED(); REQUIRE(U(CryptCATAdminAcquireContext2)); REQUIRE(U(CryptCATAdminCalcHashFromFileHandle2)); REQUIRE(UN(CryptCATAdminCalcHashFromFileHandle3));
    for (i = 0; i < sizeof t / sizeof *t; i++) {
        WCHAR p[MAX_PATH]; HANDLE f; DWORD cb; BYTE b[64]; HCATADMIN c1 = NULL, c256 = NULL, cdef = NULL;
        wpath(p, "fv.dat"); put_file(p, t[i].data, (DWORD)t[i].n);
        f = open_read(p); REQUIRE(f != INVALID_HANDLE_VALUE);
        CHECK(U(CryptCATAdminAcquireContext2)(&c1, NULL, L"SHA1", NULL, 0));
        CHECK(U(CryptCATAdminAcquireContext2)(&c256, NULL, L"SHA256", NULL, 0));
        CHECK(U(CryptCATAdminAcquireContext)(&cdef, NULL, 0));
        cb = 64; CHECKF(H1(f, &cb, b) && cb == 20 && !memcmp(b, t[i].s1, 20), "row %zu plain", i);
        cb = 64; CHECKF(H2(c1, f, &cb, b) && cb == 20 && !memcmp(b, t[i].s1, 20), "row %zu ctx sha1", i);
        cb = 64; CHECKF(H2(c256, f, &cb, b) && cb == 32 && !memcmp(b, t[i].s256, 32), "row %zu ctx sha256", i);
        cb = 64; CHECKF(H2(cdef, f, &cb, b) && cb == 20 && !memcmp(b, t[i].s1, 20), "row %zu default ctx", i);
        cb = 64; CHECKF(H3(c256, f, &cb, b, 0) && cb == 32 && !memcmp(b, t[i].s256, 32), "row %zu v3 sha256", i);
        if (c1) U(CryptCATAdminReleaseContext)(c1, 0);
        if (c256) U(CryptCATAdminReleaseContext)(c256, 0);
        if (cdef) U(CryptCATAdminReleaseContext)(cdef, 0);
        CloseHandle(f); DeleteFileW(p);
    }
}

TEST(wtadm_hash_flat_large_file)
{
    static BYTE big[70000]; WCHAR p[MAX_PATH]; HANDLE f; DWORD cb; BYTE b[64]; size_t i; HCATADMIN c256 = NULL;
    NEED(); REQUIRE(U(CryptCATAdminAcquireContext2)); REQUIRE(U(CryptCATAdminCalcHashFromFileHandle2));
    for (i = 0; i < sizeof big; i++) big[i] = (BYTE)((i * 7 + 3) & 255);
    wpath(p, "big.dat"); put_file(p, big, sizeof big);
    f = open_read(p); REQUIRE(f != INVALID_HANDLE_VALUE);
    cb = 64; CHECK(H1(f, &cb, b)); CHECK(!memcmp(b, flat_b_sha1, 20));
    CHECK(U(CryptCATAdminAcquireContext2)(&c256, NULL, L"SHA256", NULL, 0)); REQUIRE(c256);
    cb = 64; CHECK(H2(c256, f, &cb, b)); CHECK(!memcmp(b, flat_b_sha256, 32));
    U(CryptCATAdminReleaseContext)(c256, 0);
    CloseHandle(f); DeleteFileW(p);
}

TEST(wtadm_hash_flat_size_boundaries)
{
    static const size_t sizes[] = { 16, 55, 56, 57, 63, 64, 65, 119, 120, 121, 127, 128, 129, 511, 512, 513, 4095, 4096, 4097, 8191, 8192, 8193, 65535, 65536, 65537 };
    static BYTE data[65537]; size_t i; HCATADMIN c256 = NULL;
    NEED(); REQUIRE(U(CryptCATAdminAcquireContext2)); REQUIRE(U(CryptCATAdminCalcHashFromFileHandle2));
    mkflat(data, sizeof data);
    CHECK(U(CryptCATAdminAcquireContext2)(&c256, NULL, L"SHA256", NULL, 0)); REQUIRE(c256);
    for (i = 0; i < sizeof sizes / sizeof *sizes; i++) {
        WCHAR p[MAX_PATH]; HANDLE f; DWORD cb; BYTE b[64], want[32];
        wpath(p, "bnd.dat"); put_file(p, data, (DWORD)sizes[i]);
        f = open_read(p); REQUIRE(f != INVALID_HANDLE_VALUE);
        sha_of(0, data, sizes[i], want);
        cb = 64; CHECKF(H1(f, &cb, b) && cb == 20 && !memcmp(b, want, 20), "sha1 of %zu bytes", sizes[i]);
        sha_of(1, data, sizes[i], want);
        cb = 64; CHECKF(H2(c256, f, &cb, b) && cb == 32 && !memcmp(b, want, 32), "sha256 of %zu bytes", sizes[i]);
        CloseHandle(f); DeleteFileW(p);
    }
    U(CryptCATAdminReleaseContext)(c256, 0);
}

TEST(wtadm_hash_tiny_files_note)
{
    static const size_t sizes[] = { 0, 1, 2, 3, 8 };
    static BYTE data[8]; size_t i;
    NEED(); mkflat(data, sizeof data);
    for (i = 0; i < sizeof sizes / sizeof *sizes; i++) {
        WCHAR p[MAX_PATH]; HANDLE f; DWORD cb = 64; BYTE b[64], want[20]; BOOL ok;
        wpath(p, "tiny.dat"); put_file(p, data, (DWORD)sizes[i]);
        f = open_read(p); REQUIRE(f != INVALID_HANDLE_VALUE);
        SET_ERR(0);
        ok = H1(f, &cb, b);
        sha_of(0, data, sizes[i], want);
        t_note("flat file of %zu bytes: %s (GLE %lu)%s", sizes[i], ok ? "hashed" : "rejected", GetLastError(), ok && !memcmp(b, want, 20) ? ", digest = SHA-1 of the content" : "");
        CloseHandle(f); DeleteFileW(p);
    }
}

TEST(wtadm_hash_content_not_name_matters)
{
    WCHAR p1[MAX_PATH], p2[MAX_PATH], p3[MAX_PATH]; HANDLE f1, f2, f3; DWORD cb; BYTE b1[32], b2[32], b3[32];
    NEED(); wpath(p1, "same_a.dat"); wpath(p2, "other_name.txt"); wpath(p3, "changed.dat");
    put_file(p1, flat_a, sizeof flat_a); put_file(p2, flat_a, sizeof flat_a);
    { BYTE m[sizeof flat_a]; memcpy(m, flat_a, sizeof m); m[sizeof m - 1] ^= 1; put_file(p3, m, sizeof m); }
    f1 = open_read(p1); f2 = open_read(p2); f3 = open_read(p3);
    REQUIRE(f1 != INVALID_HANDLE_VALUE && f2 != INVALID_HANDLE_VALUE && f3 != INVALID_HANDLE_VALUE);
    cb = 32; CHECK(H1(f1, &cb, b1));
    cb = 32; CHECK(H1(f2, &cb, b2));
    cb = 32; CHECK(H1(f3, &cb, b3));
    CHECK(!memcmp(b1, b2, 20));
    CHECK(memcmp(b1, b3, 20) != 0);
    CloseHandle(f1); CloseHandle(f2); CloseHandle(f3);
    DeleteFileW(p1); DeleteFileW(p2); DeleteFileW(p3);
}

TEST(wtadm_hash_leaves_handle_open_and_repeatable)
{
    WCHAR p[MAX_PATH]; HANDLE f; DWORD cb; BYTE b1[20], b2[20];
    NEED(); wpath(p, "rep.dat"); put_file(p, flat_c, sizeof flat_c);
    f = open_read(p); REQUIRE(f != INVALID_HANDLE_VALUE);
    cb = 20; CHECK(H1(f, &cb, b1));
    CHECK(GetFileSize(f, NULL) == sizeof flat_c);
    cb = 20; CHECK(H1(f, &cb, b2));
    CHECK(!memcmp(b1, b2, 20));
    CHECK(!memcmp(b1, flat_c_sha1, 20));
    CHECK(CloseHandle(f));
    DeleteFileW(p);
}

TEST(wtadm_hash_from_nonzero_file_position_note)
{
    WCHAR p[MAX_PATH]; HANDLE f; DWORD cb; BYTE b[20]; BOOL ok;
    NEED(); wpath(p, "pos.dat"); put_file(p, flat_c, sizeof flat_c);
    f = open_read(p); REQUIRE(f != INVALID_HANDLE_VALUE);
    SetFilePointer(f, 10, NULL, FILE_BEGIN);
    cb = 20; SET_ERR(0);
    ok = U(CryptCATAdminCalcHashFromFileHandle)(f, &cb, b, 0);
    t_note("file pointer at offset 10: %s%s, pointer afterwards %lu", ok ? "hashed" : "failed",
           ok ? (!memcmp(b, flat_c_sha1, 20) ? " (whole file)" : " (remaining bytes only)") : "", SetFilePointer(f, 0, NULL, FILE_CURRENT));
    CloseHandle(f); DeleteFileW(p);
}

TEST(wtadm_hash_write_only_handle)
{
    WCHAR p[MAX_PATH]; HANDLE f; DWORD cb = 20; BYTE b[20];
    NEED(); wpath(p, "wo.dat"); put_file(p, flat_c, sizeof flat_c);
    f = CreateFileW(p, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL); REQUIRE(f != INVALID_HANDLE_VALUE);
    SET_ERR(0);
    CHECK(!H1(f, &cb, b));
    t_note("hashing through a write-only handle fails with GLE %lu", GetLastError());
    CloseHandle(f); DeleteFileW(p);
}

TEST(wtadm_hash_pe_vectors)
{
    static const struct { const BYTE *pe; size_t n; const BYTE *s1, *s256; const char *what; } t[] = {
        { pe_base, sizeof pe_base, pe_base_sha1, pe_base_sha256, "base image" },
        { pe_ts, sizeof pe_ts, pe_ts_sha1, pe_ts_sha256, "different time stamp" },
        { pe_chk, sizeof pe_chk, pe_chk_sha1, pe_chk_sha256, "different checksum field" },
        { pe_trail, sizeof pe_trail, pe_trail_sha1, pe_trail_sha256, "data after the last section" },
    };
    size_t i; HCATADMIN c1 = NULL, c256 = NULL;
    NEED(); REQUIRE(U(CryptCATAdminAcquireContext2)); REQUIRE(U(CryptCATAdminCalcHashFromFileHandle2));
    CHECK(U(CryptCATAdminAcquireContext2)(&c1, NULL, L"SHA1", NULL, 0));
    CHECK(U(CryptCATAdminAcquireContext2)(&c256, NULL, L"SHA256", NULL, 0));
    REQUIRE(c1 && c256);
    for (i = 0; i < sizeof t / sizeof *t; i++) {
        WCHAR p[MAX_PATH]; HANDLE f; DWORD cb; BYTE b[64];
        wpath(p, "vec.bin"); put_file(p, t[i].pe, (DWORD)t[i].n);
        f = open_read(p); REQUIRE(f != INVALID_HANDLE_VALUE);
        cb = 64; CHECKF(H1(f, &cb, b) && cb == 20 && !memcmp(b, t[i].s1, 20), "%s: plain call", t[i].what);
        cb = 64; CHECKF(H2(c1, f, &cb, b) && cb == 20 && !memcmp(b, t[i].s1, 20), "%s: SHA1 context", t[i].what);
        cb = 64; CHECKF(H2(c256, f, &cb, b) && cb == 32 && !memcmp(b, t[i].s256, 32), "%s: SHA256 context", t[i].what);
        CloseHandle(f); DeleteFileW(p);
    }
    U(CryptCATAdminReleaseContext)(c1, 0); U(CryptCATAdminReleaseContext)(c256, 0);
}

TEST(wtadm_hash_pe_not_equal_to_flat_hash)
{
    WCHAR p[MAX_PATH]; HANDLE f; DWORD cb = 20; BYTE b[20], flat[20];
    NEED(); wpath(p, "pe_vs_flat.bin"); put_file(p, pe_base, sizeof pe_base);
    f = open_read(p); REQUIRE(f != INVALID_HANDLE_VALUE);
    CHECK(H1(f, &cb, b));
    sha_of(0, pe_base, sizeof pe_base, flat);
    CHECK(memcmp(b, flat, 20) != 0);   /* a PE is hashed with the Authenticode rules, not as a flat byte stream */
    CloseHandle(f); DeleteFileW(p);
}

TEST(wtadm_hash_pe_checksum_field_excluded)
{
    WCHAR p1[MAX_PATH], p2[MAX_PATH]; HANDLE f1, f2; DWORD cb; BYTE b1[20], b2[20], img[sizeof pe_base];
    NEED(); wpath(p1, "pe_c1.bin"); wpath(p2, "pe_c2.bin");
    memcpy(img, pe_base, sizeof img);
    put_file(p1, img, sizeof img);
    { DWORD v = 0xdeadbeef; memcpy(img + 0x80 + 24 + 64, &v, 4); }
    put_file(p2, img, sizeof img);
    f1 = open_read(p1); f2 = open_read(p2); REQUIRE(f1 != INVALID_HANDLE_VALUE && f2 != INVALID_HANDLE_VALUE);
    cb = 20; CHECK(H1(f1, &cb, b1));
    cb = 20; CHECK(H1(f2, &cb, b2));
    CHECK(!memcmp(b1, b2, 20));
    CloseHandle(f1); CloseHandle(f2); DeleteFileW(p1); DeleteFileW(p2);
}

TEST(wtadm_hash_pe_section_byte_flip_changes_digest)
{
    WCHAR p1[MAX_PATH], p2[MAX_PATH]; HANDLE f1, f2; DWORD cb; BYTE b1[20], b2[20], img[sizeof pe_base];
    NEED(); wpath(p1, "pe_s1.bin"); wpath(p2, "pe_s2.bin");
    memcpy(img, pe_base, sizeof img);
    put_file(p1, img, sizeof img);
    img[0x300] ^= 0x80;
    put_file(p2, img, sizeof img);
    f1 = open_read(p1); f2 = open_read(p2); REQUIRE(f1 != INVALID_HANDLE_VALUE && f2 != INVALID_HANDLE_VALUE);
    cb = 20; CHECK(H1(f1, &cb, b1));
    cb = 20; CHECK(H1(f2, &cb, b2));
    CHECK(memcmp(b1, b2, 20) != 0);
    CloseHandle(f1); CloseHandle(f2); DeleteFileW(p1); DeleteFileW(p2);
}

TEST(wtadm_hash_system_binaries_match_reference)
{
    static const char *names[] = { "kernel32.dll", "ntdll.dll", "cmd.exe", "user32.dll" };
    size_t i; HCATADMIN c256 = NULL;
    NO_WINE(); NEED(); REQUIRE(U(CryptCATAdminAcquireContext2)); REQUIRE(U(CryptCATAdminCalcHashFromFileHandle2));
    CHECK(U(CryptCATAdminAcquireContext2)(&c256, NULL, L"SHA256", NULL, 0)); REQUIRE(c256);
    for (i = 0; i < sizeof names / sizeof *names; i++) {
        char path[MAX_PATH]; BYTE *img; size_t n; BYTE want1[20], want2[32], b[64]; HANDLE f; DWORD cb;
        GetSystemDirectoryA(path, sizeof path); strcat(path, "\\"); strcat(path, names[i]);
        img = read_all(path, &n);
        if (!img) { t_note("%s not readable", path); continue; }
        if (!pe_digest(img, n, 0, want1) || !pe_digest(img, n, 1, want2)) { t_note("%s is not a PE32+ image", names[i]); free(img); continue; }
        f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
        if (f == INVALID_HANDLE_VALUE) { free(img); continue; }
        cb = 64; CHECKF(H1(f, &cb, b) && cb == 20 && !memcmp(b, want1, 20), "%s SHA-1 Authenticode digest", names[i]);
        cb = 64; CHECKF(H2(c256, f, &cb, b) && cb == 32 && !memcmp(b, want2, 32), "%s SHA-256 Authenticode digest", names[i]);
        CloseHandle(f); free(img);
    }
    U(CryptCATAdminReleaseContext)(c256, 0);
}

TEST(wtadm_hash3_fallback_for_nonconformant_image)
{
    WCHAR p[MAX_PATH]; HANDLE f; BYTE bad[0x300]; DWORD cb; BYTE b[20]; HCATADMIN ctx = NULL; BOOL strict;
    NEED(); REQUIRE(UN(CryptCATAdminCalcHashFromFileHandle3)); REQUIRE(U(CryptCATAdminAcquireContext2));
    memset(bad, 0x41, sizeof bad); bad[0] = 'M'; bad[1] = 'Z';
    wpath(p, "badpe.bin"); put_file(p, bad, sizeof bad);
    f = open_read(p); REQUIRE(f != INVALID_HANDLE_VALUE);
    CHECK(U(CryptCATAdminAcquireContext2)(&ctx, NULL, L"SHA1", NULL, 0)); REQUIRE(ctx);
    cb = 20; SET_ERR(0);
    strict = H3(ctx, f, &cb, b, 0);
    if (strict) {
        t_note("an MZ file without a PE header is hashed as a flat file even without the fallback flag");
        CHECK(!memcmp(b, badpe_sha1, 20));
    } else {
        DWORD e = GetLastError();
        t_note("strict hashing of a malformed image fails with GLE %lu", e);
        cb = 20;
        if (e == ERROR_BAD_EXE_FORMAT || e == 0x800700c1) {
            CHECK(H3(ctx, f, &cb, b, 1));   /* flag 1: fall back to the flat-file SIP */
            CHECK(!memcmp(b, badpe_sha1, 20));
        }
    }
    U(CryptCATAdminReleaseContext)(ctx, 0);
    CloseHandle(f); DeleteFileW(p);
}

/* ---------------------------------------------------------------- catalog lookups */
TEST(wtadm_enumcatalog_invalid_parameters)
{
    HCATADMIN ctx = NULL, c256 = NULL; BYTE h20[20] = { 0 }, h32[32] = { 0 };
    NO_WINE(); NEED(); REQUIRE(U(CryptCATAdminEnumCatalogFromHash)); REQUIRE(U(CryptCATAdminAcquireContext2));
    CHECK(U(CryptCATAdminAcquireContext)(&ctx, NULL, 0)); REQUIRE(ctx);
    CHECK(U(CryptCATAdminAcquireContext2)(&c256, NULL, L"SHA256", NULL, 0)); REQUIRE(c256);
#define BAD(call) do { SET_ERR(0); CHECK((call) == NULL); EXPECT_ERR(ERROR_INVALID_PARAMETER); } while (0)
    BAD(U(CryptCATAdminEnumCatalogFromHash)(NULL, h20, 20, 0, NULL));
    BAD(U(CryptCATAdminEnumCatalogFromHash)(ctx, NULL, 20, 0, NULL));
    BAD(U(CryptCATAdminEnumCatalogFromHash)(ctx, h20, 0, 0, NULL));
    BAD(U(CryptCATAdminEnumCatalogFromHash)(ctx, h20, 19, 0, NULL));
    BAD(U(CryptCATAdminEnumCatalogFromHash)(ctx, h20, 21, 0, NULL));
    BAD(U(CryptCATAdminEnumCatalogFromHash)(ctx, h32, 32, 0, NULL));   /* a SHA-1 context wants 20 bytes */
    BAD(U(CryptCATAdminEnumCatalogFromHash)(ctx, h20, 20, 1, NULL));
    BAD(U(CryptCATAdminEnumCatalogFromHash)(ctx, h20, 20, 0x80000000, NULL));
    BAD(U(CryptCATAdminEnumCatalogFromHash)(c256, h20, 20, 0, NULL));  /* and a SHA-256 context wants 32 */
    BAD(U(CryptCATAdminEnumCatalogFromHash)(c256, h32, 31, 0, NULL));
    BAD(U(CryptCATAdminEnumCatalogFromHash)(c256, h32, 33, 0, NULL));
    BAD(U(CryptCATAdminEnumCatalogFromHash)(c256, NULL, 32, 0, NULL));
#undef BAD
    U(CryptCATAdminReleaseContext)(ctx, 0); U(CryptCATAdminReleaseContext)(c256, 0);
}

TEST(wtadm_enumcatalog_hash_in_no_catalog)
{
    HCATADMIN ctx = NULL, c256 = NULL; HCATINFO ci;
    NO_WINE(); NEED(); REQUIRE(U(CryptCATAdminEnumCatalogFromHash)); REQUIRE(U(CryptCATAdminAcquireContext2));
    CHECK(U(CryptCATAdminAcquireContext)(&ctx, NULL, 0)); REQUIRE(ctx);
    CHECK(U(CryptCATAdminAcquireContext2)(&c256, NULL, L"SHA256", NULL, 0)); REQUIRE(c256);
    SET_ERR(0);
    ci = U(CryptCATAdminEnumCatalogFromHash)(ctx, (BYTE *)flat_a_sha1, 20, 0, NULL);
    CHECK(ci == NULL);
    EXPECT_ERR(ERROR_NOT_FOUND);
    if (ci) U(CryptCATAdminReleaseCatalogContext)(ctx, ci, 0);
    SET_ERR(0);
    ci = U(CryptCATAdminEnumCatalogFromHash)(c256, (BYTE *)flat_a_sha256, 32, 0, NULL);
    CHECK(ci == NULL);
    EXPECT_ERR(ERROR_NOT_FOUND);
    if (ci) U(CryptCATAdminReleaseCatalogContext)(c256, ci, 0);
    U(CryptCATAdminReleaseContext)(ctx, 0); U(CryptCATAdminReleaseContext)(c256, 0);
}

TEST(wtadm_enumcatalog_all_zero_and_all_ff_hashes)
{
    HCATADMIN ctx = NULL; BYTE z[20], f[20]; HCATINFO ci;
    NO_WINE(); NEED(); REQUIRE(U(CryptCATAdminEnumCatalogFromHash));
    memset(z, 0, sizeof z); memset(f, 0xff, sizeof f);
    CHECK(U(CryptCATAdminAcquireContext)(&ctx, NULL, 0)); REQUIRE(ctx);
    SET_ERR(0); ci = U(CryptCATAdminEnumCatalogFromHash)(ctx, z, 20, 0, NULL); CHECK(ci == NULL); EXPECT_ERR(ERROR_NOT_FOUND);
    SET_ERR(0); ci = U(CryptCATAdminEnumCatalogFromHash)(ctx, f, 20, 0, NULL); CHECK(ci == NULL); EXPECT_ERR(ERROR_NOT_FOUND);
    U(CryptCATAdminReleaseContext)(ctx, 0);
}

TEST(wtadm_enumcatalog_hash_of_temp_files_not_found)
{
    HCATADMIN ctx = NULL; int i;
    NO_WINE(); NEED(); REQUIRE(U(CryptCATAdminEnumCatalogFromHash));
    CHECK(U(CryptCATAdminAcquireContext)(&ctx, NULL, 0)); REQUIRE(ctx);
    for (i = 0; i < 5; i++) {
        WCHAR p[MAX_PATH]; HANDLE f; DWORD cb = 20; BYTE h[20], content[64]; HCATINFO ci;
        memset(content, 'a' + i, sizeof content);
        wpath(p, "lookup.dat"); put_file(p, content, sizeof content);
        f = open_read(p); REQUIRE(f != INVALID_HANDLE_VALUE);
        CHECK(H1(f, &cb, h));
        SET_ERR(0);
        ci = U(CryptCATAdminEnumCatalogFromHash)(ctx, h, cb, 0, NULL);
        CHECKF(ci == NULL, "file %d unexpectedly found in a catalog", i);
        EXPECT_ERR(ERROR_NOT_FOUND);
        CloseHandle(f); DeleteFileW(p);
    }
    U(CryptCATAdminReleaseContext)(ctx, 0);
}

TEST(wtadm_system_file_is_found_in_a_catalog)
{
    static const char *names[] = { "kernel32.dll", "ntdll.dll", "cmd.exe" };
    size_t i; int found = 0;
    NO_WINE(); NEED(); REQUIRE(U(CryptCATAdminEnumCatalogFromHash)); REQUIRE(U(CryptCATCatalogInfoFromContext)); REQUIRE(U(CryptCATAdminReleaseCatalogContext));
    for (i = 0; i < sizeof names / sizeof *names; i++) {
        char path[MAX_PATH]; HCATADMIN ctx = NULL; HANDLE f; DWORD cb = 64; BYTE h[64]; HCATINFO ci; CATALOG_INFO info; WCHAR hex[129]; HANDLE cat;
        GetSystemDirectoryA(path, sizeof path); strcat(path, "\\"); strcat(path, names[i]);
        f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
        if (f == INVALID_HANDLE_VALUE) continue;
        CHECK(U(CryptCATAdminAcquireContext)(&ctx, NULL, 0));
        if (!ctx) { CloseHandle(f); continue; }
        CHECK(H1(f, &cb, h));
        CloseHandle(f);
        SET_ERR(0);
        ci = U(CryptCATAdminEnumCatalogFromHash)(ctx, h, cb, 0, NULL);
        if (!ci) { t_note("%s: hash not found in any catalog (GLE %lu)", names[i], GetLastError()); U(CryptCATAdminReleaseContext)(ctx, 0); continue; }
        found++;
        memset(&info, 0, sizeof info); info.cbStruct = sizeof info;
        CHECK(U(CryptCATCatalogInfoFromContext)(ci, &info, 0));
        CHECK(info.wszCatalogFile[0] != 0);
        CHECK(fexists(info.wszCatalogFile));
        CHECK(wcslen(info.wszCatalogFile) > 4 && !_wcsicmp(info.wszCatalogFile + wcslen(info.wszCatalogFile) - 4, L".cat"));
        if (UN(IsCatalogFile)) CHECK(UN(IsCatalogFile)(NULL, info.wszCatalogFile));
        /* the catalog really lists the hash as a member tag */
        hex_upper(hex, h, cb);
        cat = c_open(info.wszCatalogFile, CRYPTCAT_OPEN_EXISTING, 0, 0);
        if (cat != INVH) {
            if (!U(CryptCATGetMemberInfo)(cat, hex)) t_note("%s: no member tagged %ls in %ls (catalog may use free-form tags)", names[i], hex, info.wszCatalogFile);
            c_close(cat);
        } else t_note("could not open %ls: GLE %lu", info.wszCatalogFile, GetLastError());
        CHECK(U(CryptCATAdminReleaseCatalogContext)(ctx, ci, 0));
        U(CryptCATAdminReleaseContext)(ctx, 0);
    }
    if (!found) t_note("none of the probed system files were found in the catalog database");
}

TEST(wtadm_enumcatalog_continuation_handle)
{
    char path[MAX_PATH]; HCATADMIN ctx = NULL; HANDLE f; DWORD cb = 64; BYTE h[64]; HCATINFO ci, next; int n = 0;
    NO_WINE(); NEED(); REQUIRE(U(CryptCATAdminEnumCatalogFromHash)); REQUIRE(U(CryptCATAdminReleaseCatalogContext));
    GetSystemDirectoryA(path, sizeof path); strcat(path, "\\kernel32.dll");
    f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
    REQUIRE(f != INVALID_HANDLE_VALUE);
    CHECK(U(CryptCATAdminAcquireContext)(&ctx, NULL, 0)); REQUIRE(ctx);
    CHECK(H1(f, &cb, h));
    CloseHandle(f);
    ci = U(CryptCATAdminEnumCatalogFromHash)(ctx, h, cb, 0, NULL);
    if (!ci) { t_note("kernel32.dll not in the catalog database (GLE %lu)", GetLastError()); U(CryptCATAdminReleaseContext)(ctx, 0); return; }
    n = 1;
    while (n < 64) {
        next = U(CryptCATAdminEnumCatalogFromHash)(ctx, h, cb, 0, &ci);   /* consumes the previous handle */
        if (!next) break;
        ci = next; n++;
    }
    t_note("kernel32.dll is listed by %d catalog(s)", n);
    if (n < 64) t_note("enumeration ended with GLE %lu", GetLastError());
    else U(CryptCATAdminReleaseCatalogContext)(ctx, ci, 0);
    U(CryptCATAdminReleaseContext)(ctx, 0);
}

TEST(wtadm_catalog_info_invalid_parameters)
{
    CATALOG_INFO info;
    NO_WINE(); NEED(); REQUIRE(U(CryptCATCatalogInfoFromContext));
    memset(&info, 0, sizeof info);
    SET_ERR(0); CHECK(!U(CryptCATCatalogInfoFromContext)(NULL, &info, 0)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!U(CryptCATCatalogInfoFromContext)(NULL, NULL, 0)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!U(CryptCATCatalogInfoFromContext)((HCATINFO)(ULONG_PTR)0, &info, 0)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
}

TEST(wtadm_release_catalog_context_invalid)
{
    HCATADMIN ctx = NULL;
    NO_WINE(); NEED(); REQUIRE(U(CryptCATAdminReleaseCatalogContext));
    CHECK(U(CryptCATAdminAcquireContext)(&ctx, NULL, 0)); REQUIRE(ctx);
    SET_ERR(0); CHECK(!U(CryptCATAdminReleaseCatalogContext)(NULL, NULL, 0)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    SET_ERR(0); CHECK(!U(CryptCATAdminReleaseCatalogContext)(ctx, NULL, 0)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    {   /* a valid catalog-info needs a real lookup; pair a NULL admin with a non-NULL info only when one exists */
        HCATINFO fake = (HCATINFO)(ULONG_PTR)0x10;
        SET_ERR(0); CHECK(!U(CryptCATAdminReleaseCatalogContext)(NULL, fake, 0)); EXPECT_ERR(ERROR_INVALID_PARAMETER);
    }
    U(CryptCATAdminReleaseContext)(ctx, 0);
}

TEST(wtadm_calchash_then_open_member_roundtrip)
{
    /* A catalog built by hand lists a file under the tag the admin API would derive from its hash. */
    WCHAR cat[MAX_PATH], f[MAX_PATH], hex[41]; HANDLE h, fh; DWORD cb = 20; BYTE hash[20]; CRYPTCATMEMBER *m;
    NO_WINE(); NEED(); wpath(f, "rt_file.dat"); wpath(cat, "rt_adm.cat");
    put_file(f, flat_c, sizeof flat_c);
    fh = open_read(f); REQUIRE(fh != INVALID_HANDLE_VALUE);
    CHECK(H1(fh, &cb, hash));
    CloseHandle(fh);
    hex_upper(hex, hash, cb);
    h = c_open(cat, CRYPTCAT_OPEN_CREATENEW, 0, 0); REQUIRE(h != INVH);
    m = put_member(h, f, hex, hash);
    CHECK(m != NULL);
    CHECK(U(CryptCATGetMemberInfo)(h, hex) == m);
    c_close(h); DeleteFileW(cat); DeleteFileW(f);
}
