/* Tbsi_ShaHash (pure hashing, no TPM needed), device-ID helpers, owner auth, physical presence,
 * Windows key and attestation entry points (argument validation only; no state is ever changed). */
#include "tbsx.h"

static int emu_skip(void) { if (tbsx_emulated()) { t_skip("emulator stub"); return 1; } return 0; }

static void hex(const BYTE *p, size_t n, char *o) { for (size_t i = 0; i < n; i++) sprintf(o + 2 * i, "%02x", p[i]); o[2 * n] = 0; }

/* ---------- Tbsi_ShaHash ---------- */
static const BYTE *U8(const char *s) { return (const BYTE *)s; }

struct kat { const WCHAR *alg; UINT32 dl; const char *msg; const char *hex; };
static const struct kat k_plain[] = {
    { L"SHA1",   20, "abc", "a9993e364706816aba3e25717850c26c9cd0d89d" },
    { L"SHA256", 32, "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
    { L"SHA384", 48, "abc", "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7" },
    { L"SHA1",   20, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "84983e441c3bd26ebaae4aa1f95129e5e54670f1" },
    { L"SHA256", 32, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" },
};
struct mac { const WCHAR *alg; UINT32 dl; const BYTE *key; UINT32 kl; const char *msg; const char *hex; };
static const BYTE k_0b20[20] = { 11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11 };
static const struct mac k_hmac[] = {
    { L"SHA1",   20, k_0b20, 20, "Hi There", "b617318655057264e28bc0b6fb378c8ef146be00" },
    { L"SHA256", 32, k_0b20, 20, "Hi There", "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7" },
    { L"SHA384", 48, k_0b20, 20, "Hi There", "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6" },
    { L"SHA1",   20, (const BYTE *)"Jefe", 4, "what do ya want for nothing?", "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79" },
    { L"SHA256", 32, (const BYTE *)"Jefe", 4, "what do ya want for nothing?", "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843" },
    { L"SHA384", 48, (const BYTE *)"Jefe", 4, "what do ya want for nothing?", "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649" },
};

TEST(tbs_sha_known_answers) {
    NEED(Tbsi_ShaHash); if (emu_skip()) return;
    for (size_t i = 0; i < sizeof k_plain / sizeof *k_plain; i++) {
        BYTE out[64]; UINT32 n = 0; char h[200];
        memset(out, 0, sizeof out);
        LONG r = P(Tbsi_ShaHash)(k_plain[i].alg, NULL, 0, U8(k_plain[i].msg), (ULONG)strlen(k_plain[i].msg), out, sizeof out >= k_plain[i].dl ? k_plain[i].dl : 0, &n);
        CHECKF(r == 0, "case %zu status 0x%08lx", i, (unsigned long)r);
        EXPECT_EQ(n, k_plain[i].dl);
        hex(out, k_plain[i].dl, h);
        CHECKF(!strcmp(h, k_plain[i].hex), "case %zu digest %s", i, h);
    }
}
TEST(tbs_sha_hmac_known_answers) {
    NEED(Tbsi_ShaHash); if (emu_skip()) return;
    for (size_t i = 0; i < sizeof k_hmac / sizeof *k_hmac; i++) {
        BYTE out[64]; UINT32 n = 0; char h[200];
        memset(out, 0, sizeof out);
        LONG r = P(Tbsi_ShaHash)(k_hmac[i].alg, k_hmac[i].key, k_hmac[i].kl, U8(k_hmac[i].msg), (ULONG)strlen(k_hmac[i].msg), out, k_hmac[i].dl, &n);
        CHECKF(r == 0, "case %zu status 0x%08lx", i, (unsigned long)r);
        EXPECT_EQ(n, k_hmac[i].dl);
        hex(out, k_hmac[i].dl, h);
        CHECKF(!strcmp(h, k_hmac[i].hex), "case %zu mac %s", i, h);
    }
}
TEST(tbs_sha_empty_message) {
    NEED(Tbsi_ShaHash); if (emu_skip()) return;
    BYTE out[20]; UINT32 n = 0; char h[64];
    LONG r = P(Tbsi_ShaHash)(L"SHA1", NULL, 0, U8(""), 0, out, 20, &n);
    t_note("SHA1 of empty message: 0x%08lx", (unsigned long)r);
    if (r == 0) { hex(out, 20, h); EXPECT_STR(h, "da39a3ee5e6b4b0d3255bfef95601890afd80709"); }
    BYTE o2[32];
    r = P(Tbsi_ShaHash)(L"SHA256", NULL, 0, U8(""), 0, o2, 32, &n);
    if (r == 0) { char h2[80]; hex(o2, 32, h2); EXPECT_STR(h2, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"); }
}
TEST(tbs_sha_size_query_null_output) {
    NEED(Tbsi_ShaHash); if (emu_skip()) return;
    static const struct { const WCHAR *a; UINT32 dl; } t[] = { {L"SHA1",20}, {L"SHA256",32}, {L"SHA384",48} };
    for (size_t i = 0; i < 3; i++) {
        UINT32 n = 0xffff;
        LONG r = P(Tbsi_ShaHash)(t[i].a, NULL, 0, U8("abc"), 3, NULL, 0, &n);
        CHECKF(r == 0, "status 0x%08lx", (unsigned long)r);
        CHECKF(n == t[i].dl, "len %u", n);
    }
}
TEST(tbs_sha_size_query_zero_length_buffer) {
    NEED(Tbsi_ShaHash); if (emu_skip()) return;
    BYTE out[64]; memset(out, 0x3c, sizeof out);
    UINT32 n = 0;
    EXPECT_EQ(P(Tbsi_ShaHash)(L"SHA256", NULL, 0, U8("abc"), 3, out, 0, &n), 0);
    EXPECT_EQ(n, 32);
    for (int i = 0; i < 64; i++) CHECK(out[i] == 0x3c);
}
TEST(tbs_sha_buffer_too_small) {
    NEED(Tbsi_ShaHash); if (emu_skip()) return;
    static const struct { const WCHAR *a; UINT32 dl; } t[] = { {L"SHA1",20}, {L"SHA256",32}, {L"SHA384",48} };
    for (size_t i = 0; i < 3; i++) {
        BYTE out[64]; memset(out, 0x3c, sizeof out);
        UINT32 n = 0;
        LONG r = P(Tbsi_ShaHash)(t[i].a, NULL, 0, U8("abc"), 3, out, t[i].dl - 1, &n);
        CHECKF((ULONG)r == NT_BUFFER_TOO_SMALL, "status 0x%08lx", (unsigned long)r);
        CHECKF(n == t[i].dl, "required %u", n);
        for (int k = 0; k < 64; k++) if (out[k] != 0x3c) { CHECK(0 && "output touched"); break; }
        n = 0;
        r = P(Tbsi_ShaHash)(t[i].a, NULL, 0, U8("abc"), 3, out, 1, &n);
        CHECK((ULONG)r == NT_BUFFER_TOO_SMALL); EXPECT_EQ(n, t[i].dl);
    }
}
TEST(tbs_sha_unsupported_algorithms) {
    NEED(Tbsi_ShaHash); if (emu_skip()) return;
    static const WCHAR *const bad[] = { L"", L"MD5", L"MD2", L"MD4", L"SHA512", L"SHA-1", L"SHA", L"sha1", L"Sha256", L"SHA256 ", L" SHA256", L"SHA3_256", L"AES", L"HMAC" };
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        BYTE out[64]; UINT32 n = 0x99;
        LONG r = P(Tbsi_ShaHash)(bad[i], NULL, 0, U8("abc"), 3, out, sizeof out, &n);
        CHECKF((ULONG)r == NT_INVALID_PARAMETER, "alg #%zu -> 0x%08lx", i, (unsigned long)r);
        CHECKF(n == 0x99, "length written for rejected algorithm");
    }
}
TEST(tbs_sha_key_requires_both_key_and_length) {
    NEED(Tbsi_ShaHash); if (emu_skip()) return;
    BYTE a[20], d[20]; UINT32 n = 0;
    EXPECT_EQ(P(Tbsi_ShaHash)(L"SHA1", NULL, 0, U8("abc"), 3, a, 20, &n), 0);
    /* a key length without a key, or a key without a length, is rejected */
    n = 0x99;
    EXPECT_EQ(P(Tbsi_ShaHash)(L"SHA1", NULL, 7, U8("abc"), 3, a, 20, &n), NT_INVALID_PARAMETER);
    EXPECT_EQ(n, 0x99);
    EXPECT_EQ(P(Tbsi_ShaHash)(L"SHA1", U8("key"), 0, U8("abc"), 3, a, 20, &n), NT_INVALID_PARAMETER);
    EXPECT_EQ(n, 0x99);
    EXPECT_EQ(P(Tbsi_ShaHash)(L"SHA1", U8("key"), 3, U8("abc"), 3, d, 20, &n), 0);
    BYTE e[20];
    EXPECT_EQ(P(Tbsi_ShaHash)(L"SHA1", NULL, 0, U8("abc"), 3, e, 20, &n), 0);
    CHECK(memcmp(e, d, 20) != 0);
}
TEST(tbs_sha_hmac_key_changes_mac) {
    NEED(Tbsi_ShaHash); if (emu_skip()) return;
    BYTE a[32], b[32]; UINT32 n;
    EXPECT_EQ(P(Tbsi_ShaHash)(L"SHA256", U8("k1"), 2, U8("msg"), 3, a, 32, &n), 0);
    EXPECT_EQ(P(Tbsi_ShaHash)(L"SHA256", U8("k2"), 2, U8("msg"), 3, b, 32, &n), 0);
    CHECK(memcmp(a, b, 32) != 0);
}
TEST(tbs_sha_hmac_long_key_hashed) {
    NEED(Tbsi_ShaHash); if (emu_skip()) return;
    /* RFC 4231 test case 6: key of 131 bytes of 0xaa */
    BYTE key[131]; memset(key, 0xaa, sizeof key);
    BYTE out[32]; UINT32 n = 0; char h[80];
    EXPECT_EQ(P(Tbsi_ShaHash)(L"SHA256", key, sizeof key, U8("Test Using Larger Than Block-Size Key - Hash Key First"), 54, out, 32, &n), 0);
    hex(out, 32, h);
    EXPECT_STR(h, "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
}
TEST(tbs_sha_deterministic_repeat) {
    NEED(Tbsi_ShaHash); if (emu_skip()) return;
    BYTE a[48], b[48]; UINT32 n;
    for (int i = 0; i < 20; i++) {
        EXPECT_EQ(P(Tbsi_ShaHash)(L"SHA384", NULL, 0, U8("repeat"), 6, i ? b : a, 48, &n), 0);
        if (i) CHECK(!memcmp(a, b, 48));
    }
}
TEST(tbs_sha_large_message) {
    NEED(Tbsi_ShaHash); if (emu_skip()) return;
    /* one million 'a' (FIPS 180 long message): SHA-1 34aa973c d4c4daa4 f61eeb2b dbad2731 6534016f */
    BYTE *m = malloc(1000000);
    if (!m) { t_skip("alloc"); return; }
    memset(m, 'a', 1000000);
    BYTE out[32]; UINT32 n = 0; char h[80];
    EXPECT_EQ(P(Tbsi_ShaHash)(L"SHA1", NULL, 0, m, 1000000, out, 20, &n), 0);
    hex(out, 20, h);
    EXPECT_STR(h, "34aa973cd4c4daa4f61eeb2bdbad27316534016f");
    EXPECT_EQ(P(Tbsi_ShaHash)(L"SHA256", NULL, 0, m, 1000000, out, 32, &n), 0);
    hex(out, 32, h);
    EXPECT_STR(h, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    free(m);
}
TEST(tbs_sha_incremental_boundaries) {
    NEED(Tbsi_ShaHash); if (emu_skip()) return;
    /* messages straddling the 55/56/63/64-byte padding boundaries must not corrupt the result:
       compare against the digest for the same bytes obtained with the key-less path twice */
    static const int lens[] = { 0, 1, 54, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128, 129 };
    BYTE msg[130]; for (int i = 0; i < 130; i++) msg[i] = (BYTE)i;
    for (size_t i = 0; i < sizeof lens / sizeof *lens; i++) {
        BYTE a[32], b[32]; UINT32 n;
        if (!lens[i]) continue;
        LONG r1 = P(Tbsi_ShaHash)(L"SHA256", NULL, 0, msg, lens[i], a, 32, &n);
        LONG r2 = P(Tbsi_ShaHash)(L"SHA256", NULL, 0, msg, lens[i], b, 32, &n);
        CHECKF(r1 == 0 && r2 == 0 && !memcmp(a, b, 32), "len %d", lens[i]);
    }
}

/* ---------- Device ID helpers ---------- */
static const char b64tab[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

TEST(tbs_deviceid_string_initial_outputs_cleared) {
    NEED(GetDeviceIDString); NOEMU();
    WCHAR buf[4] = { L'X', L'X', L'X', L'X' };
    UINT32 n = 0x1234; BOOL prot = 0x5555;
    /* with a zero-length buffer the function still writes the first character and both outputs */
    LONG hr = P(GetDeviceIDString)(buf, 0, &n, &prot);
    t_note("GetDeviceIDString(cch=0): 0x%08lx n=%u prot=%d", (unsigned long)hr, n, prot);
    CHECK(buf[0] == 0);
    if (hr < 0 && (ULONG)hr != HR_INSUFFICIENT_BUFFER) CHECK(n == 0);
    if (hr == (LONG)HR_INSUFFICIENT_BUFFER) CHECK(n >= 1);
}
TEST(tbs_deviceid_string_size_protocol) {
    NEED(GetDeviceIDString); if (emu_skip()) return;
    UINT32 n = 0; BOOL prot = 0;
    LONG hr = P(GetDeviceIDString)(NULL, 0, &n, &prot);
    t_note("GetDeviceIDString(NULL): 0x%08lx n=%u", (unsigned long)hr, n);
    if (hr < 0 && (ULONG)hr != HR_INSUFFICIENT_BUFFER) { t_skip("no device ID available (0x%08lx)", (unsigned long)hr); return; }
    if (hr == 0) { CHECK(n > 1); }   /* NULL buffer: success plus required length */
    if ((ULONG)hr == HR_INSUFFICIENT_BUFFER || hr == 0) {
        /* a base64 rendering of an N-byte id needs ((N+2)/3)*4 + 1 characters */
        CHECK(n == 0 || (n - 1) % 4 == 0);
        if (n > 1) {
            WCHAR *s = calloc(n + 1, sizeof(WCHAR));
            UINT32 m = 0; BOOL p2 = 0;
            if (!s) return;
            LONG h2 = P(GetDeviceIDString)(s, n, &m, &p2);
            CHECKF(h2 == 0, "full buffer: 0x%08lx", (unsigned long)h2);
            if (h2 == 0) {
                CHECK(m == n);
                size_t len = wcslen(s);
                CHECKF(len == n - 1, "string length %zu want %u", len, n - 1);
                for (size_t i = 0; i < len; i++) {
                    WCHAR c = s[i];
                    int ok = (c < 128 && c && (strchr(b64tab, (int)c) != NULL)) || c == L'=';
                    if (!ok) { CHECKF(0, "non-base64 character 0x%x at %zu", c, i); break; }
                }
                WCHAR *t = calloc(n + 1, sizeof(WCHAR));
                if (t) {
                    UINT32 k = 0;
                    LONG h3 = P(GetDeviceIDString)(t, n - 1, &k, &p2);
                    CHECK((ULONG)h3 == HR_INSUFFICIENT_BUFFER);
                    CHECK(k == n);
                    CHECK(t[0] == 0);
                    free(t);
                }
            }
            free(s);
        }
    }
}
TEST(tbs_deviceid_raw_size_protocol) {
    NEED(GetDeviceID); if (emu_skip()) return;
    UINT32 n = 0xabcd; BOOL prot = 0;
    LONG hr = P(GetDeviceID)(NULL, 0, &n, &prot);
    t_note("GetDeviceID(NULL,0): 0x%08lx n=%u prot=%d", (unsigned long)hr, n, prot);
    if (hr < 0 && (ULONG)hr != HR_INSUFFICIENT_BUFFER) { t_skip("no device ID (0x%08lx)", (unsigned long)hr); return; }
    CHECK(n != 0xabcd);
    if (n > 0 && n <= 1024) {
        BYTE *b = calloc(1, n + 8); UINT32 m = n;
        if (!b) return;
        memset(b + n, 0xee, 8);
        hr = P(GetDeviceID)(b, n, &m, &prot);
        CHECKF(hr == 0, "0x%08lx", (unsigned long)hr);
        EXPECT_EQ(m, n);
        for (int i = 0; i < 8; i++) CHECK(b[n + i] == 0xee);
        if (n > 1) {
            UINT32 k = 0; BYTE *c = calloc(1, n);
            hr = P(GetDeviceID)(c, n - 1, &k, &prot);
            CHECK((ULONG)hr == HR_INSUFFICIENT_BUFFER);
            EXPECT_EQ(k, n);
            free(c);
        }
        free(b);
    }
}
TEST(tbs_deviceid_string_matches_raw) {
    NEED(GetDeviceID); NEED(GetDeviceIDString); if (emu_skip()) return;
    UINT32 n = 0; BOOL prot = 0;
    LONG hr = P(GetDeviceID)(NULL, 0, &n, &prot);
    if ((hr < 0 && (ULONG)hr != HR_INSUFFICIENT_BUFFER) || n == 0 || n > 1024) { t_skip("no device ID"); return; }
    BYTE *raw = calloc(1, n); UINT32 m = n;
    UINT32 cch = ((n + 2) / 3) * 4 + 1;
    WCHAR *s = calloc(cch + 1, sizeof(WCHAR)); UINT32 k = 0;
    if (!raw || !s) return;
    if (P(GetDeviceID)(raw, n, &m, &prot) != 0) { t_skip("raw fetch"); return; }
    LONG h2 = P(GetDeviceIDString)(s, cch, &k, &prot);
    CHECKF(h2 == 0, "0x%08lx", (unsigned long)h2);
    if (h2 == 0) {
        EXPECT_EQ(k, cch);
        char want[2048]; size_t o = 0;
        for (UINT32 i = 0; i < n; i += 3) {
            UINT32 v = raw[i] << 16 | (i + 1 < n ? raw[i + 1] << 8 : 0) | (i + 2 < n ? raw[i + 2] : 0);
            want[o++] = b64tab[v >> 18 & 63]; want[o++] = b64tab[v >> 12 & 63];
            want[o++] = i + 1 < n ? b64tab[v >> 6 & 63] : '=';
            want[o++] = i + 2 < n ? b64tab[v & 63] : '=';
        }
        want[o] = 0;
        char got[2048]; size_t i = 0;
        for (; s[i] && i < sizeof got - 1; i++) got[i] = (char)s[i];
        got[i] = 0;
        EXPECT_STR(got, want);
    }
    free(raw); free(s);
}
TEST(tbs_deviceid_with_timeout_zero) {
    NEED(GetDeviceIDWithTimeout); if (emu_skip()) return;
    UINT32 n = 0xabcd; BOOL prot = 0;
    DWORD t0 = GetTickCount();
    LONG hr = P(GetDeviceIDWithTimeout)(NULL, 0, &n, 0, &prot);
    DWORD dt = GetTickCount() - t0;
    t_note("GetDeviceIDWithTimeout(0): 0x%08lx n=%u prot=%d (%lu ms)", (unsigned long)hr, n, prot, dt);
    CHECK(dt < 5000);
    CHECK(n != 0xabcd);              /* the size output is always initialised to 0 first */
}
TEST(tbs_deviceid_with_timeout_matches_plain) {
    NEED(GetDeviceIDWithTimeout); NEED(GetDeviceID); if (emu_skip()) return;
    UINT32 a = 0, b = 0; BOOL p = 0;
    LONG h1 = P(GetDeviceID)(NULL, 0, &a, &p);
    LONG h2 = P(GetDeviceIDWithTimeout)(NULL, 0, &b, 0, &p);
    CHECK(h1 == h2);
    CHECK(a == b);
}

/* ---------- Tbsi_Get_OwnerAuth ---------- */
TEST(tbs_ownerauth_null_length_pointer) {
    NEED(Tbsi_Get_OwnerAuth); if (emu_skip()) return;
    BYTE b[32];
    EXPECT_EQ(P(Tbsi_Get_OwnerAuth)(NULL, 1, b, NULL), TE_INVALID_OUTPUT_POINTER);
    EXPECT_EQ(P(Tbsi_Get_OwnerAuth)(NULL, 1, NULL, NULL), TE_INVALID_OUTPUT_POINTER);
}
TEST(tbs_ownerauth_null_buffer_nonzero_length) {
    NEED(Tbsi_Get_OwnerAuth); if (emu_skip()) return;
    UINT32 n = 20;
    EXPECT_EQ(P(Tbsi_Get_OwnerAuth)(NULL, 1, NULL, &n), TE_INVALID_OUTPUT_POINTER);
    EXPECT_EQ(n, 20);
}
TEST(tbs_ownerauth_null_context) {
    NEED(Tbsi_Get_OwnerAuth); if (emu_skip()) return;
    BYTE b[32]; UINT32 n = sizeof b;
    static const UINT32 types[] = { 0, 1, 2, 3, 4, 5, 12, 13, 14, 0xffffffffu };
    for (size_t i = 0; i < sizeof types / sizeof *types; i++) {
        n = sizeof b;
        UINT32 r = P(Tbsi_Get_OwnerAuth)(NULL, types[i], b, &n);
        CHECKF(r == TE_INVALID_CONTEXT_PARAM, "type %u -> 0x%08x", types[i], r);
    }
}
TEST(tbs_ownerauth_size_query_null_context) {
    NEED(Tbsi_Get_OwnerAuth); if (emu_skip()) return;
    UINT32 n = 0;
    EXPECT_EQ(P(Tbsi_Get_OwnerAuth)(NULL, 1, NULL, &n), TE_INVALID_CONTEXT_PARAM);
}
TEST(tbs_ownerauth_closed_handle) {
    NEED(Tbsi_Get_OwnerAuth); if (emu_skip()) return;
    HANDLE e = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!e) return;
    CloseHandle(e);
    BYTE b[32]; UINT32 n = sizeof b;
    EXPECT_EQ(P(Tbsi_Get_OwnerAuth)((void *)e, 1, b, &n), TE_INVALID_CONTEXT_PARAM);
}
TEST(tbs_ownerauth_bad_type_with_context) {
    NEED(Tbsi_Get_OwnerAuth); NEED(Tbsi_Context_Create); NEED(Tbsip_Context_Close); if (emu_skip()) return;
    tbsx_devinfo di;
    if (!tbsx_tpm_present(&di)) { t_skip("no TPM"); return; }
    tbsx_params2 p = { 2, TBSX_TPM12 | TBSX_TPM20 };
    void *h = NULL;
    if (P(Tbsi_Context_Create)(&p, &h) != 0) { t_skip("context"); return; }
    static const UINT32 types[] = { 0, 5, 6, 11, 14, 100, 0xffffffffu };
    for (size_t i = 0; i < sizeof types / sizeof *types; i++) {
        UINT32 n = 0;
        UINT32 r = P(Tbsi_Get_OwnerAuth)(h, types[i], NULL, &n);
        CHECKF(r == TE_BAD_PARAMETER, "type %u -> 0x%08x", types[i], r);
    }
    P(Tbsip_Context_Close)(h);
}

/* ---------- Tbsi_Physical_Presence_Command : validation only ---------- */
TEST(tbs_pp_null_input) {
    NEED(Tbsi_Physical_Presence_Command); if (emu_skip()) return;
    BYTE out[16]; UINT32 n = sizeof out;
    EXPECT_EQ(P(Tbsi_Physical_Presence_Command)(NULL, NULL, 4, out, &n), TE_BAD_PARAMETER);
    EXPECT_EQ(P(Tbsi_Physical_Presence_Command)(NULL, NULL, 0, NULL, NULL), TE_BAD_PARAMETER);
    EXPECT_EQ(n, sizeof out);
}
TEST(tbs_pp_null_output) {
    NEED(Tbsi_Physical_Presence_Command); if (emu_skip()) return;
    BYTE in[4] = {0}; BYTE out[16]; UINT32 n = sizeof out;
    EXPECT_EQ(P(Tbsi_Physical_Presence_Command)(NULL, in, 4, NULL, &n), TE_INVALID_OUTPUT_POINTER);
    EXPECT_EQ(P(Tbsi_Physical_Presence_Command)(NULL, in, 4, out, NULL), TE_INVALID_OUTPUT_POINTER);
    EXPECT_EQ(P(Tbsi_Physical_Presence_Command)(NULL, in, 4, NULL, NULL), TE_INVALID_OUTPUT_POINTER);
}
TEST(tbs_pp_size_limits) {
    NEED(Tbsi_Physical_Presence_Command); if (emu_skip()) return;
    BYTE in[4] = {0}; BYTE out[16];
    UINT32 n = sizeof out;
    /* limit is 0x40000 for both the input and the output length; checked before any device access */
    EXPECT_EQ(P(Tbsi_Physical_Presence_Command)(NULL, in, 0x40001, out, &n), TE_BUFFER_TOO_LARGE);
    n = 0x40001;
    EXPECT_EQ(P(Tbsi_Physical_Presence_Command)(NULL, in, 4, out, &n), TE_BUFFER_TOO_LARGE);
    EXPECT_EQ(n, 0x40001);
    n = 16;
    EXPECT_EQ(P(Tbsi_Physical_Presence_Command)(NULL, in, 0xffffffffu, out, &n), TE_BUFFER_TOO_LARGE);
    n = 0xffffffffu;
    EXPECT_EQ(P(Tbsi_Physical_Presence_Command)(NULL, in, 4, out, &n), TE_BUFFER_TOO_LARGE);
}
TEST(tbs_pp_null_context_within_limits) {
    NEED(Tbsi_Physical_Presence_Command); if (emu_skip()) return;
    /* an all-zero input is not a valid PPI request; with a NULL context the device layer refuses it before the TPM sees it */
    BYTE in[4] = {0}; BYTE out[16]; UINT32 n = sizeof out;
    EXPECT_EQ(P(Tbsi_Physical_Presence_Command)(NULL, in, 4, out, &n), TE_INVALID_CONTEXT);
    n = sizeof out;
    EXPECT_EQ(P(Tbsi_Physical_Presence_Command)(NULL, in, 0, out, &n), TE_INVALID_CONTEXT);
}
TEST(tbs_pp_order_of_checks) {
    NEED(Tbsi_Physical_Presence_Command); if (emu_skip()) return;
    BYTE out[8]; UINT32 n = 8;
    /* input pointer is validated before the output pointers, which precede the size limits */
    EXPECT_EQ(P(Tbsi_Physical_Presence_Command)(NULL, NULL, 0x40001, NULL, NULL), TE_BAD_PARAMETER);
    EXPECT_EQ(P(Tbsi_Physical_Presence_Command)(NULL, out, 0x40001, NULL, &n), TE_INVALID_OUTPUT_POINTER);
}

/* ---------- Tbsi_Create_Windows_Key / Tbsi_Revoke_Attestation ---------- */
TEST(tbs_winkey_invalid_handles) {
    NEED(Tbsi_Create_Windows_Key); if (emu_skip()) return;
    /* only two handle values are accepted (0x81000001 and 0x81010001); everything else is a parameter error
       before any context is created, so nothing is ever created here */
    static const UINT32 bad[] = { 0, 1, 0x80000000u, 0x81000000u, 0x81000002u, 0x81010000u, 0x81010002u,
                                  0x81020001u, 0x01000001u, 0xffffffffu, 0x81800001u, 0x80ff0001u };
    for (size_t i = 0; i < sizeof bad / sizeof *bad; i++) {
        UINT32 r = P(Tbsi_Create_Windows_Key)(bad[i]);
        CHECKF(r == TE_BAD_PARAMETER, "handle 0x%08x -> 0x%08x", bad[i], r);
    }
}
TEST(tbs_winkey_valid_handle_values_not_called) {
    NEED(Tbsi_Create_Windows_Key);
    /* calling with 0x81000001 or 0x81010001 would create TPM keys: resolution only */
    CHECK(P(Tbsi_Create_Windows_Key) != NULL);
}
TEST(tbs_revoke_attestation_resolve_only) {
    NEED(Tbsi_Revoke_Attestation);
    CHECK(P(Tbsi_Revoke_Attestation) != NULL);   /* revokes the machine attestation identity: never invoked */
}
TEST(tbs_state_changing_exports_resolve_distinct) {
    NEED(Tbsi_Revoke_Attestation); NEED(Tbsi_Create_Windows_Key); NEED(Tbsi_Create_Attestation_From_Log); NEED(Tbsi_Physical_Presence_Command);
    CHECK((void *)P(Tbsi_Revoke_Attestation) != (void *)P(Tbsi_Create_Windows_Key));
    CHECK((void *)P(Tbsi_Create_Attestation_From_Log) != (void *)P(Tbsi_Physical_Presence_Command));
}

/* ---------- error-code table ---------- */
TEST(tbs_error_table_values) {
    static const struct { const char *n; UINT32 v; } t[] = {
        {"TBS_E_INTERNAL_ERROR",0x80284001},{"TBS_E_BAD_PARAMETER",0x80284002},{"TBS_E_INVALID_OUTPUT_POINTER",0x80284003},
        {"TBS_E_INVALID_CONTEXT",0x80284004},{"TBS_E_INSUFFICIENT_BUFFER",0x80284005},{"TBS_E_IOERROR",0x80284006},
        {"TBS_E_INVALID_CONTEXT_PARAM",0x80284007},{"TBS_E_SERVICE_NOT_RUNNING",0x80284008},
        {"TBS_E_TOO_MANY_TBS_CONTEXTS",0x80284009},{"TBS_E_TOO_MANY_RESOURCES",0x8028400A},
        {"TBS_E_SERVICE_START_PENDING",0x8028400B},{"TBS_E_PPI_NOT_SUPPORTED",0x8028400C},{"TBS_E_COMMAND_CANCELED",0x8028400D},
        {"TBS_E_BUFFER_TOO_LARGE",0x8028400E},{"TBS_E_TPM_NOT_FOUND",0x8028400F},{"TBS_E_SERVICE_DISABLED",0x80284010},
        {"TBS_E_NO_EVENT_LOG",0x80284011},{"TBS_E_ACCESS_DENIED",0x80284012},{"TBS_E_PROVISIONING_NOT_ALLOWED",0x80284013},
        {"TBS_E_PPI_FUNCTION_UNSUPPORTED",0x80284014},{"TBS_E_OWNERAUTH_NOT_FOUND",0x80284015},
        {"TBS_E_DEACTIVATED",0x80284016},
    };
    /* every code lies in the TBS facility range 0x80284001..0x80284FFF and is consecutive */
    for (size_t i = 0; i < sizeof t / sizeof *t; i++) {
        CHECKF((t[i].v & 0xffff0000u) == 0x80280000u, "%s facility", t[i].n);
        CHECKF((t[i].v & 0xffff) == 0x4001 + i, "%s consecutive", t[i].n);
        CHECKF((int)t[i].v < 0, "%s severity", t[i].n);
    }
    /* the codes documented in the Windows SDK winerror.h are those the implementation returns */
    /* cross-check against the SDK header for the codes it defines */
    CHECK((UINT32)TBS_E_INTERNAL_ERROR == TE_INTERNAL_ERROR && (UINT32)TBS_E_BAD_PARAMETER == TE_BAD_PARAMETER);
    CHECK((UINT32)TBS_E_INVALID_OUTPUT_POINTER == TE_INVALID_OUTPUT_POINTER && (UINT32)TBS_E_INSUFFICIENT_BUFFER == TE_INSUFFICIENT_BUFFER);
    CHECK((UINT32)TBS_E_INVALID_CONTEXT_PARAM == TE_INVALID_CONTEXT_PARAM && (UINT32)TBS_E_BUFFER_TOO_LARGE == TE_BUFFER_TOO_LARGE);
    CHECK((UINT32)TBS_E_TPM_NOT_FOUND == TE_TPM_NOT_FOUND);
    CHECK(TE_BAD_PARAMETER == 0x80284002 && TE_TPM_NOT_FOUND == 0x8028400F && TE_INSUFFICIENT_BUFFER == 0x80284005);
}
