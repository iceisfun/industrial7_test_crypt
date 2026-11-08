#include "zc.h"
typedef LONG (WINAPI *ssl_open)(ULONG_PTR *, LPCWSTR, DWORD);
typedef LONG (WINAPI *ssl_enumprov)(DWORD *, void **, DWORD);
typedef LONG (WINAPI *ssl_free)(void *);
typedef LONG (WINAPI *ssl_freeobj)(ULONG_PTR);
typedef LONG (WINAPI *ssl_enumcs)(ULONG_PTR, ULONG_PTR, void **, void **, DWORD);
typedef LONG (WINAPI *ssl_getprop)(ULONG_PTR, LPCWSTR, void **, DWORD *, DWORD);

static const WCHAR PROV[] = L"Microsoft SSL Protocol Provider";

TEST(ssl_open_provider_roundtrip) {
    if (t_is_wine()) { t_skip("ncrypt Ssl* exports are aborting stubs under the emulator"); return; }
    ssl_open op = (ssl_open)t_proc_in("ncrypt.dll", "SslOpenProvider");
    ssl_freeobj fo = (ssl_freeobj)t_proc_in("ncrypt.dll", "SslFreeObject");
    ULONG_PTR h = 0; LONG r;
    REQUIRE_NOTNULL(op); REQUIRE_NOTNULL(fo);
    r = op(&h, PROV, 0);
    EXPECT_EQ(r, 0); EXPECT_NE(h, 0);
    if (h) { r = fo(h); EXPECT_EQ(r, 0); }
}
TEST(ssl_open_provider_negative) {
    if (t_is_wine()) { t_skip("ncrypt Ssl* exports are aborting stubs under the emulator"); return; }
    ssl_open op = (ssl_open)t_proc_in("ncrypt.dll", "SslOpenProvider");
    ULONG_PTR h = 0x1234; LONG r;
    REQUIRE_NOTNULL(op);
    r = op(&h, L"No Such Provider", 0);
    EXPECT_EQ(r, 0xc0000225);                 /* STATUS_NOT_FOUND */
    EXPECT_EQ(h, 0x1234);                     /* untouched on failure */
    r = op(NULL, PROV, 0);
    EXPECT_EQ(r, 0x80090027);                 /* NTE_INVALID_PARAMETER */
}
TEST(ssl_enum_protocol_providers) {
    if (t_is_wine()) { t_skip("ncrypt Ssl* exports are aborting stubs under the emulator"); return; }
    ssl_enumprov ep = (ssl_enumprov)t_proc_in("ncrypt.dll", "SslEnumProtocolProviders");
    ssl_free fb = (ssl_free)t_proc_in("ncrypt.dll", "SslFreeBuffer");
    DWORD n = 0; void *list = NULL; LONG r;
    REQUIRE_NOTNULL(ep); REQUIRE_NOTNULL(fb);
    r = ep(&n, &list, 0);
    EXPECT_EQ(r, 0); EXPECT_EQ(n, 1); REQUIRE_NOTNULL(list);
    EXPECT_WSTR(((WCHAR **)list)[0], PROV);
    fb(list);
}
TEST(ssl_enum_cipher_suites_first) {
    if (t_is_wine()) { t_skip("ncrypt Ssl* exports are aborting stubs under the emulator"); return; }
    ssl_open op = (ssl_open)t_proc_in("ncrypt.dll", "SslOpenProvider");
    ssl_enumcs ec = (ssl_enumcs)t_proc_in("ncrypt.dll", "SslEnumCipherSuites");
    ssl_free fb = (ssl_free)t_proc_in("ncrypt.dll", "SslFreeBuffer");
    ssl_freeobj fo = (ssl_freeobj)t_proc_in("ncrypt.dll", "SslFreeObject");
    ULONG_PTR h = 0; void *cs = NULL, *st = NULL; LONG r;
    REQUIRE_NOTNULL(op); REQUIRE_NOTNULL(ec); REQUIRE_NOTNULL(fb); REQUIRE_NOTNULL(fo);
    REQUIRE_EQ(op(&h, PROV, 0), 0);
    r = ec(h, 0, &cs, &st, 0);
    EXPECT_EQ(r, 0); EXPECT_NE(cs, NULL); EXPECT_NE(st, NULL);
    if (cs) fb(cs);
    if (st) fb(st);
    fo(h);
}
