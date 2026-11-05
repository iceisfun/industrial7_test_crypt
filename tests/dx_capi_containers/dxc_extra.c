#include "dxc.h"

/* Extra provider-parameter / context tests on persisted containers. */

static void x_imptype_version(int pi) {
    DXC_NEED(pi);
    const char *c = dxc_name("xiv"); dxc_del(c, pi, 0);
    HCRYPTPROV h = 0; DWORD v = 0, n = 4;
    CHECK(dxc_acq(&h, c, pi, CRYPT_NEWKEYSET));
    CHECK(dxc_gpp(h, PP_IMPTYPE, &v, &n, 0));
    EXPECT_EQ(n, 4);
    EXPECT_EQ(v, CRYPT_IMPL_SOFTWARE);
    v = 0; n = 4;
    CHECK(dxc_gpp(h, PP_VERSION, &v, &n, 0));
    t_note("PP_VERSION for %s = 0x%lx", dxc_provs[pi].a, v);
    EXPECT_EQ(n, 4);
    n = 0; SET_ERR(0);
    CHECK(dxc_gpp(h, PP_IMPTYPE, NULL, &n, 0));   /* NULL buffer = size query */
    EXPECT_EQ(n, 4);
    dxc_rel(h);
    dxc_del(c, pi, 0);
}
DXC_PERPROV(dxc_extra_imptype_version, x_imptype_version)

static void x_provtype_name(int pi) {
    DXC_NEED(pi);
    const char *c = dxc_name("xpn"); dxc_del(c, pi, 0);
    HCRYPTPROV h = 0; DWORD v = 0, n = 4; char nm[200];
    CHECK(dxc_acq(&h, c, pi, CRYPT_NEWKEYSET));
    CHECK(dxc_gpp(h, PP_PROVTYPE, &v, &n, 0));
    if (v != dxc_provs[pi].type) t_note("PP_PROVTYPE %lu for provider type %lu", v, dxc_provs[pi].type);
    n = sizeof nm;
    CHECK(dxc_gpp(h, PP_NAME, nm, &n, 0));
    EXPECT_STR(nm, dxc_provs[pi].a);
    EXPECT_EQ(n, strlen(dxc_provs[pi].a) + 1);
    dxc_rel(h);
    dxc_del(c, pi, 0);
}
DXC_PERPROV(dxc_extra_provtype_name, x_provtype_name)

/* Container created through the A entry point is visible through W and vice versa. */
static void x_delete_via_w(int pi) {
    DXC_NEED(pi);
    const char *c = dxc_name("xdw"); dxc_del(c, pi, 0);
    HCRYPTPROV h = 0;
    CHECK(dxc_acq(&h, c, pi, CRYPT_NEWKEYSET));
    dxc_rel(h);
    WCHAR prov[100]; MultiByteToWideChar(CP_ACP, 0, dxc_provs[pi].a, -1, prov, 100);
    h = 0;
    SET_ERR(0);
    CHECK(U(CryptAcquireContextW)(&h, dxc_wname("xdw"), prov, dxc_provs[pi].type, CRYPT_DELETEKEYSET));
    CHECK(!dxc_exists(c, pi, 0));
    SET_ERR(0);
    CHECK(!U(CryptAcquireContextW)(&h, dxc_wname("xdw"), prov, dxc_provs[pi].type, CRYPT_DELETEKEYSET));
    EXPECT_ERR(X_NTE_BAD_KEYSET);
}
DXC_PERPROV(dxc_extra_delete_via_w, x_delete_via_w)

/* A context handle reused after its last release must not be usable; only check via a second live context. */
static void x_two_ctx_independent(int pi) {
    DXC_NEED(pi);
    const char *c = dxc_name("xtc"); dxc_del(c, pi, 0);
    HCRYPTPROV a = 0, b = 0; HCRYPTKEY k = 0;
    CHECK(dxc_acq(&a, c, pi, CRYPT_NEWKEYSET));
    CHECK(dxc_acq(&b, c, pi, 0));
    CHECK(a != b);
    dxc_rel(a);
    /* b stays usable after a is released */
    CHECK(U(CryptGenKey)(b, dxc_provs[pi].dss ? AT_SIGNATURE : AT_KEYEXCHANGE, CRYPT_EXPORTABLE, &k));
    if (k) U(CryptDestroyKey)(k);
    dxc_rel(b);
    dxc_del(c, pi, 0);
}
DXC_PERPROV(dxc_extra_two_ctx_independent, x_two_ctx_independent)
