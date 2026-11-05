#include "oidreg.h"
/* CryptSetKeyIdentifierProperty / CryptGetKeyIdentifierProperty / CryptEnumKeyIdentifierProperties.
 * Key identifiers are 1..20 byte blobs.  User scope stores the element as a file under the roaming profile
 * (Microsoft\SystemCertificates\My\Keys\<HEX>), machine scope (CRYPT_KEYID_MACHINE_FLAG, needs admin) in HKLM.
 * All identifiers used here start with the bytes "cryptt" and are removed at the end of every test. */

#define E_INVALIDARG_ ((DWORD)0x80070057)
#define CRYPT_E_NOT_FOUND_ ((DWORD)0x80092004)
#define CRYPT_E_EXISTS_ ((DWORD)0x80092005)
#define EXPECT_HRINVAL() do { DWORD e_ = GetLastError(); t_check(e_ == E_INVALIDARG_ || (t_is_wine() && e_ == 87), __FILE__, __LINE__, "last error E_INVALIDARG", "got 0x%lx", e_); } while (0)
#define WINE_DIFF if (!t_is_wine())

static BOOL kset(const CRYPT_HASH_BLOB *id, DWORD prop, DWORD fl, const void *data) {
    return U(CryptSetKeyIdentifierProperty)(id, prop, fl, NULL, NULL, (void *)data);
}
static BOOL kget(const CRYPT_HASH_BLOB *id, DWORD prop, DWORD fl, void *buf, DWORD *cb) {
    return U(CryptGetKeyIdentifierProperty)(id, prop, fl, NULL, NULL, buf, cb);
}
static BOOL kdel(const CRYPT_HASH_BLOB *id, DWORD fl) {
    return U(CryptSetKeyIdentifierProperty)(id, 0, fl | CRYPT_KEYID_DELETE_FLAG, NULL, NULL, NULL);
}

#define KIDGATE() do { if (t_is_wine()) { t_skip("emulator has no key identifier property store"); return; } } while (0)
#define SCOPE_TEST(name, fn) \
    TEST(oidreg_kid_user_##name) { KIDGATE(); REQUIRE(U(CryptSetKeyIdentifierProperty)); REQUIRE(U(CryptGetKeyIdentifierProperty)); if (!oidr_kid_begin(0)) return; fn(0); oidr_kid_cleanup(); } \
    TEST(oidreg_kid_machine_##name) { KIDGATE(); REQUIRE(U(CryptSetKeyIdentifierProperty)); REQUIRE(U(CryptGetKeyIdentifierProperty)); if (!oidr_kid_begin(1)) return; fn(CRYPT_KEYID_MACHINE_FLAG); oidr_kid_cleanup(); }

#define NEWKID(var, tag) CRYPT_HASH_BLOB var; BYTE var##_b[20]; oidr_kid(&var, var##_b, tag, 20)

/* ---- round trip ------------------------------------------------------------------------------------ */
static void s_roundtrip(DWORD sc) {
    NEWKID(id, "rt");
    BYTE payload[37]; for (int i = 0; i < 37; i++) payload[i] = (BYTE)(i * 5 + 1);
    CRYPT_DATA_BLOB blob = { sizeof payload, payload };
    SET_ERR(0xdead);
    CHECKF(kset(&id, CERT_FRIENDLY_NAME_PROP_ID, sc, &blob), "err %lu", GetLastError());
    BYTE out[64]; DWORD cb = sizeof out; memset(out, 0xcc, sizeof out);
    CHECKF(kget(&id, CERT_FRIENDLY_NAME_PROP_ID, sc, out, &cb), "err %lx", GetLastError());
    EXPECT_EQ(cb, sizeof payload);
    CHECK(!memcmp(out, payload, sizeof payload));
    CHECK(out[sizeof payload] == 0xcc);                 /* nothing written past the property */
}
SCOPE_TEST(roundtrip, s_roundtrip)

static void s_size_protocol(DWORD sc) {
    NEWKID(id, "sz");
    BYTE payload[20]; for (int i = 0; i < 20; i++) payload[i] = (BYTE)(0xA0 + i);
    CRYPT_DATA_BLOB blob = { 20, payload };
    CHECK(kset(&id, CERT_DESCRIPTION_PROP_ID, sc, &blob));
    DWORD cb = 0;
    SET_ERR(0);
    CHECK(kget(&id, CERT_DESCRIPTION_PROP_ID, sc, NULL, &cb)); EXPECT_EQ(cb, 20);
    BYTE out[32]; memset(out, 0xcc, sizeof out);
    cb = 19; SET_ERR(0);
    CHECK(!kget(&id, CERT_DESCRIPTION_PROP_ID, sc, out, &cb)); EXPECT_ERR(ERROR_MORE_DATA);
    EXPECT_EQ(cb, 20);                                  /* required size is reported */
    cb = 0; SET_ERR(0);
    CHECK(!kget(&id, CERT_DESCRIPTION_PROP_ID, sc, out, &cb)); EXPECT_ERR(ERROR_MORE_DATA); EXPECT_EQ(cb, 20);
    cb = 20; CHECK(kget(&id, CERT_DESCRIPTION_PROP_ID, sc, out, &cb)); EXPECT_EQ(cb, 20);
    CHECK(!memcmp(out, payload, 20));
    cb = 31; CHECK(kget(&id, CERT_DESCRIPTION_PROP_ID, sc, out, &cb)); EXPECT_EQ(cb, 20);   /* larger buffer: size is the data size */
}
SCOPE_TEST(size_protocol, s_size_protocol)

static void s_missing_property(DWORD sc) {
    NEWKID(id, "mp");
    CRYPT_DATA_BLOB blob = { 3, (BYTE *)"abc" };
    CHECK(kset(&id, CERT_FRIENDLY_NAME_PROP_ID, sc, &blob));
    DWORD cb = 77; BYTE out[8];
    SET_ERR(0);
    CHECK(!kget(&id, CERT_DESCRIPTION_PROP_ID, sc, out, &cb)); EXPECT_ERR(CRYPT_E_NOT_FOUND_);
    EXPECT_EQ(cb, 0);
    cb = 77; SET_ERR(0);
    CHECK(!kget(&id, CERT_DESCRIPTION_PROP_ID, sc, NULL, &cb)); EXPECT_ERR(CRYPT_E_NOT_FOUND_); EXPECT_EQ(cb, 0);
}
SCOPE_TEST(missing_property, s_missing_property)

static void s_missing_keyid(DWORD sc) {
    NEWKID(id, "mk");
    DWORD cb = 77; BYTE out[8];
    SET_ERR(0);
    CHECK(!kget(&id, CERT_FRIENDLY_NAME_PROP_ID, sc, out, &cb));
    t_note("get on unknown key identifier (scope 0x%lx): last error 0x%lx", (unsigned long)sc, (unsigned long)GetLastError());
    EXPECT_EQ(cb, 0);
}
SCOPE_TEST(missing_keyid, s_missing_keyid)

static void s_overwrite(DWORD sc) {
    NEWKID(id, "ow");
    CRYPT_DATA_BLOB a = { 5, (BYTE *)"first" }, b = { 2, (BYTE *)"22" };
    CHECK(kset(&id, CERT_FRIENDLY_NAME_PROP_ID, sc, &a));
    CHECK(kset(&id, CERT_FRIENDLY_NAME_PROP_ID, sc, &b));
    BYTE out[16]; DWORD cb = sizeof out;
    CHECK(kget(&id, CERT_FRIENDLY_NAME_PROP_ID, sc, out, &cb));
    EXPECT_EQ(cb, 2); CHECK(!memcmp(out, "22", 2));
}
SCOPE_TEST(overwrite, s_overwrite)

static void s_multiple_props(DWORD sc) {
    NEWKID(id, "mu");
    CRYPT_DATA_BLOB a = { 1, (BYTE *)"A" }, b = { 2, (BYTE *)"BB" }, c = { 3, (BYTE *)"CCC" };
    CHECK(kset(&id, 0x7001, sc, &a)); CHECK(kset(&id, 0x7002, sc, &b)); CHECK(kset(&id, 0x7003, sc, &c));
    BYTE out[8]; DWORD cb;
    cb = sizeof out; CHECK(kget(&id, 0x7001, sc, out, &cb)); EXPECT_EQ(cb, 1); CHECK(!memcmp(out, "A", 1));
    cb = sizeof out; CHECK(kget(&id, 0x7002, sc, out, &cb)); EXPECT_EQ(cb, 2); CHECK(!memcmp(out, "BB", 2));
    cb = sizeof out; CHECK(kget(&id, 0x7003, sc, out, &cb)); EXPECT_EQ(cb, 3); CHECK(!memcmp(out, "CCC", 3));
}
SCOPE_TEST(multiple_props, s_multiple_props)

static void s_delete_property_via_null(DWORD sc) {
    NEWKID(id, "dp");
    CRYPT_DATA_BLOB a = { 1, (BYTE *)"A" }, b = { 1, (BYTE *)"B" };
    CHECK(kset(&id, 0x7001, sc, &a)); CHECK(kset(&id, 0x7002, sc, &b));
    SET_ERR(0);
    CHECK(kset(&id, 0x7001, sc, NULL));                  /* NULL data deletes the property */
    DWORD cb = 8; BYTE out[8];
    SET_ERR(0);
    CHECK(!kget(&id, 0x7001, sc, out, &cb)); EXPECT_ERR(CRYPT_E_NOT_FOUND_);
    cb = 8; CHECK(kget(&id, 0x7002, sc, out, &cb)); EXPECT_EQ(cb, 1);
    CHECK(kset(&id, 0x7001, sc, NULL));                  /* deleting an absent property is not an error */
}
SCOPE_TEST(delete_property_via_null, s_delete_property_via_null)

static void s_delete_keyid(DWORD sc) {
    NEWKID(id, "dk");
    CRYPT_DATA_BLOB a = { 1, (BYTE *)"A" };
    CHECK(kset(&id, 0x7001, sc, &a)); CHECK(kset(&id, 0x7002, sc, &a));
    SET_ERR(0xdead);
    BOOL ok = kdel(&id, sc);
    CHECKF(ok, "err 0x%lx", GetLastError());
    DWORD cb = 8; BYTE out[8];
    CHECK(!kget(&id, 0x7001, sc, out, &cb));
    cb = 8; CHECK(!kget(&id, 0x7002, sc, out, &cb));
    SET_ERR(0);
    BOOL again = kdel(&id, sc);
    if (!sc) { CHECK(!again); EXPECT_ERR(ERROR_FILE_NOT_FOUND); }        /* user scope: DeleteFile of the element file fails */
    t_note("deleting an absent key identifier (scope 0x%lx): last error %lu", (unsigned long)sc, (unsigned long)GetLastError());
    CHECK(kset(&id, 0x7001, sc, &a));                    /* can be created again */
    cb = 8; CHECK(kget(&id, 0x7001, sc, out, &cb));
}
SCOPE_TEST(delete_keyid, s_delete_keyid)

static void s_set_new_flag(DWORD sc) {
    NEWKID(id, "sn");
    CRYPT_DATA_BLOB a = { 1, (BYTE *)"A" }, b = { 1, (BYTE *)"B" };
    CHECK(kset(&id, 0x7001, sc | CRYPT_KEYID_SET_NEW_FLAG, &a));      /* does not exist yet: ok */
    SET_ERR(0);
    CHECK(!kset(&id, 0x7001, sc | CRYPT_KEYID_SET_NEW_FLAG, &b)); EXPECT_ERR(CRYPT_E_EXISTS_);
    BYTE out[4]; DWORD cb = 4;
    CHECK(kget(&id, 0x7001, sc, out, &cb)); CHECK(out[0] == 'A');
    CHECK(kset(&id, 0x7002, sc | CRYPT_KEYID_SET_NEW_FLAG, &b));      /* different property id: fine */
    CHECK(kset(&id, 0x7001, sc, &b));                                  /* without the flag it overwrites */
    cb = 4; CHECK(kget(&id, 0x7001, sc, out, &cb)); CHECK(out[0] == 'B');
}
SCOPE_TEST(set_new_flag, s_set_new_flag)

static void s_alloc_flag(DWORD sc) {
    NEWKID(id, "al");
    CRYPT_DATA_BLOB a = { 9, (BYTE *)"allocated" };
    CHECK(kset(&id, 0x7001, sc, &a));
    void *p = (void *)1; DWORD cb = 0;
    SET_ERR(0);
    BOOL ok = U(CryptGetKeyIdentifierProperty)(&id, 0x7001, sc | CRYPT_KEYID_ALLOC_FLAG, NULL, NULL, &p, &cb);
    CHECK(ok);
    if (ok) { EXPECT_EQ(cb, 9); CHECK(p && !memcmp(p, "allocated", 9)); if (p) LocalFree(p); }
    p = (void *)1; cb = 5; SET_ERR(0);
    ok = U(CryptGetKeyIdentifierProperty)(&id, 0x7009, sc | CRYPT_KEYID_ALLOC_FLAG, NULL, NULL, &p, &cb);
    CHECK(!ok); EXPECT_ERR(CRYPT_E_NOT_FOUND_);
    WINE_DIFF { EXPECT_EQ(p, 0); EXPECT_EQ(cb, 0); }
}
SCOPE_TEST(alloc_flag, s_alloc_flag)

static void s_zero_length_property(DWORD sc) {
    NEWKID(id, "zl");
    CRYPT_DATA_BLOB e = { 0, NULL };
    SET_ERR(0);
    CHECKF(kset(&id, 0x7001, sc, &e), "err 0x%lx", GetLastError());
    DWORD cb = 77; SET_ERR(0);
    BOOL ok = kget(&id, 0x7001, sc, NULL, &cb);
    t_note("zero-length property: get returned %d, size %lu, error 0x%lx", ok, (unsigned long)cb, (unsigned long)GetLastError());
}
SCOPE_TEST(zero_length_property, s_zero_length_property)

static void s_large_property(DWORD sc) {
    NEWKID(id, "lg");
    static BYTE big[8192], out[8192];
    for (int i = 0; i < 8192; i++) big[i] = (BYTE)(i * 31 + (i >> 8));
    CRYPT_DATA_BLOB b = { sizeof big, big };
    CHECK(kset(&id, 0x7001, sc, &b));
    DWORD cb = sizeof out;
    CHECK(kget(&id, 0x7001, sc, out, &cb)); EXPECT_EQ(cb, sizeof big); CHECK(!memcmp(out, big, sizeof big));
}
SCOPE_TEST(large_property, s_large_property)

static void s_invalid_property_ids(DWORD sc) {
    NEWKID(id, "ip");
    CRYPT_DATA_BLOB a = { 1, (BYTE *)"A" };
    static const DWORD bad[] = { 1, 5, 0x4e, 0x4f };
    for (int i = 0; i < 4; i++) {
        SET_ERR(0);
        CHECKF(!kset(&id, bad[i], sc, &a), "prop %lu", (unsigned long)bad[i]);
        EXPECT_HRINVAL();
    }
}
SCOPE_TEST(invalid_property_ids, s_invalid_property_ids)

static void s_key_prov_info(DWORD sc) {
    NEWKID(id, "kp");
    CRYPT_KEY_PROV_INFO kp = { 0 };
    kp.pwszContainerName = L"cryptt-container"; kp.pwszProvName = L"cryptt-provider";
    kp.dwProvType = PROV_RSA_FULL; kp.dwKeySpec = AT_SIGNATURE;
    kp.dwFlags = 0x20;                      /* CRYPT_MACHINE_KEYSET */
    CHECKF(kset(&id, CERT_KEY_PROV_INFO_PROP_ID, sc, &kp), "err 0x%lx", GetLastError());
    DWORD cb = 0;
    CHECK(kget(&id, CERT_KEY_PROV_INFO_PROP_ID, sc, NULL, &cb));
    CHECK(cb >= sizeof(CRYPT_KEY_PROV_INFO));
    BYTE *buf = calloc(1, cb + 16); DWORD cb2 = cb;
    CHECK(kget(&id, CERT_KEY_PROV_INFO_PROP_ID, sc, buf, &cb2));
    CRYPT_KEY_PROV_INFO *r = (CRYPT_KEY_PROV_INFO *)buf;
    CHECK(r->pwszContainerName && !lstrcmpW(r->pwszContainerName, L"cryptt-container"));
    CHECK(r->pwszProvName && !lstrcmpW(r->pwszProvName, L"cryptt-provider"));
    EXPECT_EQ(r->dwProvType, PROV_RSA_FULL); EXPECT_EQ(r->dwKeySpec, AT_SIGNATURE); EXPECT_EQ(r->dwFlags, 0x20);
    EXPECT_EQ(r->cProvParam, 0);
    /* pointers refer into the caller's buffer */
    CHECK((BYTE *)r->pwszContainerName >= buf && (BYTE *)r->pwszContainerName < buf + cb);
    cb2 = cb - 1; SET_ERR(0);
    CHECK(!kget(&id, CERT_KEY_PROV_INFO_PROP_ID, sc, buf, &cb2));
    t_note("key prov info into a buffer one byte too small: error %lu, size %lu (needed %lu)", (unsigned long)GetLastError(), (unsigned long)cb2, (unsigned long)cb);
    free(buf);
}
SCOPE_TEST(key_prov_info, s_key_prov_info)

/* ---- identifier validity ----------------------------------------------------------------------------- */
static void s_keyid_sizes(DWORD sc) {
    BYTE b[32]; memset(b, 0, sizeof b);
    DWORD pid = GetCurrentProcessId();
    CRYPT_DATA_BLOB a = { 1, (BYTE *)"A" }; BYTE out[4]; DWORD cb;
    for (DWORD len = 1; len <= 20; len += 19) {          /* 1 and 20 are the legal extremes */
        b[10] = (BYTE)('a' + len);
        CRYPT_HASH_BLOB id = { len, b };
        b[0] = 0xFA; memcpy(b + 1, &pid, 4); b[10] = (BYTE)('a' + len);
        oidr_kid_track(b, len);                          /* register for cleanup */
        CHECKF(kset(&id, 0x7001, sc, &a), "len %lu err 0x%lx", (unsigned long)len, GetLastError());
        cb = 4; CHECKF(kget(&id, 0x7001, sc, out, &cb), "len %lu", (unsigned long)len);
    }
    static const DWORD bad[] = { 0, 21, 32 };
    for (int i = 0; i < 3; i++) {
        CRYPT_HASH_BLOB id = { bad[i], b };
        SET_ERR(0); CHECKF(!kset(&id, 0x7001, sc, &a), "len %lu", (unsigned long)bad[i]); EXPECT_HRINVAL();
        cb = 4; SET_ERR(0); CHECKF(!kget(&id, 0x7001, sc, out, &cb), "len %lu", (unsigned long)bad[i]); EXPECT_HRINVAL();
        EXPECT_EQ(cb, 0);
        SET_ERR(0); CHECKF(!kdel(&id, sc), "len %lu", (unsigned long)bad[i]); EXPECT_HRINVAL();
    }
}
SCOPE_TEST(keyid_sizes, s_keyid_sizes)

static void s_keyids_isolated(DWORD sc) {
    NEWKID(a, "ia"); NEWKID(b, "ib");
    CRYPT_DATA_BLOB va = { 1, (BYTE *)"A" }, vb = { 1, (BYTE *)"B" };
    CHECK(kset(&a, 0x7001, sc, &va)); CHECK(kset(&b, 0x7001, sc, &vb));
    BYTE out[4]; DWORD cb = 4;
    CHECK(kget(&a, 0x7001, sc, out, &cb)); CHECK(out[0] == 'A');
    cb = 4; CHECK(kget(&b, 0x7001, sc, out, &cb)); CHECK(out[0] == 'B');
    CHECK(kdel(&a, sc));
    cb = 4; CHECK(kget(&b, 0x7001, sc, out, &cb));
    /* the same bytes with a different length are a different identifier */
    CRYPT_HASH_BLOB shorter = { 19, b.pbData };
    cb = 4; CHECK(!kget(&shorter, 0x7001, sc, out, &cb));
}
SCOPE_TEST(keyids_isolated, s_keyids_isolated)

/* ---- enumeration ------------------------------------------------------------------------------------- */
typedef struct { int calls; DWORD cprop; DWORD ids[16]; BYTE data[16][40]; DWORD cbs[16]; int idmatch; int stop; } kctx;
static BOOL WINAPI kenum_cb(const CRYPT_HASH_BLOB *id, DWORD flags, void *res, void *arg, DWORD cprop, DWORD *ids, void **data, DWORD *cbs) {
    kctx *c = (kctx *)arg;
    if (id && id->cbData == 20 && id->pbData && !memcmp(id->pbData, "cryptt", 6)) {
        DWORD pid = GetCurrentProcessId();
        if (!memcmp(id->pbData + 6, &pid, 4)) {
            c->calls++; c->cprop = cprop;
            for (DWORD i = 0; i < cprop && i < 16; i++) { c->ids[i] = ids[i]; c->cbs[i] = cbs[i]; memcpy(c->data[i], data[i], cbs[i] < 40 ? cbs[i] : 40); }
        }
    }
    return TRUE;
}
static void s_enum_one_keyid(DWORD sc) {
    NEWKID(id, "en");
    CRYPT_DATA_BLOB a = { 1, (BYTE *)"A" }, b = { 2, (BYTE *)"BB" }, c = { 3, (BYTE *)"CCC" };
    CHECK(kset(&id, 0x7001, sc, &a)); CHECK(kset(&id, 0x7002, sc, &b)); CHECK(kset(&id, 0x7003, sc, &c));
    kctx k = { 0 };
    SET_ERR(0);
    BOOL ok = U(CryptEnumKeyIdentifierProperties)(&id, 0, sc, NULL, NULL, &k, kenum_cb);
    CHECKF(ok, "err 0x%lx", GetLastError());
    EXPECT_EQ(k.calls, 1);                              /* one callback with all properties */
    EXPECT_EQ(k.cprop, 3);
    int seen = 0;
    for (DWORD i = 0; i < k.cprop && i < 16; i++) {
        if (k.ids[i] == 0x7001) { seen |= 1; EXPECT_EQ(k.cbs[i], 1); CHECK(k.data[i][0] == 'A'); }
        else if (k.ids[i] == 0x7002) { seen |= 2; EXPECT_EQ(k.cbs[i], 2); CHECK(!memcmp(k.data[i], "BB", 2)); }
        else if (k.ids[i] == 0x7003) { seen |= 4; EXPECT_EQ(k.cbs[i], 3); CHECK(!memcmp(k.data[i], "CCC", 3)); }
    }
    EXPECT_EQ(seen, 7);
}
SCOPE_TEST(enum_one_keyid, s_enum_one_keyid)

static void s_enum_prop_filter(DWORD sc) {
    NEWKID(id, "ef");
    CRYPT_DATA_BLOB a = { 1, (BYTE *)"A" }, b = { 2, (BYTE *)"BB" };
    CHECK(kset(&id, 0x7001, sc, &a)); CHECK(kset(&id, 0x7002, sc, &b));
    kctx k = { 0 };
    CHECK(U(CryptEnumKeyIdentifierProperties)(&id, 0x7002, sc, NULL, NULL, &k, kenum_cb));
    EXPECT_EQ(k.calls, 1); EXPECT_EQ(k.cprop, 1);
    if (k.cprop == 1) { EXPECT_EQ(k.ids[0], 0x7002); EXPECT_EQ(k.cbs[0], 2); CHECK(!memcmp(k.data[0], "BB", 2)); }
    kctx none = { 0 };
    BOOL ok = U(CryptEnumKeyIdentifierProperties)(&id, 0x7999, sc, NULL, NULL, &none, kenum_cb);
    EXPECT_EQ(none.calls, 0);
    t_note("enum with a property id that is not present returned %d (error 0x%lx)", ok, (unsigned long)GetLastError());
}
SCOPE_TEST(enum_prop_filter, s_enum_prop_filter)

static void s_enum_unknown_keyid(DWORD sc) {
    NEWKID(id, "eu");
    kctx k = { 0 };
    SET_ERR(0);
    BOOL ok = U(CryptEnumKeyIdentifierProperties)(&id, 0, sc, NULL, NULL, &k, kenum_cb);
    EXPECT_EQ(k.calls, 0);
    CHECK(!ok);                                          /* ILS_ReadKeyIdElement failed: no callback, FALSE */
    t_note("enum of unknown key identifier: last error 0x%lx", (unsigned long)GetLastError());
}
SCOPE_TEST(enum_unknown_keyid, s_enum_unknown_keyid)

static void s_enum_all_keyids(DWORD sc) {
    NEWKID(a, "ea"); NEWKID(b, "eb");
    CRYPT_DATA_BLOB v = { 1, (BYTE *)"A" };
    CHECK(kset(&a, 0x7001, sc, &v)); CHECK(kset(&b, 0x7001, sc, &v));
    kctx k = { 0 };
    SET_ERR(0);
    BOOL ok = U(CryptEnumKeyIdentifierProperties)(NULL, 0x7001, sc, NULL, NULL, &k, kenum_cb);
    t_note("enumerate all identifiers (scope 0x%lx): returned %d, %d of ours seen", (unsigned long)sc, ok, k.calls);
    CHECK(ok);
    EXPECT_EQ(k.calls, 2);                               /* both of our identifiers carry property 0x7001 */
}
SCOPE_TEST(enum_all_keyids, s_enum_all_keyids)

static void s_enum_all_keyids_filter_excludes(DWORD sc) {
    NEWKID(a, "ex");
    CRYPT_DATA_BLOB v = { 1, (BYTE *)"A" };
    CHECK(kset(&a, 0x7001, sc, &v));
    kctx k = { 0 };
    U(CryptEnumKeyIdentifierProperties)(NULL, 0x7fff, sc, NULL, NULL, &k, kenum_cb);
    EXPECT_EQ(k.calls, 0);
}
SCOPE_TEST(enum_all_filter_excludes, s_enum_all_keyids_filter_excludes)

/* ---- scope separation -------------------------------------------------------------------------------- */
TEST(oidreg_kid_scope_user_not_visible_in_machine) {
    KIDGATE();
    REQUIRE(U(CryptSetKeyIdentifierProperty));
    if (!oidr_kid_begin(1)) return;
    NEWKID(id, "su");
    CRYPT_DATA_BLOB v = { 4, (BYTE *)"user" };
    CHECK(kset(&id, 0x7001, 0, &v));
    BYTE out[8]; DWORD cb = 8;
    CHECK(kget(&id, 0x7001, 0, out, &cb));
    cb = 8; SET_ERR(0);
    CHECK(!kget(&id, 0x7001, CRYPT_KEYID_MACHINE_FLAG, out, &cb));
    oidr_kid_cleanup();
}
TEST(oidreg_kid_scope_machine_not_visible_in_user) {
    KIDGATE();
    REQUIRE(U(CryptSetKeyIdentifierProperty));
    if (!oidr_kid_begin(1)) return;
    NEWKID(id, "sm");
    CRYPT_DATA_BLOB v = { 4, (BYTE *)"mach" };
    CHECK(kset(&id, 0x7001, CRYPT_KEYID_MACHINE_FLAG, &v));
    BYTE out[8]; DWORD cb = 8;
    CHECK(kget(&id, 0x7001, CRYPT_KEYID_MACHINE_FLAG, out, &cb));
    cb = 8; SET_ERR(0);
    CHECK(!kget(&id, 0x7001, 0, out, &cb));
    oidr_kid_cleanup();
}
TEST(oidreg_kid_scope_same_id_different_values_per_scope) {
    KIDGATE();
    REQUIRE(U(CryptSetKeyIdentifierProperty));
    if (!oidr_kid_begin(1)) return;
    NEWKID(id, "sv");
    CRYPT_DATA_BLOB u = { 1, (BYTE *)"U" }, m = { 1, (BYTE *)"M" };
    CHECK(kset(&id, 0x7001, 0, &u)); CHECK(kset(&id, 0x7001, CRYPT_KEYID_MACHINE_FLAG, &m));
    BYTE out[4]; DWORD cb = 4;
    CHECK(kget(&id, 0x7001, 0, out, &cb)); CHECK(out[0] == 'U');
    cb = 4; CHECK(kget(&id, 0x7001, CRYPT_KEYID_MACHINE_FLAG, out, &cb)); CHECK(out[0] == 'M');
    CHECK(kdel(&id, 0));
    cb = 4; CHECK(kget(&id, 0x7001, CRYPT_KEYID_MACHINE_FLAG, out, &cb)); CHECK(out[0] == 'M');   /* machine copy untouched */
    oidr_kid_cleanup();
}
TEST(oidreg_kid_machine_not_elevated_set_denied) {
    KIDGATE();
    REQUIRE(U(CryptSetKeyIdentifierProperty));
    if (oidr_can_write()) { t_skip("elevated: HKLM is writable"); return; }
    if (!oidr_kid_begin(0)) return;
    NEWKID(id, "na");
    CRYPT_DATA_BLOB v = { 1, (BYTE *)"A" };
    SET_ERR(0);
    CHECK(!kset(&id, 0x7001, CRYPT_KEYID_MACHINE_FLAG, &v));
    t_note("machine-scope set without elevation: last error %lu", (unsigned long)GetLastError());
    oidr_kid_cleanup();
}
TEST(oidreg_kid_user_element_file_location) {
    KIDGATE();
    REQUIRE(U(CryptSetKeyIdentifierProperty));
    if (!oidr_kid_begin(0)) return;
    NEWKID(id, "fl");
    CRYPT_DATA_BLOB v = { 1, (BYTE *)"A" };
    CHECK(kset(&id, 0x7001, 0, &v));
    wchar_t hx[48], appdata[MAX_PATH], p[600];
    for (int i = 0; i < 20; i++) _snwprintf(hx + 2 * i, 3, L"%02X", id.pbData[i]);
    DWORD fileattr = INVALID_FILE_ATTRIBUTES;
    if (GetEnvironmentVariableW(L"APPDATA", appdata, MAX_PATH)) {
        _snwprintf(p, 600, L"%ls\\Microsoft\\SystemCertificates\\My\\Keys\\%ls", appdata, hx);
        fileattr = GetFileAttributesW(p);
    }
    HKEY k; _snwprintf(p, 600, L"Software\\Microsoft\\SystemCertificates\\My\\Keys\\%ls", hx);
    int inreg = RegOpenKeyExW(HKEY_CURRENT_USER, p, 0, KEY_READ, &k) == 0; if (inreg) RegCloseKey(k);
    t_note("user key identifier element stored as file: %s, as HKCU key: %s", fileattr != INVALID_FILE_ATTRIBUTES ? "yes" : "no", inreg ? "yes" : "no");
    CHECK(fileattr != INVALID_FILE_ATTRIBUTES || inreg);
    oidr_kid_cleanup();
}
TEST(oidreg_kid_machine_element_in_hklm) {
    KIDGATE();
    REQUIRE(U(CryptSetKeyIdentifierProperty));
    if (!oidr_kid_begin(1)) return;
    NEWKID(id, "ml");
    CRYPT_DATA_BLOB v = { 1, (BYTE *)"A" };
    CHECK(kset(&id, 0x7001, CRYPT_KEYID_MACHINE_FLAG, &v));
    wchar_t hx[48], p[600]; HKEY k;
    for (int i = 0; i < 20; i++) _snwprintf(hx + 2 * i, 3, L"%02X", id.pbData[i]);
    _snwprintf(p, 600, L"Software\\Microsoft\\SystemCertificates\\My\\Keys\\%ls", hx);
    int ok = RegOpenKeyExW(HKEY_LOCAL_MACHINE, p, 0, KEY_READ, &k) == 0; if (ok) RegCloseKey(k);
    CHECK(ok);
    CHECK(kdel(&id, CRYPT_KEYID_MACHINE_FLAG));
    ok = RegOpenKeyExW(HKEY_LOCAL_MACHINE, p, 0, KEY_READ, &k) == 0; if (ok) RegCloseKey(k);
    CHECK(!ok);
    oidr_kid_cleanup();
}
