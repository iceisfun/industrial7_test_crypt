/* AES-CMAC, AES-GMAC and the multi-hash (BCryptCreateMultiHash / BCryptProcessMultiOperations) interfaces.
 * CMAC expected values: RFC 4493 / SP 800-38B inputs plus a key/message matrix; GMAC = GCM with empty plaintext, so the
 * tag is the GHASH of the AAD; both generated at authoring time with python3 "cryptography". */
#include "hh.h"

#define NEED() do { if (!HH_P_CREATE() || !HH_P_DATA() || !HH_P_FINISH() || !HH_P_DESTROY() || !HH_P_OPEN() || !HH_P_CLOSE()) { t_skip("missing export"); return; } } while (0)

static BCRYPT_ALG_HANDLE open_or_skip(const WCHAR *name, ULONG fl, const char *what) {
    BCRYPT_ALG_HANDLE a = NULL;
    NTSTATUS st = HH_P_OPEN()(&a, name, NULL, fl);
    if (st && t_is_wine()) { t_skip("%s not implemented by the emulator", what); return NULL; }
    if (st) { CHECKF(0, "%s: open -> 0x%08lx", what, (unsigned long)st); return NULL; }
    return a;
}

/* ===================== AES-CMAC ===================== */
enum { C_ONESHOT, C_PSEUDO, C_CREATE, C_CALLERBUF, C_REUSE, C_DUP };
static void cmac_run(int mode, ULONG chunk) {
    NEED();
    if (!HH_P_HASH()) { t_skip("missing BCryptHash"); return; }
    BCRYPT_ALG_HANDLE a = open_or_skip(L"AES-CMAC", 0, "AES-CMAC");
    if (!a) return;
    for (unsigned i = 0; i < hh_ncvecs; i++) {
        const struct hh_cvec *v = &hh_cvecs[i];
        ULONG kl, ml; BYTE *k = hh_spec_new(&v->key, &kl), *m = hh_spec_new(&v->msg, &ml), out[16];
        memset(out, 0xEE, 16);
        NTSTATUS st = 0;
        switch (mode) {
        case C_ONESHOT: st = HH_P_HASH()(a, k, kl, m, ml, out, 16); break;
        case C_PSEUDO: st = HH_P_HASH()(BCRYPT_AES_CMAC_ALG_HANDLE, k, kl, m, ml, out, 16); break;
        case C_CREATE: st = hh_compute(a, k, kl, m, ml, chunk, 0, out, 16); break;
        case C_CALLERBUF: st = hh_compute(a, k, kl, m, ml, chunk, 1, out, 16); break;
        case C_REUSE: {
            BCRYPT_HASH_HANDLE h = NULL; BYTE o2[16];
            st = HH_P_CREATE()(a, &h, NULL, 0, k, kl, BCRYPT_HASH_REUSABLE_FLAG);
            if (!st) { st = HH_P_DATA()(h, (PUCHAR)"junk", 4, 0); if (!st) st = HH_P_FINISH()(h, o2, 16, 0); }
            if (!st) { st = HH_P_DATA()(h, m, ml, 0); if (!st) st = HH_P_FINISH()(h, out, 16, 0); }
            if (!st) { st = HH_P_DATA()(h, m, ml, 0); if (!st) st = HH_P_FINISH()(h, o2, 16, 0); CHECK(!memcmp(o2, out, 16)); }
            if (h) HH_P_DESTROY()(h);
            break; }
        case C_DUP: {
            BCRYPT_HASH_HANDLE h = NULL, d = NULL; ULONG half = ml / 2;
            st = HH_P_CREATE()(a, &h, NULL, 0, k, kl, 0);
            if (!st) st = HH_P_DATA()(h, m, half, 0);
            if (!st) st = HH_P_DUP()(h, &d, NULL, 0, 0);
            if (!st) st = HH_P_DATA()(d, m + half, ml - half, 0);
            if (!st) st = HH_P_FINISH()(d, out, 16, 0);
            if (d) HH_P_DESTROY()(d);
            if (h) HH_P_DESTROY()(h);
            break; }
        }
        if (st || !hh_eqhex(out, 16, v->hex)) {
            char hx[40]; hh_tohex(out, 16, hx);
            CHECKF(0, "CMAC vec#%u keylen=%lu msglen=%lu st=0x%08lx got %s want %s", i, (unsigned long)kl, (unsigned long)ml, (unsigned long)st, hx, v->hex);
        } else t_check(1, __FILE__, __LINE__, "cmac", NULL);
        free(k); free(m);
    }
    hh_close(a);
}
TEST(hh_cmac_bchash_oneshot)     { cmac_run(C_ONESHOT, 0); }
TEST(hh_cmac_pseudo_handle)      { cmac_run(C_PSEUDO, 0); }
TEST(hh_cmac_create_heap)        { cmac_run(C_CREATE, 0); }
TEST(hh_cmac_create_callerbuf)   { cmac_run(C_CALLERBUF, 0); }
TEST(hh_cmac_chunk1)             { cmac_run(C_CREATE, 1); }
TEST(hh_cmac_chunk7)             { cmac_run(C_CREATE, 7); }
TEST(hh_cmac_chunk16)            { cmac_run(C_CREATE, 16); }
TEST(hh_cmac_chunk17)            { cmac_run(C_CALLERBUF, 17); }
TEST(hh_cmac_reusable)           { cmac_run(C_REUSE, 0); }
TEST(hh_cmac_duplicate_midstream){ if (!HH_P_DUP()) { t_skip("missing export"); return; } cmac_run(C_DUP, 0); }

TEST(hh_cmac_rfc4493_examples) {
    NEED();
    if (t_is_wine()) { t_skip("AES-CMAC not implemented by the emulator"); return; }
    static const struct { const char *msg, *mac; } t[] = {
        {"", "bb1d6929e95937287fa37d129b756746"},
        {"6bc1bee22e409f96e93d7e117393172a", "070a16b46b4d4144f79bdd9dd04a287c"},
        {"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411", "dfa66747de9ae63030ca32611497c827"},
        {"6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", "51f0bebf7e3b9d92fc49741779363cfe"},
    };
    BYTE key[16], msg[64], out[16];
    hh_unhex("2b7e151628aed2a6abf7158809cf4f3c", key);
    for (unsigned i = 0; i < 4; i++) {
        ULONG ml = hh_unhex(t[i].msg, msg);
        EXPECT_ST(HH_P_HASH()(BCRYPT_AES_CMAC_ALG_HANDLE, key, 16, msg, ml, out, 16), 0);
        CHECKF(hh_eqhex(out, 16, t[i].mac), "RFC 4493 example %u", i);
    }
}
TEST(hh_cmac_properties) {
    NEED();
    BCRYPT_ALG_HANDLE a = open_or_skip(L"AES-CMAC", 0, "AES-CMAC");
    if (!a) return;
    int ok; ULONG v = hh_prop_ulong(a, BCRYPT_HASH_LENGTH, &ok);
    CHECK(ok); EXPECT_EQ(v, 16);
    WCHAR name[32] = {0}; ULONG cb = 0;
    EXPECT_ST(HH_P_GETPROP()(a, BCRYPT_ALGORITHM_NAME, (PUCHAR)name, sizeof name, &cb, 0), 0);
    CHECK(!wcscmp(name, L"AES-CMAC"));
    v = hh_objlen(a);
    CHECK(v >= 0x46);
    hh_close(a);
}
TEST(hh_cmac_invalid_key_sizes) {
    NEED();
    BCRYPT_ALG_HANDLE a = open_or_skip(L"AES-CMAC", 0, "AES-CMAC");
    if (!a) return;
    static const ULONG sizes[] = {0, 1, 8, 15, 17, 20, 23, 25, 31, 33, 48, 64};
    BYTE key[64]; memset(key, 0x42, sizeof key);
    for (unsigned i = 0; i < sizeof sizes / sizeof *sizes; i++) {
        BCRYPT_HASH_HANDLE h = (BCRYPT_HASH_HANDLE)(ULONG_PTR)0x77;
        NTSTATUS st = HH_P_CREATE()(a, &h, NULL, 0, sizes[i] ? key : NULL, sizes[i], 0);
        CHECKF(st == NS_INVALID_PARAM, "key size %lu -> 0x%08lx", (unsigned long)sizes[i], (unsigned long)st);
        CHECK(h == (BCRYPT_HASH_HANDLE)(ULONG_PTR)0x77);
    }
    hh_close(a);
}
TEST(hh_cmac_valid_key_sizes_16_24_32) {
    NEED();
    BCRYPT_ALG_HANDLE a = open_or_skip(L"AES-CMAC", 0, "AES-CMAC");
    if (!a) return;
    BYTE key[32]; memset(key, 0x42, sizeof key);
    for (ULONG kl = 16; kl <= 32; kl += 8) {
        BCRYPT_HASH_HANDLE h = NULL;
        EXPECT_ST(HH_P_CREATE()(a, &h, NULL, 0, key, kl, 0), 0);
        if (h) HH_P_DESTROY()(h);
    }
    hh_close(a);
}
TEST(hh_cmac_finish_size_rules) {
    NEED();
    BCRYPT_ALG_HANDLE a = open_or_skip(L"AES-CMAC", 0, "AES-CMAC");
    if (!a) return;
    BYTE key[16] = {1}, out[64];
    BCRYPT_HASH_HANDLE h = NULL;
    EXPECT_ST(HH_P_CREATE()(a, &h, NULL, 0, key, 16, 0), 0);
    if (h) {
        EXPECT_ST(HH_P_FINISH()(h, out, 15, 0), NS_INVALID_PARAM);
        EXPECT_ST(HH_P_FINISH()(h, out, 17, 0), NS_INVALID_PARAM);
        EXPECT_ST(HH_P_FINISH()(h, NULL, 16, 0), NS_INVALID_PARAM);
        EXPECT_ST(HH_P_FINISH()(h, out, 16, 0), 0);
        EXPECT_ST(HH_P_FINISH()(h, out, 16, 0), NS_INVALID_HANDLE);
        HH_P_DESTROY()(h);
    }
    hh_close(a);
}
TEST(hh_cmac_algorithm_not_usable_as_plain_hash_without_key) {
    NEED();
    BCRYPT_ALG_HANDLE a = open_or_skip(L"AES-CMAC", 0, "AES-CMAC");
    if (!a) return;
    BCRYPT_HASH_HANDLE h = (BCRYPT_HASH_HANDLE)(ULONG_PTR)0x77;
    NTSTATUS st = HH_P_CREATE()(a, &h, NULL, 0, NULL, 0, 0);
    EXPECT_ST(st, NS_INVALID_PARAM);       /* the empty key is not a valid AES key */
    hh_close(a);
}

/* ===================== AES-GMAC ===================== */
enum { G_NORMAL, G_PSEUDO_DIRECT, G_REUSE, G_DUP };
static NTSTATUS gmac_compute(BCRYPT_ALG_HANDLE a, const BYTE *key, ULONG kl, const BYTE *iv, ULONG ivl, const BYTE *aad, ULONG al, ULONG chunk, ULONG fl, BYTE *out) {
    BCRYPT_HASH_HANDLE h = NULL;
    NTSTATUS st = HH_P_CREATE()(a, &h, NULL, 0, (PUCHAR)key, kl, fl);
    if (st) return st;
    st = HH_P_SETPROP()(h, L"IV", (PUCHAR)iv, ivl, 0);
    if (!st) {
        if (!chunk || chunk >= al) st = HH_P_DATA()(h, (PUCHAR)aad, al, 0);
        else for (ULONG o = 0; o < al && !st; o += chunk) st = HH_P_DATA()(h, (PUCHAR)aad + o, al - o < chunk ? al - o : chunk, 0);
    }
    if (!st) st = HH_P_FINISH()(h, out, 16, 0);
    HH_P_DESTROY()(h);
    return st;
}
static void gmac_run(int mode, ULONG chunk) {
    NEED();
    if (!HH_P_SETPROP()) { t_skip("missing BCryptSetProperty"); return; }
    BCRYPT_ALG_HANDLE a = open_or_skip(L"AES-GMAC", 0, "AES-GMAC");
    if (!a) return;
    for (unsigned i = 0; i < hh_ngvecs; i++) {
        const struct hh_gvec *v = &hh_gvecs[i];
        ULONG kl, il, al; BYTE *k = hh_spec_new(&v->key, &kl), *iv = hh_spec_new(&v->iv, &il), *aad = hh_spec_new(&v->aad, &al), out[16];
        memset(out, 0xEE, 16);
        NTSTATUS st = 0;
        switch (mode) {
        case G_NORMAL: st = gmac_compute(a, k, kl, iv, il, aad, al, chunk, 0, out); break;
        case G_PSEUDO_DIRECT: st = gmac_compute(BCRYPT_AES_GMAC_ALG_HANDLE, k, kl, iv, il, aad, al, chunk, 0, out); break;
        case G_REUSE: {
            BCRYPT_HASH_HANDLE h = NULL; BYTE o2[16];
            st = HH_P_CREATE()(a, &h, NULL, 0, k, kl, BCRYPT_HASH_REUSABLE_FLAG);
            if (!st) {
                BYTE iv2[12]; memset(iv2, 9, 12);
                st = HH_P_SETPROP()(h, L"IV", iv2, 12, 0);
                if (!st) st = HH_P_DATA()(h, (PUCHAR)"decoy", 5, 0);
                if (!st) st = HH_P_FINISH()(h, o2, 16, 0);
                if (!st) st = HH_P_SETPROP()(h, L"IV", iv, il, 0);
                if (!st) st = HH_P_DATA()(h, aad, al, 0);
                if (!st) st = HH_P_FINISH()(h, out, 16, 0);
                HH_P_DESTROY()(h);
            }
            break; }
        case G_DUP: {
            BCRYPT_HASH_HANDLE h = NULL, d = NULL; ULONG half = al / 2;
            st = HH_P_CREATE()(a, &h, NULL, 0, k, kl, 0);
            if (!st) st = HH_P_SETPROP()(h, L"IV", iv, il, 0);
            if (!st) st = HH_P_DATA()(h, aad, half, 0);
            if (!st) st = HH_P_DUP()(h, &d, NULL, 0, 0);
            if (!st) st = HH_P_DATA()(d, aad + half, al - half, 0);
            if (!st) st = HH_P_FINISH()(d, out, 16, 0);
            if (d) HH_P_DESTROY()(d);
            if (h) HH_P_DESTROY()(h);
            break; }
        }
        if (st || !hh_eqhex(out, 16, v->hex)) {
            char hx[40]; hh_tohex(out, 16, hx);
            CHECKF(0, "GMAC vec#%u keylen=%lu aadlen=%lu st=0x%08lx got %s want %s", i, (unsigned long)kl, (unsigned long)al, (unsigned long)st, hx, v->hex);
        } else t_check(1, __FILE__, __LINE__, "gmac", NULL);
        free(k); free(iv); free(aad);
    }
    hh_close(a);
}
TEST(hh_gmac_whole_aad)         { gmac_run(G_NORMAL, 0); }
TEST(hh_gmac_pseudo_handle)     { gmac_run(G_PSEUDO_DIRECT, 0); }
TEST(hh_gmac_chunk1)            { gmac_run(G_NORMAL, 1); }
TEST(hh_gmac_chunk5)            { gmac_run(G_NORMAL, 5); }
TEST(hh_gmac_chunk16)           { gmac_run(G_NORMAL, 16); }
TEST(hh_gmac_chunk17)           { gmac_run(G_NORMAL, 17); }
TEST(hh_gmac_reusable_new_iv_each_run) { gmac_run(G_REUSE, 0); }
TEST(hh_gmac_duplicate_midstream) { if (!HH_P_DUP()) { t_skip("missing export"); return; } gmac_run(G_DUP, 0); }

static BCRYPT_HASH_HANDLE gmac_new(BCRYPT_ALG_HANDLE a, ULONG fl) {
    BYTE key[16] = {1, 2, 3}; BCRYPT_HASH_HANDLE h = NULL;
    EXPECT_ST(HH_P_CREATE()(a, &h, NULL, 0, key, 16, fl), 0);
    return h;
}
TEST(hh_gmac_properties) {
    NEED();
    BCRYPT_ALG_HANDLE a = open_or_skip(L"AES-GMAC", 0, "AES-GMAC");
    if (!a) return;
    int ok; ULONG v = hh_prop_ulong(a, BCRYPT_HASH_LENGTH, &ok);
    CHECK(ok); EXPECT_EQ(v, 16);
    WCHAR name[32] = {0}; ULONG cb = 0;
    EXPECT_ST(HH_P_GETPROP()(a, BCRYPT_ALGORITHM_NAME, (PUCHAR)name, sizeof name, &cb, 0), 0);
    CHECK(!wcscmp(name, L"AES-GMAC"));
    hh_close(a);
}
TEST(hh_gmac_invalid_key_sizes) {
    NEED();
    BCRYPT_ALG_HANDLE a = open_or_skip(L"AES-GMAC", 0, "AES-GMAC");
    if (!a) return;
    static const ULONG sizes[] = {0, 1, 8, 15, 17, 20, 23, 25, 31, 33, 40, 48, 64};
    BYTE key[64]; memset(key, 0x42, sizeof key);
    for (unsigned i = 0; i < sizeof sizes / sizeof *sizes; i++) {
        BCRYPT_HASH_HANDLE h = (BCRYPT_HASH_HANDLE)(ULONG_PTR)0x77;
        NTSTATUS st = HH_P_CREATE()(a, &h, NULL, 0, sizes[i] ? key : NULL, sizes[i], 0);
        CHECKF(st == NS_INVALID_BUFFER_SIZE, "key size %lu -> 0x%08lx", (unsigned long)sizes[i], (unsigned long)st);
        CHECK(h == (BCRYPT_HASH_HANDLE)(ULONG_PTR)0x77);
    }
    hh_close(a);
}
TEST(hh_gmac_valid_key_sizes) {
    NEED();
    BCRYPT_ALG_HANDLE a = open_or_skip(L"AES-GMAC", 0, "AES-GMAC");
    if (!a) return;
    BYTE key[32]; memset(key, 0x42, sizeof key);
    for (ULONG kl = 16; kl <= 32; kl += 8) {
        BCRYPT_HASH_HANDLE h = NULL;
        EXPECT_ST(HH_P_CREATE()(a, &h, NULL, 0, key, kl, 0), 0);
        if (h) HH_P_DESTROY()(h);
    }
    hh_close(a);
}
TEST(hh_gmac_data_before_iv_rejected) {
    NEED();
    BCRYPT_ALG_HANDLE a = open_or_skip(L"AES-GMAC", 0, "AES-GMAC");
    if (!a) return;
    BCRYPT_HASH_HANDLE h = gmac_new(a, 0);
    if (h) {
        BYTE out[16];
        EXPECT_ST(HH_P_DATA()(h, (PUCHAR)"aad", 3, 0), NS_GMAC_IV_STATE);
        EXPECT_ST(HH_P_DATA()(h, NULL, 0, 0), 0);                       /* an empty update returns before the IV check */
        EXPECT_ST(HH_P_FINISH()(h, out, 16, 0), NS_GMAC_IV_STATE);
        HH_P_DESTROY()(h);
    }
    hh_close(a);
}
TEST(hh_gmac_iv_size_rules) {
    NEED();
    if (!HH_P_SETPROP()) { t_skip("missing BCryptSetProperty"); return; }
    BCRYPT_ALG_HANDLE a = open_or_skip(L"AES-GMAC", 0, "AES-GMAC");
    if (!a) return;
    BCRYPT_HASH_HANDLE h = gmac_new(a, 0);
    if (h) {
        BYTE iv[32] = {0};
        static const ULONG bad[] = {0, 1, 8, 11, 13, 16, 32};
        for (unsigned i = 0; i < sizeof bad / sizeof *bad; i++) {
            NTSTATUS st = HH_P_SETPROP()(h, L"IV", iv, bad[i], 0);
            CHECKF(st == NS_INVALID_BUFFER_SIZE, "IV size %lu -> 0x%08lx", (unsigned long)bad[i], (unsigned long)st);
        }
        EXPECT_ST(HH_P_SETPROP()(h, L"IV", iv, 12, 0), 0);           /* failed attempts did not latch the IV */
        EXPECT_ST(HH_P_SETPROP()(h, L"IV", iv, 12, 0), NS_GMAC_IV_STATE);   /* second IV on the same message */
        HH_P_DESTROY()(h);
    }
    hh_close(a);
}
TEST(hh_gmac_iv_flags_and_name) {
    NEED();
    if (!HH_P_SETPROP()) { t_skip("missing BCryptSetProperty"); return; }
    BCRYPT_ALG_HANDLE a = open_or_skip(L"AES-GMAC", 0, "AES-GMAC");
    if (!a) return;
    BCRYPT_HASH_HANDLE h = gmac_new(a, 0);
    if (h) {
        BYTE iv[12] = {0};
        EXPECT_ST(HH_P_SETPROP()(h, L"IV", iv, 12, 1), NS_INVALID_PARAM);
        EXPECT_ST(HH_P_SETPROP()(h, L"IV", iv, 12, 0x80000000), NS_INVALID_PARAM);
        EXPECT_ST(HH_P_SETPROP()(h, L"IVx", iv, 12, 0), NS_NOT_SUPPORTED);
        EXPECT_ST(HH_P_SETPROP()(h, L"iv", iv, 12, 0), NS_NOT_SUPPORTED);   /* the name comparison is exact, case sensitive */
        EXPECT_ST(HH_P_SETPROP()(h, L"IV", iv, 12, 0), 0);
        HH_P_DESTROY()(h);
    }
    hh_close(a);
}
TEST(hh_gmac_second_finish_and_reusable_requires_new_iv) {
    NEED();
    if (!HH_P_SETPROP()) { t_skip("missing BCryptSetProperty"); return; }
    BCRYPT_ALG_HANDLE a = open_or_skip(L"AES-GMAC", 0, "AES-GMAC");
    if (!a) return;
    BYTE iv[12] = {5}, out[16];
    BCRYPT_HASH_HANDLE h = gmac_new(a, 0);
    if (h) {
        EXPECT_ST(HH_P_SETPROP()(h, L"IV", iv, 12, 0), 0);
        EXPECT_ST(HH_P_FINISH()(h, out, 16, 0), 0);
        EXPECT_ST(HH_P_FINISH()(h, out, 16, 0), NS_INVALID_HANDLE);
        EXPECT_ST(HH_P_DATA()(h, (PUCHAR)"x", 1, 0), NS_INVALID_HANDLE);
        HH_P_DESTROY()(h);
    }
    h = gmac_new(a, BCRYPT_HASH_REUSABLE_FLAG);
    if (h) {
        EXPECT_ST(HH_P_SETPROP()(h, L"IV", iv, 12, 0), 0);
        EXPECT_ST(HH_P_FINISH()(h, out, 16, 0), 0);
        EXPECT_ST(HH_P_DATA()(h, (PUCHAR)"x", 1, 0), NS_GMAC_IV_STATE);   /* the IV was consumed by Finish */
        EXPECT_ST(HH_P_SETPROP()(h, L"IV", iv, 12, 0), 0);
        EXPECT_ST(HH_P_DATA()(h, (PUCHAR)"x", 1, 0), 0);
        HH_P_DESTROY()(h);
    }
    hh_close(a);
}
TEST(hh_gmac_finish_size_rules) {
    NEED();
    if (!HH_P_SETPROP()) { t_skip("missing BCryptSetProperty"); return; }
    BCRYPT_ALG_HANDLE a = open_or_skip(L"AES-GMAC", 0, "AES-GMAC");
    if (!a) return;
    BCRYPT_HASH_HANDLE h = gmac_new(a, 0);
    if (h) {
        BYTE iv[12] = {0}, out[32];
        HH_P_SETPROP()(h, L"IV", iv, 12, 0);
        EXPECT_ST(HH_P_FINISH()(h, out, 15, 0), NS_INVALID_PARAM);
        EXPECT_ST(HH_P_FINISH()(h, out, 17, 0), NS_INVALID_PARAM);
        EXPECT_ST(HH_P_FINISH()(h, NULL, 16, 0), NS_INVALID_PARAM);
        EXPECT_ST(HH_P_FINISH()(h, out, 16, 0), 0);
        HH_P_DESTROY()(h);
    }
    hh_close(a);
}
TEST(hh_gmac_nist_gcm_zero_key_empty_message) {
    NEED();
    if (!HH_P_SETPROP()) { t_skip("missing BCryptSetProperty"); return; }
    BCRYPT_ALG_HANDLE a = open_or_skip(L"AES-GMAC", 0, "AES-GMAC");
    if (!a) return;
    BYTE key[16] = {0}, iv[12] = {0}, out[16];
    EXPECT_ST(gmac_compute(a, key, 16, iv, 12, NULL, 0, 0, 0, out), 0);
    CHECK(hh_eqhex(out, 16, "58e2fccefa7e3061367f1d57a4e7455a"));   /* GCM spec test case 1 tag */
    hh_close(a);
}
TEST(hh_gmac_different_iv_different_tag) {
    NEED();
    if (!HH_P_SETPROP()) { t_skip("missing BCryptSetProperty"); return; }
    BCRYPT_ALG_HANDLE a = open_or_skip(L"AES-GMAC", 0, "AES-GMAC");
    if (!a) return;
    BYTE key[16] = {9}, iv1[12] = {1}, iv2[12] = {2}, o1[16], o2[16];
    EXPECT_ST(gmac_compute(a, key, 16, iv1, 12, (PUCHAR)"aad", 3, 0, 0, o1), 0);
    EXPECT_ST(gmac_compute(a, key, 16, iv2, 12, (PUCHAR)"aad", 3, 0, 0, o2), 0);
    CHECK(memcmp(o1, o2, 16) != 0);
    hh_close(a);
}

/* ===================== multi hash ===================== */
struct mh { const char *alg; int hmac; };
static void multi_check_one(const char *algname, int hmac, ULONG n, int interleave, int callerbuf) {
    NEED();
    if (!HH_P_CMULTI() || !HH_P_PMULTI()) { t_skip("BCryptCreateMultiHash/ProcessMultiOperations not exported"); return; }
    const struct hh_alg *ai = hh_find(algname);
    BCRYPT_ALG_HANDLE a = hh_open(ai->wname, hmac ? BCRYPT_ALG_HANDLE_HMAC_FLAG : 0);
    if (!a) return;
    BYTE *obj = NULL; ULONG ol = 0;
    if (callerbuf) {
        ULONG mol[2] = {0, 0}, cb = 0;
        if (HH_P_GETPROP()(a, L"MultiObjectLength", (PUCHAR)mol, sizeof mol, &cb, 0) == 0) {
            ol = mol[0] + mol[1] * n;
            obj = _aligned_malloc(ol + 16, 16);
        } else { t_note("%s: no MultiObjectLength", algname); hh_close(a); return; }
    }
    BCRYPT_HASH_HANDLE h = NULL;
    BYTE key[40]; hh_lcg_fill(key, sizeof key, 3);
    NTSTATUS st = HH_P_CMULTI()(a, &h, n, obj, ol, hmac ? key : NULL, hmac ? sizeof key : 0, 0);
    /* Win10 22H2 (19045): BCryptCreateMultiHash returns STATUS_NOT_SUPPORTED for every algorithm, plain and HMAC,
     * although MultiObjectLength is answered and AVX2 is present (probed). The result is pinned; the correctness
     * checks below only run on a system where multi hash is available. */
    if (st == NS_NOT_SUPPORTED) {
        EXPECT_ST(st, NS_NOT_SUPPORTED);
        if (obj) _aligned_free(obj);
        hh_close(a); return;
    }
    EXPECT_ST(st, 0);
    if (st) { if (obj) _aligned_free(obj); hh_close(a); return; }
    ULONG maxm = 200;
    BYTE msgs[17][200]; ULONG lens[17];
    for (ULONG i = 0; i < n; i++) { lens[i] = (i * 37 + 5) % maxm; hh_lcg_fill(msgs[i], maxm, 100 + i); }
    BCRYPT_MULTI_HASH_OPERATION ops[17 * 6]; ULONG no = 0; BYTE outs[17][64];
    memset(outs, 0xEE, sizeof outs);
    if (interleave) {
        for (ULONG piece = 0; piece < 2; piece++) for (ULONG i = 0; i < n; i++) {
            ULONG half = lens[i] / 2, off = piece ? half : 0, len = piece ? lens[i] - half : half;
            ops[no].iHash = i; ops[no].hashOperation = BCRYPT_HASH_OPERATION_HASH_DATA; ops[no].pbBuffer = msgs[i] + off; ops[no].cbBuffer = len; no++;
        }
    } else {
        for (ULONG i = 0; i < n; i++) { ops[no].iHash = i; ops[no].hashOperation = BCRYPT_HASH_OPERATION_HASH_DATA; ops[no].pbBuffer = msgs[i]; ops[no].cbBuffer = lens[i]; no++; }
    }
    for (ULONG i = 0; i < n; i++) { ops[no].iHash = n - 1 - i; ops[no].hashOperation = BCRYPT_HASH_OPERATION_FINISH_HASH; ops[no].pbBuffer = outs[n - 1 - i]; ops[no].cbBuffer = ai->digest; no++; }
    EXPECT_ST(HH_P_PMULTI()(h, BCRYPT_OPERATION_TYPE_HASH, ops, no * sizeof ops[0], 0), 0);
    for (ULONG i = 0; i < n; i++) {
        BYTE want[64];
        NTSTATUS s2 = HH_P_HASH()(hmac ? ai->hmac_pseudo : ai->pseudo, hmac ? key : NULL, hmac ? sizeof key : 0, msgs[i], lens[i], want, ai->digest);
        EXPECT_ST(s2, 0);
        CHECKF(!memcmp(outs[i], want, ai->digest), "%s%s element %lu of %lu (len %lu)", algname, hmac ? " HMAC" : "", (unsigned long)i, (unsigned long)n, (unsigned long)lens[i]);
    }
    EXPECT_ST(HH_P_DESTROY()(h), 0);
    if (obj) _aligned_free(obj);
    hh_close(a);
}
static void multi_all_counts(const char *alg, int hmac) {
    static const ULONG counts[] = {1, 2, 3, 4, 5, 7, 8, 9, 16, 17};
    for (unsigned c = 0; c < sizeof counts / sizeof *counts; c++) {
        multi_check_one(alg, hmac, counts[c], 0, 0);
        multi_check_one(alg, hmac, counts[c], 1, 0);
        multi_check_one(alg, hmac, counts[c], 1, 1);
    }
}
TEST(hh_multi_sha256) { multi_all_counts("SHA256", 0); }
TEST(hh_multi_sha512) { multi_all_counts("SHA512", 0); }
TEST(hh_multi_sha384) { multi_all_counts("SHA384", 0); }
TEST(hh_multi_sha1)   { multi_all_counts("SHA1", 0); }
TEST(hh_multi_md5)    { multi_all_counts("MD5", 0); }
TEST(hh_multi_md4)    { multi_all_counts("MD4", 0); }
TEST(hh_multi_md2)    { multi_all_counts("MD2", 0); }
TEST(hh_multi_hmac_sha256) { multi_all_counts("SHA256", 1); }
TEST(hh_multi_hmac_sha512) { multi_all_counts("SHA512", 1); }
TEST(hh_multi_hmac_sha384) { multi_all_counts("SHA384", 1); }
TEST(hh_multi_hmac_sha1)   { multi_all_counts("SHA1", 1); }
TEST(hh_multi_hmac_md5)    { multi_all_counts("MD5", 1); }

static BCRYPT_HASH_HANDLE multi_new(BCRYPT_ALG_HANDLE a, ULONG n) {
    BCRYPT_HASH_HANDLE h = NULL;
    NTSTATUS st = HH_P_CMULTI()(a, &h, n, NULL, 0, NULL, 0, 0);
    /* Win10 22H2: multi hash creation is STATUS_NOT_SUPPORTED for every algorithm (see multi_check_one) */
    if (st == NS_NOT_SUPPORTED) { EXPECT_ST(st, NS_NOT_SUPPORTED); return NULL; }
    EXPECT_ST(st, 0);
    return st ? NULL : h;
}
#define NEED_MULTI() do { NEED(); if (!HH_P_CMULTI() || !HH_P_PMULTI()) { t_skip("multi hash not exported"); return; } } while (0)
TEST(hh_multi_create_zero_hashes) {
    NEED_MULTI();
    BCRYPT_HASH_HANDLE h = (BCRYPT_HASH_HANDLE)(ULONG_PTR)0x77;
    EXPECT_ST(HH_P_CMULTI()(BCRYPT_SHA256_ALG_HANDLE, &h, 0, NULL, 0, NULL, 0, 0), NS_INVALID_PARAM);
    CHECK(h == (BCRYPT_HASH_HANDLE)(ULONG_PTR)0x77);
}
TEST(hh_multi_create_null_algorithm) {
    NEED_MULTI();
    BCRYPT_HASH_HANDLE h = (BCRYPT_HASH_HANDLE)(ULONG_PTR)0x77;
    EXPECT_ST(HH_P_CMULTI()(NULL, &h, 4, NULL, 0, NULL, 0, 0), NS_INVALID_HANDLE);
    EXPECT_ST(HH_P_CMULTI()(NULL, &h, 0, NULL, 0, NULL, 0, 0), NS_INVALID_HANDLE);   /* handle first, then the count */
}
TEST(hh_multi_create_null_phash_and_object_rules) {
    NEED_MULTI();
    BYTE buf[2048]; BCRYPT_HASH_HANDLE h = (BCRYPT_HASH_HANDLE)(ULONG_PTR)0x77;
    EXPECT_ST(HH_P_CMULTI()(BCRYPT_SHA256_ALG_HANDLE, NULL, 4, NULL, 0, NULL, 0, 0), NS_INVALID_PARAM);
    EXPECT_ST(HH_P_CMULTI()(BCRYPT_SHA256_ALG_HANDLE, NULL, 4, buf, sizeof buf, NULL, 0, 0), NS_INVALID_PARAM);
    EXPECT_ST(HH_P_CMULTI()(BCRYPT_SHA256_ALG_HANDLE, &h, 4, NULL, 100, NULL, 0, 0), NS_INVALID_PARAM);
    EXPECT_ST(HH_P_CMULTI()(BCRYPT_SHA256_ALG_HANDLE, &h, 4, buf, 0, NULL, 0, 0), NS_BUFFER_TOO_SMALL);
    EXPECT_ST(HH_P_CMULTI()(BCRYPT_SHA256_ALG_HANDLE, &h, 4, buf, 0x45, NULL, 0, 0), NS_BUFFER_TOO_SMALL);
    CHECK(h == (BCRYPT_HASH_HANDLE)(ULONG_PTR)0x77);
}
TEST(hh_multi_create_object_smaller_than_multiobjectlength) {
    NEED_MULTI();
    ULONG mol[2] = {0, 0}, cb = 0;
    if (HH_P_GETPROP()(BCRYPT_SHA256_ALG_HANDLE, L"MultiObjectLength", (PUCHAR)mol, sizeof mol, &cb, 0)) { t_skip("no MultiObjectLength"); return; }
    BYTE *buf = _aligned_malloc(mol[0] + mol[1] * 8 + 64, 16); BCRYPT_HASH_HANDLE h = (BCRYPT_HASH_HANDLE)(ULONG_PTR)0x77;
    NTSTATUS st = HH_P_CMULTI()(BCRYPT_SHA256_ALG_HANDLE, &h, 8, buf, mol[0] + mol[1] * 4, NULL, 0, 0);   /* sized for 4, asked for 8 */
    EXPECT_ST(st, NS_BUFFER_TOO_SMALL);
    CHECK(h == (BCRYPT_HASH_HANDLE)(ULONG_PTR)0x77);
    _aligned_free(buf);
}
TEST(hh_multi_create_flags) {
    NEED_MULTI();
    BCRYPT_HASH_HANDLE h = (BCRYPT_HASH_HANDLE)(ULONG_PTR)0x77;
    static const ULONG bad[] = {1, 2, 4, 8, 0x10, 0x40, 0x80000000};
    for (unsigned i = 0; i < sizeof bad / sizeof *bad; i++) EXPECT_ST(HH_P_CMULTI()(BCRYPT_SHA256_ALG_HANDLE, &h, 4, NULL, 0, NULL, 0, bad[i]), NS_INVALID_PARAM);
    CHECK(h == (BCRYPT_HASH_HANDLE)(ULONG_PTR)0x77);
    EXPECT_ST(HH_P_CMULTI()(BCRYPT_SHA256_ALG_HANDLE, &h, 4, NULL, 0, NULL, 0, BCRYPT_HASH_REUSABLE_FLAG), 0);
    if (h != (BCRYPT_HASH_HANDLE)(ULONG_PTR)0x77) HH_P_DESTROY()(h);
}
TEST(hh_multi_create_non_hash_algorithm) {
    NEED_MULTI();
    BCRYPT_ALG_HANDLE a = hh_open(L"AES", 0);
    if (!a) return;
    BCRYPT_HASH_HANDLE h = (BCRYPT_HASH_HANDLE)(ULONG_PTR)0x77;
    BYTE buf[4096];
    EXPECT_ST(HH_P_CMULTI()(a, &h, 4, buf, sizeof buf, NULL, 0, 0), NS_NOT_SUPPORTED);
    CHECK(h == (BCRYPT_HASH_HANDLE)(ULONG_PTR)0x77);
    hh_close(a);
}
TEST(hh_multi_create_gmac_not_supported) {
    NEED_MULTI();
    BCRYPT_ALG_HANDLE a = hh_open(L"AES-GMAC", 0);
    if (!a) return;
    BCRYPT_HASH_HANDLE h = (BCRYPT_HASH_HANDLE)(ULONG_PTR)0x77;
    BYTE key[16] = {1};
    EXPECT_ST(HH_P_CMULTI()(a, &h, 4, NULL, 0, key, 16, 0), NS_NOT_SUPPORTED);
    hh_close(a);
}
TEST(hh_multi_create_plain_hash_rejects_secret) {
    NEED_MULTI();
    if (t_is_wine()) { t_skip("emulator lacks multi hash validation"); return; }
    BCRYPT_HASH_HANDLE h = (BCRYPT_HASH_HANDLE)(ULONG_PTR)0x77;
    EXPECT_ST(HH_P_CMULTI()(BCRYPT_SHA256_ALG_HANDLE, &h, 4, NULL, 0, (PUCHAR)"k", 1, 0), NS_INVALID_PARAM);
}
TEST(hh_multi_process_null_and_foreign_handles) {
    NEED_MULTI();
    BCRYPT_MULTI_HASH_OPERATION op = {0, BCRYPT_HASH_OPERATION_HASH_DATA, (PUCHAR)"a", 1};
    EXPECT_ST(HH_P_PMULTI()(NULL, BCRYPT_OPERATION_TYPE_HASH, &op, sizeof op, 0), NS_INVALID_HANDLE);
    /* a hash created by BCryptCreateHash is not a multi hash */
    BCRYPT_HASH_HANDLE h = NULL;
    EXPECT_ST(HH_P_CREATE()(BCRYPT_SHA256_ALG_HANDLE, &h, NULL, 0, NULL, 0, 0), 0);
    if (h) {
        EXPECT_ST(HH_P_PMULTI()(h, BCRYPT_OPERATION_TYPE_HASH, &op, sizeof op, 0), NS_INVALID_HANDLE);
        HH_P_DESTROY()(h);
    }
    BCRYPT_ALG_HANDLE a = hh_open(L"SHA256", 0);
    if (a) { EXPECT_ST(HH_P_PMULTI()((BCRYPT_HASH_HANDLE)a, BCRYPT_OPERATION_TYPE_HASH, &op, sizeof op, 0), NS_INVALID_HANDLE); hh_close(a); }
}
TEST(hh_multi_process_argument_validation) {
    NEED_MULTI();
    BCRYPT_HASH_HANDLE h = multi_new(BCRYPT_SHA256_ALG_HANDLE, 4);
    if (!h) return;
    BCRYPT_MULTI_HASH_OPERATION op = {0, BCRYPT_HASH_OPERATION_HASH_DATA, (PUCHAR)"a", 1};
    EXPECT_ST(HH_P_PMULTI()(h, BCRYPT_OPERATION_TYPE_HASH, NULL, sizeof op, 0), NS_INVALID_PARAM);
    EXPECT_ST(HH_P_PMULTI()(h, BCRYPT_OPERATION_TYPE_HASH, &op, 0, 0), NS_INVALID_PARAM);
    EXPECT_ST(HH_P_PMULTI()(h, BCRYPT_OPERATION_TYPE_HASH, &op, sizeof op - 1, 0), NS_INVALID_PARAM);
    EXPECT_ST(HH_P_PMULTI()(h, BCRYPT_OPERATION_TYPE_HASH, &op, sizeof op + 1, 0), NS_INVALID_PARAM);
    EXPECT_ST(HH_P_PMULTI()(h, BCRYPT_OPERATION_TYPE_HASH, &op, sizeof op, 1), NS_INVALID_PARAM);
    EXPECT_ST(HH_P_PMULTI()(h, (BCRYPT_MULTI_OPERATION_TYPE)0, &op, sizeof op, 0), NS_INVALID_PARAM);
    EXPECT_ST(HH_P_PMULTI()(h, (BCRYPT_MULTI_OPERATION_TYPE)2, &op, sizeof op, 0), NS_INVALID_PARAM);
    EXPECT_ST(HH_P_DESTROY()(h), 0);
}
TEST(hh_multi_process_bad_operation_fields) {
    NEED_MULTI();
    BCRYPT_HASH_HANDLE h = multi_new(BCRYPT_SHA256_ALG_HANDLE, 4);
    if (!h) return;
    BYTE out[32];
    BCRYPT_MULTI_HASH_OPERATION op = {0, (BCRYPT_HASH_OPERATION_TYPE)0, (PUCHAR)"a", 1};
    EXPECT_ST(HH_P_PMULTI()(h, BCRYPT_OPERATION_TYPE_HASH, &op, sizeof op, 0), NS_INVALID_PARAM);
    op.hashOperation = (BCRYPT_HASH_OPERATION_TYPE)3;
    EXPECT_ST(HH_P_PMULTI()(h, BCRYPT_OPERATION_TYPE_HASH, &op, sizeof op, 0), NS_INVALID_PARAM);
    op.hashOperation = BCRYPT_HASH_OPERATION_FINISH_HASH; op.pbBuffer = out;
    static const ULONG badcb[] = {0, 1, 31, 33, 64};
    for (unsigned i = 0; i < sizeof badcb / sizeof *badcb; i++) { op.cbBuffer = badcb[i]; EXPECT_ST(HH_P_PMULTI()(h, BCRYPT_OPERATION_TYPE_HASH, &op, sizeof op, 0), NS_INVALID_PARAM); }
    op.cbBuffer = 32;
    EXPECT_ST(HH_P_PMULTI()(h, BCRYPT_OPERATION_TYPE_HASH, &op, sizeof op, 0), 0);   /* a correct finish still works afterwards */
    HH_P_DESTROY()(h);
}
TEST(hh_multi_process_element_index_out_of_range) {
    NEED_MULTI();
    /* SHA-1 uses the serial path whose per-operation index check is visible in bcryptprimitives */
    BCRYPT_ALG_HANDLE a = hh_open(L"SHA1", 0);
    BCRYPT_HASH_HANDLE h = a ? multi_new(a, 3) : NULL;
    if (h) {
        BCRYPT_MULTI_HASH_OPERATION op = {3, BCRYPT_HASH_OPERATION_HASH_DATA, (PUCHAR)"a", 1};
        EXPECT_ST(HH_P_PMULTI()(h, BCRYPT_OPERATION_TYPE_HASH, &op, sizeof op, 0), NS_INVALID_PARAM);
        op.iHash = 0xffffffff;
        EXPECT_ST(HH_P_PMULTI()(h, BCRYPT_OPERATION_TYPE_HASH, &op, sizeof op, 0), NS_INVALID_PARAM);
        op.iHash = 2;
        EXPECT_ST(HH_P_PMULTI()(h, BCRYPT_OPERATION_TYPE_HASH, &op, sizeof op, 0), 0);
        HH_P_DESTROY()(h);
    }
    hh_close(a);
}
TEST(hh_multi_handle_cannot_be_duplicated) {
    NEED_MULTI();
    if (!HH_P_DUP()) { t_skip("missing export"); return; }
    BCRYPT_HASH_HANDLE h = multi_new(BCRYPT_SHA256_ALG_HANDLE, 2), d = (BCRYPT_HASH_HANDLE)(ULONG_PTR)0x77;
    if (!h) return;
    EXPECT_ST(HH_P_DUP()(h, &d, NULL, 0, 0), NS_INVALID_PARAM);
    CHECK(d == (BCRYPT_HASH_HANDLE)(ULONG_PTR)0x77);
    HH_P_DESTROY()(h);
}
TEST(hh_multi_single_element_equals_plain_hash_abc) {
    NEED_MULTI();
    BCRYPT_HASH_HANDLE h = multi_new(BCRYPT_SHA256_ALG_HANDLE, 1);
    if (!h) return;
    BCRYPT_MULTI_HASH_OPERATION ops[2] = {
        {0, BCRYPT_HASH_OPERATION_HASH_DATA, (PUCHAR)"abc", 3},
        {0, BCRYPT_HASH_OPERATION_FINISH_HASH, NULL, 32},
    };
    BYTE out[32]; ops[1].pbBuffer = out;
    EXPECT_ST(HH_P_PMULTI()(h, BCRYPT_OPERATION_TYPE_HASH, ops, sizeof ops, 0), 0);
    CHECK(hh_eqhex(out, 32, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
    HH_P_DESTROY()(h);
}
TEST(hh_multi_multiple_process_calls_accumulate) {
    NEED_MULTI();
    BCRYPT_HASH_HANDLE h = multi_new(BCRYPT_SHA256_ALG_HANDLE, 2);
    if (!h) return;
    BCRYPT_MULTI_HASH_OPERATION o1[2] = {{0, BCRYPT_HASH_OPERATION_HASH_DATA, (PUCHAR)"ab", 2}, {1, BCRYPT_HASH_OPERATION_HASH_DATA, (PUCHAR)"xy", 2}};
    BCRYPT_MULTI_HASH_OPERATION o2[2] = {{0, BCRYPT_HASH_OPERATION_HASH_DATA, (PUCHAR)"c", 1}, {1, BCRYPT_HASH_OPERATION_HASH_DATA, (PUCHAR)"z", 1}};
    BYTE out0[32], out1[32], w0[32], w1[32];
    BCRYPT_MULTI_HASH_OPERATION o3[2] = {{0, BCRYPT_HASH_OPERATION_FINISH_HASH, out0, 32}, {1, BCRYPT_HASH_OPERATION_FINISH_HASH, out1, 32}};
    EXPECT_ST(HH_P_PMULTI()(h, BCRYPT_OPERATION_TYPE_HASH, o1, sizeof o1, 0), 0);
    EXPECT_ST(HH_P_PMULTI()(h, BCRYPT_OPERATION_TYPE_HASH, o2, sizeof o2, 0), 0);
    EXPECT_ST(HH_P_PMULTI()(h, BCRYPT_OPERATION_TYPE_HASH, o3, sizeof o3, 0), 0);
    HH_P_HASH()(BCRYPT_SHA256_ALG_HANDLE, NULL, 0, (PUCHAR)"abc", 3, w0, 32);
    HH_P_HASH()(BCRYPT_SHA256_ALG_HANDLE, NULL, 0, (PUCHAR)"xyz", 3, w1, 32);
    CHECK(!memcmp(out0, w0, 32)); CHECK(!memcmp(out1, w1, 32));
    HH_P_DESTROY()(h);
}
