/* Hash/algorithm properties, handle lifetime, algorithm-handle reuse, threads and processes. */
#include "hh.h"

#define NEED() do { if (!HH_P_CREATE() || !HH_P_DATA() || !HH_P_FINISH() || !HH_P_DESTROY() || !HH_P_OPEN() || !HH_P_CLOSE() || !HH_P_GETPROP()) { t_skip("missing export"); return; } } while (0)
#define FOR_ALGS(ai) for (const struct hh_alg *ai = hh_algs; ai < hh_algs + hh_nalgs; ai++)

static BCRYPT_HASH_HANDLE mk(BCRYPT_ALG_HANDLE a, const BYTE *key, ULONG kl, ULONG flags) {
    BCRYPT_HASH_HANDLE h = NULL;
    EXPECT_ST(HH_P_CREATE()(a, &h, NULL, 0, (PUCHAR)key, kl, flags), 0);
    return h;
}

/* ===================== BCryptGetProperty argument handling ===================== */
TEST(hh_prop_null_property_name) {
    NEED();
    BYTE b[16]; ULONG cb = 0;
    EXPECT_ST(HH_P_GETPROP()(BCRYPT_SHA256_ALG_HANDLE, NULL, b, sizeof b, &cb, 0), NS_INVALID_PARAM);
    EXPECT_ST(HH_P_GETPROP()(BCRYPT_SHA256_ALG_HANDLE, L"", b, sizeof b, &cb, 0), NS_INVALID_PARAM);
}
TEST(hh_prop_null_result_size_pointer) {
    NEED();
    BYTE b[16];
    EXPECT_ST(HH_P_GETPROP()(BCRYPT_SHA256_ALG_HANDLE, BCRYPT_HASH_LENGTH, b, sizeof b, NULL, 0), NS_INVALID_PARAM);
    EXPECT_ST(HH_P_GETPROP()(NULL, BCRYPT_HASH_LENGTH, b, sizeof b, NULL, 0), NS_INVALID_PARAM);   /* parameters are checked before the handle */
}
TEST(hh_prop_null_handle) {
    NEED();
    BYTE b[16]; ULONG cb = 0;
    EXPECT_ST(HH_P_GETPROP()(NULL, BCRYPT_HASH_LENGTH, b, sizeof b, &cb, 0), NS_INVALID_HANDLE);
}
TEST(hh_prop_digest_length_on_algorithm) {
    NEED();
    FOR_ALGS(ai) {
        BCRYPT_ALG_HANDLE a = hh_open(ai->wname, 0);
        ULONG v = 0, cb = 0;
        EXPECT_ST(HH_P_GETPROP()(a, BCRYPT_HASH_LENGTH, (PUCHAR)&v, 4, &cb, 0), 0);
        EXPECT_EQ(v, ai->digest); EXPECT_EQ(cb, 4);
        EXPECT_ST(HH_P_GETPROP()(ai->pseudo, BCRYPT_HASH_LENGTH, (PUCHAR)&v, 4, &cb, 0), 0);
        EXPECT_EQ(v, ai->digest);
        hh_close(a);
    }
}
TEST(hh_prop_digest_length_size_protocol) {
    NEED();
    FOR_ALGS(ai) {
        ULONG v = 0xAAAAAAAA, cb = 0;
        EXPECT_ST(HH_P_GETPROP()(ai->pseudo, BCRYPT_HASH_LENGTH, NULL, 0, &cb, 0), 0);      /* size query */
        EXPECT_EQ(cb, 4);
        cb = 0;
        EXPECT_ST(HH_P_GETPROP()(ai->pseudo, BCRYPT_HASH_LENGTH, (PUCHAR)&v, 3, &cb, 0), NS_BUFFER_TOO_SMALL);
        EXPECT_EQ(cb, 4);
        CHECK(v == 0xAAAAAAAA);
        BYTE big[16]; memset(big, 0xCC, sizeof big); cb = 0;
        EXPECT_ST(HH_P_GETPROP()(ai->pseudo, BCRYPT_HASH_LENGTH, big, sizeof big, &cb, 0), 0);
        EXPECT_EQ(cb, 4);
        CHECK(big[4] == 0xCC);
    }
}
TEST(hh_prop_block_length_on_algorithm) {
    NEED();
    FOR_ALGS(ai) {
        int ok; ULONG v = hh_prop_ulong(ai->pseudo, BCRYPT_HASH_BLOCK_LENGTH, &ok);
        if (!ok && t_is_wine()) { t_skip("emulator lacks HashBlockLength"); continue; }
        CHECKF(ok, "%s", ai->name);
        EXPECT_EQ(v, ai->block);
    }
}
TEST(hh_prop_algorithm_name_on_algorithm) {
    NEED();
    FOR_ALGS(ai) {
        WCHAR buf[32]; ULONG cb = 0, want = (ULONG)(wcslen(ai->wname) + 1) * 2;
        memset(buf, 0, sizeof buf);
        EXPECT_ST(HH_P_GETPROP()(ai->pseudo, BCRYPT_ALGORITHM_NAME, NULL, 0, &cb, 0), 0);
        EXPECT_EQ(cb, want);
        cb = 0;
        EXPECT_ST(HH_P_GETPROP()(ai->pseudo, BCRYPT_ALGORITHM_NAME, (PUCHAR)buf, sizeof buf, &cb, 0), 0);
        EXPECT_EQ(cb, want);
        CHECK(!wcscmp(buf, ai->wname));
        cb = 0;
        EXPECT_ST(HH_P_GETPROP()(ai->pseudo, BCRYPT_ALGORITHM_NAME, (PUCHAR)buf, want - 1, &cb, 0), NS_BUFFER_TOO_SMALL);
        EXPECT_EQ(cb, want);
    }
}
TEST(hh_prop_object_length_usable_for_create) {
    NEED();
    FOR_ALGS(ai) {
        int ok; ULONG ol = hh_prop_ulong(ai->pseudo, BCRYPT_OBJECT_LENGTH, &ok);
        CHECK(ok);
        t_note("%s ObjectLength=%lu", ai->name, (unsigned long)ol);
        CHECK(ol >= 0x46);
        BYTE *obj = _aligned_malloc(ol, 16); BCRYPT_HASH_HANDLE h = NULL;
        EXPECT_ST(HH_P_CREATE()(ai->pseudo, &h, obj, ol, NULL, 0, 0), 0);
        if (h) HH_P_DESTROY()(h);
        _aligned_free(obj);
    }
}
TEST(hh_prop_object_length_same_for_hmac_open_flag) {
    NEED();
    FOR_ALGS(ai) {
        BCRYPT_ALG_HANDLE a = hh_open(ai->wname, BCRYPT_ALG_HANDLE_HMAC_FLAG);
        ULONG o1 = hh_objlen(ai->pseudo), o2 = hh_objlen(a);
        t_note("%s ObjectLength plain=%lu hmac=%lu", ai->name, (unsigned long)o1, (unsigned long)o2);
        CHECK(o2 >= 0x46);
        if (a) {   /* an HMAC object needs at least as much room as a plain one */
            CHECK(o2 >= o1);
            BYTE *obj = _aligned_malloc(o2, 16); BCRYPT_HASH_HANDLE h = NULL;
            EXPECT_ST(HH_P_CREATE()(a, &h, obj, o2, (PUCHAR)"k", 1, 0), 0);
            if (h) HH_P_DESTROY()(h);
            _aligned_free(obj);
        }
        hh_close(a);
    }
}
TEST(hh_prop_on_hash_handle) {
    NEED();
    FOR_ALGS(ai) {
        BCRYPT_HASH_HANDLE h = mk(ai->pseudo, NULL, 0, 0);
        if (!h) continue;
        ULONG v = 0, cb = 0; WCHAR name[32] = {0};
        EXPECT_ST(HH_P_GETPROP()(h, BCRYPT_HASH_LENGTH, (PUCHAR)&v, 4, &cb, 0), 0);
        EXPECT_EQ(v, ai->digest);
        EXPECT_ST(HH_P_GETPROP()(h, BCRYPT_ALGORITHM_NAME, (PUCHAR)name, sizeof name, &cb, 0), 0);
        CHECK(!wcscmp(name, ai->wname));
        EXPECT_ST(HH_P_GETPROP()(h, BCRYPT_HASH_LENGTH, (PUCHAR)&v, 2, &cb, 0), NS_BUFFER_TOO_SMALL);
        HH_P_DESTROY()(h);
    }
}
TEST(hh_prop_hash_handle_after_finish_still_answers) {
    NEED();
    BCRYPT_HASH_HANDLE h = mk(BCRYPT_SHA1_ALG_HANDLE, NULL, 0, 0);
    if (!h) return;
    BYTE out[20]; ULONG v = 0, cb = 0;
    HH_P_FINISH()(h, out, 20, 0);
    NTSTATUS st = HH_P_GETPROP()(h, BCRYPT_HASH_LENGTH, (PUCHAR)&v, 4, &cb, 0);
    t_note("GetProperty(HashDigestLength) on a finished hash -> 0x%08lx", (unsigned long)st);
    HH_P_DESTROY()(h);
}
TEST(hh_prop_is_keyed_hash) {
    NEED();
    FOR_ALGS(ai) {
        int ok; ULONG v;
        BCRYPT_HASH_HANDLE hp = mk(ai->pseudo, NULL, 0, 0), hm = mk(ai->hmac_pseudo, (PUCHAR)"k", 1, 0);
        if (hp) { v = hh_prop_ulong(hp, L"IsKeyedHash", &ok); t_note("%s plain hash IsKeyedHash ok=%d v=%lu", ai->name, ok, (unsigned long)v); if (ok) CHECK(v == 0); HH_P_DESTROY()(hp); }
        if (hm) { v = hh_prop_ulong(hm, L"IsKeyedHash", &ok); CHECK(ok); EXPECT_EQ(v, 1); HH_P_DESTROY()(hm); }
    }
}
TEST(hh_prop_is_reusable_hash) {
    NEED();
    FOR_ALGS(ai) {
        int ok; ULONG v;
        /* opened handle: reusable only with the flag; pseudo handle: always reusable (probed on Win10 22H2) */
        BCRYPT_ALG_HANDLE oa = hh_open(ai->wname, 0);
        if (!oa) continue;
        BCRYPT_HASH_HANDLE h0 = mk(oa, NULL, 0, 0), h1 = mk(oa, NULL, 0, BCRYPT_HASH_REUSABLE_FLAG);
        BCRYPT_HASH_HANDLE p0 = mk(ai->pseudo, NULL, 0, 0), p1 = mk(ai->pseudo, NULL, 0, BCRYPT_HASH_REUSABLE_FLAG);
        if (h0) { v = hh_prop_ulong(h0, L"IsReusableHash", &ok); CHECK(ok); EXPECT_EQ(v, 0); HH_P_DESTROY()(h0); }
        if (h1) { v = hh_prop_ulong(h1, L"IsReusableHash", &ok); CHECK(ok); EXPECT_EQ(v, 1); HH_P_DESTROY()(h1); }
        if (p0) { v = hh_prop_ulong(p0, L"IsReusableHash", &ok); CHECK(ok); EXPECT_EQ(v, 1); HH_P_DESTROY()(p0); }
        if (p1) { v = hh_prop_ulong(p1, L"IsReusableHash", &ok); CHECK(ok); EXPECT_EQ(v, 1); HH_P_DESTROY()(p1); }
        hh_close(oa);
    }
}
TEST(hh_prop_multi_object_length) {
    NEED();
    FOR_ALGS(ai) {
        ULONG v[2] = {0, 0}, cb = 0;
        NTSTATUS st = HH_P_GETPROP()(ai->pseudo, L"MultiObjectLength", (PUCHAR)v, sizeof v, &cb, 0);
        t_note("%s MultiObjectLength -> 0x%08lx perObject=%lu perElement=%lu", ai->name, (unsigned long)st, (unsigned long)v[0], (unsigned long)v[1]);
        if (st == 0) { EXPECT_EQ(cb, 8); CHECK(v[1] > 0); }
        else CHECK(st < 0);
    }
}
TEST(hh_prop_hash_oid_list) {
    NEED();
    struct oid { ULONG cb; PUCHAR pb; };
    struct oidlist { ULONG n; struct oid *p; };
    static const struct { const char *alg; const char *der; } want[] = {
        {"MD2", "06082a864886f70d0202"}, {"MD4", "06082a864886f70d0204"}, {"MD5", "06082a864886f70d0205"},
        {"SHA1", "06052b0e03021a"}, {"SHA256", "0609608648016503040201"}, {"SHA384", "0609608648016503040202"},
        {"SHA512", "0609608648016503040203"},
    };
    for (unsigned i = 0; i < sizeof want / sizeof *want; i++) {
        const struct hh_alg *ai = hh_find(want[i].alg);
        ULONG cb = 0;
        NTSTATUS st = HH_P_GETPROP()(ai->pseudo, L"HashOIDList", NULL, 0, &cb, 0);
        if (st) { t_note("%s HashOIDList size query -> 0x%08lx", ai->name, (unsigned long)st); continue; }
        BYTE *buf = malloc(cb + 16);
        EXPECT_ST(HH_P_GETPROP()(ai->pseudo, L"HashOIDList", buf, cb, &cb, 0), 0);
        struct oidlist *l = (struct oidlist *)buf;
        CHECK(l->n >= 1);
        BYTE exp[16]; ULONG el = hh_unhex(want[i].der, exp);
        int found = 0;
        for (ULONG k = 0; k < l->n && k < 8; k++)
            if (l->p[k].cb == el && !memcmp(l->p[k].pb, exp, el)) found = 1;
        CHECKF(found, "%s: DER OID %s not in HashOIDList", ai->name, want[i].der);
        free(buf);
    }
}
TEST(hh_prop_unknown_property_fails) {
    NEED();
    BYTE b[64]; ULONG cb = 0;
    NTSTATUS st = HH_P_GETPROP()(BCRYPT_SHA256_ALG_HANDLE, L"NoSuchProperty", b, sizeof b, &cb, 0);
    t_note("unknown property -> 0x%08lx", (unsigned long)st);
    CHECK(st < 0);
}
TEST(hh_prop_set_on_hash_handle_rejected) {
    NEED();
    if (!HH_P_SETPROP()) { t_skip("missing BCryptSetProperty"); return; }
    BCRYPT_HASH_HANDLE h = mk(BCRYPT_SHA256_ALG_HANDLE, NULL, 0, 0);
    if (!h) return;
    BYTE iv[12] = {0};
    EXPECT_ST(HH_P_SETPROP()(h, NULL, iv, sizeof iv, 0), NS_INVALID_PARAM);
    NTSTATUS st = HH_P_SETPROP()(h, L"IV", iv, sizeof iv, 0);
    EXPECT_ST(st, NS_NOT_SUPPORTED);                              /* only AES-GMAC objects accept "IV" */
    EXPECT_ST(HH_P_SETPROP()(NULL, L"IV", iv, sizeof iv, 0), NS_INVALID_HANDLE);
    HH_P_DESTROY()(h);
}

/* ===================== lifetime ===================== */
TEST(hh_life_hash_survives_algorithm_close) {
    NEED();
    FOR_ALGS(ai) {
        BCRYPT_ALG_HANDLE a = hh_open(ai->wname, 0);
        BCRYPT_HASH_HANDLE h = mk(a, NULL, 0, 0);
        hh_close(a);
        if (!h) continue;
        BYTE out[64], want[64];
        HH_P_HASH()(ai->pseudo, NULL, 0, (PUCHAR)"abc", 3, want, ai->digest);
        EXPECT_ST(HH_P_DATA()(h, (PUCHAR)"abc", 3, 0), 0);
        EXPECT_ST(HH_P_FINISH()(h, out, ai->digest, 0), 0);
        CHECK(!memcmp(out, want, ai->digest));
        EXPECT_ST(HH_P_DESTROY()(h), 0);
    }
}
TEST(hh_life_algorithm_handle_after_all_hashes_destroyed) {
    NEED();
    BCRYPT_ALG_HANDLE a = hh_open(L"SHA256", 0);
    for (int i = 0; i < 4; i++) { BCRYPT_HASH_HANDLE h = mk(a, NULL, 0, 0); if (h) HH_P_DESTROY()(h); }
    BYTE out[32], want[32];
    EXPECT_ST(hh_compute(a, NULL, 0, (PUCHAR)"abc", 3, 0, 0, out, 32), 0);
    HH_P_HASH()(BCRYPT_SHA256_ALG_HANDLE, NULL, 0, (PUCHAR)"abc", 3, want, 32);
    CHECK(!memcmp(out, want, 32));
    hh_close(a);
}
TEST(hh_life_close_algorithm_twice_with_hash_alive) {
    NEED();
    BCRYPT_ALG_HANDLE a = hh_open(L"SHA256", 0);
    BCRYPT_HASH_HANDLE h = mk(a, NULL, 0, 0);
    EXPECT_ST(HH_P_CLOSE()(a, 0), 0);
    if (h) {
        BYTE out[32];
        EXPECT_ST(HH_P_FINISH()(h, out, 32, 0), 0);
        HH_P_DESTROY()(h);
    }
}
TEST(hh_life_two_algorithm_handles_independent) {
    NEED();
    BCRYPT_ALG_HANDLE a = hh_open(L"SHA1", 0), b = hh_open(L"SHA1", 0);
    CHECK(a != b);
    BYTE x[20], y[20];
    EXPECT_ST(hh_compute(a, NULL, 0, (PUCHAR)"q", 1, 0, 0, x, 20), 0);
    hh_close(a);
    EXPECT_ST(hh_compute(b, NULL, 0, (PUCHAR)"q", 1, 0, 0, y, 20), 0);
    CHECK(!memcmp(x, y, 20));
    hh_close(b);
}
TEST(hh_life_hmac_and_plain_handles_from_one_process) {
    NEED();
    BCRYPT_ALG_HANDLE p = hh_open(L"SHA256", 0), m = hh_open(L"SHA256", BCRYPT_ALG_HANDLE_HMAC_FLAG);
    BYTE a1[32], a2[32], a3[32];
    EXPECT_ST(hh_compute(p, NULL, 0, (PUCHAR)"abc", 3, 0, 0, a1, 32), 0);
    EXPECT_ST(hh_compute(m, (PUCHAR)"k", 1, (PUCHAR)"abc", 3, 0, 0, a2, 32), 0);
    EXPECT_ST(hh_compute(p, NULL, 0, (PUCHAR)"abc", 3, 0, 0, a3, 32), 0);
    CHECK(memcmp(a1, a2, 32) != 0);
    CHECK(!memcmp(a1, a3, 32));
    hh_close(p); hh_close(m);
}
TEST(hh_life_thousand_create_finish_destroy_cycles) {
    NEED();
    FOR_ALGS(ai) {
        BCRYPT_ALG_HANDLE a = hh_open(ai->wname, 0);
        BYTE first[64], cur[64];
        for (int i = 0; i < 1000; i++) {
            NTSTATUS st = hh_compute(a, NULL, 0, (PUCHAR)"cycle", 5, 0, i & 1, cur, ai->digest);
            if (st) { CHECKF(0, "%s cycle %d -> 0x%08lx", ai->name, i, (unsigned long)st); break; }
            if (i == 0) memcpy(first, cur, ai->digest);
            else if (memcmp(first, cur, ai->digest)) { CHECKF(0, "%s cycle %d differs", ai->name, i); break; }
        }
        hh_close(a);
    }
}
TEST(hh_life_interleaved_hashes_do_not_interfere) {
    NEED();
    BCRYPT_ALG_HANDLE a = hh_open(L"SHA512", 0);
    BCRYPT_HASH_HANDLE h1 = mk(a, NULL, 0, 0), h2 = mk(a, NULL, 0, 0), h3 = NULL;
    /* a key on a non-HMAC algorithm is refused whatever its length (probed: 0, 1, 2 bytes and NULL with length 2) */
    EXPECT_ST(HH_P_CREATE()(a, &h3, NULL, 0, (PUCHAR)"zz", 0, 0), NS_INVALID_PARAM);
    EXPECT_ST(HH_P_CREATE()(a, &h3, NULL, 0, (PUCHAR)"zz", 2, 0), NS_INVALID_PARAM);
    h3 = NULL;
    BYTE o1[64], o2[64], w1[64], w2[64];
    if (h1 && h2) {
        for (int i = 0; i < 50; i++) { HH_P_DATA()(h1, (PUCHAR)"AB", 2, 0); HH_P_DATA()(h2, (PUCHAR)"xyz", 3, 0); }
        EXPECT_ST(HH_P_FINISH()(h2, o2, 64, 0), 0);
        EXPECT_ST(HH_P_FINISH()(h1, o1, 64, 0), 0);
        BYTE a1[100], a2[150];
        for (int i = 0; i < 50; i++) { memcpy(a1 + 2 * i, "AB", 2); memcpy(a2 + 3 * i, "xyz", 3); }
        HH_P_HASH()(a, NULL, 0, a1, 100, w1, 64); HH_P_HASH()(a, NULL, 0, a2, 150, w2, 64);
        CHECK(!memcmp(o1, w1, 64)); CHECK(!memcmp(o2, w2, 64));
    }
    if (h1) HH_P_DESTROY()(h1);
    if (h2) HH_P_DESTROY()(h2);
    if (h3) HH_P_DESTROY()(h3);
    hh_close(a);
}

/* ===================== threads ===================== */
struct thr { BCRYPT_ALG_HANDLE a; unsigned id; int bad; };
static DWORD WINAPI thr_main(LPVOID p) {
    struct thr *t = p;
    BYTE msg[257], out[32], want[32];
    hh_lcg_fill(msg, sizeof msg, 1000 + t->id);
    NTSTATUS st = HH_P_HASH()(t->a, NULL, 0, msg, sizeof msg, want, 32);
    if (st) { t->bad++; return 1; }
    for (int i = 0; i < 300; i++) {
        st = hh_compute(t->a, NULL, 0, msg, sizeof msg, 1 + (i % 50), i % 3 ? 0 : 1, out, 32);
        if (st || memcmp(out, want, 32)) { t->bad++; break; }
    }
    return 0;
}
TEST(hh_thread_parallel_hashing_shared_algorithm_handle) {
    NEED();
    BCRYPT_ALG_HANDLE a = hh_open(L"SHA256", 0);
    struct thr t[4]; HANDLE h[4];
    for (int i = 0; i < 4; i++) { t[i].a = a; t[i].id = i; t[i].bad = 0; h[i] = CreateThread(NULL, 0, thr_main, &t[i], 0, NULL); }
    for (int i = 0; i < 4; i++) {
        if (!h[i]) { CHECK(h[i] != NULL); continue; }
        CHECK(WaitForSingleObject(h[i], 30000) == WAIT_OBJECT_0);
        EXPECT_EQ(t[i].bad, 0);
        CloseHandle(h[i]);
    }
    hh_close(a);
}
TEST(hh_thread_parallel_hashing_pseudo_handles) {
    NEED();
    struct thr t[4]; HANDLE h[4];
    for (int i = 0; i < 4; i++) { t[i].a = BCRYPT_SHA256_ALG_HANDLE; t[i].id = 10 + i; t[i].bad = 0; h[i] = CreateThread(NULL, 0, thr_main, &t[i], 0, NULL); }
    for (int i = 0; i < 4; i++) {
        if (!h[i]) continue;
        CHECK(WaitForSingleObject(h[i], 30000) == WAIT_OBJECT_0);
        EXPECT_EQ(t[i].bad, 0);
        CloseHandle(h[i]);
    }
}
struct hand { BCRYPT_HASH_HANDLE h; NTSTATUS st; };
static DWORD WINAPI hand_main(LPVOID p) {
    struct hand *x = p;
    x->st = HH_P_DATA()(x->h, (PUCHAR)"def", 3, 0);
    return 0;
}
TEST(hh_thread_hash_handle_moves_between_threads) {
    NEED();
    BCRYPT_HASH_HANDLE h = mk(BCRYPT_SHA256_ALG_HANDLE, NULL, 0, 0);
    if (!h) return;
    EXPECT_ST(HH_P_DATA()(h, (PUCHAR)"abc", 3, 0), 0);
    struct hand x = {h, 0x12345};
    HANDLE th = CreateThread(NULL, 0, hand_main, &x, 0, NULL);
    CHECK(th != NULL);
    if (th) { WaitForSingleObject(th, 10000); CloseHandle(th); }
    EXPECT_EQ(x.st, 0);
    BYTE out[32], want[32];
    EXPECT_ST(HH_P_FINISH()(h, out, 32, 0), 0);
    HH_P_HASH()(BCRYPT_SHA256_ALG_HANDLE, NULL, 0, (PUCHAR)"abcdef", 6, want, 32);
    CHECK(!memcmp(out, want, 32));
    HH_P_DESTROY()(h);
}

/* ===================== separate process ===================== */
CHILD(hh_digests) {
    /* first use of every pseudo handle in a fresh process */
    for (unsigned i = 0; i < hh_nalgs; i++) {
        BYTE out[64];
        if (U(BCryptHash)(hh_algs[i].pseudo, NULL, 0, (PUCHAR)"abc", 3, out, hh_algs[i].digest)) return 10 + i;
        for (unsigned k = 0; k < hh_nhvecs; k++) {
            if (strcmp(hh_hvecs[k].alg, hh_algs[i].name) || hh_hvecs[k].in.kind != 'l' || strcmp(hh_hvecs[k].in.hex, "616263")) continue;
            if (!hh_eqhex(out, hh_algs[i].digest, hh_hvecs[k].hex)) return 30 + i;
        }
    }
    return 0;
}
TEST(hh_process_fresh_process_pseudo_handles) {
    EXPECT_EQ(t_run_child("hh_digests", "", 30000), 0);
}
CHILD(hh_hmac_child) {
    BCRYPT_ALG_HANDLE a = NULL;
    if (U(BCryptOpenAlgorithmProvider)(&a, L"SHA256", NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG)) return 1;
    BYTE out[32];
    if (U(BCryptHash)(a, (PUCHAR)"Jefe", 4, (PUCHAR)"what do ya want for nothing?", 28, out, 32)) return 2;
    if (!hh_eqhex(out, 32, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")) return 3;
    U(BCryptCloseAlgorithmProvider)(a, 0);
    return 0;
}
TEST(hh_process_hmac_in_child) {
    EXPECT_EQ(t_run_child("hh_hmac_child", "", 30000), 0);
}

/* ===================== BCryptOpenAlgorithmProvider flags as they apply to hashes ===================== */
TEST(hh_open_flag_bit0_invalid) {
    NEED();
    FOR_ALGS(ai) {
        BCRYPT_ALG_HANDLE a = (BCRYPT_ALG_HANDLE)(ULONG_PTR)0x77;
        EXPECT_ST(HH_P_OPEN()(&a, ai->wname, NULL, 1), NS_INVALID_PARAM);
        EXPECT_ST(HH_P_OPEN()(&a, ai->wname, NULL, 0x21), NS_INVALID_PARAM);
        CHECK(a == (BCRYPT_ALG_HANDLE)(ULONG_PTR)0x77);
    }
}
TEST(hh_open_null_arguments) {
    NEED();
    BCRYPT_ALG_HANDLE a = NULL;
    EXPECT_ST(HH_P_OPEN()(NULL, L"SHA256", NULL, 0), NS_INVALID_PARAM);
    EXPECT_ST(HH_P_OPEN()(&a, NULL, NULL, 0), NS_INVALID_PARAM);
}
TEST(hh_open_hmac_flag_and_reusable_flag_combine) {
    NEED();
    FOR_ALGS(ai) {
        BCRYPT_ALG_HANDLE a = NULL;
        NTSTATUS st = HH_P_OPEN()(&a, ai->wname, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG | BCRYPT_HASH_REUSABLE_FLAG);
        EXPECT_ST(st, 0);
        if (st) continue;
        BCRYPT_HASH_HANDLE h = NULL;
        EXPECT_ST(HH_P_CREATE()(a, &h, NULL, 0, (PUCHAR)"key", 3, 0), 0);
        if (h) {
            BYTE o1[64], o2[64], want[64];
            HH_P_HASH()(ai->hmac_pseudo, (PUCHAR)"key", 3, (PUCHAR)"abc", 3, want, ai->digest);
            HH_P_DATA()(h, (PUCHAR)"abc", 3, 0);
            EXPECT_ST(HH_P_FINISH()(h, o1, ai->digest, 0), 0);
            HH_P_DATA()(h, (PUCHAR)"abc", 3, 0);
            EXPECT_ST(HH_P_FINISH()(h, o2, ai->digest, 0), 0);
            CHECK(!memcmp(o1, want, ai->digest)); CHECK(!memcmp(o2, want, ai->digest));
            HH_P_DESTROY()(h);
        }
        hh_close(a);
    }
}
TEST(hh_open_hmac_flag_digest_properties_unchanged) {
    NEED();
    FOR_ALGS(ai) {
        BCRYPT_ALG_HANDLE a = hh_open(ai->wname, BCRYPT_ALG_HANDLE_HMAC_FLAG);
        int ok; ULONG v = hh_prop_ulong(a, BCRYPT_HASH_LENGTH, &ok);
        CHECK(ok); EXPECT_EQ(v, ai->digest);
        hh_close(a);
    }
}
TEST(hh_open_hmac_flag_hash_handle_properties) {
    NEED();
    FOR_ALGS(ai) {
        BCRYPT_ALG_HANDLE a = hh_open(ai->wname, BCRYPT_ALG_HANDLE_HMAC_FLAG);
        BCRYPT_HASH_HANDLE h = mk(a, (PUCHAR)"k", 1, 0);
        if (h) {
            int ok; ULONG v = hh_prop_ulong(h, BCRYPT_HASH_LENGTH, &ok);
            CHECK(ok); EXPECT_EQ(v, ai->digest);
            HH_P_DESTROY()(h);
        }
        hh_close(a);
    }
}
