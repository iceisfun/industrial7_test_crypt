/* Known-answer hash tests: MD4 MD5 SHA1 SHA256 SHA384 SHA512 (digests generated at authoring time with
 * python3 hashlib / openssl, inputs are published suite strings, padding-boundary lengths and a fixed
 * byte pattern), plus the RFC 1319 MD2 suite. Every call goes through GetProcAddress. */
#include "hh.h"

enum { K_ONESHOT, K_PSEUDO, K_CREATE, K_CALLERBUF, K_REUSABLE, K_DUP, K_DUPDESTROY, K_FIN_THEN_RECREATE };

static void kat_run(const char *algname, int mode, ULONG chunk, ULONG maxlen) {
    const struct hh_alg *ai = hh_find(algname);
    BCRYPT_ALG_HANDLE a = NULL; BCRYPT_HASH_HANDLE reuse = NULL;
    if (!HH_P_OPEN() || !HH_P_CREATE() || !HH_P_HASH()) { t_skip("missing export"); return; }
    if (!ai) return;
    a = hh_open(ai->wname, 0);
    if (!a) return;
    if (mode == K_REUSABLE) {
        NTSTATUS st = HH_P_CREATE()(a, &reuse, NULL, 0, NULL, 0, BCRYPT_HASH_REUSABLE_FLAG);
        EXPECT_EQ(st, 0);
        if (st) { hh_close(a); return; }
    }
    unsigned ran = 0;
    for (unsigned i = 0; i < hh_nhvecs; i++) {
        const struct hh_hvec *v = &hh_hvecs[i];
        if (strcmp(v->alg, algname)) continue;
        ULONG n; BYTE *d = hh_spec_new(&v->in, &n);
        if (n > maxlen) { free(d); continue; }
        if (chunk && n / chunk > 20000) { free(d); continue; }
        BYTE out[64]; memset(out, 0xEE, sizeof out);
        NTSTATUS st = 0;
        switch (mode) {
        case K_ONESHOT: st = HH_P_HASH()(a, NULL, 0, d, n, out, ai->digest); break;
        case K_PSEUDO:  st = HH_P_HASH()(ai->pseudo, NULL, 0, d, n, out, ai->digest); break;
        case K_CREATE:  st = hh_compute(a, NULL, 0, d, n, chunk, 0, out, ai->digest); break;
        case K_CALLERBUF: st = hh_compute(a, NULL, 0, d, n, chunk, 1, out, ai->digest); break;
        case K_REUSABLE: {
            st = HH_P_DATA()(reuse, d, n, 0);
            if (!st) st = HH_P_FINISH()(reuse, out, ai->digest, 0);
            break; }
        case K_DUP: case K_DUPDESTROY: {
            BCRYPT_HASH_HANDLE h = NULL, h2 = NULL;
            ULONG half = n / 2;
            st = HH_P_CREATE()(a, &h, NULL, 0, NULL, 0, 0);
            if (!st) st = HH_P_DATA()(h, d, half, 0);
            if (!st) st = HH_P_DUP()(h, &h2, NULL, 0, 0);
            if (!st) {
                if (mode == K_DUPDESTROY) { HH_P_DESTROY()(h); h = NULL; }
                st = HH_P_DATA()(h2, d + half, n - half, 0);
                if (!st) st = HH_P_FINISH()(h2, out, ai->digest, 0);
                if (!st && h) {
                    BYTE out2[64]; memset(out2, 0, sizeof out2);
                    NTSTATUS s2 = HH_P_DATA()(h, d + half, n - half, 0);
                    if (!s2) s2 = HH_P_FINISH()(h, out2, ai->digest, 0);
                    EXPECT_EQ(s2, 0);
                    CHECKF(!memcmp(out, out2, ai->digest), "original and duplicate diverge for vector %u", i);
                }
                HH_P_DESTROY()(h2);
            }
            if (h) HH_P_DESTROY()(h);
            break; }
        case K_FIN_THEN_RECREATE: {
            /* a non-reusable hash is dead after Finish; a fresh one from the same alg handle starts clean */
            BCRYPT_HASH_HANDLE h = NULL;
            st = HH_P_CREATE()(a, &h, NULL, 0, NULL, 0, 0);
            if (!st) { BYTE junk[64]; HH_P_DATA()(h, (PUCHAR)"junk", 4, 0); HH_P_FINISH()(h, junk, ai->digest, 0); HH_P_DESTROY()(h); }
            st = hh_compute(a, NULL, 0, d, n, chunk, 0, out, ai->digest);
            break; }
        }
        if (st != 0 || !hh_eqhex(out, ai->digest, v->hex)) {
            char hx[140]; hh_tohex(out, ai->digest, hx);
            CHECKF(0, "%s vec#%u len=%lu st=0x%08lx got %s want %s", algname, i, (unsigned long)n, (unsigned long)st, hx, v->hex);
        } else t_check(1, __FILE__, __LINE__, "kat", NULL);
        ran++;
        free(d);
    }
    CHECK(ran > 0 || maxlen == 0);
    if (reuse) HH_P_DESTROY()(reuse);
    hh_close(a);
}

#define KAT_SET(TAG, NAME) \
TEST(hh_kat_##TAG##_bchash_oneshot)  { kat_run(NAME, K_ONESHOT, 0, 1000000); } \
TEST(hh_kat_##TAG##_pseudo_handle)   { kat_run(NAME, K_PSEUDO, 0, 1000000); } \
TEST(hh_kat_##TAG##_create_heap)     { kat_run(NAME, K_CREATE, 0, 1000000); } \
TEST(hh_kat_##TAG##_create_callerbuf){ kat_run(NAME, K_CALLERBUF, 0, 1000000); } \
TEST(hh_kat_##TAG##_chunk1)          { kat_run(NAME, K_CREATE, 1, 4100); } \
TEST(hh_kat_##TAG##_chunk3)          { kat_run(NAME, K_CREATE, 3, 100000); } \
TEST(hh_kat_##TAG##_chunk7)          { kat_run(NAME, K_CREATE, 7, 100000); } \
TEST(hh_kat_##TAG##_chunk63)         { kat_run(NAME, K_CREATE, 63, 1000000); } \
TEST(hh_kat_##TAG##_chunk64)         { kat_run(NAME, K_CREATE, 64, 1000000); } \
TEST(hh_kat_##TAG##_chunk65)         { kat_run(NAME, K_CREATE, 65, 1000000); } \
TEST(hh_kat_##TAG##_chunk127)        { kat_run(NAME, K_CREATE, 127, 1000000); } \
TEST(hh_kat_##TAG##_chunk128)        { kat_run(NAME, K_CREATE, 128, 1000000); } \
TEST(hh_kat_##TAG##_chunk129)        { kat_run(NAME, K_CREATE, 129, 1000000); } \
TEST(hh_kat_##TAG##_chunk_callerbuf_61){ kat_run(NAME, K_CALLERBUF, 61, 100000); } \
TEST(hh_kat_##TAG##_chunk4096)       { kat_run(NAME, K_CREATE, 4096, 1000000); } \
TEST(hh_kat_##TAG##_reusable_handle_many_vectors) { kat_run(NAME, K_REUSABLE, 0, 100000); } \
TEST(hh_kat_##TAG##_duplicate_midstream) { kat_run(NAME, K_DUP, 0, 100000); } \
TEST(hh_kat_##TAG##_duplicate_then_destroy_original) { kat_run(NAME, K_DUPDESTROY, 0, 100000); } \
TEST(hh_kat_##TAG##_fresh_after_finished_hash) { kat_run(NAME, K_FIN_THEN_RECREATE, 0, 1000); }

KAT_SET(md4, "MD4")
KAT_SET(md5, "MD5")
KAT_SET(sha1, "SHA1")
KAT_SET(sha256, "SHA256")
KAT_SET(sha384, "SHA384")
KAT_SET(sha512, "SHA512")

/* ---- named published vectors, spelled out ---------------------------------- */
struct lit { const char *alg, *msg, *hex; };
static void lit_run(const struct lit *t, unsigned n) {
    if (!HH_P_HASH()) { t_skip("missing export"); return; }
    for (unsigned i = 0; i < n; i++) {
        const struct hh_alg *ai = hh_find(t[i].alg);
        BYTE out[64];
        NTSTATUS st = HH_P_HASH()(ai->pseudo, NULL, 0, (PUCHAR)t[i].msg, (ULONG)strlen(t[i].msg), out, ai->digest);
        EXPECT_EQ(st, 0);
        CHECKF(hh_eqhex(out, ai->digest, t[i].hex), "%s(\"%s\")", t[i].alg, t[i].msg);
    }
}
TEST(hh_kat_md2_rfc1319_suite) {
    static const struct lit t[] = {
        {"MD2", "", "8350e5a3e24c153df2275c9f80692773"},
        {"MD2", "a", "32ec01ec4a6dac72c0ab96fb34c0b5d1"},
        {"MD2", "abc", "da853b0d3f88d99b30283a69e6ded6bb"},
        {"MD2", "message digest", "ab4f496bfb2a530b219ff33031fe06b0"},
        {"MD2", "abcdefghijklmnopqrstuvwxyz", "4e8ddff3650292ab5a4108c3aa47940b"},
        {"MD2", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "da33def2a42df13975352846c30338cd"},
        {"MD2", "12345678901234567890123456789012345678901234567890123456789012345678901234567890", "d5976f79d83d3a0dc9806c3c66f3efd8"},
    };
    lit_run(t, sizeof t / sizeof t[0]);
}
TEST(hh_kat_md4_rfc1320_suite) {
    static const struct lit t[] = {
        {"MD4", "", "31d6cfe0d16ae931b73c59d7e0c089c0"},
        {"MD4", "a", "bde52cb31de33e46245e05fbdbd6fb24"},
        {"MD4", "abc", "a448017aaf21d8525fc10ae87aa6729d"},
        {"MD4", "message digest", "d9130a8164549fe818874806e1c7014b"},
        {"MD4", "abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9"},
        {"MD4", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "043f8582f241db351ce627e153e7f0e4"},
        {"MD4", "12345678901234567890123456789012345678901234567890123456789012345678901234567890", "e33b4ddc9c38f2199c3e7b164fcc0536"},
    };
    lit_run(t, sizeof t / sizeof t[0]);
}
TEST(hh_kat_md5_rfc1321_suite) {
    static const struct lit t[] = {
        {"MD5", "", "d41d8cd98f00b204e9800998ecf8427e"},
        {"MD5", "a", "0cc175b9c0f1b6a831c399e269772661"},
        {"MD5", "abc", "900150983cd24fb0d6963f7d28e17f72"},
        {"MD5", "message digest", "f96b697d7cb7938d525a2f31aaf161d0"},
        {"MD5", "abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b"},
        {"MD5", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", "d174ab98d277d9f5a5611c2c9f419d9f"},
        {"MD5", "12345678901234567890123456789012345678901234567890123456789012345678901234567890", "57edf4a22be3c955ac49da2e2107b67a"},
    };
    lit_run(t, sizeof t / sizeof t[0]);
}
TEST(hh_kat_sha1_fips180_examples) {
    static const struct lit t[] = {
        {"SHA1", "abc", "a9993e364706816aba3e25717850c26c9cd0d89d"},
        {"SHA1", "", "da39a3ee5e6b4b0d3255bfef95601890afd80709"},
        {"SHA1", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "84983e441c3bd26ebaae4aa1f95129e5e54670f1"},
        {"SHA1", "The quick brown fox jumps over the lazy dog", "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"},
    };
    lit_run(t, sizeof t / sizeof t[0]);
}
TEST(hh_kat_sha2_fips180_examples) {
    static const struct lit t[] = {
        {"SHA256", "abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
        {"SHA256", "", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        {"SHA256", "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
        {"SHA384", "abc", "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"},
        {"SHA384", "", "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"},
        {"SHA384", "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039"},
        {"SHA512", "abc", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"},
        {"SHA512", "", "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"},
        {"SHA512", "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu", "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"},
    };
    lit_run(t, sizeof t / sizeof t[0]);
}

/* ---- million 'a' by name, and partial block / length-field edge cases ---------- */
static void million_a(const char *name, const char *hex, ULONG chunk) {
    const struct hh_alg *ai = hh_find(name);
    if (!HH_P_CREATE()) { t_skip("missing export"); return; }
    BYTE *d = malloc(1000000); memset(d, 'a', 1000000);
    BYTE out[64];
    NTSTATUS st = hh_compute(ai->pseudo, NULL, 0, d, 1000000, chunk, 0, out, ai->digest);
    EXPECT_EQ(st, 0);
    CHECKF(hh_eqhex(out, ai->digest, hex), "%s million a chunk %lu", name, (unsigned long)chunk);
    free(d);
}
TEST(hh_million_a_md5_whole)    { million_a("MD5", "7707d6ae4e027c70eea2a935c2296f21", 0); }
TEST(hh_million_a_md5_chunk1000){ million_a("MD5", "7707d6ae4e027c70eea2a935c2296f21", 1000); }
TEST(hh_million_a_sha1_whole)   { million_a("SHA1", "34aa973cd4c4daa4f61eeb2bdbad27316534016f", 0); }
TEST(hh_million_a_sha1_chunk999){ million_a("SHA1", "34aa973cd4c4daa4f61eeb2bdbad27316534016f", 999); }
TEST(hh_million_a_sha256_whole) { million_a("SHA256", "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0", 0); }
TEST(hh_million_a_sha256_chunk4097) { million_a("SHA256", "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0", 4097); }
TEST(hh_million_a_sha384_whole) { million_a("SHA384", "9d0e1809716474cb086e834e310a4a1ced149e9c00f248527972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985", 0); }
TEST(hh_million_a_sha512_whole) { million_a("SHA512", "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b", 0); }
TEST(hh_million_a_sha512_chunk333) { million_a("SHA512", "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973ebde0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b", 333); }
TEST(hh_million_a_md4_whole)    { million_a("MD4", "bbce80cc6bb65e5c6745e30d4eeca9a4", 0); }

/* ---- chunk invariance for every algorithm including MD2 (no external vector: whole == split) ---- */
static void invariance(const char *name, int mode, int keyed) {
    const struct hh_alg *ai = hh_find(name);
    if (!HH_P_CREATE()) { t_skip("missing export"); return; }
    BCRYPT_ALG_HANDLE a = hh_open(ai->wname, keyed ? BCRYPT_ALG_HANDLE_HMAC_FLAG : 0);
    if (!a) return;
    enum { N = 3000 };
    BYTE d[N], key[200]; hh_lcg_fill(d, N, 12345); hh_lcg_fill(key, sizeof key, 777);
    static const ULONG lens[] = {0,1,2,15,16,17,31,32,33,55,56,57,63,64,65,111,112,113,119,120,121,127,128,129,191,192,193,1000,2999,3000};
    static const ULONG chunks[] = {1,2,3,5,13,16,17,31,64,65,100,128,129,1000};
    for (unsigned li = 0; li < sizeof lens / sizeof *lens; li++) {
        BYTE ref[64], got[64];
        ULONG kl = keyed ? 1 + (li * 13) % 190 : 0;
        NTSTATUS st = hh_compute(a, keyed ? key : NULL, kl, d, lens[li], 0, mode, ref, ai->digest);
        EXPECT_EQ(st, 0);
        for (unsigned ci = 0; ci < sizeof chunks / sizeof *chunks; ci++) {
            memset(got, 0, sizeof got);
            st = hh_compute(a, keyed ? key : NULL, kl, d, lens[li], chunks[ci], mode, got, ai->digest);
            if (st || memcmp(ref, got, ai->digest)) CHECKF(0, "%s len=%lu chunk=%lu st=%08lx", name, (unsigned long)lens[li], (unsigned long)chunks[ci], (unsigned long)st);
            else t_check(1, __FILE__, __LINE__, "inv", NULL);
        }
    }
    hh_close(a);
}
#define INV(TAG, NAME) \
TEST(hh_chunk_invariance_##TAG)          { invariance(NAME, 0, 0); } \
TEST(hh_chunk_invariance_##TAG##_callerbuf) { invariance(NAME, 1, 0); } \
TEST(hh_chunk_invariance_##TAG##_reusable)  { invariance(NAME, 2, 0); } \
TEST(hh_chunk_invariance_hmac_##TAG)     { invariance(NAME, 0, 1); } \
TEST(hh_chunk_invariance_hmac_##TAG##_reusable) { invariance(NAME, 2, 1); }
INV(md2, "MD2") INV(md4, "MD4") INV(md5, "MD5") INV(sha1, "SHA1") INV(sha256, "SHA256") INV(sha384, "SHA384") INV(sha512, "SHA512")

/* MD2 has no external generated vectors for long input; check a fixed pattern against an explicit second path:
 * BCryptHash one-shot vs create/hash/finish and the million-a streaming must agree with itself. */
TEST(hh_md2_oneshot_equals_streamed_pattern) {
    if (!HH_P_HASH()) { t_skip("missing export"); return; }
    BYTE d[5000]; hh_lcg_fill(d, sizeof d, 99);
    for (ULONG n = 0; n <= 300; n += 7) {
        BYTE a1[16], a2[16];
        EXPECT_ST(HH_P_HASH()(BCRYPT_MD2_ALG_HANDLE, NULL, 0, d, n, a1, 16), 0);
        EXPECT_ST(hh_compute(BCRYPT_MD2_ALG_HANDLE, NULL, 0, d, n, 5, 0, a2, 16), 0);
        CHECK(!memcmp(a1, a2, 16));
    }
}
TEST(hh_hash_distinguishes_inputs_and_algorithms) {
    if (!HH_P_HASH()) { t_skip("missing export"); return; }
    BYTE h[7][64], one[2] = {0,0};
    for (unsigned i = 0; i < hh_nalgs; i++) {
        BYTE x[64], y[64];
        memset(h[i], 0, 64);
        EXPECT_ST(HH_P_HASH()(hh_algs[i].pseudo, NULL, 0, one, 1, x, hh_algs[i].digest), 0);
        EXPECT_ST(HH_P_HASH()(hh_algs[i].pseudo, NULL, 0, one, 2, y, hh_algs[i].digest), 0);
        CHECK(memcmp(x, y, hh_algs[i].digest) != 0);   /* one NUL vs two NULs */
        EXPECT_ST(HH_P_HASH()(hh_algs[i].pseudo, NULL, 0, NULL, 0, h[i], hh_algs[i].digest), 0);
    }
    for (unsigned i = 0; i < hh_nalgs; i++) for (unsigned j = i + 1; j < hh_nalgs; j++)
        if (hh_algs[i].digest == hh_algs[j].digest) CHECK(memcmp(h[i], h[j], hh_algs[i].digest) != 0);
}
