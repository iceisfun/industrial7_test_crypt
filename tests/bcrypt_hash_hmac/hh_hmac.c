/* HMAC tests: algorithms opened with BCRYPT_ALG_HANDLE_HMAC_FLAG, the HMAC pseudo handles, and one-shot BCryptHash with a
 * secret. Expected values: RFC 2202 / RFC 4231 style inputs and a key-length x message-length matrix whose MACs were
 * generated at authoring time with python3 hmac / openssl (HMAC is deterministic by definition, RFC 2104). */
#include "hh.h"

enum { M_ONESHOT, M_PSEUDO, M_CREATE, M_CALLERBUF, M_REUSE_TWICE, M_DUP, M_PSEUDO_CREATE };

static void hmac_run(const char *algname, int mode, ULONG chunk) {
    const struct hh_alg *ai = hh_find(algname);
    if (!HH_P_OPEN() || !HH_P_CREATE() || !HH_P_HASH()) { t_skip("missing export"); return; }
    BCRYPT_ALG_HANDLE a = hh_open(ai->wname, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!a) return;
    unsigned ran = 0, pseudo_unsupported = 0;
    for (unsigned i = 0; i < hh_nmvecs; i++) {
        const struct hh_mvec *v = &hh_mvecs[i];
        if (strcmp(v->alg, algname)) continue;
        ULONG kl, ml; BYTE *k = hh_spec_new(&v->key, &kl), *m = hh_spec_new(&v->msg, &ml);
        BYTE out[64]; memset(out, 0xEE, sizeof out);
        NTSTATUS st = 0;
        const BYTE *kp = kl ? k : NULL;
        switch (mode) {
        case M_ONESHOT: st = HH_P_HASH()(a, (PUCHAR)kp, kl, m, ml, out, ai->digest); break;
        case M_PSEUDO:
            st = HH_P_HASH()(ai->hmac_pseudo, (PUCHAR)kp, kl, m, ml, out, ai->digest);
            if (st == NS_NOT_SUPPORTED || st == NS_INVALID_HANDLE) { pseudo_unsupported++; goto skip; }
            break;
        case M_PSEUDO_CREATE:
            st = hh_compute(ai->hmac_pseudo, kp, kl, m, ml, 0, 0, out, ai->digest);
            if (st == NS_NOT_SUPPORTED || st == NS_INVALID_HANDLE) { pseudo_unsupported++; goto skip; }
            break;
        case M_CREATE: st = hh_compute(a, kp, kl, m, ml, chunk, 0, out, ai->digest); break;
        case M_CALLERBUF: st = hh_compute(a, kp, kl, m, ml, chunk, 1, out, ai->digest); break;
        case M_REUSE_TWICE: {
            BCRYPT_HASH_HANDLE h = NULL;
            st = HH_P_CREATE()(a, &h, NULL, 0, (PUCHAR)kp, kl, BCRYPT_HASH_REUSABLE_FLAG);
            if (!st) {
                BYTE decoy[64];
                st = HH_P_DATA()(h, (PUCHAR)"decoy", 5, 0);
                if (!st) st = HH_P_FINISH()(h, decoy, ai->digest, 0);
                if (!st) st = HH_P_DATA()(h, m, ml, 0);
                if (!st) st = HH_P_FINISH()(h, out, ai->digest, 0);
                if (!st) {   /* and once more on the same handle: must start from the keyed initial state again */
                    BYTE out2[64]; memset(out2, 0, sizeof out2);
                    st = HH_P_DATA()(h, m, ml, 0);
                    if (!st) st = HH_P_FINISH()(h, out2, ai->digest, 0);
                    CHECKF(!memcmp(out, out2, ai->digest), "reusable HMAC second run differs (vec %u)", i);
                }
                HH_P_DESTROY()(h);
            }
            break; }
        case M_DUP: {
            BCRYPT_HASH_HANDLE h = NULL, h2 = NULL; ULONG half = ml / 2;
            st = HH_P_CREATE()(a, &h, NULL, 0, (PUCHAR)kp, kl, 0);
            if (!st) st = HH_P_DATA()(h, m, half, 0);
            if (!st) st = HH_P_DUP()(h, &h2, NULL, 0, 0);
            if (!st) st = HH_P_DATA()(h2, m + half, ml - half, 0);
            if (!st) st = HH_P_FINISH()(h2, out, ai->digest, 0);
            if (h2) HH_P_DESTROY()(h2);
            if (h) HH_P_DESTROY()(h);
            break; }
        }
        if (st != 0 || !hh_eqhex(out, ai->digest, v->hex)) {
            char hx[140]; hh_tohex(out, ai->digest, hx);
            CHECKF(0, "HMAC-%s vec#%u keylen=%lu msglen=%lu st=0x%08lx got %s want %s", algname, i, (unsigned long)kl, (unsigned long)ml, (unsigned long)st, hx, v->hex);
        } else t_check(1, __FILE__, __LINE__, "hmac", NULL);
        ran++;
    skip:
        free(k); free(m);
    }
    if (pseudo_unsupported) t_note("HMAC-%s pseudo handle rejected on %u vectors", algname, pseudo_unsupported);
    CHECK(ran > 0 || pseudo_unsupported);
    hh_close(a);
}

#define HMAC_SET(TAG, NAME) \
TEST(hh_hmac_##TAG##_bchash_oneshot)   { hmac_run(NAME, M_ONESHOT, 0); } \
TEST(hh_hmac_##TAG##_create_heap)      { hmac_run(NAME, M_CREATE, 0); } \
TEST(hh_hmac_##TAG##_create_callerbuf) { hmac_run(NAME, M_CALLERBUF, 0); } \
TEST(hh_hmac_##TAG##_chunk1)           { hmac_run(NAME, M_CREATE, 1); } \
TEST(hh_hmac_##TAG##_chunk5)           { hmac_run(NAME, M_CREATE, 5); } \
TEST(hh_hmac_##TAG##_chunk64)          { hmac_run(NAME, M_CREATE, 64); } \
TEST(hh_hmac_##TAG##_chunk65)          { hmac_run(NAME, M_CALLERBUF, 65); } \
TEST(hh_hmac_##TAG##_chunk129)         { hmac_run(NAME, M_CREATE, 129); } \
TEST(hh_hmac_##TAG##_reusable_run_twice) { hmac_run(NAME, M_REUSE_TWICE, 0); } \
TEST(hh_hmac_##TAG##_duplicate_midstream) { hmac_run(NAME, M_DUP, 0); } \
TEST(hh_hmac_##TAG##_pseudo_handle_oneshot) { hmac_run(NAME, M_PSEUDO, 0); } \
TEST(hh_hmac_##TAG##_pseudo_handle_create) { hmac_run(NAME, M_PSEUDO_CREATE, 0); }
HMAC_SET(md4, "MD4")
HMAC_SET(md5, "MD5")
HMAC_SET(sha1, "SHA1")
HMAC_SET(sha256, "SHA256")
HMAC_SET(sha384, "SHA384")
HMAC_SET(sha512, "SHA512")

/* ---- RFC vectors spelled out (key/data literal in the source) -------------- */
static void rfc_names(const char *alg, const char *only) {
    if (!HH_P_HASH()) { t_skip("missing export"); return; }
    unsigned ran = 0;
    for (unsigned i = 0; i < hh_nrfcvecs; i++) {
        const struct hh_rfcvec *v = &hh_rfcvecs[i];
        if (strcmp(v->alg, alg) || (only && !strstr(v->name, only))) continue;
        const struct hh_alg *ai = hh_find(alg);
        BYTE k[300], d[300], out[64];
        ULONG kl = hh_unhex(v->keyhex, k), dl = hh_unhex(v->datahex, d);
        NTSTATUS st = HH_P_HASH()(ai->hmac_pseudo, k, kl, d, dl, out, ai->digest);
        EXPECT_EQ(st, 0);
        char hx[140]; hh_tohex(out, ai->digest, hx);
        CHECKF(!strcmp(hx, v->mac), "%s case %s got %s", alg, v->name, hx);
        ran++;
    }
    CHECK(ran > 0);
}
TEST(hh_hmac_rfc_md5)    { rfc_names("MD5", NULL); }
TEST(hh_hmac_rfc_sha1)   { rfc_names("SHA1", NULL); }
TEST(hh_hmac_rfc_sha256) { rfc_names("SHA256", NULL); }
TEST(hh_hmac_rfc_sha384) { rfc_names("SHA384", NULL); }
TEST(hh_hmac_rfc_sha512) { rfc_names("SHA512", NULL); }
TEST(hh_hmac_rfc_sha256_key_longer_than_block) { rfc_names("SHA256", "6"); rfc_names("SHA256", "7"); }
TEST(hh_hmac_rfc_sha512_key_longer_than_block) { rfc_names("SHA512", "6"); rfc_names("SHA512", "7"); }
TEST(hh_hmac_rfc_sha384_truncation_case) { rfc_names("SHA384", "5"); }

/* ---- HMAC semantics ------------------------------------------------------- */
static void manual_hmac(const char *name, const BYTE *key, ULONG kl, const BYTE *msg, ULONG ml, BYTE *out, ULONG *block_out) {
    /* RFC 2104 built from the plain hash of the same module: block size comes from the HashBlockLength property */
    const struct hh_alg *ai = hh_find(name);
    BCRYPT_ALG_HANDLE a = hh_open(ai->wname, 0);
    int ok; ULONG B = hh_prop_ulong(a, BCRYPT_HASH_BLOCK_LENGTH, &ok);
    if (!ok && t_is_wine()) { B = ai->block; ok = 1; }   /* emulator lacks the property; Windows must report it */
    EXPECT_EQ(ok, 1);
    if (block_out) *block_out = B;
    BYTE k0[256] = {0}, inner[300], ih[64];
    if (kl > B) EXPECT_ST(hh_compute(a, NULL, 0, key, kl, 0, 0, k0, ai->digest), 0);
    else memcpy(k0, key, kl);
    BYTE *buf = malloc(B + ml + 1);
    for (ULONG i = 0; i < B; i++) buf[i] = k0[i] ^ 0x36;
    memcpy(buf + B, msg, ml);
    EXPECT_ST(hh_compute(a, NULL, 0, buf, B + ml, 0, 0, ih, ai->digest), 0);
    for (ULONG i = 0; i < B; i++) inner[i] = k0[i] ^ 0x5c;
    memcpy(inner + B, ih, ai->digest);
    EXPECT_ST(hh_compute(a, NULL, 0, inner, B + ai->digest, 0, 0, out, ai->digest), 0);
    free(buf);
    hh_close(a);
}
static void hmac_manual_all(const char *name) {
    if (!HH_P_CREATE()) { t_skip("missing export"); return; }
    const struct hh_alg *ai = hh_find(name);
    BCRYPT_ALG_HANDLE h = hh_open(ai->wname, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!h) return;
    BYTE key[300], msg[400]; hh_lcg_fill(key, sizeof key, 5); hh_lcg_fill(msg, sizeof msg, 6);
    static const ULONG kls[] = {0, 1, 15, 16, 17, 20, 32, 63, 64, 65, 127, 128, 129, 200};
    static const ULONG mls[] = {0, 1, 63, 64, 65, 200};
    for (unsigned i = 0; i < sizeof kls / sizeof *kls; i++) for (unsigned j = 0; j < sizeof mls / sizeof *mls; j++) {
        BYTE want[64], got[64];
        manual_hmac(name, key, kls[i], msg, mls[j], want, NULL);
        NTSTATUS st = hh_compute(h, kls[i] ? key : NULL, kls[i], msg, mls[j], 0, 0, got, ai->digest);
        EXPECT_EQ(st, 0);
        CHECKF(!memcmp(want, got, ai->digest), "HMAC-%s keylen=%lu msglen=%lu differs from RFC 2104 construction", name, (unsigned long)kls[i], (unsigned long)mls[j]);
    }
    hh_close(h);
}
TEST(hh_hmac_rfc2104_construction_md2)    { hmac_manual_all("MD2"); }
TEST(hh_hmac_rfc2104_construction_md4)    { hmac_manual_all("MD4"); }
TEST(hh_hmac_rfc2104_construction_md5)    { hmac_manual_all("MD5"); }
TEST(hh_hmac_rfc2104_construction_sha1)   { hmac_manual_all("SHA1"); }
TEST(hh_hmac_rfc2104_construction_sha256) { hmac_manual_all("SHA256"); }
TEST(hh_hmac_rfc2104_construction_sha384) { hmac_manual_all("SHA384"); }
TEST(hh_hmac_rfc2104_construction_sha512) { hmac_manual_all("SHA512"); }
TEST(hh_hmac_md2_block_size_is_16_for_ipad) {
    BYTE out[16]; ULONG B = 0;
    if (!HH_P_CREATE()) { t_skip("missing export"); return; }
    manual_hmac("MD2", (const BYTE *)"k", 1, (const BYTE *)"m", 1, out, &B);
    EXPECT_EQ(B, 16);
}

TEST(hh_hmac_key_longer_than_block_equals_hashed_key) {
    if (!HH_P_HASH()) { t_skip("missing export"); return; }
    for (unsigned i = 2; i < hh_nalgs; i++) {   /* the key >B is replaced by its digest */
        const struct hh_alg *ai = &hh_algs[i];
        BYTE key[300], dk[64], m1[64], m2[64];
        hh_lcg_fill(key, sizeof key, 31);
        EXPECT_ST(HH_P_HASH()(ai->pseudo, NULL, 0, key, ai->block + 1, dk, ai->digest), 0);
        EXPECT_ST(HH_P_HASH()(ai->hmac_pseudo, key, ai->block + 1, (PUCHAR)"msg", 3, m1, ai->digest), 0);
        EXPECT_ST(HH_P_HASH()(ai->hmac_pseudo, dk, ai->digest, (PUCHAR)"msg", 3, m2, ai->digest), 0);
        CHECKF(!memcmp(m1, m2, ai->digest), "%s", ai->name);
    }
}
TEST(hh_hmac_key_exactly_block_not_hashed) {
    if (!HH_P_HASH()) { t_skip("missing export"); return; }
    for (unsigned i = 2; i < hh_nalgs; i++) {
        const struct hh_alg *ai = &hh_algs[i];
        BYTE key[200], key1[200], m1[64], m2[64];
        hh_lcg_fill(key, sizeof key, 77);
        memcpy(key1, key, sizeof key); key1[ai->block - 1] ^= 1;
        EXPECT_ST(HH_P_HASH()(ai->hmac_pseudo, key, ai->block, (PUCHAR)"x", 1, m1, ai->digest), 0);
        EXPECT_ST(HH_P_HASH()(ai->hmac_pseudo, key1, ai->block, (PUCHAR)"x", 1, m2, ai->digest), 0);
        CHECKF(memcmp(m1, m2, ai->digest) != 0, "%s: last key byte at block size must matter", ai->name);
    }
}
TEST(hh_hmac_key_shorter_equals_zero_padded) {
    if (!HH_P_HASH()) { t_skip("missing export"); return; }
    for (unsigned i = 2; i < hh_nalgs; i++) {
        const struct hh_alg *ai = &hh_algs[i];
        BYTE k1[3] = {1, 2, 3}, k2[200] = {1, 2, 3}, m1[64], m2[64];
        EXPECT_ST(HH_P_HASH()(ai->hmac_pseudo, k1, 3, (PUCHAR)"x", 1, m1, ai->digest), 0);
        EXPECT_ST(HH_P_HASH()(ai->hmac_pseudo, k2, ai->block, (PUCHAR)"x", 1, m2, ai->digest), 0);
        CHECKF(!memcmp(m1, m2, ai->digest), "%s: key is zero-padded to the block size", ai->name);
    }
}
TEST(hh_hmac_empty_key_null_and_nonnull_pointer_agree) {
    if (!HH_P_HASH()) { t_skip("missing export"); return; }
    for (unsigned i = 2; i < hh_nalgs; i++) {
        const struct hh_alg *ai = &hh_algs[i];
        BYTE m1[64], m2[64], dummy = 0;
        NTSTATUS s1 = HH_P_HASH()(ai->hmac_pseudo, NULL, 0, (PUCHAR)"x", 1, m1, ai->digest);
        NTSTATUS s2 = HH_P_HASH()(ai->hmac_pseudo, &dummy, 0, (PUCHAR)"x", 1, m2, ai->digest);
        EXPECT_EQ(s1, 0); EXPECT_EQ(s2, 0);
        CHECK(!memcmp(m1, m2, ai->digest));
    }
}
TEST(hh_hmac_flag_on_open_equals_pseudo_hmac_handle) {
    if (!HH_P_HASH() || !HH_P_OPEN()) { t_skip("missing export"); return; }
    for (unsigned i = 2; i < hh_nalgs; i++) {
        const struct hh_alg *ai = &hh_algs[i];
        BCRYPT_ALG_HANDLE a = hh_open(ai->wname, BCRYPT_ALG_HANDLE_HMAC_FLAG);
        BYTE m1[64], m2[64];
        if (!a) continue;
        EXPECT_ST(HH_P_HASH()(a, (PUCHAR)"key", 3, (PUCHAR)"data", 4, m1, ai->digest), 0);
        EXPECT_ST(HH_P_HASH()(ai->hmac_pseudo, (PUCHAR)"key", 3, (PUCHAR)"data", 4, m2, ai->digest), 0);
        CHECK(!memcmp(m1, m2, ai->digest));
        hh_close(a);
    }
}
TEST(hh_hmac_different_keys_different_macs) {
    if (!HH_P_HASH()) { t_skip("missing export"); return; }
    for (unsigned i = 2; i < hh_nalgs; i++) {
        const struct hh_alg *ai = &hh_algs[i];
        BYTE m1[64], m2[64];
        EXPECT_ST(HH_P_HASH()(ai->hmac_pseudo, (PUCHAR)"key1", 4, (PUCHAR)"data", 4, m1, ai->digest), 0);
        EXPECT_ST(HH_P_HASH()(ai->hmac_pseudo, (PUCHAR)"key2", 4, (PUCHAR)"data", 4, m2, ai->digest), 0);
        CHECK(memcmp(m1, m2, ai->digest) != 0);
    }
}
TEST(hh_hmac_secret_on_plain_hash_rejected) {
    if (!HH_P_HASH()) { t_skip("missing export"); return; }
    if (t_is_wine()) { t_skip("emulator accepts a secret on a non-HMAC hash (Windows: STATUS_INVALID_PARAMETER)"); return; }
    for (unsigned i = 0; i < hh_nalgs; i++) {
        BYTE out[64];
        EXPECT_ST(HH_P_HASH()(hh_algs[i].pseudo, (PUCHAR)"key", 3, (PUCHAR)"x", 1, out, hh_algs[i].digest), NS_INVALID_PARAM);
        EXPECT_ST(HH_P_HASH()(hh_algs[i].pseudo, NULL, 1, (PUCHAR)"x", 1, out, hh_algs[i].digest), NS_INVALID_PARAM);
    }
}
