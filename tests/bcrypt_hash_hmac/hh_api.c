/* BCryptCreateHash / HashData / FinishHash / DestroyHash / DuplicateHash / BCryptHash: argument validation, status codes,
 * buffer-size protocol and state machine. Status codes come from the Windows 10 19041 decompilation of bcrypt.dll
 * (base.c) and bcryptprimitives.dll (msprim hash.c): 0xC0000008 invalid handle, 0xC000000D invalid parameter,
 * 0xC0000023 buffer too small, 0xC00000BB not supported. */
#include "hh.h"

#define NEED() do { if (!HH_P_CREATE() || !HH_P_DATA() || !HH_P_FINISH() || !HH_P_DESTROY() || !HH_P_OPEN() || !HH_P_CLOSE()) { t_skip("missing export"); return; } } while (0)
#define NEED_DUP() do { NEED(); if (!HH_P_DUP()) { t_skip("missing BCryptDuplicateHash"); return; } } while (0)
#define FOR_ALGS(ai) for (const struct hh_alg *ai = hh_algs; ai < hh_algs + hh_nalgs; ai++)
#define SENT ((BCRYPT_HASH_HANDLE)(ULONG_PTR)0x5a5a5a5a5a5aULL)

/* caller-supplied hash object with 32 guard bytes on each side */
typedef struct { BYTE *raw, *buf; ULONG cb; } objbuf;
static objbuf ob_new(ULONG cb) {
    objbuf o; o.cb = cb; o.raw = _aligned_malloc(cb + 64, 16); memset(o.raw, 0xA5, cb + 64);
    o.buf = o.raw + 32; return o;
}
static int ob_guards_ok(const objbuf *o) {
    for (int i = 0; i < 32; i++) if (o->raw[i] != 0xA5 || o->raw[32 + o->cb + i] != 0xA5) return 0;
    return 1;
}
static void ob_free(objbuf *o) { _aligned_free(o->raw); o->raw = NULL; }

static BCRYPT_HASH_HANDLE mkhash(BCRYPT_ALG_HANDLE a, ULONG flags) {
    BCRYPT_HASH_HANDLE h = NULL;
    NTSTATUS st = HH_P_CREATE()(a, &h, NULL, 0, NULL, 0, flags);
    EXPECT_EQ(st, 0);
    return st ? NULL : h;
}
static void sha_abc(const struct hh_alg *ai, BYTE *out) { HH_P_HASH()(ai->pseudo, NULL, 0, (PUCHAR)"abc", 3, out, ai->digest); }

/* ===================== BCryptCreateHash ===================== */
TEST(hh_create_null_algorithm_handle) {
    NEED();
    BCRYPT_HASH_HANDLE h = SENT;
    EXPECT_ST(HH_P_CREATE()(NULL, &h, NULL, 0, NULL, 0, 0), NS_INVALID_HANDLE);
    CHECK(h == SENT);
    BYTE buf[1024];
    EXPECT_ST(HH_P_CREATE()(NULL, &h, buf, sizeof buf, NULL, 0, 0), NS_INVALID_HANDLE);
}
TEST(hh_create_out_of_range_pseudo_handle) {
    NEED();
    BCRYPT_HASH_HANDLE h = SENT;
    static const ULONG_PTR bad[] = {0x3a1, 0x1001, 0x10001, 0xfffffff1};
    for (unsigned i = 0; i < sizeof bad / sizeof *bad; i++) {
        BYTE buf[1024];
        EXPECT_ST(HH_P_CREATE()((BCRYPT_ALG_HANDLE)bad[i], &h, buf, sizeof buf, NULL, 0, 0), NS_INVALID_HANDLE);
        EXPECT_ST(HH_P_CREATE()((BCRYPT_ALG_HANDLE)bad[i], &h, NULL, 0, NULL, 0, 0), NS_INVALID_HANDLE);
    }
    CHECK(h == SENT);
}
TEST(hh_create_hash_handle_used_as_algorithm_handle) {
    NEED();
    BCRYPT_ALG_HANDLE a = hh_open(L"SHA256", 0);
    BCRYPT_HASH_HANDLE h = mkhash(a, 0), h2 = SENT;
    if (h) {
        BYTE buf[1024];
        EXPECT_ST(HH_P_CREATE()((BCRYPT_ALG_HANDLE)h, &h2, buf, sizeof buf, NULL, 0, 0), NS_INVALID_HANDLE);
        CHECK(h2 == SENT);
        HH_P_DESTROY()(h);
    }
    hh_close(a);
}
TEST(hh_create_null_phash_with_heap_object) {
    NEED();
    FOR_ALGS(ai) EXPECT_ST(HH_P_CREATE()(ai->pseudo, NULL, NULL, 0, NULL, 0, 0), NS_INVALID_PARAM);
}
TEST(hh_create_null_phash_with_caller_object) {
    NEED();
    FOR_ALGS(ai) {
        objbuf o = ob_new(2048);
        EXPECT_ST(HH_P_CREATE()(ai->pseudo, NULL, o.buf, o.cb, NULL, 0, 0), NS_INVALID_PARAM);
        CHECK(ob_guards_ok(&o));
        ob_free(&o);
    }
}
TEST(hh_create_object_null_with_nonzero_size) {
    NEED();
    FOR_ALGS(ai) {
        BCRYPT_HASH_HANDLE h = SENT;
        EXPECT_ST(HH_P_CREATE()(ai->pseudo, &h, NULL, 1, NULL, 0, 0), NS_INVALID_PARAM);
        EXPECT_ST(HH_P_CREATE()(ai->pseudo, &h, NULL, 0x1000, NULL, 0, 0), NS_INVALID_PARAM);
        CHECK(h == SENT);
    }
}
TEST(hh_create_object_nonnull_with_zero_size) {
    NEED();
    FOR_ALGS(ai) {
        BYTE buf[1024]; BCRYPT_HASH_HANDLE h = SENT;
        EXPECT_ST(HH_P_CREATE()(ai->pseudo, &h, buf, 0, NULL, 0, 0), NS_BUFFER_TOO_SMALL);
        CHECK(h == SENT);
    }
}
TEST(hh_create_object_size_below_0x46_too_small) {
    NEED();
    static const ULONG sizes[] = {1, 8, 0x27, 0x28, 0x29, 0x40, 0x45};
    FOR_ALGS(ai) for (unsigned i = 0; i < sizeof sizes / sizeof *sizes; i++) {
        objbuf o = ob_new(0x200); BCRYPT_HASH_HANDLE h = SENT;
        EXPECT_ST(HH_P_CREATE()(ai->pseudo, &h, o.buf, sizes[i], NULL, 0, 0), NS_BUFFER_TOO_SMALL);
        CHECK(h == SENT);
        ob_free(&o);
    }
}
TEST(hh_create_object_size_too_small_for_algorithm) {
    NEED();
    FOR_ALGS(ai) {
        ULONG ol = hh_objlen(ai->pseudo);
        CHECKF(ol >= 0x46, "%s ObjectLength %lu", ai->name, (unsigned long)ol);
        if (ol < 0x47) continue;
        objbuf o = ob_new(ol + 64); BCRYPT_HASH_HANDLE h = SENT;
        NTSTATUS st = HH_P_CREATE()(ai->pseudo, &h, o.buf, 0x46, NULL, 0, 0);
        EXPECT_EQ(st, NS_BUFFER_TOO_SMALL);
        CHECK(h == SENT);
        CHECK(ob_guards_ok(&o));
        ob_free(&o);
    }
}
TEST(hh_create_object_exact_objectlength_aligned_ok) {
    NEED();
    FOR_ALGS(ai) {
        ULONG ol = hh_objlen(ai->pseudo);
        objbuf o = ob_new(ol); BCRYPT_HASH_HANDLE h = NULL;
        NTSTATUS st = HH_P_CREATE()(ai->pseudo, &h, o.buf, ol, NULL, 0, 0);
        EXPECT_EQ(st, 0);
        if (!st) {
            CHECKF(ob_guards_ok(&o), "%s wrote outside the supplied object", ai->name);
            BYTE out[64], want[64]; sha_abc(ai, want);
            EXPECT_ST(HH_P_DATA()(h, (PUCHAR)"abc", 3, 0), 0);
            EXPECT_ST(HH_P_FINISH()(h, out, ai->digest, 0), 0);
            CHECK(!memcmp(out, want, ai->digest));
            CHECK(ob_guards_ok(&o));
            EXPECT_ST(HH_P_DESTROY()(h), 0);
            CHECK(ob_guards_ok(&o));
        }
        ob_free(&o);
    }
}
TEST(hh_create_object_one_byte_short_is_reported_not_corrupted) {
    NEED();
    FOR_ALGS(ai) {
        ULONG ol = hh_objlen(ai->pseudo);
        objbuf o = ob_new(ol - 1); BCRYPT_HASH_HANDLE h = NULL;
        NTSTATUS st = HH_P_CREATE()(ai->pseudo, &h, o.buf, ol - 1, NULL, 0, 0);
        t_note("%s: Create with ObjectLength-1 (%lu) -> 0x%08lx", ai->name, (unsigned long)(ol - 1), (unsigned long)st);
        CHECK(st == 0 || st == NS_BUFFER_TOO_SMALL);
        CHECK(ob_guards_ok(&o));
        if (!st) HH_P_DESTROY()(h);
        ob_free(&o);
    }
}
TEST(hh_create_misaligned_caller_object_with_slack) {
    NEED();
    FOR_ALGS(ai) for (ULONG off = 1; off < 16; off += 3) {
        ULONG ol = hh_objlen(ai->pseudo);
        objbuf o = ob_new(ol + 32); BCRYPT_HASH_HANDLE h = NULL;
        BYTE *p = o.buf + off;
        NTSTATUS st = HH_P_CREATE()(ai->pseudo, &h, p, ol + 32 - off, NULL, 0, 0);
        EXPECT_EQ(st, 0);
        if (!st) {
            CHECK(((ULONG_PTR)h & 15) == 0);
            CHECK((BYTE *)h >= p && (BYTE *)h < p + ol + 32 - off);
            BYTE out[64], want[64]; sha_abc(ai, want);
            EXPECT_ST(HH_P_DATA()(h, (PUCHAR)"abc", 3, 0), 0);
            EXPECT_ST(HH_P_FINISH()(h, out, ai->digest, 0), 0);
            CHECK(!memcmp(out, want, ai->digest));
            HH_P_DESTROY()(h);
        }
        CHECK(ob_guards_ok(&o));
        ob_free(&o);
    }
}
TEST(hh_create_handle_lives_inside_caller_object) {
    NEED();
    FOR_ALGS(ai) {
        ULONG ol = hh_objlen(ai->pseudo);
        objbuf o = ob_new(ol + 16); BCRYPT_HASH_HANDLE h = NULL;
        EXPECT_ST(HH_P_CREATE()(ai->pseudo, &h, o.buf, ol + 16, NULL, 0, 0), 0);
        if (h) {
            CHECK((BYTE *)h >= o.buf && (BYTE *)h < o.buf + o.cb);
            CHECK(((ULONG_PTR)h & 15) == 0);
            HH_P_DESTROY()(h);
        }
        ob_free(&o);
    }
}
TEST(hh_create_heap_object_handles_distinct_and_nonnull) {
    NEED();
    BCRYPT_HASH_HANDLE hs[32];
    FOR_ALGS(ai) {
        for (int i = 0; i < 32; i++) { hs[i] = NULL; EXPECT_ST(HH_P_CREATE()(ai->pseudo, &hs[i], NULL, 0, NULL, 0, 0), 0); CHECK(hs[i] != NULL); }
        for (int i = 0; i < 32; i++) for (int j = i + 1; j < 32; j++) CHECK(hs[i] != hs[j]);
        for (int i = 0; i < 32; i++) if (hs[i]) EXPECT_ST(HH_P_DESTROY()(hs[i]), 0);
    }
}
TEST(hh_create_flags_valid_values) {
    NEED();
    FOR_ALGS(ai) {
        BCRYPT_HASH_HANDLE h = NULL;
        EXPECT_ST(HH_P_CREATE()(ai->pseudo, &h, NULL, 0, NULL, 0, 0), 0);
        if (h) HH_P_DESTROY()(h);
        h = NULL;
        EXPECT_ST(HH_P_CREATE()(ai->pseudo, &h, NULL, 0, NULL, 0, BCRYPT_HASH_REUSABLE_FLAG), 0);
        if (h) HH_P_DESTROY()(h);
    }
}
TEST(hh_create_flags_invalid_values) {
    NEED();
    static const ULONG bad[] = {0x1, 0x2, 0x4, 0x8, 0x10, 0x40, 0x80, 0x100, 0x8000, 0x10000, 0x80000000, 0x21, 0x28, 0xffffffff, 0xffffffdf};
    FOR_ALGS(ai) for (unsigned i = 0; i < sizeof bad / sizeof *bad; i++) {
        BCRYPT_HASH_HANDLE h = SENT;
        NTSTATUS st = HH_P_CREATE()(ai->pseudo, &h, NULL, 0, NULL, 0, bad[i]);
        CHECKF(st == NS_INVALID_PARAM, "%s flags 0x%lx -> 0x%08lx", ai->name, (unsigned long)bad[i], (unsigned long)st);
        CHECK(h == SENT);
    }
}
TEST(hh_create_flags_invalid_with_caller_object_leaves_object_unused) {
    NEED();
    FOR_ALGS(ai) {
        ULONG ol = hh_objlen(ai->pseudo);
        objbuf o = ob_new(ol); BCRYPT_HASH_HANDLE h = SENT;
        EXPECT_ST(HH_P_CREATE()(ai->pseudo, &h, o.buf, ol, NULL, 0, 0x40), NS_INVALID_PARAM);
        CHECK(h == SENT);
        CHECK(ob_guards_ok(&o));
        ob_free(&o);
    }
}
TEST(hh_create_on_non_hash_algorithm_not_supported) {
    NEED();
    static const WCHAR *names[] = {L"AES", L"3DES", L"RC4", L"RNG", L"DES"};
    for (unsigned i = 0; i < sizeof names / sizeof *names; i++) {
        BCRYPT_ALG_HANDLE a = NULL;
        NTSTATUS st = HH_P_OPEN()(&a, names[i], NULL, 0);
        if (st) { t_note("%ls: open -> 0x%08lx", names[i], (unsigned long)st); continue; }
        objbuf o = ob_new(4096); BCRYPT_HASH_HANDLE h = SENT;
        EXPECT_ST(HH_P_CREATE()(a, &h, o.buf, o.cb, NULL, 0, 0), NS_NOT_SUPPORTED);
        CHECK(h == SENT);
        CHECK(ob_guards_ok(&o));
        ob_free(&o);
        hh_close(a);
    }
}
TEST(hh_create_on_non_hash_algorithm_heap_object) {
    NEED();
    BCRYPT_ALG_HANDLE a = hh_open(L"AES", 0);
    if (!a) return;
    BCRYPT_HASH_HANDLE h = SENT;
    EXPECT_ST(HH_P_CREATE()(a, &h, NULL, 0, NULL, 0, 0), NS_NOT_SUPPORTED);
    CHECK(h == SENT);
    hh_close(a);
}
TEST(hh_create_plain_hash_rejects_secret) {
    NEED();
    if (t_is_wine()) { t_skip("emulator accepts secrets on non-HMAC hashes"); return; }
    FOR_ALGS(ai) {
        BCRYPT_HASH_HANDLE h = SENT;
        EXPECT_ST(HH_P_CREATE()(ai->pseudo, &h, NULL, 0, (PUCHAR)"k", 1, 0), NS_INVALID_PARAM);
        EXPECT_ST(HH_P_CREATE()(ai->pseudo, &h, NULL, 0, NULL, 4, 0), NS_INVALID_PARAM);
        BYTE z = 0;
        EXPECT_ST(HH_P_CREATE()(ai->pseudo, &h, NULL, 0, &z, 0, 0), NS_INVALID_PARAM);   /* non-NULL pointer alone is enough */
        CHECK(h == SENT);
    }
}
TEST(hh_create_hmac_accepts_empty_and_null_secret) {
    NEED();
    FOR_ALGS(ai) {
        BCRYPT_HASH_HANDLE h = NULL; BYTE z = 0;
        EXPECT_ST(HH_P_CREATE()(ai->hmac_pseudo, &h, NULL, 0, NULL, 0, 0), 0);
        if (h) HH_P_DESTROY()(h);
        h = NULL;
        EXPECT_ST(HH_P_CREATE()(ai->hmac_pseudo, &h, NULL, 0, &z, 0, 0), 0);
        if (h) HH_P_DESTROY()(h);
    }
}
TEST(hh_create_works_with_opened_and_pseudo_handles) {
    NEED();
    FOR_ALGS(ai) {
        BCRYPT_ALG_HANDLE a = hh_open(ai->wname, 0);
        BYTE x[64], y[64];
        EXPECT_ST(hh_compute(a, NULL, 0, (PUCHAR)"abc", 3, 0, 0, x, ai->digest), 0);
        EXPECT_ST(hh_compute(ai->pseudo, NULL, 0, (PUCHAR)"abc", 3, 0, 0, y, ai->digest), 0);
        CHECK(!memcmp(x, y, ai->digest));
        hh_close(a);
    }
}
TEST(hh_create_many_live_handles_one_algorithm) {
    NEED();
    enum { N = 100 };
    BCRYPT_ALG_HANDLE a = hh_open(L"SHA256", 0);
    BCRYPT_HASH_HANDLE hs[N]; BYTE msg[N];
    for (int i = 0; i < N; i++) { hs[i] = mkhash(a, 0); msg[i] = (BYTE)(i * 7); }
    for (int round = 0; round < 3; round++) for (int i = 0; i < N; i++) if (hs[i]) HH_P_DATA()(hs[i], &msg[i], 1, 0);
    for (int i = 0; i < N; i++) {
        BYTE out[32], want[32], three[3] = {msg[i], msg[i], msg[i]};
        if (!hs[i]) continue;
        EXPECT_ST(HH_P_FINISH()(hs[i], out, 32, 0), 0);
        HH_P_HASH()(a, NULL, 0, three, 3, want, 32);
        CHECK(!memcmp(out, want, 32));
        HH_P_DESTROY()(hs[i]);
    }
    hh_close(a);
}

/* ===================== BCryptHashData ===================== */
TEST(hh_hashdata_null_handle) {
    NEED();
    EXPECT_ST(HH_P_DATA()(NULL, (PUCHAR)"abc", 3, 0), NS_INVALID_HANDLE);
    EXPECT_ST(HH_P_DATA()(NULL, NULL, 0, 0), NS_INVALID_HANDLE);
    EXPECT_ST(HH_P_DATA()(NULL, (PUCHAR)"abc", 3, 1), NS_INVALID_HANDLE);   /* handle is validated before flags */
}
TEST(hh_hashdata_algorithm_handle_is_not_a_hash) {
    NEED();
    BCRYPT_ALG_HANDLE a = hh_open(L"SHA1", 0);
    if (!a) return;
    EXPECT_ST(HH_P_DATA()((BCRYPT_HASH_HANDLE)a, (PUCHAR)"abc", 3, 0), NS_INVALID_HANDLE);
    BYTE out[20];
    EXPECT_ST(HH_P_FINISH()((BCRYPT_HASH_HANDLE)a, out, 20, 0), NS_INVALID_HANDLE);
    BCRYPT_HASH_HANDLE d = SENT;
    if (HH_P_DUP()) EXPECT_ST(HH_P_DUP()((BCRYPT_HASH_HANDLE)a, &d, NULL, 0, 0), NS_INVALID_HANDLE);
    EXPECT_ST(HH_P_DESTROY()((BCRYPT_HASH_HANDLE)a), NS_INVALID_PARAM);
    hh_close(a);
}
TEST(hh_hashdata_nonzero_flags_rejected_state_preserved) {
    NEED();
    static const ULONG bad[] = {0x1, 0x2, 0x8, 0x10, 0x20, 0x40, 0x100, 0x80000000, 0xfffffffb};
    FOR_ALGS(ai) {
        BCRYPT_HASH_HANDLE h = mkhash(ai->pseudo, 0);
        if (!h) continue;
        for (unsigned i = 0; i < sizeof bad / sizeof *bad; i++) {
            NTSTATUS st = HH_P_DATA()(h, (PUCHAR)"zzz", 3, bad[i]);
            CHECKF(st == NS_INVALID_PARAM, "%s flags 0x%lx -> 0x%08lx", ai->name, (unsigned long)bad[i], (unsigned long)st);
        }
        EXPECT_ST(HH_P_DATA()(h, (PUCHAR)"abc", 3, 0), 0);
        BYTE out[64], want[64]; sha_abc(ai, want);
        EXPECT_ST(HH_P_FINISH()(h, out, ai->digest, 0), 0);
        CHECKF(!memcmp(out, want, ai->digest), "%s: rejected HashData calls must not alter the state", ai->name);
        HH_P_DESTROY()(h);
    }
}
TEST(hh_hashdata_zero_length_ignores_pointer) {
    NEED();
    FOR_ALGS(ai) {
        BCRYPT_HASH_HANDLE h = mkhash(ai->pseudo, 0);
        if (!h) continue;
        BYTE z = 7;
        EXPECT_ST(HH_P_DATA()(h, NULL, 0, 0), 0);
        EXPECT_ST(HH_P_DATA()(h, &z, 0, 0), 0);
        EXPECT_ST(HH_P_DATA()(h, (PUCHAR)"abc", 3, 0), 0);
        EXPECT_ST(HH_P_DATA()(h, NULL, 0, 0), 0);
        BYTE out[64], want[64]; sha_abc(ai, want);
        EXPECT_ST(HH_P_FINISH()(h, out, ai->digest, 0), 0);
        CHECK(!memcmp(out, want, ai->digest));
        HH_P_DESTROY()(h);
    }
}
TEST(hh_hashdata_empty_hash_without_any_hashdata_call) {
    NEED();
    FOR_ALGS(ai) {
        BCRYPT_HASH_HANDLE h = mkhash(ai->pseudo, 0);
        if (!h) continue;
        BYTE out[64], want[64];
        EXPECT_ST(HH_P_FINISH()(h, out, ai->digest, 0), 0);
        EXPECT_ST(HH_P_HASH()(ai->pseudo, NULL, 0, NULL, 0, want, ai->digest), 0);
        CHECK(!memcmp(out, want, ai->digest));
        HH_P_DESTROY()(h);
    }
}
TEST(hh_hashdata_after_finish_invalid_handle) {
    NEED();
    FOR_ALGS(ai) {
        BCRYPT_HASH_HANDLE h = mkhash(ai->pseudo, 0);
        if (!h) continue;
        BYTE out[64];
        EXPECT_ST(HH_P_FINISH()(h, out, ai->digest, 0), 0);
        EXPECT_ST(HH_P_DATA()(h, (PUCHAR)"abc", 3, 0), NS_INVALID_HANDLE);
        EXPECT_ST(HH_P_DATA()(h, NULL, 0, 0), NS_INVALID_HANDLE);   /* even an empty update is refused on a finished hash */
        EXPECT_ST(HH_P_DESTROY()(h), 0);
    }
}
TEST(hh_hashdata_after_destroy_caller_object) {
    NEED();
    FOR_ALGS(ai) {
        ULONG ol = hh_objlen(ai->pseudo);
        objbuf o = ob_new(ol); BCRYPT_HASH_HANDLE h = NULL;
        if (HH_P_CREATE()(ai->pseudo, &h, o.buf, ol, NULL, 0, 0)) { ob_free(&o); continue; }
        EXPECT_ST(HH_P_DESTROY()(h), 0);
        BYTE out[64];
        EXPECT_ST(HH_P_DATA()(h, (PUCHAR)"abc", 3, 0), NS_INVALID_HANDLE);
        EXPECT_ST(HH_P_FINISH()(h, out, ai->digest, 0), NS_INVALID_HANDLE);
        EXPECT_ST(HH_P_DESTROY()(h), NS_INVALID_PARAM);
        BCRYPT_HASH_HANDLE d = SENT;
        if (HH_P_DUP()) { EXPECT_ST(HH_P_DUP()(h, &d, NULL, 0, 0), NS_INVALID_HANDLE); CHECK(d == SENT); }
        ob_free(&o);
    }
}
TEST(hh_hashdata_input_alignment_does_not_matter) {
    NEED();
    BYTE raw[600]; hh_lcg_fill(raw, sizeof raw, 4242);
    FOR_ALGS(ai) {
        BYTE base[64];
        BYTE *aligned = _aligned_malloc(512, 64); memcpy(aligned, raw, 300);
        EXPECT_ST(hh_compute(ai->pseudo, NULL, 0, aligned, 300, 0, 0, base, ai->digest), 0);
        for (int off = 1; off < 9; off++) {
            BYTE got[64];
            memcpy(aligned + off, raw, 300);
            EXPECT_ST(hh_compute(ai->pseudo, NULL, 0, aligned + off, 300, 0, 0, got, ai->digest), 0);
            CHECKF(!memcmp(base, got, ai->digest), "%s offset %d", ai->name, off);
        }
        _aligned_free(aligned);
    }
}
TEST(hh_hashdata_large_single_call_4mb) {
    NEED();
    ULONG n = 4u << 20; BYTE *d = malloc(n); hh_lcg_fill(d, n, 17);
    FOR_ALGS(ai) {
        BYTE one[64], split[64];
        EXPECT_ST(hh_compute(ai->pseudo, NULL, 0, d, n, 0, 0, one, ai->digest), 0);
        EXPECT_ST(hh_compute(ai->pseudo, NULL, 0, d, n, 1u << 20, 0, split, ai->digest), 0);
        CHECK(!memcmp(one, split, ai->digest));
    }
    free(d);
}

/* ===================== BCryptFinishHash ===================== */
TEST(hh_finish_null_handle) {
    NEED();
    BYTE out[64];
    EXPECT_ST(HH_P_FINISH()(NULL, out, 20, 0), NS_INVALID_HANDLE);
    EXPECT_ST(HH_P_FINISH()(NULL, NULL, 0, 0), NS_INVALID_HANDLE);
}
TEST(hh_finish_null_output_buffer) {
    NEED();
    FOR_ALGS(ai) {
        BCRYPT_HASH_HANDLE h = mkhash(ai->pseudo, 0);
        if (!h) continue;
        EXPECT_ST(HH_P_FINISH()(h, NULL, ai->digest, 0), NS_INVALID_PARAM);   /* no size-query protocol: NULL is a plain error */
        EXPECT_ST(HH_P_FINISH()(h, NULL, 0, 0), NS_INVALID_PARAM);
        BYTE out[64], want[64]; sha_abc(ai, want);
        EXPECT_ST(HH_P_DATA()(h, (PUCHAR)"abc", 3, 0), 0);
        EXPECT_ST(HH_P_FINISH()(h, out, ai->digest, 0), 0);
        CHECK(!memcmp(out, want, ai->digest));
        HH_P_DESTROY()(h);
    }
}
TEST(hh_finish_wrong_output_size_is_invalid_parameter) {
    NEED();
    FOR_ALGS(ai) {
        BCRYPT_HASH_HANDLE h = mkhash(ai->pseudo, 0);
        if (!h) continue;
        ULONG sizes[] = {0, 1, ai->digest - 1, ai->digest + 1, ai->digest * 2, 64, 0x1000, 0xffffffff};
        for (unsigned i = 0; i < sizeof sizes / sizeof *sizes; i++) {
            if (sizes[i] == ai->digest) continue;
            BYTE out[128]; memset(out, 0xEE, sizeof out);
            NTSTATUS st = HH_P_FINISH()(h, out, sizes[i] > 128 ? 128 : sizes[i], 0);
            if (sizes[i] > 128) { /* do not claim more than we own: only the sizes that fit are probed with real sizes */ }
            CHECKF(st == NS_INVALID_PARAM || sizes[i] > 128, "%s cb=%lu -> 0x%08lx", ai->name, (unsigned long)sizes[i], (unsigned long)st);
            for (int j = 0; j < 128; j++) if (out[j] != 0xEE) { CHECKF(0, "%s cb=%lu: output modified on failure", ai->name, (unsigned long)sizes[i]); break; }
        }
        HH_P_DESTROY()(h);
    }
}
TEST(hh_finish_wrong_size_does_not_consume_the_hash) {
    NEED();
    FOR_ALGS(ai) {
        BCRYPT_HASH_HANDLE h = mkhash(ai->pseudo, 0);
        if (!h) continue;
        BYTE out[128], want[64]; sha_abc(ai, want);
        EXPECT_ST(HH_P_DATA()(h, (PUCHAR)"abc", 3, 0), 0);
        EXPECT_ST(HH_P_FINISH()(h, out, ai->digest - 1, 0), NS_INVALID_PARAM);
        EXPECT_ST(HH_P_FINISH()(h, out, ai->digest + 1, 0), NS_INVALID_PARAM);
        EXPECT_ST(HH_P_FINISH()(h, out, ai->digest, 0), 0);
        CHECKF(!memcmp(out, want, ai->digest), "%s", ai->name);
        HH_P_DESTROY()(h);
    }
}
TEST(hh_finish_nonzero_flags_rejected_state_preserved) {
    NEED();
    static const ULONG bad[] = {0x1, 0x4, 0x20, 0x80000000, 0xffffffff};
    FOR_ALGS(ai) {
        BCRYPT_HASH_HANDLE h = mkhash(ai->pseudo, 0);
        if (!h) continue;
        BYTE out[64], want[64]; sha_abc(ai, want);
        EXPECT_ST(HH_P_DATA()(h, (PUCHAR)"abc", 3, 0), 0);
        for (unsigned i = 0; i < sizeof bad / sizeof *bad; i++) {
            memset(out, 0xEE, sizeof out);
            NTSTATUS st = HH_P_FINISH()(h, out, ai->digest, bad[i]);
            CHECKF(st == NS_INVALID_PARAM, "%s flags 0x%lx -> 0x%08lx", ai->name, (unsigned long)bad[i], (unsigned long)st);
            CHECK(out[0] == 0xEE);
        }
        EXPECT_ST(HH_P_FINISH()(h, out, ai->digest, 0), 0);
        CHECK(!memcmp(out, want, ai->digest));
        HH_P_DESTROY()(h);
    }
}
TEST(hh_finish_writes_exactly_digest_size) {
    NEED();
    FOR_ALGS(ai) {
        BCRYPT_HASH_HANDLE h = mkhash(ai->pseudo, 0);
        if (!h) continue;
        BYTE out[128]; memset(out, 0xC3, sizeof out);
        EXPECT_ST(HH_P_FINISH()(h, out + 8, ai->digest, 0), 0);
        for (int i = 0; i < 8; i++) CHECK(out[i] == 0xC3);
        for (ULONG i = 8 + ai->digest; i < 128; i++) CHECK(out[i] == 0xC3);
        HH_P_DESTROY()(h);
    }
}
TEST(hh_finish_twice_second_is_invalid_handle) {
    NEED();
    FOR_ALGS(ai) {
        BCRYPT_HASH_HANDLE h = mkhash(ai->pseudo, 0);
        if (!h) continue;
        BYTE out[64], out2[64]; memset(out2, 0xEE, sizeof out2);
        EXPECT_ST(HH_P_FINISH()(h, out, ai->digest, 0), 0);
        EXPECT_ST(HH_P_FINISH()(h, out2, ai->digest, 0), NS_INVALID_HANDLE);
        CHECK(out2[0] == 0xEE);
        /* the handle check happens before argument validation of the output */
        EXPECT_ST(HH_P_FINISH()(h, out2, 0, 0), NS_INVALID_HANDLE);
        EXPECT_ST(HH_P_FINISH()(h, NULL, ai->digest, 0), NS_INVALID_HANDLE);
        EXPECT_ST(HH_P_DESTROY()(h), 0);
    }
}
TEST(hh_finish_reusable_twice_second_is_empty_hash) {
    NEED();
    FOR_ALGS(ai) {
        BCRYPT_HASH_HANDLE h = mkhash(ai->pseudo, BCRYPT_HASH_REUSABLE_FLAG);
        if (!h) continue;
        BYTE a1[64], a2[64];
        EXPECT_ST(HH_P_DATA()(h, (PUCHAR)"abc", 3, 0), 0);
        EXPECT_ST(HH_P_FINISH()(h, a1, ai->digest, 0), 0);
        EXPECT_ST(HH_P_FINISH()(h, a2, ai->digest, 0), 0);
        BYTE empty[64]; HH_P_HASH()(ai->pseudo, NULL, 0, NULL, 0, empty, ai->digest);
        CHECKF(!memcmp(a2, empty, ai->digest), "%s: finish on a reset reusable hash must give the empty-message digest", ai->name);
        HH_P_DESTROY()(h);
    }
}
TEST(hh_finish_reusable_wrong_size_keeps_data) {
    NEED();
    FOR_ALGS(ai) {
        BCRYPT_HASH_HANDLE h = mkhash(ai->pseudo, BCRYPT_HASH_REUSABLE_FLAG);
        if (!h) continue;
        BYTE out[128], want[64]; sha_abc(ai, want);
        EXPECT_ST(HH_P_DATA()(h, (PUCHAR)"abc", 3, 0), 0);
        EXPECT_ST(HH_P_FINISH()(h, out, ai->digest + 1, 0), NS_INVALID_PARAM);
        EXPECT_ST(HH_P_FINISH()(h, out, ai->digest, 0), 0);
        CHECK(!memcmp(out, want, ai->digest));
        HH_P_DESTROY()(h);
    }
}
TEST(hh_finish_reusable_flag_from_open_applies_to_hashes) {
    NEED();
    FOR_ALGS(ai) {
        BCRYPT_ALG_HANDLE a = NULL;
        NTSTATUS st = HH_P_OPEN()(&a, ai->wname, NULL, BCRYPT_HASH_REUSABLE_FLAG);
        if (st) { t_note("%s: open with REUSABLE flag -> 0x%08lx", ai->name, (unsigned long)st); continue; }
        BCRYPT_HASH_HANDLE h = mkhash(a, 0);
        BYTE o1[64], o2[64], want[64]; sha_abc(ai, want);
        if (h) {
            EXPECT_ST(HH_P_DATA()(h, (PUCHAR)"abc", 3, 0), 0);
            EXPECT_ST(HH_P_FINISH()(h, o1, ai->digest, 0), 0);
            EXPECT_ST(HH_P_DATA()(h, (PUCHAR)"abc", 3, 0), 0);
            EXPECT_ST(HH_P_FINISH()(h, o2, ai->digest, 0), 0);
            CHECK(!memcmp(o1, want, ai->digest)); CHECK(!memcmp(o2, want, ai->digest));
            HH_P_DESTROY()(h);
        }
        hh_close(a);
    }
}

/* ===================== BCryptDestroyHash ===================== */
TEST(hh_destroy_null_handle_is_invalid_parameter) {
    NEED();
    EXPECT_ST(HH_P_DESTROY()(NULL), NS_INVALID_PARAM);   /* not STATUS_INVALID_HANDLE */
}
TEST(hh_destroy_unfinished_and_finished_both_ok) {
    NEED();
    FOR_ALGS(ai) {
        BCRYPT_HASH_HANDLE h = mkhash(ai->pseudo, 0), h2 = mkhash(ai->pseudo, 0);
        if (!h || !h2) continue;
        BYTE out[64];
        HH_P_DATA()(h, (PUCHAR)"x", 1, 0);
        EXPECT_ST(HH_P_DESTROY()(h), 0);
        HH_P_DATA()(h2, (PUCHAR)"x", 1, 0);
        HH_P_FINISH()(h2, out, ai->digest, 0);
        EXPECT_ST(HH_P_DESTROY()(h2), 0);
    }
}
TEST(hh_destroy_twice_on_caller_object) {
    NEED();
    FOR_ALGS(ai) {
        ULONG ol = hh_objlen(ai->pseudo);
        objbuf o = ob_new(ol); BCRYPT_HASH_HANDLE h = NULL;
        if (HH_P_CREATE()(ai->pseudo, &h, o.buf, ol, NULL, 0, 0)) { ob_free(&o); continue; }
        EXPECT_ST(HH_P_DESTROY()(h), 0);
        EXPECT_ST(HH_P_DESTROY()(h), NS_INVALID_PARAM);
        CHECK(ob_guards_ok(&o));
        ob_free(&o);
    }
}
TEST(hh_destroy_caller_object_can_be_reused_for_new_hash) {
    NEED();
    FOR_ALGS(ai) {
        ULONG ol = hh_objlen(ai->pseudo);
        objbuf o = ob_new(ol);
        for (int round = 0; round < 3; round++) {
            BCRYPT_HASH_HANDLE h = NULL; BYTE out[64], want[64]; sha_abc(ai, want);
            EXPECT_ST(HH_P_CREATE()(ai->pseudo, &h, o.buf, ol, NULL, 0, 0), 0);
            if (!h) break;
            HH_P_DATA()(h, (PUCHAR)"abc", 3, 0);
            EXPECT_ST(HH_P_FINISH()(h, out, ai->digest, 0), 0);
            CHECK(!memcmp(out, want, ai->digest));
            EXPECT_ST(HH_P_DESTROY()(h), 0);
        }
        ob_free(&o);
    }
}

/* ===================== BCryptDuplicateHash ===================== */
TEST(hh_dup_null_handle) {
    NEED_DUP();
    BCRYPT_HASH_HANDLE d = SENT;
    EXPECT_ST(HH_P_DUP()(NULL, &d, NULL, 0, 0), NS_INVALID_HANDLE);
    CHECK(d == SENT);
}
TEST(hh_dup_nonzero_flags) {
    NEED_DUP();
    static const ULONG bad[] = {0x1, 0x20, 0x80000000};
    FOR_ALGS(ai) {
        BCRYPT_HASH_HANDLE h = mkhash(ai->pseudo, 0), d = SENT;
        if (!h) continue;
        for (unsigned i = 0; i < sizeof bad / sizeof *bad; i++) EXPECT_ST(HH_P_DUP()(h, &d, NULL, 0, bad[i]), NS_INVALID_PARAM);
        CHECK(d == SENT);
        HH_P_DESTROY()(h);
    }
}
TEST(hh_dup_null_output_handle) {
    NEED_DUP();
    FOR_ALGS(ai) {
        BCRYPT_HASH_HANDLE h = mkhash(ai->pseudo, 0);
        if (!h) continue;
        EXPECT_ST(HH_P_DUP()(h, NULL, NULL, 0, 0), NS_INVALID_PARAM);
        objbuf o = ob_new(hh_objlen(ai->pseudo));
        EXPECT_ST(HH_P_DUP()(h, NULL, o.buf, o.cb, 0), NS_INVALID_PARAM);
        CHECK(ob_guards_ok(&o));
        ob_free(&o);
        HH_P_DESTROY()(h);
    }
}
TEST(hh_dup_null_object_with_nonzero_size) {
    NEED_DUP();
    FOR_ALGS(ai) {
        BCRYPT_HASH_HANDLE h = mkhash(ai->pseudo, 0), d = SENT;
        if (!h) continue;
        EXPECT_ST(HH_P_DUP()(h, &d, NULL, 0x400, 0), NS_INVALID_PARAM);
        CHECK(d == SENT);
        HH_P_DESTROY()(h);
    }
}
TEST(hh_dup_object_buffer_too_small) {
    NEED_DUP();
    static const ULONG sizes[] = {0, 1, 0x45, 0x46};
    FOR_ALGS(ai) {
        BCRYPT_HASH_HANDLE h = mkhash(ai->pseudo, 0);
        if (!h) continue;
        for (unsigned i = 0; i < sizeof sizes / sizeof *sizes; i++) {
            objbuf o = ob_new(0x200); BCRYPT_HASH_HANDLE d = SENT;
            EXPECT_ST(HH_P_DUP()(h, &d, o.buf, sizes[i], 0), NS_BUFFER_TOO_SMALL);
            CHECK(d == SENT);
            CHECK(ob_guards_ok(&o));
            ob_free(&o);
        }
        HH_P_DESTROY()(h);
    }
}
TEST(hh_dup_into_exact_objectlength_buffer) {
    NEED_DUP();
    FOR_ALGS(ai) {
        BCRYPT_HASH_HANDLE h = mkhash(ai->pseudo, 0), d = NULL;
        if (!h) continue;
        ULONG ol = hh_objlen(ai->pseudo);
        objbuf o = ob_new(ol);
        HH_P_DATA()(h, (PUCHAR)"ab", 2, 0);
        EXPECT_ST(HH_P_DUP()(h, &d, o.buf, ol, 0), 0);
        if (d) {
            CHECK((BYTE *)d >= o.buf && (BYTE *)d < o.buf + ol);
            BYTE out[64], want[64]; sha_abc(ai, want);
            HH_P_DATA()(d, (PUCHAR)"c", 1, 0);
            EXPECT_ST(HH_P_FINISH()(d, out, ai->digest, 0), 0);
            CHECK(!memcmp(out, want, ai->digest));
            CHECK(ob_guards_ok(&o));
            HH_P_DESTROY()(d);
        }
        HH_P_DESTROY()(h);
        ob_free(&o);
    }
}
TEST(hh_dup_copies_state_then_diverges) {
    NEED_DUP();
    FOR_ALGS(ai) {
        BCRYPT_HASH_HANDLE h = mkhash(ai->pseudo, 0), d = NULL;
        if (!h) continue;
        BYTE oa[64], ob[64], wa[64], wb[64];
        HH_P_DATA()(h, (PUCHAR)"common-", 7, 0);
        EXPECT_ST(HH_P_DUP()(h, &d, NULL, 0, 0), 0);
        CHECK(d != NULL && d != h);
        if (!d) { HH_P_DESTROY()(h); continue; }
        HH_P_DATA()(h, (PUCHAR)"AAA", 3, 0);
        HH_P_DATA()(d, (PUCHAR)"BBBB", 4, 0);
        EXPECT_ST(HH_P_FINISH()(d, ob, ai->digest, 0), 0);
        EXPECT_ST(HH_P_FINISH()(h, oa, ai->digest, 0), 0);
        HH_P_HASH()(ai->pseudo, NULL, 0, (PUCHAR)"common-AAA", 10, wa, ai->digest);
        HH_P_HASH()(ai->pseudo, NULL, 0, (PUCHAR)"common-BBBB", 11, wb, ai->digest);
        CHECKF(!memcmp(oa, wa, ai->digest), "%s original", ai->name);
        CHECKF(!memcmp(ob, wb, ai->digest), "%s duplicate", ai->name);
        HH_P_DESTROY()(d); HH_P_DESTROY()(h);
    }
}
TEST(hh_dup_at_empty_state) {
    NEED_DUP();
    FOR_ALGS(ai) {
        BCRYPT_HASH_HANDLE h = mkhash(ai->pseudo, 0), d = NULL;
        if (!h) continue;
        EXPECT_ST(HH_P_DUP()(h, &d, NULL, 0, 0), 0);
        BYTE o1[64], o2[64];
        if (d) {
            EXPECT_ST(HH_P_FINISH()(d, o1, ai->digest, 0), 0);
            EXPECT_ST(HH_P_FINISH()(h, o2, ai->digest, 0), 0);
            CHECK(!memcmp(o1, o2, ai->digest));
            HH_P_DESTROY()(d);
        }
        HH_P_DESTROY()(h);
    }
}
TEST(hh_dup_survives_destruction_of_original) {
    NEED_DUP();
    FOR_ALGS(ai) {
        BCRYPT_HASH_HANDLE h = mkhash(ai->pseudo, 0), d = NULL;
        if (!h) continue;
        HH_P_DATA()(h, (PUCHAR)"ab", 2, 0);
        EXPECT_ST(HH_P_DUP()(h, &d, NULL, 0, 0), 0);
        EXPECT_ST(HH_P_DESTROY()(h), 0);
        if (d) {
            BYTE out[64], want[64]; sha_abc(ai, want);
            HH_P_DATA()(d, (PUCHAR)"c", 1, 0);
            EXPECT_ST(HH_P_FINISH()(d, out, ai->digest, 0), 0);
            CHECK(!memcmp(out, want, ai->digest));
            HH_P_DESTROY()(d);
        }
    }
}
TEST(hh_dup_chain_matches_prefixes) {
    NEED_DUP();
    FOR_ALGS(ai) {
        BCRYPT_HASH_HANDLE hs[6]; hs[0] = mkhash(ai->pseudo, 0);
        if (!hs[0]) continue;
        for (int i = 1; i < 6; i++) {
            HH_P_DATA()(hs[i - 1], (PUCHAR)"x", 1, 0);
            EXPECT_ST(HH_P_DUP()(hs[i - 1], &hs[i], NULL, 0, 0), 0);
        }
        /* a handle is updated once more after it is duplicated, so hs[i] (i<5) holds i+1 bytes, hs[5] holds 5 */
        for (int i = 0; i < 6; i++) {
            BYTE out[64], want[64]; char msg[8] = "xxxxxxx";
            if (HH_P_FINISH()(hs[i], out, ai->digest, 0)) continue;
            HH_P_HASH()(ai->pseudo, NULL, 0, (PUCHAR)msg, (ULONG)(i < 5 ? i + 1 : 5), want, ai->digest);
            CHECKF(!memcmp(out, want, ai->digest), "%s chain element %d", ai->name, i);
        }
        for (int i = 0; i < 6; i++) HH_P_DESTROY()(hs[i]);
    }
}
TEST(hh_dup_hmac_keeps_key) {
    NEED_DUP();
    FOR_ALGS(ai) {
        BCRYPT_HASH_HANDLE h = NULL, d = NULL;
        if (HH_P_CREATE()(ai->hmac_pseudo, &h, NULL, 0, (PUCHAR)"secret", 6, 0)) continue;
        HH_P_DATA()(h, (PUCHAR)"he", 2, 0);
        EXPECT_ST(HH_P_DUP()(h, &d, NULL, 0, 0), 0);
        if (d) {
            BYTE o1[64], o2[64], want[64];
            HH_P_DATA()(h, (PUCHAR)"llo", 3, 0); HH_P_DATA()(d, (PUCHAR)"llo", 3, 0);
            EXPECT_ST(HH_P_FINISH()(h, o1, ai->digest, 0), 0);
            EXPECT_ST(HH_P_FINISH()(d, o2, ai->digest, 0), 0);
            HH_P_HASH()(ai->hmac_pseudo, (PUCHAR)"secret", 6, (PUCHAR)"hello", 5, want, ai->digest);
            CHECK(!memcmp(o1, want, ai->digest)); CHECK(!memcmp(o2, want, ai->digest));
            HH_P_DESTROY()(d);
        }
        HH_P_DESTROY()(h);
    }
}
TEST(hh_dup_of_reusable_hash_is_reusable) {
    NEED_DUP();
    FOR_ALGS(ai) {
        BCRYPT_HASH_HANDLE h = mkhash(ai->pseudo, BCRYPT_HASH_REUSABLE_FLAG), d = NULL;
        if (!h) continue;
        HH_P_DATA()(h, (PUCHAR)"a", 1, 0);
        EXPECT_ST(HH_P_DUP()(h, &d, NULL, 0, 0), 0);
        if (d) {
            BYTE o1[64], o2[64], want[64]; sha_abc(ai, want);
            EXPECT_ST(HH_P_FINISH()(d, o1, ai->digest, 0), 0);
            HH_P_DATA()(d, (PUCHAR)"abc", 3, 0);
            EXPECT_ST(HH_P_FINISH()(d, o2, ai->digest, 0), 0);
            CHECK(!memcmp(o2, want, ai->digest));
            HH_P_DESTROY()(d);
        }
        HH_P_DESTROY()(h);
    }
}
TEST(hh_dup_of_finished_hash_is_still_finished) {
    NEED_DUP();
    FOR_ALGS(ai) {
        BCRYPT_HASH_HANDLE h = mkhash(ai->pseudo, 0), d = NULL;
        if (!h) continue;
        BYTE out[64];
        HH_P_FINISH()(h, out, ai->digest, 0);
        NTSTATUS st = HH_P_DUP()(h, &d, NULL, 0, 0);
        t_note("%s: BCryptDuplicateHash on a finished non-reusable hash -> 0x%08lx", ai->name, (unsigned long)st);
        if (st == 0 && d) {
            EXPECT_ST(HH_P_DATA()(d, (PUCHAR)"x", 1, 0), NS_INVALID_HANDLE);
            EXPECT_ST(HH_P_FINISH()(d, out, ai->digest, 0), NS_INVALID_HANDLE);
            HH_P_DESTROY()(d);
        }
        HH_P_DESTROY()(h);
    }
}
TEST(hh_dup_caller_object_guards) {
    NEED_DUP();
    FOR_ALGS(ai) {
        BCRYPT_HASH_HANDLE h = mkhash(ai->pseudo, 0), d = NULL;
        if (!h) continue;
        ULONG ol = hh_objlen(ai->pseudo);
        objbuf o = ob_new(ol + 40);
        EXPECT_ST(HH_P_DUP()(h, &d, o.buf + 3, ol + 40 - 3, 0), 0);
        CHECK(ob_guards_ok(&o));
        if (d) { CHECK(((ULONG_PTR)d & 15) == 0); HH_P_DESTROY()(d); }
        CHECK(ob_guards_ok(&o));
        ob_free(&o);
        HH_P_DESTROY()(h);
    }
}

/* ===================== BCryptHash (one-shot, Windows 10) ===================== */
TEST(hh_bchash_null_algorithm_handle) {
    if (!HH_P_HASH()) { t_skip("missing BCryptHash"); return; }
    BYTE out[32];
    EXPECT_ST(HH_P_HASH()(NULL, NULL, 0, (PUCHAR)"abc", 3, out, 32), NS_INVALID_HANDLE);
    EXPECT_ST(HH_P_HASH()((BCRYPT_ALG_HANDLE)(ULONG_PTR)0x3a1, NULL, 0, (PUCHAR)"abc", 3, out, 32), NS_INVALID_HANDLE);
}
TEST(hh_bchash_null_output) {
    if (!HH_P_HASH()) { t_skip("missing BCryptHash"); return; }
    FOR_ALGS(ai) EXPECT_ST(HH_P_HASH()(ai->pseudo, NULL, 0, (PUCHAR)"abc", 3, NULL, ai->digest), NS_INVALID_PARAM);
}
TEST(hh_bchash_wrong_output_size) {
    if (!HH_P_HASH()) { t_skip("missing BCryptHash"); return; }
    FOR_ALGS(ai) {
        BYTE out[128]; memset(out, 0xEE, sizeof out);
        EXPECT_ST(HH_P_HASH()(ai->pseudo, NULL, 0, (PUCHAR)"abc", 3, out, 0), NS_INVALID_PARAM);
        EXPECT_ST(HH_P_HASH()(ai->pseudo, NULL, 0, (PUCHAR)"abc", 3, out, ai->digest - 1), NS_INVALID_PARAM);
        EXPECT_ST(HH_P_HASH()(ai->pseudo, NULL, 0, (PUCHAR)"abc", 3, out, ai->digest + 1), NS_INVALID_PARAM);
        CHECK(out[0] == 0xEE);
    }
}
TEST(hh_bchash_empty_input_null_pointer) {
    if (!HH_P_HASH()) { t_skip("missing BCryptHash"); return; }
    FOR_ALGS(ai) {
        BYTE a1[64], a2[64]; BYTE z = 1;
        EXPECT_ST(HH_P_HASH()(ai->pseudo, NULL, 0, NULL, 0, a1, ai->digest), 0);
        EXPECT_ST(HH_P_HASH()(ai->pseudo, NULL, 0, &z, 0, a2, ai->digest), 0);
        CHECK(!memcmp(a1, a2, ai->digest));
    }
}
TEST(hh_bchash_non_hash_algorithm) {
    if (!HH_P_HASH()) { t_skip("missing BCryptHash"); return; }
    BCRYPT_ALG_HANDLE a = hh_open(L"AES", 0);
    if (!a) return;
    BYTE out[32];
    EXPECT_ST(HH_P_HASH()(a, NULL, 0, (PUCHAR)"abc", 3, out, 32), NS_NOT_SUPPORTED);
    EXPECT_ST(HH_P_HASH()(BCRYPT_AES_CBC_ALG_HANDLE, NULL, 0, (PUCHAR)"abc", 3, out, 32), NS_NOT_SUPPORTED);
    hh_close(a);
}
TEST(hh_bchash_matches_create_hash_sequence_for_all_pseudo_handles) {
    NEED();
    if (!HH_P_HASH()) { t_skip("missing BCryptHash"); return; }
    BYTE msg[777]; hh_lcg_fill(msg, sizeof msg, 8);
    FOR_ALGS(ai) {
        BYTE x[64], y[64], z[64];
        EXPECT_ST(HH_P_HASH()(ai->pseudo, NULL, 0, msg, sizeof msg, x, ai->digest), 0);
        EXPECT_ST(hh_compute(ai->pseudo, NULL, 0, msg, sizeof msg, 100, 0, y, ai->digest), 0);
        BCRYPT_ALG_HANDLE a = hh_open(ai->wname, 0);
        EXPECT_ST(HH_P_HASH()(a, NULL, 0, msg, sizeof msg, z, ai->digest), 0);
        CHECK(!memcmp(x, y, ai->digest)); CHECK(!memcmp(x, z, ai->digest));
        hh_close(a);
    }
}
TEST(hh_bchash_does_not_touch_output_on_failed_create) {
    if (!HH_P_HASH()) { t_skip("missing BCryptHash"); return; }
    BYTE out[32]; memset(out, 0x77, sizeof out);
    EXPECT_ST(HH_P_HASH()(NULL, NULL, 0, (PUCHAR)"x", 1, out, 32), NS_INVALID_HANDLE);
    for (int i = 0; i < 32; i++) CHECK(out[i] == 0x77);
}
