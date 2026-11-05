/* crypt32 internal LRU cache (I_Crypt*Lru*): behaviour reconstructed from the Windows 10 implementation. */
#include "fw.h"

typedef struct {
    DWORD dwFlags;                 /* 0x00 */
    void *pfnFree;                 /* 0x08  void (*)(void *pvData)                          */
    void *pfnHash;                 /* 0x10  DWORD (*)(PCRYPT_DATA_BLOB pIdentifier)         */
    void *pfnOnRemove;             /* 0x18  void (*)(void *pvData, void *pvRemoveContext)   */
    DWORD cBuckets;                /* 0x20 */
    DWORD cMaxEntries;             /* 0x24  0 = unbounded */
} LRUCFG;
#define LRU_NO_SERIALIZE 1
#define LRU_NO_COPY_IDENTIFIER 2
#define LRU_SUPPRESS_REMOVE_NOTIFICATION 4

typedef HANDLE HLRU;
UDECL(BOOL, I_CryptCreateLruCache, (LRUCFG *, HLRU *));
UDECL(BOOL, I_CryptCreateLruEntry, (HLRU, PCRYPT_DATA_BLOB, void *, HLRU *));
UDECL(void, I_CryptInsertLruEntry, (HLRU, void *));
UDECL(HLRU, I_CryptFindLruEntry, (HLRU, PCRYPT_DATA_BLOB));
UDECL(void *, I_CryptFindLruEntryData, (HLRU, PCRYPT_DATA_BLOB, HLRU *));
UDECL(void *, I_CryptGetLruEntryData, (HLRU));
UDECL(PCRYPT_DATA_BLOB, I_CryptGetLruEntryIdentifier, (HLRU));
UDECL(void, I_CryptAddRefLruEntry, (HLRU));
UDECL(void, I_CryptReleaseLruEntry, (HLRU));
UDECL(void, I_CryptTouchLruEntry, (HLRU, DWORD));
UDECL(void, I_CryptRemoveLruEntry, (HLRU, DWORD, void *));
UDECL(void, I_CryptFlushLruCache, (HLRU, DWORD, void *));
UDECL(void, I_CryptFreeLruCache, (HLRU, DWORD, void *));
UDECL(HLRU, I_CryptEnumMatchingLruEntries, (HLRU));
UDECL(void, I_CryptWalkAllLruCacheEntries, (HLRU, BOOL (WINAPI *)(void *, HLRU), void *));
UDECL(void, I_CryptDisableLruOfEntries, (HLRU));
UDECL(void, I_CryptEnableLruOfEntries, (HLRU, void *));

#define NEED_LRU() do { \
    REQUIRE(UN(I_CryptCreateLruCache)); REQUIRE(UN(I_CryptCreateLruEntry)); REQUIRE(UN(I_CryptInsertLruEntry)); \
    REQUIRE(UN(I_CryptFindLruEntry)); REQUIRE(UN(I_CryptReleaseLruEntry)); REQUIRE(UN(I_CryptFreeLruCache)); \
    if (t_is_wine()) { t_skip("LRU cache not available under wine"); return; } } while (0)

/* ---- instrumentation ---- */
enum { EV_REMOVE = 1, EV_FREE = 2 };
static struct { int kind; void *data; void *ctx; } g_ev[512];
static volatile LONG g_nev, g_hash_calls;
static BYTE g_hash_last[64]; static DWORD g_hash_last_cb;
static void ev_reset(void) { g_nev = 0; g_hash_calls = 0; }
static void ev_add(int k, void *d, void *c) { LONG i = InterlockedIncrement(&g_nev) - 1; if (i < 512) { g_ev[i].kind = k; g_ev[i].data = d; g_ev[i].ctx = c; } }
static int ev_count(int kind) { int n = 0; for (int i = 0; i < g_nev && i < 512; i++) if (g_ev[i].kind == kind) n++; return n; }
static void WINAPI cb_free(void *d) { ev_add(EV_FREE, d, NULL); }
static void WINAPI cb_remove(void *d, void *c) { ev_add(EV_REMOVE, d, c); }
static DWORD WINAPI cb_hash(PCRYPT_DATA_BLOB b) {
    InterlockedIncrement(&g_hash_calls);
    g_hash_last_cb = b->cbData;
    memcpy(g_hash_last, b->pbData, b->cbData < 64 ? b->cbData : 64);
    return b->cbData ? b->pbData[0] : 0;
}
static DWORD WINAPI cb_hash_const(PCRYPT_DATA_BLOB b) { return 0xFFFFFFFFu; }

static HLRU mk(DWORD flags, DWORD buckets, DWORD max) {
    LRUCFG c; memset(&c, 0, sizeof c);
    c.dwFlags = flags; c.pfnFree = cb_free; c.pfnHash = cb_hash; c.pfnOnRemove = cb_remove; c.cBuckets = buckets; c.cMaxEntries = max;
    HLRU h = NULL;
    BOOL r = UN(I_CryptCreateLruCache)(&c, &h);
    CHECK(r == TRUE); CHECK(h != NULL);
    return h;
}
static void mkid(BYTE *b, int i) { b[0] = (BYTE)i; b[1] = 'x'; }
#define DATA(i) ((void *)(ULONG_PTR)(1000 + (i)))
/* create + insert + drop creator's reference */
static HLRU put(HLRU c, int i, void *ctx) {
    BYTE id[2]; mkid(id, i);
    CRYPT_DATA_BLOB b = {2, id};
    HLRU e = NULL;
    BOOL r = UN(I_CryptCreateLruEntry)(c, &b, DATA(i), &e);
    CHECKF(r && e, "create %d", i);
    if (!r) return NULL;
    UN(I_CryptInsertLruEntry)(e, ctx);
    UN(I_CryptReleaseLruEntry)(e);
    return e;
}
static int present(HLRU c, int i) {
    BYTE id[2]; mkid(id, i);
    CRYPT_DATA_BLOB b = {2, id};
    HLRU e = UN(I_CryptFindLruEntry)(c, &b);
    if (e) UN(I_CryptReleaseLruEntry)(e);
    return e != NULL;
}
static int npresent(HLRU c, int lo, int hi) { int n = 0; for (int i = lo; i <= hi; i++) n += present(c, i); return n; }
static void drop(HLRU c) { UN(I_CryptFreeLruCache)(c, LRU_SUPPRESS_REMOVE_NOTIFICATION, NULL); }
static int ev_has(int kind, void *data) { for (int i = 0; i < g_nev && i < 512; i++) if (g_ev[i].kind == kind && g_ev[i].data == data) return 1; return 0; }

/* ================= creation / destruction ================= */
TEST(lru_create_and_free_empty_cache) {
    NEED_LRU();
    HLRU c = mk(0, 8, 0);
    UN(I_CryptFreeLruCache)(c, 0, NULL);
}
TEST(lru_free_null_cache_is_noop) {
    NEED_LRU();
    UN(I_CryptFreeLruCache)(NULL, 0, NULL);
    UN(I_CryptFreeLruCache)(NULL, 4, NULL);
}
TEST(lru_create_clears_output_first) {
    NEED_LRU();
    LRUCFG c; memset(&c, 0, sizeof c);
    c.pfnHash = cb_hash; c.cBuckets = 4;
    HLRU h = (HLRU)(ULONG_PTR)0x1234;
    BOOL r = UN(I_CryptCreateLruCache)(&c, &h);
    CHECK(r == TRUE); CHECK(h != NULL && h != (HLRU)(ULONG_PTR)0x1234);
    UN(I_CryptFreeLruCache)(h, 0, NULL);
}
TEST(lru_create_without_callbacks) {
    NEED_LRU();
    LRUCFG c; memset(&c, 0, sizeof c);
    c.pfnHash = cb_hash; c.cBuckets = 4; c.cMaxEntries = 2;
    HLRU h = NULL;
    CHECK(UN(I_CryptCreateLruCache)(&c, &h) && h);
    BYTE id[2]; mkid(id, 1); CRYPT_DATA_BLOB b = {2, id};
    HLRU e = NULL;
    CHECK(UN(I_CryptCreateLruEntry)(h, &b, DATA(1), &e) && e);
    UN(I_CryptInsertLruEntry)(e, NULL);
    UN(I_CryptReleaseLruEntry)(e);
    UN(I_CryptFlushLruCache)(h, 0, NULL);
    UN(I_CryptFreeLruCache)(h, 0, NULL);
}
TEST(lru_two_caches_are_independent) {
    NEED_LRU();
    HLRU a = mk(0, 4, 0), b = mk(0, 4, 0);
    CHECK(a != b);
    put(a, 1, NULL);
    CHECK(present(a, 1) == 1); CHECK(present(b, 1) == 0);
    drop(a); drop(b);
}

/* ================= entries ================= */
TEST(lru_entry_has_data_and_identifier) {
    NEED_LRU(); REQUIRE(UN(I_CryptGetLruEntryData)); REQUIRE(UN(I_CryptGetLruEntryIdentifier));
    HLRU c = mk(0, 4, 0);
    BYTE id[5] = {9, 8, 7, 6, 5}; CRYPT_DATA_BLOB b = {5, id};
    HLRU e = NULL;
    CHECK(UN(I_CryptCreateLruEntry)(c, &b, DATA(7), &e) && e);
    CHECK(UN(I_CryptGetLruEntryData)(e) == DATA(7));
    PCRYPT_DATA_BLOB p = UN(I_CryptGetLruEntryIdentifier)(e);
    CHECK(p != NULL);
    if (p) { CHECK(p->cbData == 5); CHECK(p->pbData != id); CHECK(p->pbData && !memcmp(p->pbData, id, 5)); }
    memset(id, 0, sizeof id);
    if (p) CHECK(p->pbData[0] == 9);   /* the identifier was copied */
    ev_reset();
    UN(I_CryptReleaseLruEntry)(e);
    CHECK(ev_count(EV_FREE) == 1);
    drop(c);
}
TEST(lru_entry_identifier_no_copy_flag) {
    NEED_LRU(); REQUIRE(UN(I_CryptGetLruEntryIdentifier));
    HLRU c = mk(LRU_NO_COPY_IDENTIFIER, 4, 0);
    BYTE id[3] = {1, 2, 3}; CRYPT_DATA_BLOB b = {3, id};
    HLRU e = NULL;
    CHECK(UN(I_CryptCreateLruEntry)(c, &b, DATA(1), &e) && e);
    PCRYPT_DATA_BLOB p = UN(I_CryptGetLruEntryIdentifier)(e);
    CHECK(p && p->cbData == 3 && p->pbData == id);
    UN(I_CryptReleaseLruEntry)(e);
    drop(c);
}
TEST(lru_entry_identifier_is_stable_pointer_into_entry) {
    NEED_LRU(); REQUIRE(UN(I_CryptGetLruEntryIdentifier));
    HLRU c = mk(0, 4, 0);
    HLRU e = put(c, 3, NULL);
    (void)e;
    BYTE id[2]; mkid(id, 3); CRYPT_DATA_BLOB b = {2, id};
    HLRU f = UN(I_CryptFindLruEntry)(c, &b);
    CHECK(f != NULL);
    if (f) {
        PCRYPT_DATA_BLOB p1 = UN(I_CryptGetLruEntryIdentifier)(f), p2 = UN(I_CryptGetLruEntryIdentifier)(f);
        CHECK(p1 && p1 == p2);
        UN(I_CryptReleaseLruEntry)(f);
    }
    drop(c);
}
TEST(lru_entry_null_data_allowed) {
    NEED_LRU(); REQUIRE(UN(I_CryptGetLruEntryData));
    HLRU c = mk(0, 4, 0);
    BYTE id[2]; mkid(id, 2); CRYPT_DATA_BLOB b = {2, id};
    HLRU e = NULL;
    CHECK(UN(I_CryptCreateLruEntry)(c, &b, NULL, &e) && e);
    CHECK(UN(I_CryptGetLruEntryData)(e) == NULL);
    ev_reset();
    UN(I_CryptReleaseLruEntry)(e);
    CHECK(ev_count(EV_FREE) == 1 && g_ev[0].data == NULL);
    drop(c);
}
TEST(lru_entry_created_is_not_findable_until_inserted) {
    NEED_LRU();
    HLRU c = mk(0, 4, 0);
    BYTE id[2]; mkid(id, 5); CRYPT_DATA_BLOB b = {2, id};
    HLRU e = NULL;
    CHECK(UN(I_CryptCreateLruEntry)(c, &b, DATA(5), &e) && e);
    CHECK(present(c, 5) == 0);
    UN(I_CryptInsertLruEntry)(e, NULL);
    CHECK(present(c, 5) == 1);
    UN(I_CryptReleaseLruEntry)(e);
    drop(c);
}
TEST(lru_entry_release_of_uninserted_entry_frees_data) {
    NEED_LRU();
    HLRU c = mk(0, 4, 0);
    BYTE id[2]; mkid(id, 6); CRYPT_DATA_BLOB b = {2, id};
    HLRU e = NULL;
    CHECK(UN(I_CryptCreateLruEntry)(c, &b, DATA(6), &e) && e);
    ev_reset();
    UN(I_CryptReleaseLruEntry)(e);
    CHECK(g_nev == 1 && g_ev[0].kind == EV_FREE && g_ev[0].data == DATA(6));
    CHECK(ev_count(EV_REMOVE) == 0);
    drop(c);
}
TEST(lru_entry_addref_delays_free) {
    NEED_LRU(); REQUIRE(UN(I_CryptAddRefLruEntry));
    HLRU c = mk(0, 4, 0);
    BYTE id[2]; mkid(id, 7); CRYPT_DATA_BLOB b = {2, id};
    HLRU e = NULL;
    CHECK(UN(I_CryptCreateLruEntry)(c, &b, DATA(7), &e) && e);
    UN(I_CryptAddRefLruEntry)(e);
    UN(I_CryptAddRefLruEntry)(e);
    ev_reset();
    UN(I_CryptReleaseLruEntry)(e); CHECK(g_nev == 0);
    UN(I_CryptReleaseLruEntry)(e); CHECK(g_nev == 0);
    UN(I_CryptReleaseLruEntry)(e); CHECK(ev_count(EV_FREE) == 1);
    drop(c);
}
TEST(lru_entry_binary_identifiers_with_nul) {
    NEED_LRU();
    HLRU c = mk(0, 4, 0);
    BYTE i1[4] = {0, 1, 2, 3}, i2[4] = {0, 1, 2, 4}; CRYPT_DATA_BLOB b1 = {4, i1}, b2 = {4, i2};
    HLRU e1 = NULL, e2 = NULL;
    CHECK(UN(I_CryptCreateLruEntry)(c, &b1, DATA(1), &e1) && UN(I_CryptCreateLruEntry)(c, &b2, DATA(2), &e2));
    UN(I_CryptInsertLruEntry)(e1, NULL); UN(I_CryptInsertLruEntry)(e2, NULL);
    HLRU f1 = UN(I_CryptFindLruEntry)(c, &b1), f2 = UN(I_CryptFindLruEntry)(c, &b2);
    CHECK(f1 == e1 && f2 == e2 && f1 != f2);
    UN(I_CryptReleaseLruEntry)(f1); UN(I_CryptReleaseLruEntry)(f2);
    UN(I_CryptReleaseLruEntry)(e1); UN(I_CryptReleaseLruEntry)(e2);
    drop(c);
}
TEST(lru_hash_receives_identifier) {
    NEED_LRU();
    HLRU c = mk(0, 4, 0);
    BYTE id[6] = {0x42, 1, 2, 3, 4, 5}; CRYPT_DATA_BLOB b = {6, id};
    HLRU e = NULL;
    ev_reset();
    CHECK(UN(I_CryptCreateLruEntry)(c, &b, DATA(1), &e) && e);
    CHECK(g_hash_calls >= 1 && g_hash_last_cb == 6 && !memcmp(g_hash_last, id, 6));
    UN(I_CryptInsertLruEntry)(e, NULL);
    ev_reset();
    HLRU f = UN(I_CryptFindLruEntry)(c, &b);
    CHECK(f == e);
    CHECK(g_hash_calls >= 1 && g_hash_last_cb == 6 && !memcmp(g_hash_last, id, 6));
    UN(I_CryptReleaseLruEntry)(f); UN(I_CryptReleaseLruEntry)(e);
    drop(c);
}
TEST(lru_huge_hash_values_are_reduced_modulo_buckets) {
    NEED_LRU();
    LRUCFG cfg; memset(&cfg, 0, sizeof cfg);
    cfg.pfnHash = cb_hash_const; cfg.pfnFree = cb_free; cfg.pfnOnRemove = cb_remove; cfg.cBuckets = 5;
    HLRU c = NULL;
    CHECK(UN(I_CryptCreateLruCache)(&cfg, &c) && c);
    for (int i = 0; i < 6; i++) put(c, i, NULL);
    CHECK(npresent(c, 0, 5) == 6);
    drop(c);
}

/* ================= insert / find ================= */
TEST(lru_find_returns_inserted_entry) {
    NEED_LRU();
    HLRU c = mk(0, 8, 0);
    BYTE id[2]; mkid(id, 4); CRYPT_DATA_BLOB b = {2, id};
    HLRU e = NULL;
    CHECK(UN(I_CryptCreateLruEntry)(c, &b, DATA(4), &e) && e);
    UN(I_CryptInsertLruEntry)(e, NULL);
    HLRU f = UN(I_CryptFindLruEntry)(c, &b);
    CHECK(f == e);
    BYTE id2[2]; mkid(id2, 4); CRYPT_DATA_BLOB b2 = {2, id2};      /* different buffer, same bytes */
    HLRU g = UN(I_CryptFindLruEntry)(c, &b2);
    CHECK(g == e);
    UN(I_CryptReleaseLruEntry)(f); UN(I_CryptReleaseLruEntry)(g); UN(I_CryptReleaseLruEntry)(e);
    drop(c);
}
TEST(lru_find_miss_returns_null) {
    NEED_LRU();
    HLRU c = mk(0, 8, 0);
    put(c, 1, NULL);
    CHECK(present(c, 2) == 0);
    CHECK(present(c, 1 + 8) == 0);
    drop(c);
}
TEST(lru_find_requires_equal_length) {
    NEED_LRU();
    HLRU c = mk(0, 8, 0);
    put(c, 1, NULL);                                   /* identifier {1,'x'} */
    BYTE a[3] = {1, 'x', 'y'}; CRYPT_DATA_BLOB ba = {3, a};
    HLRU e = UN(I_CryptFindLruEntry)(c, &ba);
    CHECK(e == NULL);
    BYTE s[1] = {1}; CRYPT_DATA_BLOB bs = {1, s};
    e = UN(I_CryptFindLruEntry)(c, &bs);
    CHECK(e == NULL);
    drop(c);
}
TEST(lru_find_is_exact_byte_compare) {
    NEED_LRU();
    HLRU c = mk(0, 1, 0);        /* everything collides in one bucket */
    put(c, 1, NULL);
    BYTE a[2] = {1, 'X'}; CRYPT_DATA_BLOB ba = {2, a};
    CHECK(UN(I_CryptFindLruEntry)(c, &ba) == NULL);
    drop(c);
}
TEST(lru_find_entry_data_returns_data_and_entry) {
    NEED_LRU(); REQUIRE(UN(I_CryptFindLruEntryData));
    HLRU c = mk(0, 8, 0);
    HLRU e = put(c, 3, NULL); (void)e;
    BYTE id[2]; mkid(id, 3); CRYPT_DATA_BLOB b = {2, id};
    HLRU f = (HLRU)(ULONG_PTR)0x99;
    void *d = UN(I_CryptFindLruEntryData)(c, &b, &f);
    CHECK(d == DATA(3)); CHECK(f != NULL && f != (HLRU)(ULONG_PTR)0x99);
    if (f) UN(I_CryptReleaseLruEntry)(f);
    drop(c);
}
TEST(lru_find_entry_data_miss) {
    NEED_LRU(); REQUIRE(UN(I_CryptFindLruEntryData));
    HLRU c = mk(0, 8, 0);
    BYTE id[2]; mkid(id, 9); CRYPT_DATA_BLOB b = {2, id};
    HLRU f = (HLRU)(ULONG_PTR)0x99;
    void *d = UN(I_CryptFindLruEntryData)(c, &b, &f);
    CHECK(d == NULL); CHECK(f == NULL);
    drop(c);
}
TEST(lru_find_entry_data_for_null_data_entry) {
    NEED_LRU(); REQUIRE(UN(I_CryptFindLruEntryData));
    HLRU c = mk(0, 8, 0);
    BYTE id[2]; mkid(id, 9); CRYPT_DATA_BLOB b = {2, id};
    HLRU e = NULL;
    CHECK(UN(I_CryptCreateLruEntry)(c, &b, NULL, &e));
    UN(I_CryptInsertLruEntry)(e, NULL); UN(I_CryptReleaseLruEntry)(e);
    HLRU f = NULL;
    CHECK(UN(I_CryptFindLruEntryData)(c, &b, &f) == NULL);
    CHECK(f == e); /* a NULL data pointer is distinguishable from a miss only by the entry out-param */
    if (f) UN(I_CryptReleaseLruEntry)(f);
    drop(c);
}
TEST(lru_insert_keeps_entry_alive_after_creator_release) {
    NEED_LRU();
    HLRU c = mk(0, 8, 0);
    ev_reset();
    put(c, 1, NULL);
    CHECK(g_nev == 0);
    CHECK(present(c, 1));
    drop(c);
}
TEST(lru_find_adds_reference) {
    NEED_LRU();
    HLRU c = mk(0, 8, 0);
    put(c, 1, NULL);
    BYTE id[2]; mkid(id, 1); CRYPT_DATA_BLOB b = {2, id};
    HLRU f = UN(I_CryptFindLruEntry)(c, &b);
    CHECK(f != NULL);
    ev_reset();
    UN(I_CryptRemoveLruEntry)(f, 0, (void *)0x5);   /* the cache drops its reference; ours keeps the entry alive */
    CHECK(ev_count(EV_REMOVE) == 1);
    CHECK(ev_count(EV_FREE) == 0);
    UN(I_CryptReleaseLruEntry)(f);
    CHECK(ev_count(EV_FREE) == 1);
    drop(c);
}
TEST(lru_serialized_and_unserialized_caches_behave_alike) {
    NEED_LRU();
    DWORD fl[] = {0, LRU_NO_SERIALIZE, LRU_NO_COPY_IDENTIFIER, LRU_NO_SERIALIZE | LRU_NO_COPY_IDENTIFIER};
    for (int k = 0; k < 4; k++) {
        HLRU c = mk(fl[k], 8, 3);
        /* identifiers must outlive entries when NO_COPY is set */
        static BYTE ids[16][2];
        for (int i = 0; i < 5; i++) {
            mkid(ids[i], i);
            CRYPT_DATA_BLOB b = {2, ids[i]};
            HLRU e = NULL;
            CHECK(UN(I_CryptCreateLruEntry)(c, &b, DATA(i), &e) && e);
            UN(I_CryptInsertLruEntry)(e, NULL); UN(I_CryptReleaseLruEntry)(e);
        }
        CHECKF(npresent(c, 0, 4) == 3, "flags %lu", fl[k]);
        CHECKF(!present(c, 0) && !present(c, 1) && present(c, 4), "flags %lu", fl[k]);
        UN(I_CryptFreeLruCache)(c, LRU_SUPPRESS_REMOVE_NOTIFICATION, NULL);
    }
}

/* ================= removal and flushing ================= */
TEST(lru_remove_entry_notifies_with_context) {
    NEED_LRU(); REQUIRE(UN(I_CryptRemoveLruEntry));
    HLRU c = mk(0, 8, 0);
    put(c, 1, NULL); put(c, 2, NULL);
    BYTE id[2]; mkid(id, 1); CRYPT_DATA_BLOB b = {2, id};
    HLRU f = UN(I_CryptFindLruEntry)(c, &b);
    ev_reset();
    UN(I_CryptRemoveLruEntry)(f, 0, (void *)0xC0DE);
    CHECK(g_nev == 1 && g_ev[0].kind == EV_REMOVE && g_ev[0].data == DATA(1) && g_ev[0].ctx == (void *)0xC0DE);
    CHECK(!present(c, 1)); CHECK(present(c, 2));
    UN(I_CryptReleaseLruEntry)(f);
    CHECK(g_nev == 2 && g_ev[1].kind == EV_FREE && g_ev[1].data == DATA(1));   /* removal callback precedes data free */
    drop(c);
}
TEST(lru_remove_flag_suppresses_notification) {
    NEED_LRU(); REQUIRE(UN(I_CryptRemoveLruEntry));
    HLRU c = mk(0, 8, 0);
    put(c, 1, NULL);
    BYTE id[2]; mkid(id, 1); CRYPT_DATA_BLOB b = {2, id};
    HLRU f = UN(I_CryptFindLruEntry)(c, &b);
    ev_reset();
    UN(I_CryptRemoveLruEntry)(f, LRU_SUPPRESS_REMOVE_NOTIFICATION, (void *)0xC0DE);
    CHECK(ev_count(EV_REMOVE) == 0);
    CHECK(!present(c, 1));
    UN(I_CryptReleaseLruEntry)(f);
    CHECK(ev_count(EV_FREE) == 1);
    drop(c);
}
TEST(lru_remove_unrelated_flag_bits_still_notify) {
    NEED_LRU(); REQUIRE(UN(I_CryptRemoveLruEntry));
    HLRU c = mk(0, 8, 0);
    put(c, 1, NULL);
    BYTE id[2]; mkid(id, 1); CRYPT_DATA_BLOB b = {2, id};
    HLRU f = UN(I_CryptFindLruEntry)(c, &b);
    ev_reset();
    UN(I_CryptRemoveLruEntry)(f, 0x1 | 0x2, NULL);
    CHECK(ev_count(EV_REMOVE) == 1);
    UN(I_CryptReleaseLruEntry)(f);
    drop(c);
}
TEST(lru_flush_removes_everything) {
    NEED_LRU(); REQUIRE(UN(I_CryptFlushLruCache));
    HLRU c = mk(0, 4, 0);
    for (int i = 0; i < 10; i++) put(c, i, NULL);
    ev_reset();
    UN(I_CryptFlushLruCache)(c, 0, (void *)0xF1);
    CHECK(ev_count(EV_REMOVE) == 10);
    CHECK(ev_count(EV_FREE) == 10);
    for (int i = 0; i < g_nev && i < 512; i++) if (g_ev[i].kind == EV_REMOVE) CHECK(g_ev[i].ctx == (void *)0xF1);
    CHECK(npresent(c, 0, 9) == 0);
    drop(c);
}
TEST(lru_flush_flag_suppresses_notifications) {
    NEED_LRU(); REQUIRE(UN(I_CryptFlushLruCache));
    HLRU c = mk(0, 4, 0);
    for (int i = 0; i < 6; i++) put(c, i, NULL);
    ev_reset();
    UN(I_CryptFlushLruCache)(c, LRU_SUPPRESS_REMOVE_NOTIFICATION, NULL);
    CHECK(ev_count(EV_REMOVE) == 0);
    CHECK(ev_count(EV_FREE) == 6);
    CHECK(npresent(c, 0, 5) == 0);
    drop(c);
}
TEST(lru_flush_empty_cache) {
    NEED_LRU(); REQUIRE(UN(I_CryptFlushLruCache));
    HLRU c = mk(0, 4, 0);
    ev_reset();
    UN(I_CryptFlushLruCache)(c, 0, NULL);
    CHECK(g_nev == 0);
    drop(c);
}
TEST(lru_flush_defers_free_of_externally_held_entries) {
    NEED_LRU(); REQUIRE(UN(I_CryptFlushLruCache));
    HLRU c = mk(0, 4, 0);
    put(c, 1, NULL); put(c, 2, NULL);
    BYTE id[2]; mkid(id, 2); CRYPT_DATA_BLOB b = {2, id};
    HLRU held = UN(I_CryptFindLruEntry)(c, &b);
    ev_reset();
    UN(I_CryptFlushLruCache)(c, 0, NULL);
    CHECK(ev_count(EV_REMOVE) == 2);
    CHECK(ev_count(EV_FREE) == 1);           /* only the entry nobody holds */
    CHECK(!ev_has(EV_FREE, DATA(2)));
    UN(I_CryptReleaseLruEntry)(held);
    CHECK(ev_has(EV_FREE, DATA(2)));
    drop(c);
}
TEST(lru_cache_reusable_after_flush) {
    NEED_LRU(); REQUIRE(UN(I_CryptFlushLruCache));
    HLRU c = mk(0, 4, 2);
    for (int i = 0; i < 4; i++) put(c, i, NULL);
    UN(I_CryptFlushLruCache)(c, LRU_SUPPRESS_REMOVE_NOTIFICATION, NULL);
    put(c, 7, NULL); put(c, 8, NULL); put(c, 9, NULL);
    CHECK(!present(c, 7) && present(c, 8) && present(c, 9));
    drop(c);
}
TEST(lru_free_cache_with_flags_purges_entries) {
    NEED_LRU();
    HLRU c = mk(0, 4, 0);
    for (int i = 0; i < 5; i++) put(c, i, NULL);
    ev_reset();
    UN(I_CryptFreeLruCache)(c, 1, (void *)0xAA);
    CHECK(ev_count(EV_REMOVE) == 5);
    CHECK(ev_count(EV_FREE) == 5);
    for (int i = 0; i < g_nev && i < 512; i++) if (g_ev[i].kind == EV_REMOVE) CHECK(g_ev[i].ctx == (void *)0xAA);
}
TEST(lru_free_cache_suppress_flag_skips_notification) {
    NEED_LRU();
    HLRU c = mk(0, 4, 0);
    for (int i = 0; i < 5; i++) put(c, i, NULL);
    ev_reset();
    UN(I_CryptFreeLruCache)(c, LRU_SUPPRESS_REMOVE_NOTIFICATION, NULL);
    CHECK(ev_count(EV_REMOVE) == 0);
    CHECK(ev_count(EV_FREE) == 5);
}

/* ================= bounded cache: eviction ================= */
static void evict_oldest_scenario(DWORD buckets) {
    HLRU c = mk(0, buckets, 3);
    ev_reset();
    put(c, 1, (void *)0x11); put(c, 2, (void *)0x12); put(c, 3, (void *)0x13);
    CHECK(g_nev == 0);
    put(c, 4, (void *)0x14);
    CHECKF(ev_count(EV_REMOVE) == 1 && g_ev[0].kind == EV_REMOVE && g_ev[0].data == DATA(1), "buckets %lu: first eviction", buckets);
    CHECK(g_ev[0].ctx == (void *)0x14);              /* context of the insert that forced the eviction */
    CHECK(g_ev[1].kind == EV_FREE && g_ev[1].data == DATA(1));
    put(c, 5, (void *)0x15);
    CHECKF(g_nev == 4 && g_ev[2].data == DATA(2) && g_ev[2].ctx == (void *)0x15, "buckets %lu: second eviction", buckets);
    CHECK(npresent(c, 1, 5) == 3);
    CHECK(!present(c, 1) && !present(c, 2) && present(c, 3) && present(c, 4) && present(c, 5));
    drop(c);
}
TEST(lru_evicts_oldest_one_bucket)    { NEED_LRU(); evict_oldest_scenario(1); }
TEST(lru_evicts_oldest_two_buckets)   { NEED_LRU(); evict_oldest_scenario(2); }
TEST(lru_evicts_oldest_prime_buckets) { NEED_LRU(); evict_oldest_scenario(7); }
TEST(lru_evicts_oldest_many_buckets)  { NEED_LRU(); evict_oldest_scenario(251); }

static void touch_scenario(DWORD buckets, int how) {
    /* how: 0 = I_CryptFindLruEntryData (touches), 1 = I_CryptFindLruEntry (does not touch), 2 = explicit touch */
    HLRU c = mk(0, buckets, 3);
    put(c, 1, NULL); put(c, 2, NULL); put(c, 3, NULL);
    BYTE id[2]; mkid(id, 1); CRYPT_DATA_BLOB b = {2, id};
    HLRU f = NULL;
    if (how == 0) { UN(I_CryptFindLruEntryData)(c, &b, &f); }
    else { f = UN(I_CryptFindLruEntry)(c, &b); if (how == 2) UN(I_CryptTouchLruEntry)(f, 0); }
    CHECK(f != NULL);
    if (f) UN(I_CryptReleaseLruEntry)(f);
    ev_reset();
    put(c, 4, NULL);
    int victim = (how == 1) ? 1 : 2;
    CHECKF(ev_count(EV_REMOVE) == 1 && g_ev[0].data == DATA(victim), "buckets %lu how %d: evicted %p want %d", buckets, how, ev_count(EV_REMOVE) ? g_ev[0].data : 0, victim);
    drop(c);
}
TEST(lru_find_entry_data_touches_entry)   { NEED_LRU(); REQUIRE(UN(I_CryptFindLruEntryData)); touch_scenario(1, 0); touch_scenario(4, 0); touch_scenario(64, 0); }
TEST(lru_find_entry_does_not_touch)       { NEED_LRU(); touch_scenario(1, 1); touch_scenario(4, 1); touch_scenario(64, 1); }
TEST(lru_touch_entry_makes_it_newest)     { NEED_LRU(); REQUIRE(UN(I_CryptTouchLruEntry)); touch_scenario(1, 2); touch_scenario(4, 2); touch_scenario(64, 2); }
TEST(lru_touch_order_decides_eviction_sequence) {
    NEED_LRU(); REQUIRE(UN(I_CryptTouchLruEntry));
    HLRU c = mk(0, 5, 4);
    for (int i = 1; i <= 4; i++) put(c, i, NULL);
    /* touch order 2, 4, 1  ->  recency (old to new): 3, 2, 4, 1 */
    int order[3] = {2, 4, 1};
    for (int k = 0; k < 3; k++) {
        BYTE id[2]; mkid(id, order[k]); CRYPT_DATA_BLOB b = {2, id};
        HLRU f = UN(I_CryptFindLruEntry)(c, &b);
        UN(I_CryptTouchLruEntry)(f, 0); UN(I_CryptReleaseLruEntry)(f);
    }
    ev_reset();
    put(c, 10, NULL); put(c, 11, NULL); put(c, 12, NULL); put(c, 13, NULL);
    int want[4] = {3, 2, 4, 1};
    for (int k = 0; k < 4; k++) CHECKF(g_ev[2 * k].kind == EV_REMOVE && g_ev[2 * k].data == DATA(want[k]), "eviction %d", k);
    drop(c);
}
TEST(lru_unbounded_cache_never_evicts) {
    NEED_LRU();
    HLRU c = mk(0, 16, 0);
    ev_reset();
    for (int i = 0; i < 100; i++) put(c, i, NULL);
    CHECK(g_nev == 0);
    CHECK(npresent(c, 0, 99) == 100);
    drop(c);
}
TEST(lru_max_one_keeps_only_last) {
    NEED_LRU();
    HLRU c = mk(0, 3, 1);
    ev_reset();
    for (int i = 0; i < 6; i++) put(c, i, NULL);
    CHECK(ev_count(EV_REMOVE) == 5);
    CHECK(npresent(c, 0, 5) == 1 && present(c, 5));
    drop(c);
}
TEST(lru_eviction_of_externally_held_entry_defers_free) {
    NEED_LRU();
    HLRU c = mk(0, 4, 2);
    put(c, 1, NULL);
    BYTE id[2]; mkid(id, 1); CRYPT_DATA_BLOB b = {2, id};
    HLRU held = UN(I_CryptFindLruEntry)(c, &b);
    put(c, 2, NULL);
    ev_reset();
    put(c, 3, (void *)0x3);
    CHECK(ev_count(EV_REMOVE) == 1 && g_ev[0].data == DATA(1));
    CHECK(ev_count(EV_FREE) == 0);
    UN(I_CryptReleaseLruEntry)(held);
    CHECK(ev_count(EV_FREE) == 1 && ev_has(EV_FREE, DATA(1)));
    drop(c);
}
TEST(lru_evicted_entry_can_be_reinserted) {
    NEED_LRU();
    HLRU c = mk(0, 4, 2);
    put(c, 1, NULL); put(c, 2, NULL); put(c, 3, NULL);
    CHECK(!present(c, 1));
    put(c, 1, NULL);
    CHECK(present(c, 1) && present(c, 3) && !present(c, 2));
    drop(c);
}

/* ================= disable / enable LRU ================= */
TEST(lru_disable_suspends_eviction) {
    NEED_LRU(); REQUIRE(UN(I_CryptDisableLruOfEntries)); REQUIRE(UN(I_CryptEnableLruOfEntries));
    HLRU c = mk(0, 4, 2);
    UN(I_CryptDisableLruOfEntries)(c);
    ev_reset();
    for (int i = 0; i < 6; i++) put(c, i, NULL);
    CHECK(ev_count(EV_REMOVE) == 0);
    CHECK(npresent(c, 0, 5) == 6);
    UN(I_CryptEnableLruOfEntries)(c, (void *)0xE1);
    CHECK(ev_count(EV_REMOVE) == 4);
    for (int k = 0; k < 4; k++) CHECKF(g_ev[2 * k].kind == EV_REMOVE && g_ev[2 * k].data == DATA(k) && g_ev[2 * k].ctx == (void *)0xE1, "purge %d", k);
    CHECK(npresent(c, 0, 5) == 2 && present(c, 4) && present(c, 5));
    drop(c);
}
TEST(lru_disable_is_counted) {
    NEED_LRU(); REQUIRE(UN(I_CryptDisableLruOfEntries)); REQUIRE(UN(I_CryptEnableLruOfEntries));
    HLRU c = mk(0, 4, 2);
    UN(I_CryptDisableLruOfEntries)(c); UN(I_CryptDisableLruOfEntries)(c);
    for (int i = 0; i < 5; i++) put(c, i, NULL);
    ev_reset();
    UN(I_CryptEnableLruOfEntries)(c, NULL);
    CHECK(ev_count(EV_REMOVE) == 0);               /* still disabled once */
    CHECK(npresent(c, 0, 4) == 5);
    UN(I_CryptEnableLruOfEntries)(c, NULL);
    CHECK(ev_count(EV_REMOVE) == 3);
    CHECK(npresent(c, 0, 4) == 2);
    drop(c);
}
TEST(lru_enable_below_limit_removes_nothing) {
    NEED_LRU(); REQUIRE(UN(I_CryptDisableLruOfEntries)); REQUIRE(UN(I_CryptEnableLruOfEntries));
    HLRU c = mk(0, 4, 5);
    UN(I_CryptDisableLruOfEntries)(c);
    for (int i = 0; i < 3; i++) put(c, i, NULL);
    ev_reset();
    UN(I_CryptEnableLruOfEntries)(c, NULL);
    CHECK(g_nev == 0);
    CHECK(npresent(c, 0, 2) == 3);
    drop(c);
}
TEST(lru_eviction_resumes_after_enable) {
    NEED_LRU(); REQUIRE(UN(I_CryptDisableLruOfEntries)); REQUIRE(UN(I_CryptEnableLruOfEntries));
    HLRU c = mk(0, 4, 2);
    UN(I_CryptDisableLruOfEntries)(c);
    put(c, 1, NULL); put(c, 2, NULL); put(c, 3, NULL);
    UN(I_CryptEnableLruOfEntries)(c, NULL);
    ev_reset();
    put(c, 4, NULL);
    CHECK(ev_count(EV_REMOVE) == 1 && g_ev[0].data == DATA(2));
    CHECK(npresent(c, 1, 4) == 2 && present(c, 4) && present(c, 3) && !present(c, 2));
    drop(c);
}
TEST(lru_enable_purge_honours_touch_order) {
    NEED_LRU(); REQUIRE(UN(I_CryptDisableLruOfEntries)); REQUIRE(UN(I_CryptEnableLruOfEntries)); REQUIRE(UN(I_CryptTouchLruEntry));
    HLRU c = mk(0, 3, 2);
    UN(I_CryptDisableLruOfEntries)(c);
    for (int i = 1; i <= 4; i++) put(c, i, NULL);
    BYTE id[2]; mkid(id, 1); CRYPT_DATA_BLOB b = {2, id};
    HLRU f = UN(I_CryptFindLruEntry)(c, &b);
    UN(I_CryptTouchLruEntry)(f, 0); UN(I_CryptReleaseLruEntry)(f);
    ev_reset();
    UN(I_CryptEnableLruOfEntries)(c, NULL);
    CHECK(ev_count(EV_REMOVE) == 2 && g_ev[0].data == DATA(2) && g_ev[2].data == DATA(3));
    CHECK(present(c, 1) && present(c, 4));
    drop(c);
}

/* ================= duplicates and enumeration ================= */
TEST(lru_duplicate_identifiers_newest_found_first) {
    NEED_LRU(); REQUIRE(UN(I_CryptEnumMatchingLruEntries)); REQUIRE(UN(I_CryptGetLruEntryData));
    HLRU c = mk(0, 4, 0);
    BYTE id[2]; mkid(id, 5); CRYPT_DATA_BLOB b = {2, id};
    HLRU e[3];
    for (int i = 0; i < 3; i++) {
        CHECK(UN(I_CryptCreateLruEntry)(c, &b, (void *)(ULONG_PTR)(2000 + i), &e[i]) && e[i]);
        UN(I_CryptInsertLruEntry)(e[i], NULL);
    }
    HLRU f = UN(I_CryptFindLruEntry)(c, &b);
    CHECK(f == e[2]);
    HLRU n1 = UN(I_CryptEnumMatchingLruEntries)(f);            /* consumes f */
    CHECK(n1 == e[1]);
    HLRU n2 = UN(I_CryptEnumMatchingLruEntries)(n1);
    CHECK(n2 == e[0]);
    HLRU n3 = UN(I_CryptEnumMatchingLruEntries)(n2);
    CHECK(n3 == NULL);
    for (int i = 0; i < 3; i++) UN(I_CryptReleaseLruEntry)(e[i]);
    drop(c);
}
TEST(lru_enum_matching_skips_other_identifiers_in_bucket) {
    NEED_LRU(); REQUIRE(UN(I_CryptEnumMatchingLruEntries));
    HLRU c = mk(0, 1, 0);                                     /* single bucket: every entry shares the chain */
    BYTE a[2] = {1, 'a'}, b2[2] = {1, 'b'}; CRYPT_DATA_BLOB ba = {2, a}, bb = {2, b2};
    HLRU ea1, eb, ea2;
    CHECK(UN(I_CryptCreateLruEntry)(c, &ba, DATA(1), &ea1)); UN(I_CryptInsertLruEntry)(ea1, NULL);
    CHECK(UN(I_CryptCreateLruEntry)(c, &bb, DATA(2), &eb));  UN(I_CryptInsertLruEntry)(eb, NULL);
    CHECK(UN(I_CryptCreateLruEntry)(c, &ba, DATA(3), &ea2)); UN(I_CryptInsertLruEntry)(ea2, NULL);
    HLRU f = UN(I_CryptFindLruEntry)(c, &ba);
    CHECK(f == ea2);
    HLRU n = UN(I_CryptEnumMatchingLruEntries)(f);
    CHECK(n == ea1);
    CHECK(UN(I_CryptEnumMatchingLruEntries)(n) == NULL);
    UN(I_CryptReleaseLruEntry)(ea1); UN(I_CryptReleaseLruEntry)(eb); UN(I_CryptReleaseLruEntry)(ea2);
    drop(c);
}
TEST(lru_enum_matching_with_single_entry_returns_null) {
    NEED_LRU(); REQUIRE(UN(I_CryptEnumMatchingLruEntries));
    HLRU c = mk(0, 4, 0);
    put(c, 1, NULL);
    BYTE id[2]; mkid(id, 1); CRYPT_DATA_BLOB b = {2, id};
    HLRU f = UN(I_CryptFindLruEntry)(c, &b);
    CHECK(UN(I_CryptEnumMatchingLruEntries)(f) == NULL);
    drop(c);
}
TEST(lru_enum_matching_balances_references) {
    NEED_LRU(); REQUIRE(UN(I_CryptEnumMatchingLruEntries));
    HLRU c = mk(0, 4, 0);
    BYTE id[2]; mkid(id, 5); CRYPT_DATA_BLOB b = {2, id};
    HLRU e0, e1;
    CHECK(UN(I_CryptCreateLruEntry)(c, &b, DATA(0), &e0)); UN(I_CryptInsertLruEntry)(e0, NULL); UN(I_CryptReleaseLruEntry)(e0);
    CHECK(UN(I_CryptCreateLruEntry)(c, &b, DATA(1), &e1)); UN(I_CryptInsertLruEntry)(e1, NULL); UN(I_CryptReleaseLruEntry)(e1);
    HLRU f = UN(I_CryptFindLruEntry)(c, &b);
    HLRU n = UN(I_CryptEnumMatchingLruEntries)(f);
    CHECK(n == e0);
    ev_reset();
    UN(I_CryptReleaseLruEntry)(n);
    CHECK(g_nev == 0);                   /* the cache still owns both entries */
    UN(I_CryptFlushLruCache)(c, LRU_SUPPRESS_REMOVE_NOTIFICATION, NULL);
    CHECK(ev_count(EV_FREE) == 2);       /* nobody leaked a reference */
    drop(c);
}

/* ================= walking ================= */
typedef struct { int n, stop_after; void *seen[64]; } WALK;
static BOOL WINAPI walk_cb(void *arg, HLRU e) {
    WALK *w = arg;
    if (w->n < 64) w->seen[w->n] = UN(I_CryptGetLruEntryData)(e);
    w->n++;
    return !(w->stop_after && w->n >= w->stop_after);
}
TEST(lru_walk_visits_every_entry) {
    NEED_LRU(); REQUIRE(UN(I_CryptWalkAllLruCacheEntries)); REQUIRE(UN(I_CryptGetLruEntryData));
    HLRU c = mk(0, 5, 0);
    for (int i = 0; i < 12; i++) put(c, i, NULL);
    WALK w; memset(&w, 0, sizeof w);
    UN(I_CryptWalkAllLruCacheEntries)(c, walk_cb, &w);
    CHECK(w.n == 12);
    for (int i = 0; i < 12; i++) { int found = 0; for (int k = 0; k < w.n; k++) if (w.seen[k] == DATA(i)) found++; CHECKF(found == 1, "entry %d visited %d times", i, found); }
    drop(c);
}
TEST(lru_walk_single_bucket_is_newest_first) {
    NEED_LRU(); REQUIRE(UN(I_CryptWalkAllLruCacheEntries)); REQUIRE(UN(I_CryptGetLruEntryData));
    HLRU c = mk(0, 1, 0);
    for (int i = 0; i < 6; i++) put(c, i, NULL);
    WALK w; memset(&w, 0, sizeof w);
    UN(I_CryptWalkAllLruCacheEntries)(c, walk_cb, &w);
    CHECK(w.n == 6);
    for (int k = 0; k < 6 && k < w.n; k++) CHECKF(w.seen[k] == DATA(5 - k), "position %d", k);
    drop(c);
}
TEST(lru_walk_buckets_in_index_order) {
    NEED_LRU(); REQUIRE(UN(I_CryptWalkAllLruCacheEntries)); REQUIRE(UN(I_CryptGetLruEntryData));
    HLRU c = mk(0, 4, 0);                       /* hash = first byte, bucket = byte % 4 */
    int ids[8] = {5, 2, 7, 0, 4, 1, 6, 3};
    for (int k = 0; k < 8; k++) put(c, ids[k], NULL);
    WALK w; memset(&w, 0, sizeof w);
    UN(I_CryptWalkAllLruCacheEntries)(c, walk_cb, &w);
    CHECK(w.n == 8);
    /* bucket 0: 4 (newer), 0 ; bucket 1: 1, 5 ; bucket 2: 6, 2 ; bucket 3: 3, 7 */
    int want[8] = {4, 0, 1, 5, 6, 2, 3, 7};
    for (int k = 0; k < 8 && k < w.n; k++) CHECKF(w.seen[k] == DATA(want[k]), "position %d", k);
    drop(c);
}
TEST(lru_walk_stops_when_callback_returns_false) {
    NEED_LRU(); REQUIRE(UN(I_CryptWalkAllLruCacheEntries));
    HLRU c = mk(0, 5, 0);
    for (int i = 0; i < 12; i++) put(c, i, NULL);
    WALK w; memset(&w, 0, sizeof w); w.stop_after = 3;
    UN(I_CryptWalkAllLruCacheEntries)(c, walk_cb, &w);
    CHECK(w.n == 3);
    drop(c);
}
TEST(lru_walk_empty_cache_makes_no_calls) {
    NEED_LRU(); REQUIRE(UN(I_CryptWalkAllLruCacheEntries));
    HLRU c = mk(0, 5, 0);
    WALK w; memset(&w, 0, sizeof w);
    UN(I_CryptWalkAllLruCacheEntries)(c, walk_cb, &w);
    CHECK(w.n == 0);
    drop(c);
}
TEST(lru_walk_does_not_touch_entries) {
    NEED_LRU(); REQUIRE(UN(I_CryptWalkAllLruCacheEntries));
    HLRU c = mk(0, 3, 3);
    put(c, 1, NULL); put(c, 2, NULL); put(c, 3, NULL);
    WALK w; memset(&w, 0, sizeof w);
    UN(I_CryptWalkAllLruCacheEntries)(c, walk_cb, &w);
    ev_reset();
    put(c, 4, NULL);
    CHECK(ev_count(EV_REMOVE) == 1 && g_ev[0].data == DATA(1));
    drop(c);
}
static BOOL WINAPI walk_remove_cb(void *arg, HLRU e) {
    int *n = arg; (*n)++;
    UN(I_CryptRemoveLruEntry)(e, LRU_SUPPRESS_REMOVE_NOTIFICATION, NULL);
    return TRUE;
}
TEST(lru_walk_callback_may_remove_current_entry) {
    NEED_LRU(); REQUIRE(UN(I_CryptWalkAllLruCacheEntries)); REQUIRE(UN(I_CryptRemoveLruEntry));
    HLRU c = mk(LRU_NO_SERIALIZE, 3, 0);
    for (int i = 0; i < 9; i++) put(c, i, NULL);
    int n = 0;
    ev_reset();
    UN(I_CryptWalkAllLruCacheEntries)(c, walk_remove_cb, &n);
    CHECK(n == 9);
    CHECK(ev_count(EV_FREE) == 9);
    CHECK(npresent(c, 0, 8) == 0);
    drop(c);
}
TEST(lru_walk_does_not_add_references) {
    NEED_LRU(); REQUIRE(UN(I_CryptWalkAllLruCacheEntries));
    HLRU c = mk(0, 3, 0);
    for (int i = 0; i < 4; i++) put(c, i, NULL);
    WALK w; memset(&w, 0, sizeof w);
    UN(I_CryptWalkAllLruCacheEntries)(c, walk_cb, &w);
    ev_reset();
    UN(I_CryptFlushLruCache)(c, LRU_SUPPRESS_REMOVE_NOTIFICATION, NULL);
    CHECK(ev_count(EV_FREE) == 4);
    drop(c);
}

/* ================= quirks visible in the implementation ================= */
TEST(lru_enable_on_unbounded_cache_purges_everything) {
    NEED_LRU(); REQUIRE(UN(I_CryptDisableLruOfEntries)); REQUIRE(UN(I_CryptEnableLruOfEntries));
    /* with cMaxEntries == 0 the "entries above the limit" loop treats the limit as zero */
    HLRU c = mk(LRU_NO_SERIALIZE, 4, 0);
    for (int i = 0; i < 5; i++) put(c, i, NULL);
    UN(I_CryptDisableLruOfEntries)(c);
    ev_reset();
    UN(I_CryptEnableLruOfEntries)(c, (void *)0x7);
    CHECK(ev_count(EV_REMOVE) == 5);
    CHECK(npresent(c, 0, 4) == 0);
    drop(c);
}

/* ================= threads ================= */
typedef struct { HLRU c; int base; int n; } LTH;
static DWORD WINAPI lru_thread(void *p) {
    LTH *t = p;
    for (int i = 0; i < t->n; i++) {
        BYTE id[3]; id[0] = (BYTE)(t->base + i); id[1] = (BYTE)((t->base + i) >> 8); id[2] = 'z';
        CRYPT_DATA_BLOB b = {3, id};
        HLRU e = NULL;
        if (!UN(I_CryptCreateLruEntry)(t->c, &b, (void *)(ULONG_PTR)(t->base + i + 1), &e)) return 1;
        UN(I_CryptInsertLruEntry)(e, NULL);
        UN(I_CryptReleaseLruEntry)(e);
        HLRU f = UN(I_CryptFindLruEntry)(t->c, &b);
        if (!f) return 2;
        UN(I_CryptReleaseLruEntry)(f);
    }
    return 0;
}
TEST(lru_concurrent_inserts_and_finds) {
    NEED_LRU();
    HLRU c = mk(0, 31, 0);
    LTH t[4]; HANDLE h[4];
    for (int i = 0; i < 4; i++) { t[i].c = c; t[i].base = i * 1000; t[i].n = 300; h[i] = CreateThread(NULL, 0, lru_thread, &t[i], 0, NULL); }
    for (int i = 0; i < 4; i++) {
        DWORD code = 99;
        CHECK(WaitForSingleObject(h[i], 30000) == WAIT_OBJECT_0);
        GetExitCodeThread(h[i], &code); CloseHandle(h[i]);
        CHECKF(code == 0, "thread %d code %lu", i, code);
    }
    int found = 0;
    for (int i = 0; i < 4; i++) for (int k = 0; k < 300; k++) {
        int v = i * 1000 + k;
        BYTE id[3] = {(BYTE)v, (BYTE)(v >> 8), 'z'}; CRYPT_DATA_BLOB b = {3, id};
        HLRU f = UN(I_CryptFindLruEntry)(c, &b);
        if (f) { found++; UN(I_CryptReleaseLruEntry)(f); }
    }
    CHECK(found == 1200);
    UN(I_CryptFreeLruCache)(c, LRU_SUPPRESS_REMOVE_NOTIFICATION, NULL);
}
TEST(lru_concurrent_bounded_cache_never_exceeds_limit) {
    NEED_LRU();
    HLRU c = mk(0, 31, 50);
    LTH t[4]; HANDLE h[4];
    for (int i = 0; i < 4; i++) { t[i].c = c; t[i].base = i * 1000; t[i].n = 200; h[i] = CreateThread(NULL, 0, lru_thread, &t[i], 0, NULL); }
    for (int i = 0; i < 4; i++) {
        DWORD code = 99;
        CHECK(WaitForSingleObject(h[i], 30000) == WAIT_OBJECT_0);
        GetExitCodeThread(h[i], &code); CloseHandle(h[i]);
        t_note("thread %d exit %lu", i, code);
    }
    int found = 0;
    for (int i = 0; i < 4; i++) for (int k = 0; k < 200; k++) {
        int v = i * 1000 + k;
        BYTE id[3] = {(BYTE)v, (BYTE)(v >> 8), 'z'}; CRYPT_DATA_BLOB b = {3, id};
        HLRU f = UN(I_CryptFindLruEntry)(c, &b);
        if (f) { found++; UN(I_CryptReleaseLruEntry)(f); }
    }
    CHECK(found == 50);
    UN(I_CryptFreeLruCache)(c, LRU_SUPPRESS_REMOVE_NOTIFICATION, NULL);
}
