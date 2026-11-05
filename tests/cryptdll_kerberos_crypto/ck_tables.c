/* CDLocateCSystem / CDLocateCheckSum / CDLocateRng, the built-in tables, CDBuildVect, CDFindCommon*,
 * CDBuildIntegrityVect / CDGetIntegrityVect. These tests never register anything: the process-global
 * tables must stay pristine (registration is exercised in child processes, see ck_register.c). */
#include "ck.h"

#define NEED_LOC() CK_NEED(CDLocateCSystem)

/* etypes that the 19041 DLL registers in LibAttach, in registration order (table index 0..15) */
static const LONG ck_builtin_cs_sure[] = { ET_AES256, ET_AES128, ET_RC4_HMAC, ET_RC4_HMAC_OLD, ET_RC4_MD4, ET_DES_MD5, ET_DES_CRC };

TEST(cktab_locate_csystem_known_etypes) {
    NEED_LOC();
    static const LONG ids[] = { ET_DES_CRC, ET_DES_MD5, ET_AES128, ET_AES256, ET_RC4_HMAC, ET_RC4_HMAC_EXP,
                                ET_RC4_MD4, ET_DES_PLAIN, ET_RC4_HMAC_OLD, ET_RC4_HMAC_OLD_EXP };
    for (size_t i = 0; i < sizeof ids / sizeof ids[0]; i++) {
        CSX *p = NULL;
        NTSTATUS st = CKP(CDLocateCSystem)(ids[i], &p);
        CHECKF(st == 0 && p != NULL, "etype %ld st=0x%08lx", (long)ids[i], (unsigned long)st);
        if (st == 0 && p) CHECKF((LONG)p->EncryptionType == ids[i], "etype %ld field %ld", (long)ids[i], (long)p->EncryptionType);
    }
}

TEST(cktab_locate_csystem_unknown_etypes_fail) {
    NEED_LOC();
    static const LONG ids[] = { 0, 2, 4, 5, 7, 16, 19, 20, 22, 25, 100, 1000, -1, -2, -127, -129, -130, -131, -137,
                                -200, 0x7fffffff, (LONG)0x80000000, (LONG)0xFFFFFFFF };
    for (size_t i = 0; i < sizeof ids / sizeof ids[0]; i++) {
        CSX *p = (CSX *)(ULONG_PTR)0x1234;
        NTSTATUS st = CKP(CDLocateCSystem)(ids[i], &p);
        CHECKF(st == NS_NO_CSYSTEM, "etype %ld st=0x%08lx", (long)ids[i], (unsigned long)st);
        CHECKF(p == (CSX *)(ULONG_PTR)0x1234, "output pointer must be left alone for %ld", (long)ids[i]);
    }
}

TEST(cktab_locate_csystem_stable_pointer) {
    NEED_LOC();
    CSX *a = NULL, *b = NULL;
    EXPECT_NS(CKP(CDLocateCSystem)(ET_AES128, &a), 0);
    EXPECT_NS(CKP(CDLocateCSystem)(ET_AES128, &b), 0);
    CHECK(a != NULL && a == b);
}

TEST(cktab_locate_csystem_points_into_dll_image) {
    NEED_LOC();
    HMODULE h = t_module(CK_DLL);
    BYTE *base = (BYTE *)h;
    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(base + ((IMAGE_DOS_HEADER *)base)->e_lfanew);
    CSX *p = NULL;
    EXPECT_NS(CKP(CDLocateCSystem)(ET_RC4_HMAC, &p), 0);
    CHECK((BYTE *)p >= base && (BYTE *)p < base + nt->OptionalHeader.SizeOfImage);
}

TEST(cktab_csystem_entries_have_0x80_stride) {
    NEED_LOC();
    /* first seven builtins are registered consecutively: AES256, AES128, RC4_HMAC, RC4_HMAC_OLD, RC4_MD4, DES_MD5, DES_CRC */
    const CSX *first = ck_cs(ck_builtin_cs_sure[0]);
    CHECK(first != NULL);
    if (!first) return;
    for (size_t i = 1; i < sizeof ck_builtin_cs_sure / sizeof ck_builtin_cs_sure[0]; i++) {
        const CSX *p = ck_cs(ck_builtin_cs_sure[i]);
        CHECKF(p == (const CSX *)((const BYTE *)first + 0x80 * i), "index %zu etype %ld", i, (long)ck_builtin_cs_sure[i]);
    }
}

TEST(cktab_struct_layout_constants) {
    CHECK(sizeof(CSX) == 0x80);
    CHECK(offsetof(CSX, Attributes) == 0x18);
    CHECK(offsetof(CSX, Name) == 0x20);
    CHECK(offsetof(CSX, RandomKey) == 0x50);
    CHECK(offsetof(CSX, PrfPlus) == 0x78);
    CHECK(sizeof(CKX) == 0x40);
    CHECK(offsetof(CKX, InitializeEx) == 0x30);
    CHECK(sizeof(RNX) == 0x18);
}

TEST(cktab_key_sizes_match_specs) {
    NEED_LOC();
    static const struct { LONG et; ULONG ks; } t[] = { {ET_AES128, 16}, {ET_AES256, 32}, {ET_RC4_HMAC, 16}, {ET_DES_CRC, 8}, {ET_DES_MD5, 8} };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        const CSX *c = ck_cs(t[i].et);
        CHECK(c != NULL);
        if (c) CHECKF(c->KeySize == t[i].ks, "etype %ld key size %lu", (long)t[i].et, (unsigned long)c->KeySize);
    }
}

TEST(cktab_key_sizes_other_systems_observed) {
    NEED_LOC();
    static const LONG ids[] = { ET_RC4_HMAC_EXP, ET_RC4_MD4, ET_DES_PLAIN, ET_RC4_HMAC_OLD, ET_RC4_HMAC_OLD_EXP };
    for (size_t i = 0; i < sizeof ids / sizeof ids[0]; i++) {
        const CSX *c = ck_cs(ids[i]);
        if (!c) { t_note("etype %ld not registered", (long)ids[i]); continue; }
        t_note("etype %ld: block=%lu keysize=%lu header=%lu cksum=%ld attr=0x%lx exportable=%ld", (long)ids[i],
               (unsigned long)c->BlockSize, (unsigned long)c->KeySize, (unsigned long)c->HeaderSize,
               (long)(LONG)c->PreferredCheckSum, (unsigned long)c->Attributes, (long)(LONG)c->ExportableEncryptionType);
    }
}

TEST(cktab_names_present) {
    NEED_LOC();
    static const LONG ids[] = { ET_DES_CRC, ET_DES_MD5, ET_AES128, ET_AES256, ET_RC4_HMAC, ET_RC4_HMAC_EXP };
    for (size_t i = 0; i < sizeof ids / sizeof ids[0]; i++) {
        const CSX *c = ck_cs(ids[i]);
        CHECK(c != NULL);
        if (!c) continue;
        CHECKF(c->Name != NULL && c->Name[0] != 0, "etype %ld name", (long)ids[i]);
        if (c->Name) t_note("etype %ld name: %ls", (long)ids[i], c->Name);
    }
}

TEST(cktab_function_pointers_populated) {
    NEED_LOC();
    static const LONG ids[] = { ET_DES_CRC, ET_DES_MD5, ET_AES128, ET_AES256, ET_RC4_HMAC, ET_RC4_HMAC_EXP,
                                ET_RC4_MD4, ET_RC4_HMAC_OLD, ET_RC4_HMAC_OLD_EXP, ET_DES_PLAIN };
    for (size_t i = 0; i < sizeof ids / sizeof ids[0]; i++) {
        const CSX *c = ck_cs(ids[i]);
        CHECKF(c != NULL, "etype %ld", (long)ids[i]);
        if (!c) continue;
        CHECKF(c->Initialize && c->Encrypt && c->Decrypt && c->Finish && c->RandomKey, "etype %ld core entries", (long)ids[i]);
        int sure = ids[i] == ET_DES_CRC || ids[i] == ET_DES_MD5 || ids[i] == ET_AES128 || ids[i] == ET_AES256 || ids[i] == ET_RC4_HMAC || ids[i] == ET_RC4_MD4;
        if (sure) {
            CHECKF(c->HashPassword != NULL, "etype %ld HashPassword", (long)ids[i]);
            CHECKF(c->Control != NULL, "etype %ld Control", (long)ids[i]);
        } else if (!c->HashPassword || !c->Control) t_note("etype %ld: HashPassword=%p Control=%p", (long)ids[i], c->HashPassword, c->Control);
    }
}

TEST(cktab_prfplus_present_for_kerberos_systems) {
    NEED_LOC();
    static const LONG ids[] = { ET_AES128, ET_AES256, ET_RC4_HMAC };
    for (size_t i = 0; i < sizeof ids / sizeof ids[0]; i++) {
        const CSX *c = ck_cs(ids[i]);
        CHECK(c != NULL);
        if (c) CHECKF(c->PrfPlus != NULL, "etype %ld", (long)ids[i]);
    }
}

TEST(cktab_distinct_function_pointers_between_aes_and_rc4) {
    NEED_LOC();
    const CSX *a = ck_cs(ET_AES128), *r = ck_cs(ET_RC4_HMAC), *d = ck_cs(ET_DES_MD5);
    CHECK(a && r && d);
    if (!(a && r && d)) return;
    CHECK(a->Encrypt != r->Encrypt && a->Encrypt != d->Encrypt && r->Encrypt != d->Encrypt);
    CHECK(a->Decrypt != r->Decrypt);
    CHECK(a->HashPassword != r->HashPassword);
}

TEST(cktab_aes128_aes256_share_implementation) {
    NEED_LOC();
    const CSX *a = ck_cs(ET_AES128), *b = ck_cs(ET_AES256);
    CHECK(a && b);
    if (!(a && b)) return;
    CHECK(a->Initialize == b->Initialize);
    CHECK(a->Encrypt == b->Encrypt);
    CHECK(a->Decrypt == b->Decrypt);
    CHECK(a->Finish == b->Finish);
    CHECK(a->HashPassword != b->HashPassword);   /* separate 128/256-bit string-to-key entry points */
    CHECK(a->RandomKey != b->RandomKey);
}

TEST(cktab_rc4_family_shares_hash_password) {
    NEED_LOC();
    const CSX *a = ck_cs(ET_RC4_HMAC), *b = ck_cs(ET_RC4_HMAC_EXP), *c = ck_cs(ET_RC4_MD4);
    CHECK(a && b && c);
    if (!(a && b && c)) return;
    CHECK(a->HashPassword == c->HashPassword);
    if (a->HashPassword != b->HashPassword) t_note("RC4-HMAC-EXP uses a different HashPassword entry");
}

/* ------------------------------------------------------------------------------------------------------ */
TEST(cktab_builtin_csystem_count_and_order) {
    CK_NEED(CDBuildVect);
    ULONG n = 0;
    EXPECT_NS(CKP(CDBuildVect)(&n, NULL), 0);
    EXPECT_EQ(n, 16);
    LONG v[32] = {0};
    n = 0;
    EXPECT_NS(CKP(CDBuildVect)(&n, v), 0);
    EXPECT_EQ(n, 16);
    for (size_t i = 0; i < sizeof ck_builtin_cs_sure / sizeof ck_builtin_cs_sure[0]; i++)
        CHECKF(v[i] == ck_builtin_cs_sure[i], "index %zu got %ld want %ld", i, (long)v[i], (long)ck_builtin_cs_sure[i]);
    CHECK(v[9] == ET_RC4_HMAC_EXP);
    CHECK(v[10] == ET_RC4_HMAC_OLD_EXP);
    CHECK(v[13] == ET_DES_PLAIN);
    for (int i = 0; i < 16; i++) t_note("csystem[%d] = %ld", i, (long)v[i]);
}

TEST(cktab_buildvect_all_entries_locatable_and_unique) {
    CK_NEED(CDBuildVect); NEED_LOC();
    LONG v[64] = {0}; ULONG n = 0;
    EXPECT_NS(CKP(CDBuildVect)(&n, v), 0);
    for (ULONG i = 0; i < n; i++) {
        const CSX *c = ck_cs(v[i]);
        CHECKF(c != NULL && (LONG)c->EncryptionType == v[i], "index %lu etype %ld", (unsigned long)i, (long)v[i]);
        for (ULONG j = i + 1; j < n; j++) CHECKF(v[i] != v[j], "duplicate %ld", (long)v[i]);
    }
}

TEST(cktab_buildvect_ignores_incoming_capacity) {
    CK_NEED(CDBuildVect);
    /* the count is only an output: the whole table is copied regardless of what *n held on entry */
    LONG v[32]; for (int i = 0; i < 32; i++) v[i] = 0x55555555;
    ULONG n = 1;
    EXPECT_NS(CKP(CDBuildVect)(&n, v), 0);
    EXPECT_EQ(n, 16);
    for (int i = 0; i < 16; i++) CHECKF(v[i] != 0x55555555, "index %d", i);
    for (int i = 16; i < 32; i++) CHECKF(v[i] == 0x55555555, "index %d overwritten", i);
}

TEST(cktab_buildvect_null_vector_only_counts) {
    CK_NEED(CDBuildVect);
    ULONG n = 0xDEADBEEF;
    EXPECT_NS(CKP(CDBuildVect)(&n, NULL), 0);
    EXPECT_EQ(n, 16);
    n = 0;
    EXPECT_NS(CKP(CDBuildVect)(&n, NULL), 0);
    EXPECT_EQ(n, 16);
}

TEST(cktab_pristine_process_has_no_registered_extras) {
    CK_NEED(CDBuildVect);
    ULONG n = 0;
    EXPECT_NS(CKP(CDBuildVect)(&n, NULL), 0);
    EXPECT_EQ(n, 16);
    CSX *p;
    EXPECT_NS(CKP(CDLocateCSystem)(0x7e57, &p), NS_NO_CSYSTEM);
}

/* ------------------------------------------------------------------------------------------------------ */
TEST(cktab_locate_checksum_known_types) {
    CK_NEED(CDLocateCheckSum);
    static const struct { LONG t; ULONG size; } k[] = {
        { CS_CRC32, 4 }, { CS_MD4, 16 }, { CS_MD5, 16 }, { CS_AES128, 12 }, { CS_AES256, 12 },
        { CS_SHA1, 20 }, { CS_REAL_CRC32, 4 }, { CS_HMAC_MD5, 16 } };
    for (size_t i = 0; i < sizeof k / sizeof k[0]; i++) {
        CKX *p = NULL;
        NTSTATUS st = CKP(CDLocateCheckSum)(k[i].t, &p);
        CHECKF(st == 0 && p, "type %ld st=0x%08lx", (long)k[i].t, (unsigned long)st);
        if (st || !p) continue;
        CHECKF((LONG)p->Type == k[i].t, "type %ld field %ld", (long)k[i].t, (long)p->Type);
        CHECKF(p->Size == k[i].size, "type %ld size %lu want %lu", (long)k[i].t, (unsigned long)p->Size, (unsigned long)k[i].size);
    }
}

TEST(cktab_locate_checksum_other_types_observed) {
    CK_NEED(CDLocateCheckSum);
    static const LONG t[] = { CS_MD5_HMAC, CS_AES128_KI, CS_AES256_KI, 3, 4, 5, 8, -128, -130, -133, -134, -135, -136, -139 };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        const CKX *p = ck_ck(t[i]);
        if (p) t_note("checksum %ld present: size=%lu attr=0x%lx", (long)t[i], (unsigned long)p->Size, (unsigned long)p->Attributes);
        else t_note("checksum %ld absent", (long)t[i]);
    }
}

TEST(cktab_locate_checksum_unknown_fail) {
    CK_NEED(CDLocateCheckSum);
    static const LONG t[] = { 0, 6, 9, 10, 14, 17, 100, -1, -100, -300, 0x7fffffff, (LONG)0x80000000 };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        CKX *p = (CKX *)(ULONG_PTR)0x4321;
        NTSTATUS st = CKP(CDLocateCheckSum)(t[i], &p);
        CHECKF(st == NS_NO_CHECKSUM, "type %ld st=0x%08lx", (long)t[i], (unsigned long)st);
        CHECKF(p == (CKX *)(ULONG_PTR)0x4321, "output untouched for %ld", (long)t[i]);
    }
}

TEST(cktab_checksum_entries_have_0x40_stride) {
    CK_NEED(CDLocateCheckSum);
    const CKX *a = ck_ck(CS_MD4), *b = ck_ck(CS_MD5);
    CHECK(a && b);
    if (a && b) CHECK((((const BYTE *)b - (const BYTE *)a) % 0x40) == 0);
}

TEST(cktab_checksum_function_pointers) {
    CK_NEED(CDLocateCheckSum);
    static const LONG t[] = { CS_CRC32, CS_MD4, CS_MD5, CS_AES128, CS_AES256, CS_SHA1, CS_REAL_CRC32, CS_HMAC_MD5 };
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++) {
        const CKX *p = ck_ck(t[i]);
        CHECK(p != NULL);
        if (!p) continue;
        CHECKF(p->Sum && p->Finalize && p->Finish, "type %ld", (long)t[i]);
        CHECKF(p->InitializeEx != NULL, "type %ld InitializeEx", (long)t[i]);
    }
    const CKX *k = ck_ck(CS_MD5);
    if (k) CHECK(k->Initialize != NULL);
}

/* ------------------------------------------------------------------------------------------------------ */
static LONG ck_default_rng_type(RNX **ent) {
    for (LONG t = -8; t <= 16; t++) {
        RNX *r = NULL;
        if (CKP(CDLocateRng)(t, &r) && r && r->P2) { if (ent) *ent = r; return t; }
    }
    return 0x7fffffff;
}

TEST(cktab_rng_default_registered) {
    CK_NEED(CDLocateRng);
    RNX *e = NULL;
    LONG t = ck_default_rng_type(&e);
    CHECK(t != 0x7fffffff);
    if (t == 0x7fffffff) return;
    t_note("default rng type = %ld", (long)t);
    CHECK(e->P2 != NULL);
}

TEST(cktab_rng_default_function_generates_bytes) {
    CK_NEED(CDLocateRng);
    RNX *e = NULL;
    if (ck_default_rng_type(&e) == 0x7fffffff) { t_skip("no default rng"); return; }
    rng_fn f = (rng_fn)e->P2;
    BYTE a[32] = {0}, b[32] = {0};
    CHECK(f(a, sizeof a) == TRUE);
    CHECK(f(b, sizeof b) == TRUE);
    static const BYTE z[32] = {0};
    CHECK(memcmp(a, z, 32) != 0);
    CHECK(memcmp(a, b, 32) != 0);
}

TEST(cktab_rng_locate_missing_returns_false_and_nulls_output) {
    CK_NEED(CDLocateRng);
    RNX *e = (RNX *)(ULONG_PTR)0x99;
    BOOLEAN r = CKP(CDLocateRng)(0x12345, &e);
    EXPECT_EQ(r, 0);
    CHECK(e == NULL);
}

TEST(cktab_rng_locate_scans_all_four_slots_regardless_of_count) {
    CK_NEED(CDLocateRng);
    /* the lookup walks the fixed four-slot array: type 0 matches an unused (zero) slot when the built-in rng has a
       non-zero type, and the returned entry is all zero */
    RNX *d = NULL;
    LONG dt = ck_default_rng_type(&d);
    if (dt == 0 || dt == 0x7fffffff) { t_skip("default rng type unusable for this probe"); return; }
    RNX *e = NULL;
    BOOLEAN r = CKP(CDLocateRng)(0, &e);
    CHECK(r == TRUE);
    CHECK(e != NULL);
    if (e) { CHECK(e->Type == 0 && e->P1 == NULL && e->P2 == NULL); }
}

TEST(cktab_rng_entries_have_0x18_stride) {
    CK_NEED(CDLocateRng);
    RNX *a = NULL, *b = NULL;
    CHECK(CKP(CDLocateRng)(0, &a) == TRUE);   /* first empty slot */
    RNX *d = NULL;
    LONG dt = ck_default_rng_type(&d);
    if (dt == 0x7fffffff || dt == 0 || !a) { t_skip("no usable default"); return; }
    b = d;
    CHECK(((const BYTE *)a - (const BYTE *)b) == 0x18);
}

TEST(cktab_generate_random_bits_default) {
    CK_NEED(CDGenerateRandomBits);
    BYTE a[64] = {0}, b[64] = {0};
    CHECK(CKP(CDGenerateRandomBits)(a, sizeof a) == TRUE);
    CHECK(CKP(CDGenerateRandomBits)(b, sizeof b) == TRUE);
    static const BYTE z[64] = {0};
    CHECK(memcmp(a, z, 64) != 0);
    CHECK(memcmp(a, b, 64) != 0);
}

TEST(cktab_generate_random_bits_does_not_overrun) {
    CK_NEED(CDGenerateRandomBits);
    BYTE buf[48]; memset(buf, 0xCC, sizeof buf);
    CHECK(CKP(CDGenerateRandomBits)(buf + 16, 16) == TRUE);
    for (int i = 0; i < 16; i++) { CHECKF(buf[i] == 0xCC, "pre %d", i); CHECKF(buf[32 + i] == 0xCC, "post %d", i); }
}

TEST(cktab_generate_random_bits_zero_length) {
    CK_NEED(CDGenerateRandomBits);
    BYTE buf[4] = { 1, 2, 3, 4 };
    BOOLEAN r = CKP(CDGenerateRandomBits)(buf, 0);
    t_note("zero-length CDGenerateRandomBits returned %u", r);
    CHECK(buf[0] == 1 && buf[1] == 2 && buf[2] == 3 && buf[3] == 4);
}

TEST(cktab_generate_random_bits_large_buffers_vary) {
    CK_NEED(CDGenerateRandomBits);
    static BYTE a[4096], b[4096];
    CHECK(CKP(CDGenerateRandomBits)(a, sizeof a) == TRUE);
    CHECK(CKP(CDGenerateRandomBits)(b, sizeof b) == TRUE);
    CHECK(memcmp(a, b, sizeof a) != 0);
    int zeros = 0; for (int i = 0; i < 4096; i++) zeros += a[i] == 0;
    CHECK(zeros < 100);   /* expectation 16; 100 is far in the tail */
}

/* ------------------------------------------------------------------------------------------------------ */
TEST(cktab_findcommon_first_client_match_wins) {
    CK_NEED(CDFindCommonCSystem);
    LONG out = 99;
    LONG l1[] = { 99, ET_AES128, ET_AES256 };
    EXPECT_NS(CKP(CDFindCommonCSystem)(3, l1, &out), 0); EXPECT_EQ(out, ET_AES128);
    LONG l2[] = { ET_RC4_HMAC, ET_AES128 };
    EXPECT_NS(CKP(CDFindCommonCSystem)(2, l2, &out), 0); EXPECT_EQ(out, ET_RC4_HMAC);
    LONG l3[] = { ET_AES256, ET_RC4_HMAC };
    EXPECT_NS(CKP(CDFindCommonCSystem)(2, l3, &out), 0); EXPECT_EQ(out, ET_AES256);
    LONG l4[] = { 1000, 1001, 1002, ET_DES_CRC };
    EXPECT_NS(CKP(CDFindCommonCSystem)(4, l4, &out), 0); EXPECT_EQ(out, ET_DES_CRC);
}

TEST(cktab_findcommon_none_zeroes_output) {
    CK_NEED(CDFindCommonCSystem);
    LONG out = 77;
    LONG l[] = { 99, 98, 97 };
    EXPECT_NS(CKP(CDFindCommonCSystem)(3, l, &out), NS_NO_CSYSTEM);
    EXPECT_EQ(out, 0);
}

TEST(cktab_findcommon_empty_list) {
    CK_NEED(CDFindCommonCSystem);
    LONG out = 77; LONG l[] = { ET_AES128 };
    EXPECT_NS(CKP(CDFindCommonCSystem)(0, l, &out), NS_NO_CSYSTEM);
    EXPECT_EQ(out, 0);
}

TEST(cktab_findcommon_count_limits_scan) {
    CK_NEED(CDFindCommonCSystem);
    LONG out = 77; LONG l[] = { 99, 98, ET_AES128 };
    EXPECT_NS(CKP(CDFindCommonCSystem)(2, l, &out), NS_NO_CSYSTEM);
    EXPECT_EQ(out, 0);
    EXPECT_NS(CKP(CDFindCommonCSystem)(3, l, &out), 0);
    EXPECT_EQ(out, ET_AES128);
}

TEST(cktab_findcommon_negative_ids_and_duplicates) {
    CK_NEED(CDFindCommonCSystem);
    LONG out = 0; LONG l[] = { -5, -128, -128, 17 };
    EXPECT_NS(CKP(CDFindCommonCSystem)(4, l, &out), 0);
    EXPECT_EQ(out, ET_RC4_MD4);
}

TEST(cktab_findcommon_withkey_requires_key_list_membership) {
    CK_NEED(CDFindCommonCSystemWithKey);
    LONG out = 55;
    LONG t[] = { ET_AES128, ET_AES256, ET_RC4_HMAC };
    LONG k1[] = { ET_RC4_HMAC };
    EXPECT_NS(CKP(CDFindCommonCSystemWithKey)(3, t, 1, k1, &out), 0); EXPECT_EQ(out, ET_RC4_HMAC);
    LONG k2[] = { ET_AES256, ET_RC4_HMAC };
    EXPECT_NS(CKP(CDFindCommonCSystemWithKey)(3, t, 2, k2, &out), 0); EXPECT_EQ(out, ET_AES256);
    LONG k3[] = { 5, 6, 7 };
    out = 55;
    EXPECT_NS(CKP(CDFindCommonCSystemWithKey)(3, t, 3, k3, &out), NS_NO_CSYSTEM); EXPECT_EQ(out, 0);
}

TEST(cktab_findcommon_withkey_empty_key_list) {
    CK_NEED(CDFindCommonCSystemWithKey);
    LONG out = 55; LONG t[] = { ET_AES128 }; LONG k[] = { ET_AES128 };
    EXPECT_NS(CKP(CDFindCommonCSystemWithKey)(1, t, 0, k, &out), NS_NO_CSYSTEM);
    EXPECT_EQ(out, 0);
}

TEST(cktab_findcommon_withkey_empty_type_list) {
    CK_NEED(CDFindCommonCSystemWithKey);
    LONG out = 55; LONG t[] = { ET_AES128 }; LONG k[] = { ET_AES128 };
    EXPECT_NS(CKP(CDFindCommonCSystemWithKey)(0, t, 1, k, &out), NS_NO_CSYSTEM);
    EXPECT_EQ(out, 0);
}

TEST(cktab_findcommon_withkey_unregistered_type_in_key_list_ignored) {
    CK_NEED(CDFindCommonCSystemWithKey);
    LONG out = 0; LONG t[] = { 4242, ET_DES_MD5 }; LONG k[] = { 4242, ET_DES_MD5 };
    EXPECT_NS(CKP(CDFindCommonCSystemWithKey)(2, t, 2, k, &out), 0);
    EXPECT_EQ(out, ET_DES_MD5);   /* 4242 is in both lists but is not a registered system */
}

TEST(cktab_findcommon_withkey_client_order_preserved) {
    CK_NEED(CDFindCommonCSystemWithKey);
    LONG out = 0; LONG t[] = { ET_DES_CRC, ET_DES_MD5, ET_AES128 }; LONG k[] = { ET_AES128, ET_DES_MD5, ET_DES_CRC };
    EXPECT_NS(CKP(CDFindCommonCSystemWithKey)(3, t, 3, k, &out), 0);
    EXPECT_EQ(out, ET_DES_CRC);
}

/* ------------------------------------------------------------------------------------------------------ */
static ULONG ck_registry_mask(void) {
    static const char *k1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters";
    static const char *k2 = "System\\CurrentControlSet\\Control\\Lsa\\Kerberos\\Parameters";
    HKEY h = NULL; DWORD ty = 0, val = 0, sz = 4; LONG r, q; int first;
    ULONG mask;
    r = RegOpenKeyExA(HKEY_LOCAL_MACHINE, k1, 0, KEY_READ, &h);
    first = (r == ERROR_FILE_NOT_FOUND);
    if (first) r = RegOpenKeyExA(HKEY_LOCAL_MACHINE, k2, 0, KEY_READ, &h);
    if (r != 0) { mask = 0xfffffffc; goto done; }
    q = RegQueryValueExA(h, "SupportedEncryptionTypes", NULL, &ty, (LPBYTE)&val, &sz);
    if (q == ERROR_FILE_NOT_FOUND) {
        if (!first) {
            RegCloseKey(h); h = NULL;
            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, k2, 0, KEY_READ, &h) == 0) {
                ty = 0; val = 0; sz = 4;
                q = RegQueryValueExA(h, "SupportedEncryptionTypes", NULL, &ty, (LPBYTE)&val, &sz);
                goto have;
            }
        }
        mask = 0xfffffffc;
    } else {
have:
        mask = (q != 0 || ty != 4 || val == 0) ? 0xfffffffc : val;
    }
    if (h) RegCloseKey(h);
done:
    mask &= 0x1f;
    if (!mask) mask = 0x1c;
    return mask;
}

static int ck_bit_for(LONG et, ULONG mask, int *known) {
    *known = 1;
    switch (et) {
    case ET_DES_CRC: return !!(mask & 1);
    case ET_DES_MD5: return !!(mask & 2);
    case ET_AES128: return !!(mask & 8);
    case ET_AES256: return !!(mask & 0x10);
    case ET_RC4_HMAC: case ET_RC4_HMAC_EXP: case ET_RC4_MD4: case ET_RC4_HMAC_OLD: case ET_RC4_HMAC_OLD_EXP:
        return !!(mask & 4);
    }
    *known = 0; return 0;
}

TEST(cktab_get_integrity_vect_mask_matches_registry_policy) {
    CK_NEED(CDGetIntegrityVect);
    ULONG m = 0xdead;
    EXPECT_NS(CKP(CDGetIntegrityVect)(&m), 0);
    ULONG want = ck_registry_mask();
    CHECKF(m == want, "mask 0x%lx want 0x%lx", (unsigned long)m, (unsigned long)want);
    CHECK(m != 0 && (m & ~0x1fu) == 0);
    t_note("SupportedEncryptionTypes mask = 0x%lx", (unsigned long)m);
}

TEST(cktab_get_integrity_vect_idempotent) {
    CK_NEED(CDGetIntegrityVect);
    ULONG a = 0, b = 0;
    EXPECT_NS(CKP(CDGetIntegrityVect)(&a), 0);
    EXPECT_NS(CKP(CDGetIntegrityVect)(&b), 0);
    EXPECT_EQ(a, b);
}

TEST(cktab_get_integrity_vect_sets_attribute_bit) {
    CK_NEED(CDGetIntegrityVect);
    ULONG m = 0;
    EXPECT_NS(CKP(CDGetIntegrityVect)(&m), 0);
    static const LONG ids[] = { ET_DES_CRC, ET_DES_MD5, ET_AES128, ET_AES256, ET_RC4_HMAC, ET_RC4_HMAC_EXP, ET_RC4_MD4,
                                ET_RC4_HMAC_OLD, ET_RC4_HMAC_OLD_EXP };
    for (size_t i = 0; i < sizeof ids / sizeof ids[0]; i++) {
        const CSX *c = ck_cs(ids[i]);
        int known; int want = ck_bit_for(ids[i], m, &known);
        CHECK(c != NULL);
        if (c) CHECKF(!!(c->Attributes & CSYS_INTEGRITY) == want, "etype %ld attr 0x%lx mask 0x%lx", (long)ids[i], (unsigned long)c->Attributes, (unsigned long)m);
    }
}

TEST(cktab_get_integrity_vect_leaves_unrelated_systems_alone) {
    CK_NEED(CDGetIntegrityVect);
    static const LONG other[] = { ET_DES_PLAIN, -134, -136, -140, -141, -148, -149 };
    ULONG before[8]; int have[8];
    for (size_t i = 0; i < sizeof other / sizeof other[0]; i++) { const CSX *c = ck_cs(other[i]); have[i] = c != NULL; before[i] = c ? c->Attributes : 0; }
    ULONG m;
    EXPECT_NS(CKP(CDGetIntegrityVect)(&m), 0);
    for (size_t i = 0; i < sizeof other / sizeof other[0]; i++) {
        const CSX *c = ck_cs(other[i]);
        if (have[i] && c) CHECKF(c->Attributes == before[i], "etype %ld attributes changed", (long)other[i]);
    }
}

static int ck_in_vect(const LONG *v, ULONG n, LONG e) { for (ULONG i = 0; i < n; i++) if (v[i] == e) return 1; return 0; }

TEST(cktab_integrity_vect_contents_follow_mask) {
    CK_NEED(CDGetIntegrityVect); CK_NEED(CDBuildIntegrityVect);
    ULONG m;
    EXPECT_NS(CKP(CDGetIntegrityVect)(&m), 0);
    ULONG n = 32; LONG v[32] = {0};
    EXPECT_NS(CKP(CDBuildIntegrityVect)(&n, v), 0);
    static const LONG ids[] = { ET_DES_CRC, ET_DES_MD5, ET_AES128, ET_AES256, ET_RC4_HMAC, ET_RC4_HMAC_EXP, ET_RC4_MD4,
                                ET_RC4_HMAC_OLD, ET_RC4_HMAC_OLD_EXP };
    for (size_t i = 0; i < sizeof ids / sizeof ids[0]; i++) {
        int known; int want = ck_bit_for(ids[i], m, &known);
        CHECKF(ck_in_vect(v, n, ids[i]) == want, "etype %ld mask 0x%lx", (long)ids[i], (unsigned long)m);
    }
    CHECK(n >= 1 && n <= 16);
}

TEST(cktab_integrity_vect_query_with_null_vector) {
    CK_NEED(CDGetIntegrityVect); CK_NEED(CDBuildIntegrityVect);
    ULONG m; CKP(CDGetIntegrityVect)(&m);
    ULONG n = 0;
    EXPECT_NS(CKP(CDBuildIntegrityVect)(&n, NULL), 0);
    ULONG cnt = n;
    CHECK(cnt >= 1);
    LONG v[32]; n = 32;
    EXPECT_NS(CKP(CDBuildIntegrityVect)(&n, v), 0);
    EXPECT_EQ(n, cnt);
    n = 1000;
    EXPECT_NS(CKP(CDBuildIntegrityVect)(&n, NULL), 0);
    EXPECT_EQ(n, cnt);
}

TEST(cktab_integrity_vect_exact_capacity_ok_and_reports_count) {
    CK_NEED(CDGetIntegrityVect); CK_NEED(CDBuildIntegrityVect);
    ULONG m; CKP(CDGetIntegrityVect)(&m);
    ULONG n = 0;
    CKP(CDBuildIntegrityVect)(&n, NULL);
    ULONG cnt = n;
    LONG v[32]; n = cnt;
    EXPECT_NS(CKP(CDBuildIntegrityVect)(&n, v), 0);
    EXPECT_EQ(n, cnt);
    n = 32;
    EXPECT_NS(CKP(CDBuildIntegrityVect)(&n, v), 0);
    EXPECT_EQ(n, cnt);   /* *n reports the number of entries, not the capacity */
}

TEST(cktab_integrity_vect_small_capacity_fails_and_leaves_count) {
    CK_NEED(CDGetIntegrityVect); CK_NEED(CDBuildIntegrityVect);
    ULONG m; CKP(CDGetIntegrityVect)(&m);
    ULONG n = 0; CKP(CDBuildIntegrityVect)(&n, NULL);
    ULONG cnt = n;
    if (cnt < 1) { t_skip("no integrity systems"); return; }
    LONG ref[32]; n = 32; CKP(CDBuildIntegrityVect)(&n, ref);
    for (ULONG cap = 0; cap < cnt; cap++) {
        LONG v[32]; for (int i = 0; i < 32; i++) v[i] = 0x7777;
        n = cap;
        EXPECT_NS(CKP(CDBuildIntegrityVect)(&n, v), NS_BUF_TOO_SMALL);
        EXPECT_EQ(n, cap);
        for (ULONG i = 0; i < cap; i++) CHECKF(v[i] == ref[i], "cap %lu entry %lu", (unsigned long)cap, (unsigned long)i);
        for (ULONG i = cap; i < 32; i++) CHECKF(v[i] == 0x7777, "cap %lu entry %lu written", (unsigned long)cap, (unsigned long)i);
    }
}

TEST(cktab_integrity_vect_order_follows_table) {
    CK_NEED(CDGetIntegrityVect); CK_NEED(CDBuildIntegrityVect); CK_NEED(CDBuildVect);
    ULONG m; CKP(CDGetIntegrityVect)(&m);
    LONG all[32]; ULONG na = 0; CKP(CDBuildVect)(&na, all);
    LONG iv[32]; ULONG ni = 32; CKP(CDBuildIntegrityVect)(&ni, iv);
    ULONG pos = 0;
    for (ULONG i = 0; i < ni; i++) {
        while (pos < na && all[pos] != iv[i]) pos++;
        CHECKF(pos < na, "integrity entry %ld not found in order", (long)iv[i]);
        pos++;
    }
}
