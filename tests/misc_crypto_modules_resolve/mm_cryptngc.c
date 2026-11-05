/* cryptngc.dll: only entry points whose decompilation shows pure argument validation or a constant
 * stub are called. Nothing here touches NGC containers, keys, PINs or the NGC broker. */
#include "t.h"

typedef LONG (WINAPI *ngc_fn9)(PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID, PVOID);
#define NGC(name) ((ngc_fn9)t_proc_in("cryptngc.dll", name))

#define E_POINTER_      0x80004003u
#define E_INVALIDARG_   0x80070057u
#define NTE_BAD_FLAGS_  0x80090009u
#define NTE_INVPARAM_   0x80090027u
#define STATUS_NOT_IMPL 0xC0000002u

#define EQ32(got, want) do { unsigned g_ = (unsigned)(got); \
    t_check(g_ == (unsigned)(want), __FILE__, __LINE__, #got " == " #want, "got 0x%08x want 0x%08x", g_, (unsigned)(want)); } while (0)

#define NEED(name, var) ngc_fn9 var = NGC(name); REQUIRE(var)

/* ---- Fido* stubs: one shared body returning STATUS_NOT_IMPLEMENTED ------------------------ */
static void fido(const char *n) {
    NEED(n, f);
    EQ32(f(0, 0, 0, 0, 0, 0, 0, 0, 0), STATUS_NOT_IMPL);
    char junk[16] = {0};
    PVOID o = junk;
    EQ32(f(o, o, o, o, o, o, o, o, o), STATUS_NOT_IMPL);
    EQ32(f((PVOID)1, (PVOID)2, (PVOID)3, (PVOID)4, 0, 0, 0, 0, 0), STATUS_NOT_IMPL);
    EQ32(f(0, 0, 0, 0, 0, 0, 0, 0, 0), STATUS_NOT_IMPL);
    CHECK(junk[0] == 0 && junk[15] == 0);   /* the stub does not write through arguments */
}
TEST(mm_ngc_fido_create_credential_not_implemented) { fido("FidoCreateCredential"); }
TEST(mm_ngc_fido_get_credential_not_implemented) { fido("FidoGetCredential"); }
TEST(mm_ngc_fido_sign_with_credential_not_implemented) { fido("FidoSignWithCredential"); }
TEST(mm_ngc_fido_ordinals_same_result) {
    for (unsigned o = 1; o <= 3; o++) {
        ngc_fn9 f = (ngc_fn9)t_proc_ord("cryptngc.dll", o); REQUIRE(f);
        EQ32(f(0, 0, 0, 0, 0, 0, 0, 0, 0), STATUS_NOT_IMPL);
    }
}

/* ---- NgcGetEventInterface ---------------------------------------------------------------- */
TEST(mm_ngc_event_interface_null_is_invalid_parameter) {
    NEED("NgcGetEventInterface", f);
    EQ32(f(0, 0, 0, 0, 0, 0, 0, 0, 0), ERROR_INVALID_PARAMETER);
}
TEST(mm_ngc_event_interface_returns_static_table) {
    NEED("NgcGetEventInterface", f);
    PVOID a = (PVOID)(ULONG_PTR)0x1111, b = (PVOID)(ULONG_PTR)0x2222;
    EQ32(f(&a, 0, 0, 0, 0, 0, 0, 0, 0), 0);
    EQ32(f(&b, 0, 0, 0, 0, 0, 0, 0, 0), 0);
    CHECK(a != NULL && a != (PVOID)(ULONG_PTR)0x1111);
    CHECK(a == b);   /* a pointer to one static object */
    HMODULE m = t_module("cryptngc.dll");
    MEMORY_BASIC_INFORMATION mbi;
    if (a && VirtualQuery(a, &mbi, sizeof mbi)) CHECK(mbi.AllocationBase == (PVOID)m);
}
TEST(mm_ngc_event_interface_by_ordinal) {
    ngc_fn9 f = (ngc_fn9)t_proc_ord("cryptngc.dll", 30); REQUIRE(f);
    CHECK(f == NGC("NgcGetEventInterface"));
    EQ32(f(0, 0, 0, 0, 0, 0, 0, 0, 0), ERROR_INVALID_PARAMETER);
}

/* ---- credential buffer helpers ------------------------------------------------------------ */
/* NgcUnpackAuthBuffer(buf, cb, &a, &b, &c, p6, &d, p8): any NULL pointer -> E_POINTER; cb==0 -> E_INVALIDARG */
TEST(mm_ngc_unpack_auth_buffer_null_pointers) {
    NEED("NgcUnpackAuthBuffer", f);
    char buf[8] = {0}; PVOID o1 = 0, o2 = 0, o3 = 0, o4 = 0; ULONG_PTR sz = 1;
    PVOID args[8] = {buf, (PVOID)8, &o1, &o2, &o3, &sz, &o4, &sz};
    for (int i = 0; i < 8; i++) {
        if (i == 1) continue;           /* the size is checked separately */
        PVOID save = args[i]; args[i] = 0;
        o1 = o2 = o3 = o4 = (PVOID)7;
        EQ32(f(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], 0), E_POINTER_);
        CHECKF(o1 == (PVOID)7 && o2 == (PVOID)7 && o3 == (PVOID)7 && o4 == (PVOID)7, "outputs untouched, arg %d", i);
        args[i] = save;
    }
}
TEST(mm_ngc_unpack_auth_buffer_zero_size) {
    NEED("NgcUnpackAuthBuffer", f);
    char buf[8] = {0}; PVOID o1 = (PVOID)7, o2 = (PVOID)7, o3 = (PVOID)7, o4 = (PVOID)7; ULONG_PTR sz = 1;
    EQ32(f(buf, 0, &o1, &o2, &o3, &sz, &o4, &sz, 0), E_INVALIDARG_);
    CHECK(o1 == (PVOID)7 && o2 == (PVOID)7 && o3 == (PVOID)7 && o4 == (PVOID)7);
}
TEST(mm_ngc_unpack_password_change_auth_buffer_null_pointers) {
    NEED("NgcUnpackPasswordChangeAuthBuffer", f);
    char buf[8] = {0}; PVOID o1 = 0, o2 = 0, o3 = 0, o4 = 0; ULONG_PTR sz = 1;
    PVOID args[8] = {buf, (PVOID)8, &o1, &o2, &o3, &sz, &o4, &sz};
    for (int i = 0; i < 8; i++) {
        if (i == 1) continue;
        PVOID save = args[i]; args[i] = 0;
        EQ32(f(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], 0), E_POINTER_);
        args[i] = save;
    }
}
TEST(mm_ngc_unpack_password_change_auth_buffer_zero_size) {
    NEED("NgcUnpackPasswordChangeAuthBuffer", f);
    char buf[8] = {0}; PVOID o1 = (PVOID)7, o2 = (PVOID)7, o3 = (PVOID)7, o4 = (PVOID)7; ULONG_PTR sz = 1;
    EQ32(f(buf, 0, &o1, &o2, &o3, &sz, &o4, &sz, 0), E_INVALIDARG_);
    CHECK(o1 == (PVOID)7 && o4 == (PVOID)7);
}
/* NgcUnpackCredData(buf, cb, &a, p4, &b, p6) */
TEST(mm_ngc_unpack_cred_data_null_pointers) {
    NEED("NgcUnpackCredData", f);
    char buf[8] = {0}; PVOID o1 = 0, o2 = 0; ULONG_PTR sz = 1;
    PVOID args[6] = {buf, (PVOID)8, &o1, &sz, &o2, &sz};
    for (int i = 0; i < 6; i++) {
        if (i == 1) continue;
        PVOID save = args[i]; args[i] = 0;
        EQ32(f(args[0], args[1], args[2], args[3], args[4], args[5], 0, 0, 0), E_POINTER_);
        args[i] = save;
    }
}
TEST(mm_ngc_unpack_cred_data_zero_size) {
    NEED("NgcUnpackCredData", f);
    char buf[8] = {0}; PVOID o1 = (PVOID)7, o2 = (PVOID)7; ULONG_PTR sz = 1;
    EQ32(f(buf, 0, &o1, &sz, &o2, &sz, 0, 0, 0), E_INVALIDARG_);
    CHECK(o1 == (PVOID)7 && o2 == (PVOID)7);
}
/* NgcPackAuthBuffer(user, domain, pwd, p4, p5, p6, p7, &out, &cb): required: 1,2,3,5,8,9 */
TEST(mm_ngc_pack_auth_buffer_null_required) {
    NEED("NgcPackAuthBuffer", f);
    WCHAR s[] = L"x"; PVOID out = (PVOID)7; ULONG cb = 5;
    PVOID args[9] = {s, s, s, 0, s, 0, 0, &out, &cb};
    static const int req[] = {0, 1, 2, 4, 7, 8};
    for (unsigned k = 0; k < 6; k++) {
        int i = req[k]; PVOID save = args[i]; args[i] = 0;
        EQ32(f(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8]), E_POINTER_);
        args[i] = save;
    }
    CHECK(out == (PVOID)7); CHECK(cb == 5);
}
/* NgcPackPasswordChangeAuthBuffer(p1,p2,p3,p4,p5,p6,&out,p8): required 1,2,3,5,7,8 */
TEST(mm_ngc_pack_password_change_null_required) {
    NEED("NgcPackPasswordChangeAuthBuffer", f);
    WCHAR s[] = L"x"; PVOID out = (PVOID)7; ULONG cb = 5;
    PVOID args[8] = {s, s, s, 0, s, 0, &out, &cb};
    static const int req[] = {0, 1, 2, 4, 6, 7};
    for (unsigned k = 0; k < 6; k++) {
        int i = req[k]; PVOID save = args[i]; args[i] = 0;
        EQ32(f(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], 0), E_POINTER_);
        args[i] = save;
    }
    CHECK(out == (PVOID)7);
}

/* ---- parameter validation of NGC operations that take a handle/info as first argument ------- */
static void null_first_invalid(const char *n) {
    NEED(n, f);
    EQ32(f(0, 0, 0, 0, 0, 0, 0, 0, 0), NTE_INVPARAM_);
}
TEST(mm_ngc_add_bio_protector_null_first) { null_first_invalid("NgcAddBioProtector"); }
TEST(mm_ngc_add_companion_device_protector_null_first) { null_first_invalid("NgcAddCompanionDeviceProtector"); }
TEST(mm_ngc_add_preboot_protector_null_args) { null_first_invalid("NgcAddPrebootProtector"); }
TEST(mm_ngc_remove_bio_protector_null_first) { null_first_invalid("NgcRemoveBioProtector"); }
TEST(mm_ngc_remove_companion_device_protector_null_first) { null_first_invalid("NgcRemoveCompanionDeviceProtector"); }
TEST(mm_ngc_remove_preboot_protector_null_first) { null_first_invalid("NgcRemovePrebootProtector"); }
TEST(mm_ngc_change_pin_null_first) { null_first_invalid("NgcChangePin"); }
TEST(mm_ngc_change_pin_silent_null_args) { null_first_invalid("NgcChangePinSilent"); }
TEST(mm_ngc_get_policy_null_args) { null_first_invalid("NgcGetPolicy"); }
TEST(mm_ngc_create_user_id_key_null_account_info) { null_first_invalid("NgcCreateUserIdKey"); }
TEST(mm_ngc_create_user_id_key_ex_null_account_info) { null_first_invalid("NgcCreateUserIdKeyEx"); }

TEST(mm_ngc_get_policy_each_required_pointer) {
    NEED("NgcGetPolicy", f);
    char a[16] = {0}, b[16] = {0}, c[16] = {0};
    EQ32(f(0, a, a, b, c, 0, 0, 0, 0), NTE_INVPARAM_);
    EQ32(f(a, a, a, 0, c, 0, 0, 0, 0), NTE_INVPARAM_);
    EQ32(f(a, a, a, b, 0, 0, 0, 0, 0), NTE_INVPARAM_);
}
TEST(mm_ngc_add_preboot_each_required_pointer) {
    NEED("NgcAddPrebootProtector", f);
    char a[16] = {0};
    PVOID args[6] = {a, 0, 0, a, a, a};
    for (int i = 0; i < 6; i++) {
        if (i == 1 || i == 2) continue;     /* arguments 2 and 3 are not validated */
        PVOID save = args[i]; args[i] = 0;
        EQ32(f(args[0], args[1], args[2], args[3], args[4], args[5], 0, 0, 0), NTE_INVPARAM_);
        args[i] = save;
    }
}
TEST(mm_ngc_create_ticket_smartcard_null_args) {
    NEED("NgcCreateTicketForSmartCardKeyOperation", f);
    WCHAR n[] = L"user"; char b[16] = {0};
    EQ32(f(n, 0, (PVOID)1, b, 0, 0, 0, 0, 0), NTE_INVPARAM_);
    EQ32(f(n, b, 0, b, 0, 0, 0, 0, 0), NTE_INVPARAM_);
    EQ32(f(0, 0, 0, 0, 0, 0, 0, 0, 0), NTE_INVPARAM_);
}
TEST(mm_ngc_enum_containers_null_outputs) {
    NEED("NgcEnumContainers", f);
    char a[16] = {0};
    EQ32(f(0, 0, a, 0, 0, 0, 0, 0, 0), NTE_INVPARAM_);
    EQ32(f(0, a, 0, 0, 0, 0, 0, 0, 0), NTE_INVPARAM_);
    EQ32(f(a, 0, 0, 0, 0, 0, 0, 0, 0), NTE_INVPARAM_);
}
TEST(mm_ngc_sign_with_user_id_key_ex_bad_flags) {
    NEED("NgcSignWithUserIdKeyEx", f);
    /* args: key name, data, cb, hwnd, pin/prompt, flags, &sig, &cbSig; flags other than 0/1 are rejected first */
    static const unsigned bad[] = {2, 3, 4, 0x80, 0x100, 0x10000, 0x80000000u, 0xFFFFFFFEu, 0xFFFFFFFFu};
    for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++)
        CHECKF((unsigned)f(0, 0, 0, 0, 0, (PVOID)(ULONG_PTR)bad[i], 0, 0, 0) == NTE_BAD_FLAGS_, "flags 0x%x", bad[i]);
}
TEST(mm_ngc_sign_with_user_id_key_ex_flags_checked_before_pointers) {
    NEED("NgcSignWithUserIdKeyEx", f);
    WCHAR k[] = L"k"; char d[4] = {0}; PVOID sig = (PVOID)7; ULONG cb = 9;
    EQ32(f(k, d, (PVOID)4, 0, 0, (PVOID)2, &sig, &cb, 0), NTE_BAD_FLAGS_);
    CHECK(sig == (PVOID)7 && cb == 9);
}
