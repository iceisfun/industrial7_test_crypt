/* Additional handle-lifetime and control-type checks (decomp: CryptMsgDuplicate/Close/Control). */
#include "ml.h"

TEST(mlx_duplicate_null_returns_null) {
    REQ_MSG(); REQUIRE(mDup());
    CHECK(mDup()(NULL) == NULL);
}
TEST(mlx_close_null_twice_true) {
    REQ_MSG();
    CHECK(mClose()(NULL));
    CHECK(mClose()(NULL));
}
TEST(mlx_duplicate_chain_refcount_three) {
    REQ_MSG(); REQUIRE(mDup());
    HCRYPTMSG m = mOpenEnc()(ENC, 0, CMSG_DATA, NULL, NULL, NULL);
    CHECK(m != NULL);
    if (!m) return;
    HCRYPTMSG a = mDup()(m), b = mDup()(a);
    CHECK(a == m && b == m);
    CHECK(mUpdate()(m, (const BYTE *)"xy", 2, TRUE));
    CHECK(mClose()(m));
    CHECK(mClose()(a));
    DWORD n = 0; BYTE *p = ml_param(b, CMSG_CONTENT_PARAM, 0, &n);
    CHECK(p != NULL && n >= 2);
    ml_free(p);
    CHECK(mClose()(b));
}
TEST(mlx_decode_unknown_control_types) {
    REQ_MSG();
    static const DWORD bad[] = {0, 0x40, 0x1000, 0xffffffff};
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        HCRYPTMSG m = ml_decode(M_SIGNED_NOATTR, M_SIGNED_NOATTR_LEN, 0, 0);
        CHECKF(m != NULL, "ctl %lx", (unsigned long)bad[i]);
        if (!m) continue;
        SET_ERR(0);
        CHECKF(!mControl()(m, 0, bad[i], NULL), "ctl %lx", (unsigned long)bad[i]);
        EXPECT_ERR(CRYPT_E_CONTROL_TYPE);
        mClose()(m);
    }
}
TEST(mlx_decode_del_signer_bad_index_leaves_count) {
    REQ_MSG();
    HCRYPTMSG m = ml_decode(M_SIGNED_NOATTR, M_SIGNED_NOATTR_LEN, 0, 0);
    CHECK(m != NULL);
    if (!m) return;
    DWORD idx = 5, v = 0;
    SET_ERR(0);
    CHECK(!mControl()(m, 0, CMSG_CTRL_DEL_SIGNER, &idx));
    EXPECT_ERR(CRYPT_E_INVALID_INDEX);
    CHECK(ml_param_dword(m, CMSG_SIGNER_COUNT_PARAM, 0, &v) && v == 1);
    mClose()(m);
}
