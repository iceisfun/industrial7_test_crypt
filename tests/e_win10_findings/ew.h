/* e_win10_findings: regression pins for the key Win10 22H2 behaviours found in pass 1. Every pin was probed on the oracle
 * (std and adm identical unless the test says otherwise) and each is paired with a control call that behaves differently. */
#ifndef EW_H
#define EW_H
#include "t.h"
#include <wincrypt.h>
#include <bcrypt.h>
#include "bcrypt_handles.h"
#include <ncrypt.h>
#include <lm.h>
#define ADV(n) ((__typeof__(&n))t_proc_in("advapi32.dll", #n))
#define C32(n) ((__typeof__(&n))t_proc_in("crypt32.dll", #n))
#define NCR(n) ((__typeof__(&n))t_proc_in("ncrypt.dll", #n))
#define BCR(n) ((__typeof__(&n))t_proc_in("bcrypt.dll", #n))
#define ERR_PASSWORD_RESTRICTION 1325   /* 0x52d */
#define ERR_NTE_BAD_KEYSET 0x80090016
#define ERR_NTE_PROV_TYPE_NOT_DEF 0x80090017
#define ERR_NTE_KEYSET_NOT_DEF 0x80090019
#define ERR_NTE_BAD_KEY_STATE 0x8009000B
#define ERR_CRYPT_E_NOT_FOUND 0x80092004
#define STATUS_BUFFER_TOO_SMALL_ 0xC0000023
#endif
