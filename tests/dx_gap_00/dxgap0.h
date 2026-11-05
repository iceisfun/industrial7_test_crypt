/* Shared helpers for the dx_gap_00 area (state-changing: HKCU Disallowed / TrustedPeople / My stores, key containers). */
#ifndef DXGAP0_H
#define DXGAP0_H
#include "t.h"
#include <wincrypt.h>
#include "dxgap0_data.h"

#define DX_ENC (X509_ASN_ENCODING | PKCS_7_ASN_ENCODING)

static HCERTSTORE dx_open_hkcu(const WCHAR *name) {
    return U(CertOpenStore)(CERT_STORE_PROV_SYSTEM_W, 0, 0, CERT_SYSTEM_STORE_CURRENT_USER, name);
}
#endif
