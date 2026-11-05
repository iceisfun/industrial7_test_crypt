#include "sip_common.h"

void sipt_wide(WCHAR *dst, size_t n, const char *src)
{
    size_t i = 0;
    for (; src[i] && i + 1 < n; i++) dst[i] = (WCHAR)(unsigned char)src[i];
    dst[i] = 0;
}

int sipt_put(const char *path, const void *buf, size_t n)
{
    HANDLE h = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD w = 0;
    if (h == INVALID_HANDLE_VALUE) return 0;
    BOOL ok = n == 0 || WriteFile(h, buf, (DWORD)n, &w, NULL);
    CloseHandle(h);
    return ok && w == n;
}

size_t sipt_get(const char *path, u8 *buf, size_t cap)
{
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    DWORD r = 0;
    if (h == INVALID_HANDLE_VALUE) return 0;
    BOOL ok = ReadFile(h, buf, (DWORD)cap, &r, NULL);
    CloseHandle(h);
    return ok ? r : 0;
}

size_t sipt_size(const char *path)
{
    WIN32_FILE_ATTRIBUTE_DATA d;
    if (!GetFileAttributesExA(path, GetFileExInfoStandard, &d)) return (size_t)-1;
    return d.nFileSizeLow;
}

void sipt_mkpe(char *path, size_t cap, const char *leaf, unsigned variant)
{
    u8 b[4096];
    size_t n = sipi_pe(variant, b, sizeof b);
    t_tmpfile(path, cap, leaf);
    if (!sipt_put(path, b, n)) t_note("could not create fixture %s", path);
}

void sipt_mkcab(char *path, size_t cap, const char *leaf)
{
    u8 b[256];
    size_t n = sipi_cab(b, sizeof b);
    t_tmpfile(path, cap, leaf);
    if (!sipt_put(path, b, n)) t_note("could not create fixture %s", path);
}

HANDLE sipt_open(const char *path, DWORD access)
{
    return CreateFileA(path, access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
}

void sipt_subject(SIP_SUBJECTINFO *si, const GUID *g, HANDLE h, const WCHAR *wname, const char *alg, DWORD flags)
{
    memset(si, 0, sizeof *si);
    si->cbSize = sizeof *si;
    si->pgSubjectType = (GUID *)g;
    si->hFile = h;
    si->pwsFileName = wname;
    si->DigestAlgorithm.pszObjId = (LPSTR)alg;
    si->dwFlags = flags;
    si->dwEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
}

int sipt_sip_is_registered(const GUID *g)
{
    SIP_DISPATCH_INFO d;
    memset(&d, 0, sizeof d);
    d.cbSize = sizeof d;
    return U(CryptSIPLoad) && U(CryptSIPLoad)(g, 0, &d);
}

size_t sipt_make_ctl(u8 *out, size_t cap, const char *usage)
{
    CTL_INFO ctl;
    CMSG_SIGNED_ENCODE_INFO si;
    LPSTR usages[1];
    BYTE ctlder[512];
    DWORD cbctl = sizeof ctlder, cbout = 0;
    HCRYPTMSG msg;
    size_t ret = 0;
    memset(&ctl, 0, sizeof ctl);
    ctl.dwVersion = 0;
    usages[0] = (LPSTR)usage;
    if (usage) { ctl.SubjectUsage.cUsageIdentifier = 1; ctl.SubjectUsage.rgpszUsageIdentifier = usages; }
    ctl.ThisUpdate.dwLowDateTime = 0xD53E8000; ctl.ThisUpdate.dwHighDateTime = 0x01D6A000;
    ctl.SubjectAlgorithm.pszObjId = (LPSTR)szOID_OIWSEC_sha1;
    if (!U(CryptEncodeObject) || !U(CryptMsgOpenToEncode) || !U(CryptMsgUpdate) || !U(CryptMsgGetParam) || !U(CryptMsgClose)) return 0;
    if (!U(CryptEncodeObject)(X509_ASN_ENCODING, PKCS_CTL, &ctl, ctlder, &cbctl)) return 0;
    memset(&si, 0, sizeof si);
    si.cbSize = sizeof si;
    msg = U(CryptMsgOpenToEncode)(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CMSG_SIGNED, &si, (LPSTR)szOID_CTL, NULL);
    if (!msg) return 0;
    if (U(CryptMsgUpdate)(msg, ctlder, cbctl, TRUE)) {
        cbout = (DWORD)cap;
        if (U(CryptMsgGetParam)(msg, CMSG_CONTENT_PARAM, 0, out, &cbout)) ret = cbout;
    }
    U(CryptMsgClose)(msg);
    return ret;
}
