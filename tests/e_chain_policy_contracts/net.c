/* Harness-level boundary check: the guest must not be able to reach an external address.  Uses a reserved
 * documentation address (never a real host) and a short non-blocking TCP connect.  Nothing is sent on success paths
 * because there are none expected; a successful connect would be reported as a failure of the boundary. */
#include "cp.h"

typedef UINT_PTR SOCK;
typedef struct { unsigned short fam; unsigned short port; unsigned char addr[4]; char zero[8]; } SA4;
typedef struct { unsigned int n; SOCK a[64]; } FDS;
typedef struct { long sec, usec; } TV;
typedef int (WINAPI *p_start)(WORD, void *);
typedef SOCK (WINAPI *p_socket)(int, int, int);
typedef int (WINAPI *p_connect)(SOCK, const SA4 *, int);
typedef int (WINAPI *p_ioctl)(SOCK, long, unsigned long *);
typedef int (WINAPI *p_select)(int, FDS *, FDS *, FDS *, const TV *);
typedef int (WINAPI *p_getopt)(SOCK, int, int, char *, int *);
typedef int (WINAPI *p_close)(SOCK);
typedef int (WINAPI *p_lasterr)(void);
typedef DWORD (WINAPI *p_bestroute)(DWORD, DWORD, void *);

/* returns: 0 not connected (blocked), 1 connected, -1 could not run the probe */
static int tcp_probe(const unsigned char ip[4], unsigned short port, int *werr, int *phase) {
    HMODULE m = LoadLibraryA("ws2_32.dll");
    char wsa[512]; SOCK s; SA4 sa; unsigned long nb = 1; int r, e = 0;
    p_start st; p_socket so; p_connect co; p_ioctl io; p_select se; p_getopt go; p_close cl; p_lasterr le;
    *werr = 0; *phase = 0;
    if (!m) return -1;
    st = (p_start)GetProcAddress(m, "WSAStartup"); so = (p_socket)GetProcAddress(m, "socket");
    co = (p_connect)GetProcAddress(m, "connect"); io = (p_ioctl)GetProcAddress(m, "ioctlsocket");
    se = (p_select)GetProcAddress(m, "select"); go = (p_getopt)GetProcAddress(m, "getsockopt");
    cl = (p_close)GetProcAddress(m, "closesocket"); le = (p_lasterr)GetProcAddress(m, "WSAGetLastError");
    if (!st || !so || !co || !io || !se || !go || !cl || !le) return -1;
    if (st(0x0202, wsa)) return -1;
    s = so(2, 1, 6);
    if (s == (SOCK)~0) { *werr = le(); return -1; }
    io(s, (long)0x8004667E, &nb);                    /* FIONBIO */
    memset(&sa, 0, sizeof sa); sa.fam = 2; sa.port = (unsigned short)((port >> 8) | (port << 8)); memcpy(sa.addr, ip, 4);
    r = co(s, &sa, sizeof sa);
    if (r == 0) { cl(s); return 1; }
    e = le();
    if (e != 10035) { *werr = e; *phase = 1; cl(s); return 0; }     /* immediate failure (WSAEWOULDBLOCK = in progress) */
    { FDS w, x; TV tv = {3, 0}; memset(&w, 0, sizeof w); memset(&x, 0, sizeof x); w.n = 1; w.a[0] = s; x.n = 1; x.a[0] = s;
      r = se(0, NULL, &w, &x, &tv);
      if (r > 0) { int soerr = 0, l = sizeof soerr; go(s, 0xffff, 0x1007, (char *)&soerr, &l); *werr = soerr; *phase = w.n ? 2 : 3; cl(s); return w.n && soerr == 0; }
      *werr = 0; *phase = 4;   /* 2: writable, 3: exception set (SO_ERROR in wsaerr), 4: no answer within 3 s */
    }
    cl(s);
    return 0;
}

TEST(guest_cannot_reach_external_address) {
    /* The oracle runs with no route.  Each probe is a TCP connect to a reserved documentation address; the stack
     * answers "network unreachable" (WSAENETUNREACH) at once, so nothing leaves the guest. */
    static const unsigned char a1[4] = {192, 0, 2, 1}, a2[4] = {198, 51, 100, 7}, a3[4] = {203, 0, 113, 9};
    const unsigned char *ips[3] = {a1, a2, a3};
    for (int i = 0; i < 3; i++) {
        int we, ph, r = tcp_probe(ips[i], 443, &we, &ph);
        t_label("%u.%u.%u.%u", ips[i][0], ips[i][1], ips[i][2], ips[i][3]);
        CHECKF(r == 0, "probe result %d (1 = connected, -1 = could not run)", r);
        CHECKF(ph == 3 && we == 10051, "phase %d wsaerr %d want exception set / WSAENETUNREACH", ph, we);
    }
    t_label(NULL);
    { HMODULE m = LoadLibraryA("iphlpapi.dll"); p_bestroute br = m ? (p_bestroute)GetProcAddress(m, "GetBestRoute") : NULL;
      unsigned char row[64]; DWORD rc;
      if (!br) { t_skip("GetBestRoute unavailable"); return; }
      memset(row, 0, sizeof row);
      rc = br(0x010200C0, 0, row);                     /* 192.0.2.1 */
      CHECKF(rc == ERROR_NETWORK_UNREACHABLE, "GetBestRoute rc %lu want 1231", rc); }
}
