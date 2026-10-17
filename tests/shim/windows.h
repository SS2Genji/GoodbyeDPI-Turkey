#ifndef _SHIM_WINDOWS_H
#define _SHIM_WINDOWS_H

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

typedef uint8_t   BYTE;
typedef uint8_t   UINT8;
typedef int16_t   INT16;
typedef uint16_t  UINT16;
typedef uint32_t  UINT;
typedef uint32_t  UINT32;
typedef int64_t   INT64;
typedef uint64_t  UINT64;
typedef uint32_t  DWORD;
typedef int       BOOL;
typedef int       INT;
typedef intptr_t  INT_PTR;
typedef const char *LPCSTR;
typedef char     *LPTSTR;
typedef void     *PVOID;
typedef void     *HANDLE;
typedef void     *HMODULE;
typedef uint16_t  u_short;
typedef uint64_t  ULONGLONG;

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

#define WINAPI
#define WSAAPI
#define WINSOCK_API_LINKAGE
#define INVALID_HANDLE_VALUE ((HANDLE)(intptr_t)-1)

#define FORMAT_MESSAGE_ALLOCATE_BUFFER 0x00000100
#define FORMAT_MESSAGE_IGNORE_INSERTS  0x00000200
#define FORMAT_MESSAGE_FROM_SYSTEM     0x00001000
#define LANG_ENGLISH                   0x09
#define SUBLANG_DEFAULT                0x01
#define MAKELANGID(p, s)               ((((uint16_t)(s)) << 10) | (uint16_t)(p))
#define BASE_SEARCH_PATH_ENABLE_SAFE_SEARCHMODE 0x1
#define BASE_SEARCH_PATH_PERMANENT              0x8000

static inline DWORD GetLastError(void) { return 0; }
static inline DWORD FormatMessage(DWORD dwFlags, const void *lpSource, DWORD dwMessageId,
                                  DWORD dwLanguageId, LPTSTR lpBuffer, DWORD nSize, void *Arguments) {
    (void)dwFlags; (void)lpSource; (void)dwMessageId; (void)dwLanguageId; (void)nSize; (void)Arguments;
    if (lpBuffer) *(char **)lpBuffer = NULL;
    return 0;
}
static inline void LocalFree(void *hMem) { free(hMem); }
static inline BOOL SetDllDirectory(LPCSTR lpPathName) { (void)lpPathName; return TRUE; }
static inline BOOL SetSearchPathMode(DWORD Flags) { (void)Flags; return TRUE; }

static inline INT_PTR dummy_dns_flush(void) { return 1; }
static inline HMODULE LoadLibrary(LPCSTR lpLibFileName) { (void)lpLibFileName; return (HMODULE)0x1; }
static inline void *GetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
    (void)hModule; (void)lpProcName;
    return (void *)(uintptr_t)dummy_dns_flush;
}
static inline BOOL FreeLibrary(HMODULE hLibModule) { (void)hLibModule; return TRUE; }

static inline ULONGLONG GetTickCount64(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (ULONGLONG)ts.tv_sec * 1000ULL + (ULONGLONG)(ts.tv_nsec / 1000000ULL);
}

static inline int rand_s(unsigned int *randomValue) {
    static uint64_t state = 0x853c49e6748fea9bULL;
    state ^= state >> 12;
    state ^= state << 25;
    state ^= state >> 27;
    *randomValue = (unsigned int)((state * 0x2545F4914F6CDD1DULL) >> 32);
    return 0;
}

/* Service Control Manager stubs for host compilation */
typedef void (*LPSERVICE_MAIN_FUNCTION)(int, char **);
typedef void (*LPHANDLER_FUNCTION)(DWORD);
typedef intptr_t SERVICE_STATUS_HANDLE;
typedef struct _SERVICE_TABLE_ENTRY {
    char *lpServiceName;
    LPSERVICE_MAIN_FUNCTION lpServiceProc;
} SERVICE_TABLE_ENTRY;
typedef struct _SERVICE_STATUS {
    DWORD dwServiceType;
    DWORD dwCurrentState;
    DWORD dwControlsAccepted;
    DWORD dwWin32ExitCode;
    DWORD dwServiceSpecificExitCode;
    DWORD dwCheckPoint;
    DWORD dwWaitHint;
} SERVICE_STATUS;

#define SERVICE_WIN32_OWN_PROCESS 0x00000010
#define SERVICE_RUNNING           0x00000004
#define SERVICE_STOPPED           0x00000001
#define SERVICE_ACCEPT_STOP       0x00000001
#define SERVICE_ACCEPT_SHUTDOWN   0x00000004
#define SERVICE_CONTROL_STOP      0x00000001
#define SERVICE_CONTROL_SHUTDOWN  0x00000005

static inline BOOL StartServiceCtrlDispatcher(const SERVICE_TABLE_ENTRY *lpServiceStartTable) {
    (void)lpServiceStartTable;
    return FALSE;
}
static inline SERVICE_STATUS_HANDLE RegisterServiceCtrlHandler(LPCSTR lpServiceName, LPHANDLER_FUNCTION lpHandlerProc) {
    (void)lpServiceName; (void)lpHandlerProc;
    return 1;
}
static inline BOOL SetServiceStatus(SERVICE_STATUS_HANDLE hServiceStatus, SERVICE_STATUS *lpServiceStatus) {
    (void)hServiceStatus; (void)lpServiceStatus;
    return TRUE;
}

#endif /* _SHIM_WINDOWS_H */
