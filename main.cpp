#include <windows.h>
#include <psapi.h>
#include <string.h>
#include <stdio.h>
#include "lib/CTools.h"

#pragma comment(lib, "psapi.lib")

// =====================================================================
// Proxy DLL untuk Lost Saga.
// Drop sebagai `xinput1_3.dll`; rename DLL asli jadi `xinput1_3_org.dll`.
//
// MODE DIAGNOSTIK: enumerate semua loaded module, scan pola kandidat
// string nProtect/GameGuard/Exit, log hasilnya ke `bypass.log`.
// Tujuannya cari MODULE mana yg berisi string target supaya bisa
// di-target untuk patch.
// =====================================================================

#pragma comment(linker, "/export:XInputGetState=xinput1_3_org.XInputGetState,@2")
#pragma comment(linker, "/export:XInputSetState=xinput1_3_org.XInputSetState,@3")
#pragma comment(linker, "/export:XInputGetCapabilities=xinput1_3_org.XInputGetCapabilities,@4")
#pragma comment(linker, "/export:XInputEnable=xinput1_3_org.XInputEnable,@5")
#pragma comment(linker, "/export:XInputGetDSoundAudioDeviceGuids=xinput1_3_org.XInputGetDSoundAudioDeviceGuids,@6")
#pragma comment(linker, "/export:XInputGetBatteryInformation=xinput1_3_org.XInputGetBatteryInformation,@7")
#pragma comment(linker, "/export:XInputGetKeystroke=xinput1_3_org.XInputGetKeystroke,@8")
#pragma comment(linker, "/export:XInputGetStateEx=xinput1_3_org.XInputGetStateEx,@100")

// ---- Logger ------------------------------------------------------------
static CRITICAL_SECTION g_logLock;
static bool g_logInit = false;

static void LogInit()
{
    if (!g_logInit) {
        InitializeCriticalSection(&g_logLock);
        g_logInit = true;
        FILE* f = fopen("bypass.log", "w");
        if (f) { fprintf(f, "=== bypass.log (diagnostic mode) ===\n"); fclose(f); }
    }
}

static void Log(const char* fmt, ...)
{
    LogInit();
    EnterCriticalSection(&g_logLock);
    FILE* f = fopen("bypass.log", "a");
    if (f) {
        SYSTEMTIME st; GetLocalTime(&st);
        fprintf(f, "[%02d:%02d:%02d.%03d] ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
        va_list args; va_start(args, fmt);
        vfprintf(f, fmt, args);
        va_end(args);
        fprintf(f, "\n");
        fclose(f);
    }
    LeaveCriticalSection(&g_logLock);
}

// ---- Pattern scan ------------------------------------------------------
static PBYTE FindBytes(PBYTE base, DWORD size, const BYTE* pattern, DWORD patSize)
{
    if (size < patSize) return NULL;
    DWORD last = size - patSize;
    for (DWORD i = 0; i <= last; ++i) {
        if (memcmp(base + i, pattern, patSize) == 0)
            return base + i;
    }
    return NULL;
}

// ---- Hexdump kecil untuk verifikasi pattern hit -------------------------
static void LogHexAround(PBYTE addr, int beforeLen, int afterLen)
{
    char buf[256] = {0};
    int pos = 0;
    PBYTE start = addr - beforeLen;
    int total = beforeLen + afterLen;
    for (int i = 0; i < total && pos < (int)sizeof(buf) - 4; ++i) {
        pos += sprintf(buf + pos, "%02X ", start[i]);
    }
    Log("    bytes: %s", buf);
}

// ---- Daftar string kandidat untuk discovery -----------------------------
struct CandidateStr {
    const char* label;
    const BYTE* bytes;
    DWORD       len;
    bool        printable; // dump preview
};

// Variasi panjang/pendek dari nProtect & GameGuard error messages
static const BYTE S_NPROTECT[]    = { 'n','P','r','o','t','e','c','t' };
static const BYTE S_NPROT_ERR[]   = { 'n','P','r','o','t','e','c','t',' ','E','r','r','o','r' };
static const BYTE S_NPROT_FULL[]  = { 'n','P','r','o','t','e','c','t',' ','E','r','r','o','r',' ',':',' ','%','s',':','%','s','\n','\0' };
static const BYTE S_NPROT_OLD[]   = { 'n','P','r','o','t','e','c','t',' ','E','r','r','o','r',' ',':',' ','%','s',' ',':',' ','%','s','\n','\0' };
static const BYTE S_INITCMP[]     = { 'I','n','i','t',' ','C','o','m','p','l','e','t','e' };
static const BYTE S_GAMEGUARD[]   = { 'G','a','m','e','G','u','a','r','d' };
static const BYTE S_GAMEGUARDDES[]= { 'G','a','m','e','G','u','a','r','d','.','d','e','s' };
static const BYTE S_GAMEMON[]     = { 'G','a','m','e','M','o','n' };
static const BYTE S_EXITPROG[]    = { 'E','x','i','t','P','r','o','g','r','a','m' };
static const BYTE S_EXITPROG23[]  = { 'E','x','i','t','P','r','o','g','r','a','m',' ','-',' ','2','3' };
static const BYTE S_NPROT_INIT[]  = { 'n','P','r','o','t','e','c','t',' ','I','n','i','t' };
static const BYTE S_NPGGNT[]      = { 'n','p','g','g','N','T' };
static const BYTE S_NPKCRYPT[]    = { 'n','p','k','c','r','y','p','t' };
static const BYTE S_INCAINTER[]   = { 'I','N','C','A',' ','I','n','t','e','r','n','e','t' };

static const CandidateStr CANDIDATES[] = {
    {"nProtect",       S_NPROTECT,     sizeof(S_NPROTECT),     true},
    {"nProtect Error", S_NPROT_ERR,    sizeof(S_NPROT_ERR),    true},
    {"nProtect Err+%s",S_NPROT_FULL,   sizeof(S_NPROT_FULL),   false},
    {"nProtect old",   S_NPROT_OLD,    sizeof(S_NPROT_OLD),    false},
    {"nProtect Init",  S_NPROT_INIT,   sizeof(S_NPROT_INIT),   true},
    {"Init Complete",  S_INITCMP,      sizeof(S_INITCMP),      true},
    {"GameGuard",      S_GAMEGUARD,    sizeof(S_GAMEGUARD),    true},
    {"GameGuard.des",  S_GAMEGUARDDES, sizeof(S_GAMEGUARDDES), true},
    {"GameMon",        S_GAMEMON,      sizeof(S_GAMEMON),      true},
    {"ExitProgram",    S_EXITPROG,     sizeof(S_EXITPROG),     true},
    {"ExitProgram -23",S_EXITPROG23,   sizeof(S_EXITPROG23),   true},
    {"npggNT",         S_NPGGNT,       sizeof(S_NPGGNT),       true},
    {"npkcrypt",       S_NPKCRYPT,     sizeof(S_NPKCRYPT),     true},
    {"INCA Internet",  S_INCAINTER,    sizeof(S_INCAINTER),    true},
};

// ---- Scan satu module untuk semua kandidat string -----------------------
static void ScanModule(const char* moduleName, PBYTE base, DWORD size)
{
    int nCandidates = sizeof(CANDIDATES) / sizeof(CANDIDATES[0]);
    int hits = 0;
    for (int i = 0; i < nCandidates; ++i) {
        PBYTE p = FindBytes(base, size, CANDIDATES[i].bytes, CANDIDATES[i].len);
        if (p) {
            Log("  [HIT] %-18s @ %p  (offset 0x%lX)",
                CANDIDATES[i].label, p, (DWORD)(p - base));
            if (CANDIDATES[i].printable) {
                LogHexAround(p, 0, 32);
            }
            hits++;
        }
    }
    if (hits == 0) {
        Log("  (no candidate strings found in %s)", moduleName);
    }
}

// ---- Diagnostic thread -------------------------------------------------
static DWORD WINAPI Diagnostic(LPVOID)
{
    Log("diagnostic thread start");

    // Beri waktu image utama dan import-nya untuk fully map.
    Sleep(200);

    HMODULE modules[256];
    DWORD needed = 0;
    HANDLE hProc = GetCurrentProcess();
    if (!EnumProcessModules(hProc, modules, sizeof(modules), &needed)) {
        Log("EnumProcessModules failed: %lu", GetLastError());
        return 0;
    }
    DWORD nMod = needed / sizeof(HMODULE);
    Log("enumerated %lu loaded modules", nMod);

    for (DWORD i = 0; i < nMod; ++i) {
        char modName[MAX_PATH] = {0};
        char modPath[MAX_PATH] = {0};
        GetModuleBaseNameA(hProc, modules[i], modName, sizeof(modName));
        GetModuleFileNameExA(hProc, modules[i], modPath, sizeof(modPath));

        MODULEINFO mi = {0};
        if (!GetModuleInformation(hProc, modules[i], &mi, sizeof(mi)))
            continue;

        // Filter: skip system DLLs (windows, system32) -- noise.
        bool isSystem =
            strstr(modPath, "\\Windows\\")  ||
            strstr(modPath, "\\windows\\")  ||
            strstr(modPath, "\\WINDOWS\\");
        if (isSystem) continue;

        Log("--- module: %s  base=%p  size=%lu (0x%lX) ---",
            modName, mi.lpBaseOfDll, mi.SizeOfImage, mi.SizeOfImage);
        ScanModule(modName, (PBYTE)mi.lpBaseOfDll, mi.SizeOfImage);
    }

    Log("diagnostic done");
    return 0;
}

// ---- GG kill loop ------------------------------------------------------
static DWORD WINAPI GGKillLoop(LPVOID)
{
    CTools tools;
    int killed = 0;
    while (1) {
        if (tools.TerminateProcessByName("GameGuard.des")) {
            killed++;
            if (killed <= 5 || (killed % 100) == 0)
                Log("killed GameGuard.des (count=%d)", killed);
        }
        Sleep(20);
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        Log("DllMain DLL_PROCESS_ATTACH (hModule=%p)", hModule);
        CreateThread(NULL, 0, Diagnostic, NULL, 0, NULL);
        CreateThread(NULL, 0, GGKillLoop,  NULL, 0, NULL);
    }
    return TRUE;
}
