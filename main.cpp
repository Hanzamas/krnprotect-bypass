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
// Strategi (build 12861, hasil diagnostic sebelumnya):
//   - lostsaga.exe pakai string `"GameMon Error : %d"` & `"ExitProgram - 23"`
//   - Cari kedua string itu di module lostsaga.exe
//   - Cari instruksi `push <strAddr>` (xref) di .text
//   - Walk back ke prologue fungsi (55 8B EC)
//   - Patch awal fungsi dengan `xor eax,eax; ret` (return 0 = no error)
//   - Loop terminate process GameGuard.des
//
// Log: `bypass.log` di folder game.
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
        if (f) { fprintf(f, "=== bypass.log ===\n"); fclose(f); }
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

// ---- Module helpers ----------------------------------------------------
static bool GetMainModuleRange(PBYTE& base, DWORD& size)
{
    HMODULE mod = GetModuleHandleA(NULL);
    if (!mod) return false;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)mod;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PBYTE)mod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    base = (PBYTE)mod;
    size = nt->OptionalHeader.SizeOfImage;
    return true;
}

// ---- Pattern utilities -------------------------------------------------
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

// Cari semua occurrence dari `push imm32` (0x68 + 4-byte). Kembalikan
// occurrence ke-`nth` (0-indexed). NULL kalau tidak ada lagi.
static PBYTE FindPushImm32_N(PBYTE base, DWORD size, DWORD imm, int nth)
{
    if (size < 5) return NULL;
    DWORD last = size - 5;
    int seen = 0;
    for (DWORD i = 0; i <= last; ++i) {
        if (base[i] == 0x68 && *(DWORD*)(base + i + 1) == imm) {
            if (seen == nth) return base + i;
            seen++;
        }
    }
    return NULL;
}

static PBYTE FindFuncStartBack(PBYTE addr, DWORD maxBack)
{
    for (DWORD i = 0; i < maxBack; ++i) {
        PBYTE p = addr - i;
        if (p[0] == 0x55 && p[1] == 0x8B && p[2] == 0xEC)
            return p;
    }
    return NULL;
}

static bool PatchBytes(PBYTE addr, const BYTE* bytes, DWORD len)
{
    DWORD oldProt = 0, tmp = 0;
    if (!VirtualProtect(addr, len, PAGE_EXECUTE_READWRITE, &oldProt)) {
        Log("  PatchBytes: VirtualProtect failed at %p, err=%lu", addr, GetLastError());
        return false;
    }
    memcpy(addr, bytes, len);
    VirtualProtect(addr, len, oldProt, &tmp);
    FlushInstructionCache(GetCurrentProcess(), addr, len);
    return true;
}

static void LogHexAt(const char* tag, PBYTE addr, int n)
{
    char buf[256] = {0};
    int pos = 0;
    for (int i = 0; i < n && pos < (int)sizeof(buf) - 4; ++i)
        pos += sprintf(buf + pos, "%02X ", addr[i]);
    Log("  %s @ %p: %s", tag, addr, buf);
}

// ---- Patch by string xref ----------------------------------------------
// Coba semua xref `push <strAddr>`. Untuk tiap xref:
//   1. walk back cari prologue
//   2. patch dengan `xor eax,eax; ret`
// Berhenti setelah patch pertama berhasil.
static bool PatchFuncContainingString(const char* tag, PBYTE base, DWORD size,
                                      const BYTE* strBytes, DWORD strLen)
{
    PBYTE strAddr = FindBytes(base, size, strBytes, strLen);
    if (!strAddr) {
        Log("[%s] string NOT FOUND", tag);
        return false;
    }
    Log("[%s] string at %p (offset 0x%lX)", tag, strAddr, (DWORD)(strAddr - base));

    static const BYTE STUB[] = { 0x31, 0xC0, 0xC3 }; // xor eax,eax; ret

    int xrefIdx = 0;
    int patchedCount = 0;
    while (xrefIdx < 16) {
        PBYTE pushSite = FindPushImm32_N(base, size, (DWORD)(DWORD_PTR)strAddr, xrefIdx);
        if (!pushSite) break;
        Log("[%s] xref #%d: push at %p", tag, xrefIdx, pushSite);

        PBYTE funcStart = FindFuncStartBack(pushSite, 0x1000);
        if (!funcStart) {
            Log("[%s] no prologue 55 8B EC within 4KB above xref", tag);
        } else {
            Log("[%s] prologue at %p (xref offset -%lu)",
                tag, funcStart, (DWORD)(pushSite - funcStart));
            LogHexAt("orig", funcStart, 16);
            if (PatchBytes(funcStart, STUB, sizeof(STUB))) {
                Log("[%s] PATCHED xref #%d at %p", tag, xrefIdx, funcStart);
                patchedCount++;
            }
        }
        xrefIdx++;
    }
    Log("[%s] xrefs found=%d, patched=%d", tag, xrefIdx, patchedCount);
    return patchedCount > 0;
}

// ---- Target strings (yang BENERAN ada di lostsaga.exe build 12861) -----
//   "GameMon Error : %d\0"  -- error printer dari nProtect-style check
static const BYTE STR_GAMEMON_ERR[] = {
    'G','a','m','e','M','o','n',' ','E','r','r','o','r',' ',':',' ','%','d','\0'
};

//   "ExitProgram - 23\0"  -- exit reason 23 (GG validation fail)
static const BYTE STR_EXITPROG23[] = {
    'E','x','i','t','P','r','o','g','r','a','m',' ','-',' ','2','3','\0'
};

//   "ExitProgram - 1\0"  -- exit reason 1 (variant)
static const BYTE STR_EXITPROG1[] = {
    'E','x','i','t','P','r','o','g','r','a','m',' ','-',' ','1','\0'
};

// ---- Bypass thread -----------------------------------------------------
static DWORD WINAPI Bypass(LPVOID)
{
    Log("bypass thread start");
    Sleep(150); // beri waktu lostsaga ter-map sempurna

    PBYTE base = NULL;
    DWORD size = 0;
    if (!GetMainModuleRange(base, size)) {
        Log("FATAL: GetMainModuleRange failed");
    } else {
        Log("lostsaga.exe: base=%p size=%lu (0x%lX)", base, size, size);
        PatchFuncContainingString("GameMonErr", base, size,
                                  STR_GAMEMON_ERR, sizeof(STR_GAMEMON_ERR));
        PatchFuncContainingString("ExitProg23", base, size,
                                  STR_EXITPROG23, sizeof(STR_EXITPROG23));
        PatchFuncContainingString("ExitProg1",  base, size,
                                  STR_EXITPROG1,  sizeof(STR_EXITPROG1));
    }

    Log("entering kill-loop for GameGuard.des");
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
        CreateThread(NULL, 0, Bypass, NULL, 0, NULL);
    }
    return TRUE;
}
