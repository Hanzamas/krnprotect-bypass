#include <windows.h>
#include <string.h>
#include <stdio.h>
#include "lib/CTools.h"

// =====================================================================
// Proxy DLL untuk Lost Saga (build 12861).
// Drop sebagai `xinput1_3.dll`; rename DLL asli jadi `xinput1_3_org.dll`.
//
// lostsaga.exe ter-pack: strings (incl. error message GG) baru ada
// SETELAH unpacker decrypt section .rdata. Dimana DllMain dipanggil di
// titik awal, kita harus retry scan sampai strings muncul.
//
// Strategi:
//   - Background loop scan tiap 200ms
//   - Untuk setiap string target: cari -> xref -> walk back ke prologue
//     -> patch dengan `xor eax,eax; ret`
//   - Stop setelah semua target ke-patch atau timeout
//   - Paralel: kill loop GameGuard.des
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

static void LogHex(const char* tag, const void* data, int n)
{
    char buf[256] = {0};
    int pos = 0;
    const BYTE* p = (const BYTE*)data;
    for (int i = 0; i < n && pos < (int)sizeof(buf) - 4; ++i)
        pos += sprintf(buf + pos, "%02X ", p[i]);
    Log("  %s: %s", tag, buf);
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
// Safe-read: pakai SEH/IsBadReadPtr-style guard via VirtualQuery, supaya
// scan tidak crash bila beberapa page belum committed.
static bool IsReadable(PBYTE p, DWORD n)
{
    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery(p, &mbi, sizeof(mbi))) return false;
    if (mbi.State != MEM_COMMIT) return false;
    if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) return false;
    PBYTE regionEnd = (PBYTE)mbi.BaseAddress + mbi.RegionSize;
    return (p + n) <= regionEnd;
}

static PBYTE FindBytes(PBYTE base, DWORD size, const BYTE* pattern, DWORD patSize)
{
    if (size < patSize) return NULL;
    DWORD last = size - patSize;

    // Scan halaman demi halaman (4KB), skip yang non-committed.
    const DWORD PAGE = 0x1000;
    for (DWORD i = 0; i <= last; ) {
        // Cek apakah pattern bisa muat di sini (cross-page check).
        if (!IsReadable(base + i, patSize)) {
            // Skip ke awal halaman berikutnya.
            DWORD nextPage = ((DWORD)(DWORD_PTR)(base + i) & ~(PAGE - 1)) + PAGE
                             - (DWORD)(DWORD_PTR)base;
            if (nextPage <= i) i++;
            else i = nextPage;
            continue;
        }
        if (memcmp(base + i, pattern, patSize) == 0)
            return base + i;
        i++;
    }
    return NULL;
}

static PBYTE FindStrZ(PBYTE base, DWORD size, const char* str)
{
    DWORD len = (DWORD)strlen(str) + 1;
    return FindBytes(base, size, (const BYTE*)str, len);
}

// `push imm32` (0x68 + 4-byte). Kembalikan occurrence ke-`nth`.
static PBYTE FindPushImm32_N(PBYTE base, DWORD size, DWORD imm, int nth)
{
    if (size < 5) return NULL;
    DWORD last = size - 5;
    int seen = 0;
    for (DWORD i = 0; i <= last; ++i) {
        if (!IsReadable(base + i, 5)) { i += 0x1000; continue; }
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
        if (!IsReadable(p, 3)) continue;
        if (p[0] == 0x55 && p[1] == 0x8B && p[2] == 0xEC)
            return p;
    }
    return NULL;
}

static bool PatchBytes(PBYTE addr, const BYTE* bytes, DWORD len)
{
    DWORD oldProt = 0, tmp = 0;
    if (!VirtualProtect(addr, len, PAGE_EXECUTE_READWRITE, &oldProt)) {
        Log("  VirtualProtect failed at %p err=%lu", addr, GetLastError());
        return false;
    }
    memcpy(addr, bytes, len);
    VirtualProtect(addr, len, oldProt, &tmp);
    FlushInstructionCache(GetCurrentProcess(), addr, len);
    return true;
}

// ---- Patch via string xref ---------------------------------------------
static bool PatchFuncByString(const char* tag, PBYTE base, DWORD size, const char* str)
{
    PBYTE strAddr = FindStrZ(base, size, str);
    if (!strAddr) return false;

    Log("[%s] string '%s' at %p (offset 0x%lX)",
        tag, str, strAddr, (DWORD)(strAddr - base));
    LogHex("at-strAddr-32B", strAddr, 32);

    static const BYTE STUB[] = { 0x31, 0xC0, 0xC3 }; // xor eax,eax; ret
    int xrefIdx = 0, patched = 0;
    while (xrefIdx < 16) {
        PBYTE pushSite = FindPushImm32_N(base, size, (DWORD)(DWORD_PTR)strAddr, xrefIdx);
        if (!pushSite) break;
        Log("[%s] xref #%d push at %p", tag, xrefIdx, pushSite);

        PBYTE funcStart = FindFuncStartBack(pushSite, 0x1000);
        if (!funcStart) {
            Log("[%s]   no `55 8B EC` prologue within 4KB above", tag);
        } else {
            Log("[%s]   prologue at %p (-%lu from xref)",
                tag, funcStart, (DWORD)(pushSite - funcStart));
            LogHex("orig-16B", funcStart, 16);
            if (PatchBytes(funcStart, STUB, sizeof(STUB))) {
                Log("[%s]   PATCHED", tag);
                patched++;
            }
        }
        xrefIdx++;
    }
    return patched > 0;
}

// ---- Worker: scan + patch (retry until found atau timeout) -------------
static DWORD WINAPI ScanWorker(LPVOID)
{
    Log("scan worker start");
    Sleep(100);

    PBYTE base = NULL;
    DWORD size = 0;
    if (!GetMainModuleRange(base, size)) {
        Log("FATAL: GetMainModuleRange failed");
        return 0;
    }
    Log("lostsaga.exe: base=%p size=%lu (0x%lX)", base, size, size);

    bool got_gameMon = false;
    bool got_exit23  = false;
    bool got_exit1   = false;

    // Retry sampai 120 attempts x 250ms = 30 detik max.
    for (int attempt = 0; attempt < 120; ++attempt) {
        if (!got_gameMon &&
            PatchFuncByString("GameMonErr", base, size, "GameMon Error : %d"))
            got_gameMon = true;

        if (!got_exit23 &&
            PatchFuncByString("ExitProg23", base, size, "ExitProgram - 23"))
            got_exit23 = true;

        if (!got_exit1 &&
            PatchFuncByString("ExitProg1", base, size, "ExitProgram - 1"))
            got_exit1 = true;

        if (got_gameMon && got_exit23 && got_exit1) {
            Log("all targets patched at attempt #%d", attempt);
            break;
        }

        // Log progress tiap 4 attempts (1 detik) supaya bisa liat polling.
        if ((attempt % 4) == 0) {
            Log("attempt #%d: gameMon=%d exit23=%d exit1=%d",
                attempt, got_gameMon, got_exit23, got_exit1);
        }
        Sleep(250);
    }

    Log("scan worker done. gameMon=%d exit23=%d exit1=%d",
        got_gameMon, got_exit23, got_exit1);
    return 0;
}

// ---- GG kill loop (parallel thread) ------------------------------------
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
        CreateThread(NULL, 0, ScanWorker, NULL, 0, NULL);
        CreateThread(NULL, 0, GGKillLoop, NULL, 0, NULL);
    }
    return TRUE;
}
