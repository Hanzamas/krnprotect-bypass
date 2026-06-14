#include <windows.h>
#include <string.h>
#include <stdio.h>
#include "lib/CTools.h"

// =====================================================================
// Proxy DLL untuk Lost Saga.
// Drop file ini sebagai `xinput1_3.dll` di folder game; rename DLL asli
// menjadi `xinput1_3_org.dll`. Semua fungsi XInput di-forward ke DLL
// asli sehingga gamepad tetap berfungsi.
//
// DllMain men-spawn thread bypass yang:
//   1. Mencari & mem-patch fungsi nProtect/exit di lostsaga.exe via
//      AOB (Array Of Bytes) string scan -- tidak butuh offset hardcoded.
//   2. Terus-menerus terminate process GameGuard.des supaya GG tidak
//      berhasil melakukan validasi.
//
// LOG: ditulis ke `bypass.log` di folder game (working directory).
// =====================================================================

#pragma comment(linker, "/export:XInputGetState=xinput1_3_org.XInputGetState,@2")
#pragma comment(linker, "/export:XInputSetState=xinput1_3_org.XInputSetState,@3")
#pragma comment(linker, "/export:XInputGetCapabilities=xinput1_3_org.XInputGetCapabilities,@4")
#pragma comment(linker, "/export:XInputEnable=xinput1_3_org.XInputEnable,@5")
#pragma comment(linker, "/export:XInputGetDSoundAudioDeviceGuids=xinput1_3_org.XInputGetDSoundAudioDeviceGuids,@6")
#pragma comment(linker, "/export:XInputGetBatteryInformation=xinput1_3_org.XInputGetBatteryInformation,@7")
#pragma comment(linker, "/export:XInputGetKeystroke=xinput1_3_org.XInputGetKeystroke,@8")
#pragma comment(linker, "/export:XInputGetStateEx=xinput1_3_org.XInputGetStateEx,@100")

// ---- Logger sederhana (write to file) ----------------------------------
static CRITICAL_SECTION g_logLock;
static bool g_logInit = false;

static void LogInit()
{
    if (!g_logInit) {
        InitializeCriticalSection(&g_logLock);
        g_logInit = true;
        // truncate log on first init
        FILE* f = fopen("bypass.log", "w");
        if (f) {
            fprintf(f, "=== bypass.log started ===\n");
            fclose(f);
        }
    }
}

static void Log(const char* fmt, ...)
{
    LogInit();
    EnterCriticalSection(&g_logLock);
    FILE* f = fopen("bypass.log", "a");
    if (f) {
        SYSTEMTIME st;
        GetLocalTime(&st);
        fprintf(f, "[%02d:%02d:%02d.%03d] ",
                st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
        va_list args;
        va_start(args, fmt);
        vfprintf(f, fmt, args);
        va_end(args);
        fprintf(f, "\n");
        fclose(f);
    }
    LeaveCriticalSection(&g_logLock);
}

// ---- Helper: ambil rentang module utama (lostsaga.exe) ------------------
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

// ---- Helper: cari pola byte di rentang memori ---------------------------
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

// ---- Helper: cari instruksi `push imm32` (0x68 XX XX XX XX) -------------
static PBYTE FindPushImm32(PBYTE base, DWORD size, DWORD imm)
{
    if (size < 5) return NULL;
    DWORD last = size - 5;
    for (DWORD i = 0; i <= last; ++i) {
        if (base[i] == 0x68 && *(DWORD*)(base + i + 1) == imm)
            return base + i;
    }
    return NULL;
}

// ---- Helper: jalan mundur cari prologue fungsi (55 8B EC) --------------
static PBYTE FindFuncStartBack(PBYTE addr, DWORD maxBack)
{
    for (DWORD i = 0; i < maxBack; ++i) {
        PBYTE p = addr - i;
        if (p[0] == 0x55 && p[1] == 0x8B && p[2] == 0xEC)
            return p;
    }
    return NULL;
}

// ---- Helper: patch byte dengan handle proteksi memory -------------------
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

// ---- Bypass via string xref --------------------------------------------
static bool BypassByStringXref(const char* name, PBYTE base, DWORD size,
                               const BYTE* strBytes, DWORD strLen)
{
    Log("[%s] scanning string (%lu bytes)...", name, strLen);
    PBYTE strAddr = FindBytes(base, size, strBytes, strLen);
    if (!strAddr) {
        Log("[%s] string NOT FOUND", name);
        return false;
    }
    Log("[%s] string at %p", name, strAddr);

    PBYTE pushSite = FindPushImm32(base, size, (DWORD)(DWORD_PTR)strAddr);
    if (!pushSite) {
        Log("[%s] no `push imm32` xref to string", name);
        return false;
    }
    Log("[%s] push xref at %p", name, pushSite);

    PBYTE funcStart = FindFuncStartBack(pushSite, 0x800);
    if (!funcStart) {
        Log("[%s] no prologue 55 8B EC within 2KB", name);
        return false;
    }
    Log("[%s] func prologue at %p (offset -%lu from xref)",
        name, funcStart, (DWORD)(pushSite - funcStart));

    // Log original first 8 bytes of function for forensic.
    Log("[%s] orig: %02X %02X %02X %02X %02X %02X %02X %02X",
        name, funcStart[0], funcStart[1], funcStart[2], funcStart[3],
              funcStart[4], funcStart[5], funcStart[6], funcStart[7]);

    static const BYTE STUB[] = { 0x31, 0xC0, 0xC3 }; // xor eax,eax; ret
    bool ok = PatchBytes(funcStart, STUB, sizeof(STUB));
    Log("[%s] patch %s", name, ok ? "OK" : "FAILED");
    return ok;
}

// "nProtect Error : %s:%s\n\0"
static const BYTE STR_NPROT_ERR[] = {
    0x6E,0x50,0x72,0x6F,0x74,0x65,0x63,0x74,0x20,
    0x45,0x72,0x72,0x6F,0x72,0x20,0x3A,0x20,
    0x25,0x73,0x3A,0x25,0x73,0x0A,0x00
};

// "ExitProgram - 23\0"
static const BYTE STR_EXITPROG23[] = {
    0x45,0x78,0x69,0x74,0x50,0x72,0x6F,0x67,0x72,0x61,0x6D,0x20,0x2D,0x20,0x32,0x33,0x00
};

static DWORD WINAPI NProtectBypass(LPVOID)
{
    Log("bypass thread start");

    CTools tools;
    Sleep(50); // give image a moment to fully map

    PBYTE base = NULL;
    DWORD size = 0;
    if (!GetMainModuleRange(base, size)) {
        Log("FATAL: GetMainModuleRange failed");
    } else {
        Log("main module: base=%p size=%lu (0x%lX)", base, size, size);
        BypassByStringXref("nProtect", base, size, STR_NPROT_ERR, sizeof(STR_NPROT_ERR));
        BypassByStringXref("ExitProg23", base, size, STR_EXITPROG23, sizeof(STR_EXITPROG23));
    }

    Log("entering kill-loop for GameGuard.des");
    int killed = 0;
    while (1) {
        if (tools.TerminateProcessByName("GameGuard.des")) {
            killed++;
            if (killed <= 5 || (killed % 50) == 0)
                Log("killed GameGuard.des (count=%d)", killed);
        }
        Sleep(20);
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID /*reserved*/)
{
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        Log("DllMain DLL_PROCESS_ATTACH (hModule=%p)", hModule);
        CreateThread(NULL, 0, NProtectBypass, NULL, 0, NULL);
    }
    return TRUE;
}
