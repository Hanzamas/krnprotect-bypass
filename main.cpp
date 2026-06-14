#include <windows.h>
#include <string.h>
#include <stdio.h>
#include "lib/CTools.h"

// =====================================================================
// Proxy DLL untuk Lost Saga (build 12861).
// Drop sebagai `xinput1_3.dll`; rename DLL asli jadi `xinput1_3_org.dll`.
//
// Offset diadopsi dari LSLog/ls-addon-main update 18 Sep 2024.
// Kita gunakan teknik DetourFunction klasik:
//   1. Jump dari InitStart -> InitComplete (skip nProtect init)
//   2. Replace JE di Exit23 dengan JMP (force skip exit path 23)
//   3. Replace JE di Exit24 dengan JMP (force skip exit path 24)
//   4. Kill GameGuard.des / GameMon.des / GameMon64.des
//
// Source offsets (relatif ke module base lostsaga.exe):
//   InitStart    = base + 0x105EF66
//   InitComplete = base + 0x105F171
//   Exit23       = base + 0x1D86CF5
//   Exit23JMP    = Exit23 + 0xF1
//   Exit24       = base + 0x1D870E5
//   Exit24JMP    = Exit24 + 0x225
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

// ---- Logger sederhana --------------------------------------------------
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

// ---- DetourFunction: tulis JMP rel32 dari `from` ke `to` (5 byte) -------
static bool DetourFunction(PBYTE from, DWORD to, DWORD len)
{
    DWORD oldProt = 0, tmp = 0;
    if (!VirtualProtect(from, len, PAGE_EXECUTE_READWRITE, &oldProt))
        return false;

    INT32 rel = (INT32)(to - ((DWORD)(DWORD_PTR)from + 5));
    from[0] = 0xE9; // JMP rel32
    *(INT32*)(from + 1) = rel;
    // Sisa byte (jika len > 5) di-NOP supaya tidak ada instruksi rusak.
    for (DWORD i = 5; i < len; ++i) from[i] = 0x90;

    VirtualProtect(from, len, oldProt, &tmp);
    FlushInstructionCache(GetCurrentProcess(), from, len);
    return true;
}

// ---- Bypass thread (mirip LSLog) ---------------------------------------
static DWORD WINAPI NProtectBypass(LPVOID)
{
    Log("bypass thread start");
    Sleep(150); // beri waktu lostsaga ter-map

    DWORD base = (DWORD)(DWORD_PTR)GetModuleHandleA("lostsaga.exe");
    if (!base) base = (DWORD)(DWORD_PTR)GetModuleHandleA(NULL);
    Log("lostsaga.exe base = %08lX", base);

    // Offset hasil RE LSLog 18 Sep 2024.
    DWORD InitStart    = base + 0x105EF66;
    DWORD InitComplete = base + 0x105F171;
    DWORD Exit23       = base + 0x1D86CF5;
    DWORD Exit23JMP    = Exit23 + 0xF1;
    DWORD Exit24       = base + 0x1D870E5;
    DWORD Exit24JMP    = Exit24 + 0x225;

    Log("targets: InitStart=%08lX -> InitComplete=%08lX", InitStart, InitComplete);
    Log("targets: Exit23=%08lX -> Exit23JMP=%08lX",       Exit23,    Exit23JMP);
    Log("targets: Exit24=%08lX -> Exit24JMP=%08lX",       Exit24,    Exit24JMP);

    CTools tools;
    int loopCount = 0;
    while (true) {
        DetourFunction((PBYTE)InitStart, InitComplete, 5);
        DetourFunction((PBYTE)Exit23,    Exit23JMP,    5);
        DetourFunction((PBYTE)Exit24,    Exit24JMP,    5);

        // Kill semua process anti-cheat
        tools.TerminateProcessByName("GameGuard.des");
        tools.TerminateProcessByName("GameMon.des");
        tools.TerminateProcessByName("GameMon64.des");

        loopCount++;
        if (loopCount == 1 || loopCount == 50 || (loopCount % 500) == 0)
            Log("bypass loop iteration #%d", loopCount);

        Sleep(20);
    }
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        Log("DllMain DLL_PROCESS_ATTACH (hModule=%p)", hModule);
        CreateThread(NULL, 0, NProtectBypass, NULL, 0, NULL);
    }
    return TRUE;
}
