#include <windows.h>
#include "lib/CFramework.h"
#include "lib/CTools.h"
#include "Offset.h"

// =====================================================================
// Proxy DLL: ditaruh sebagai `xinput1_3.dll` di folder game.
// DLL asli harus di-rename jadi `xinput1_3_org.dll` di folder yang sama.
// Semua export di-forward ke DLL asli supaya gamepad/XInput tetap jalan,
// sementara DllMain di bawah memicu thread bypass GameGuard.
// =====================================================================
#pragma comment(linker, "/export:XInputGetState=xinput1_3_org.XInputGetState,@2")
#pragma comment(linker, "/export:XInputSetState=xinput1_3_org.XInputSetState,@3")
#pragma comment(linker, "/export:XInputGetCapabilities=xinput1_3_org.XInputGetCapabilities,@4")
#pragma comment(linker, "/export:XInputEnable=xinput1_3_org.XInputEnable,@5")
#pragma comment(linker, "/export:XInputGetDSoundAudioDeviceGuids=xinput1_3_org.XInputGetDSoundAudioDeviceGuids,@6")
#pragma comment(linker, "/export:XInputGetBatteryInformation=xinput1_3_org.XInputGetBatteryInformation,@7")
#pragma comment(linker, "/export:XInputGetKeystroke=xinput1_3_org.XInputGetKeystroke,@8")
// Ordinal 100 (undocumented, dipakai beberapa game)
#pragma comment(linker, "/export:XInputGetStateEx=xinput1_3_org.XInputGetStateEx,@100")

static void NProtectBypass()
{
    CTools* Tools = new CTools();
    CFramework* Framework = new CFramework();
    while (1)
    {
        if (Tools->TerminateProcessByName("GameGuard.des")) {
            Framework->DetourFunction((PBYTE)nInitStart, (DWORD)nInitComplete, 5);
            Framework->DetourFunction((PBYTE)n23, (DWORD)n23JMP, 5);
            Framework->DetourFunction((PBYTE)n24, (DWORD)n24JMP, 5);
        }

        Sleep(20);
    }
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);

        CreateThread(nullptr, NULL, (LPTHREAD_START_ROUTINE)NProtectBypass, nullptr, NULL, nullptr);
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
