#include <windows.h>
#include <string.h>
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
// =====================================================================

#pragma comment(linker, "/export:XInputGetState=xinput1_3_org.XInputGetState,@2")
#pragma comment(linker, "/export:XInputSetState=xinput1_3_org.XInputSetState,@3")
#pragma comment(linker, "/export:XInputGetCapabilities=xinput1_3_org.XInputGetCapabilities,@4")
#pragma comment(linker, "/export:XInputEnable=xinput1_3_org.XInputEnable,@5")
#pragma comment(linker, "/export:XInputGetDSoundAudioDeviceGuids=xinput1_3_org.XInputGetDSoundAudioDeviceGuids,@6")
#pragma comment(linker, "/export:XInputGetBatteryInformation=xinput1_3_org.XInputGetBatteryInformation,@7")
#pragma comment(linker, "/export:XInputGetKeystroke=xinput1_3_org.XInputGetKeystroke,@8")
#pragma comment(linker, "/export:XInputGetStateEx=xinput1_3_org.XInputGetStateEx,@100")

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

// ---- Helper: cari pertama kali pola byte di rentang memori --------------
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
    if (!VirtualProtect(addr, len, PAGE_EXECUTE_READWRITE, &oldProt))
        return false;
    memcpy(addr, bytes, len);
    VirtualProtect(addr, len, oldProt, &tmp);
    FlushInstructionCache(GetCurrentProcess(), addr, len);
    return true;
}

// ---- Bypass via string xref --------------------------------------------
// Cari string `str` di memory module, cari instruksi `push <strAddr>` yang
// merefer ke string itu, lalu walk back ke prologue fungsi, dan replace
// fungsi dengan `xor eax,eax; ret` (return 0 = "no error").
static bool BypassByStringXref(PBYTE base, DWORD size,
                               const BYTE* strBytes, DWORD strLen)
{
    PBYTE strAddr = FindBytes(base, size, strBytes, strLen);
    if (!strAddr) return false;

    PBYTE pushSite = FindPushImm32(base, size, (DWORD)(DWORD_PTR)strAddr);
    if (!pushSite) return false;

    PBYTE funcStart = FindFuncStartBack(pushSite, 0x800);
    if (!funcStart) return false;

    static const BYTE STUB[] = { 0x31, 0xC0, 0xC3 }; // xor eax,eax; ret
    return PatchBytes(funcStart, STUB, sizeof(STUB));
}

// ---- AOB string -- "nProtect Error : %s:%s\n\0" -------------------------
static const BYTE STR_NPROT_ERR[] = {
    0x6E,0x50,0x72,0x6F,0x74,0x65,0x63,0x74,0x20,
    0x45,0x72,0x72,0x6F,0x72,0x20,0x3A,0x20,
    0x25,0x73,0x3A,0x25,0x73,0x0A,0x00
};

// ---- AOB string -- "ExitProgram - 23\0" ---------------------------------
static const BYTE STR_EXITPROG23[] = {
    0x45,0x78,0x69,0x74,0x50,0x72,0x6F,0x67,0x72,0x61,0x6D,0x20,0x2D,0x20,0x32,0x33,0x00
};

// ---- Thread bypass utama -----------------------------------------------
static DWORD WINAPI NProtectBypass(LPVOID)
{
    CTools tools;

    // Tunggu sebentar supaya seluruh image lostsaga.exe ter-map sempurna.
    Sleep(50);

    PBYTE base = NULL;
    DWORD size = 0;
    if (GetMainModuleRange(base, size)) {
        BypassByStringXref(base, size, STR_NPROT_ERR, sizeof(STR_NPROT_ERR));
        BypassByStringXref(base, size, STR_EXITPROG23, sizeof(STR_EXITPROG23));
    }

    while (1) {
        tools.TerminateProcessByName("GameGuard.des");
        Sleep(20);
    }
}

// ---- DllMain ------------------------------------------------------------
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID /*reserved*/)
{
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        CreateThread(NULL, 0, NProtectBypass, NULL, 0, NULL);
    }
    return TRUE;
}
