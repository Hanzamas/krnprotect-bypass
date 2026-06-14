#include <windows.h>
#include <string.h>
#include <stdio.h>
#include "lib/CTools.h"

// =====================================================================
// Proxy DLL untuk Lost Saga (build 12861).
// Drop sebagai `xinput1_3.dll`; rename DLL asli jadi `xinput1_3_org.dll`.
//
// lostsaga.exe ter-pack: strings (incl. error message GG) baru ada
// SETELAH unpacker decrypt section .rdata. Jadi kita retry scan sampai
// strings muncul.
//
// Strategi:
//   - Worker: scan + patch tiap 200ms, retry sampai semua patch atau timeout
//   - SEH wrapper untuk handle bila page belum committed
//   - Walk per region (VirtualQuery per region, bukan per byte) supaya cepat
//   - Paralel: kill loop GameGuard.des
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

// ---- SEH-safe memcmp ---------------------------------------------------
static int SafeMemcmp(const void* a, const void* b, size_t n)
{
    __try {
        return memcmp(a, b, n);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return 1; // tidak match -> lanjut iterasi
    }
}

// ---- Pattern utilities (region-aware, fast) ----------------------------
// Walk per region (VirtualQuery per region) supaya tidak panggil syscall
// 48 juta kali. Skip region yang non-committed/no-access.
static PBYTE FindBytesRegion(PBYTE rangeStart, DWORD rangeSize,
                             const BYTE* pattern, DWORD patSize)
{
    if (rangeSize < patSize) return NULL;
    PBYTE rangeEnd = rangeStart + rangeSize;
    PBYTE p = rangeStart;

    while (p + patSize <= rangeEnd) {
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery(p, &mbi, sizeof(mbi))) {
            p += 0x1000;
            continue;
        }
        PBYTE regionEnd = (PBYTE)mbi.BaseAddress + mbi.RegionSize;
        if (regionEnd > rangeEnd) regionEnd = rangeEnd;

        bool readable = (mbi.State == MEM_COMMIT) &&
                        ((mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) == 0);
        if (!readable) {
            p = regionEnd;
            continue;
        }

        // Scan dalam region. Pattern dapat melewati boundary region jika
        // berdekatan; untuk simpel kita batasi tidak melewati regionEnd.
        DWORD scanCount = (DWORD)(regionEnd - p);
        if (scanCount >= patSize) {
            DWORD lim = scanCount - patSize + 1;
            for (DWORD i = 0; i < lim; ++i) {
                if (SafeMemcmp(p + i, pattern, patSize) == 0)
                    return p + i;
            }
        }
        p = regionEnd;
    }
    return NULL;
}

static PBYTE FindStrZ(PBYTE base, DWORD size, const char* str)
{
    DWORD len = (DWORD)strlen(str) + 1;
    return FindBytesRegion(base, size, (const BYTE*)str, len);
}

// `push imm32` (0x68 + 4-byte). Kembalikan occurrence ke-`nth` (region-aware).
static PBYTE FindPushImm32_N(PBYTE rangeStart, DWORD rangeSize, DWORD imm, int nth)
{
    PBYTE rangeEnd = rangeStart + rangeSize;
    PBYTE p = rangeStart;
    int seen = 0;

    while (p + 5 <= rangeEnd) {
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery(p, &mbi, sizeof(mbi))) {
            p += 0x1000;
            continue;
        }
        PBYTE regionEnd = (PBYTE)mbi.BaseAddress + mbi.RegionSize;
        if (regionEnd > rangeEnd) regionEnd = rangeEnd;

        bool readable = (mbi.State == MEM_COMMIT) &&
                        ((mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) == 0);
        bool executable = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                          PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
        if (!readable || !executable) {
            p = regionEnd;
            continue;
        }

        DWORD scanCount = (DWORD)(regionEnd - p);
        if (scanCount >= 5) {
            DWORD lim = scanCount - 5 + 1;
            for (DWORD i = 0; i < lim; ++i) {
                __try {
                    if (p[i] == 0x68 && *(DWORD*)(p + i + 1) == imm) {
                        if (seen == nth) return p + i;
                        seen++;
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    break; // region rusak, pindah
                }
            }
        }
        p = regionEnd;
    }
    return NULL;
}

static PBYTE FindFuncStartBack(PBYTE addr, DWORD maxBack)
{
    for (DWORD i = 0; i < maxBack; ++i) {
        PBYTE p = addr - i;
        __try {
            if (p[0] == 0x55 && p[1] == 0x8B && p[2] == 0xEC)
                return p;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return NULL;
        }
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

// Scan forward dari `start` cari epilogue `5D C3` (pop ebp; ret) atau
// `5D C2 NN NN` (pop ebp; ret imm16). Itu ujung natural fungsi -- stack
// di-restore dengan benar tanpa kita perlu tahu calling convention.
static PBYTE FindFunctionEpilogue(PBYTE start, DWORD maxScan)
{
    for (DWORD i = 0; i < maxScan; ++i) {
        PBYTE p = start + i;
        __try {
            if (p[0] == 0x5D && (p[1] == 0xC3 || p[1] == 0xC2))
                return p;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return NULL;
        }
    }
    return NULL;
}

// Tulis JMP rel32 dari `from` ke `to` (5 byte: E9 + 4-byte offset).
static bool PatchJumpRel32(PBYTE from, PBYTE to)
{
    INT32 rel = (INT32)((PBYTE)to - (from + 5));
    BYTE patch[5] = { 0xE9, 0, 0, 0, 0 };
    memcpy(patch + 1, &rel, 4);
    return PatchBytes(from, patch, 5);
}

// ---- Patch via string xref ---------------------------------------------
static bool PatchFuncByString(const char* tag, PBYTE base, DWORD size, const char* str)
{
    PBYTE strAddr = FindStrZ(base, size, str);
    if (!strAddr) return false;

    Log("[%s] string '%s' at %p (offset 0x%lX)",
        tag, str, strAddr, (DWORD)(strAddr - base));
    LogHex("at-strAddr-32B", strAddr, 32);

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

            // Cari epilogue fungsi (`5D C3` atau `5D C2 NN NN`) ke depan
            // dalam range max 8KB. Jika ada, JMP dari prologue ke epilogue
            // -- stack dibersihkan oleh epilogue natural fungsi.
            PBYTE epilogue = FindFunctionEpilogue(funcStart + 3, 0x2000);
            if (epilogue) {
                Log("[%s]   epilogue at %p (+%lu from prologue)",
                    tag, epilogue, (DWORD)(epilogue - funcStart));
                LogHex("epilogue-bytes", epilogue, 8);
                if (PatchJumpRel32(funcStart, epilogue)) {
                    Log("[%s]   PATCHED (jmp prologue -> epilogue)", tag);
                    patched++;
                }
            } else {
                // Fallback: xor eax,eax; ret (cdecl-friendly tapi rusak utk stdcall)
                Log("[%s]   no epilogue found, fallback to xor-eax-ret", tag);
                static const BYTE STUB[] = { 0x31, 0xC0, 0xC3 };
                if (PatchBytes(funcStart, STUB, sizeof(STUB))) {
                    Log("[%s]   PATCHED (xor eax,eax; ret)", tag);
                    patched++;
                }
            }
        }
        xrefIdx++;
    }
    return patched > 0;
}

// ---- Worker: scan + patch (retry sampai found atau timeout) ------------
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

    // Retry sampai 240 attempts x 250ms = 60 detik max.
    for (int attempt = 0; attempt < 240; ++attempt) {
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
            Log("ALL targets patched at attempt #%d", attempt);
            break;
        }

        if ((attempt % 8) == 0) {
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
