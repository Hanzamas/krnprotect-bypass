#include <windows.h>
#include <string.h>
#include <stdio.h>
#include "lib/CTools.h"

// =====================================================================
// Proxy DLL untuk Lost Saga (build 12861).
// Drop sebagai `xinput1_3.dll`; rename DLL asli jadi `xinput1_3_org.dll`.
//
// lostsaga.exe ter-pack: strings baru muncul setelah unpacker decrypt.
// Strategi:
//   - Worker: scan + patch tiap 250ms, retry sampai semua patch atau timeout
//   - Cari xref via `push imm32` (0x68) DAN `mov reg, imm32` (B8-BF)
//   - Untuk fungsi target: patch dengan JMP rel32 ke epilogue fungsi
//     sendiri (`5D C3` atau `5D C2 NN NN`) supaya stack restored benar.
//   - Patch banyak exit reasons: ExitProgram - 1 sampai 30.
//   - Plus: kill loop GameGuard.des
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

// Dump ASCII strings (>=4 chars) di rentang.
static void DumpStringsIn(PBYTE start, DWORD len)
{
    DWORD i = 0;
    while (i < len) {
        // mulai string?
        if (start[i] >= 0x20 && start[i] < 0x7F) {
            DWORD begin = i;
            while (i < len && start[i] >= 0x20 && start[i] < 0x7F) i++;
            DWORD slen = i - begin;
            if (slen >= 4) {
                char buf[128] = {0};
                DWORD copy = slen < sizeof(buf) - 1 ? slen : sizeof(buf) - 1;
                memcpy(buf, start + begin, copy);
                Log("  str@+%lu (%lu): %s", begin, slen, buf);
            }
        }
        i++;
    }
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

// ---- SEH-safe helpers --------------------------------------------------
static int SafeMemcmp(const void* a, const void* b, size_t n)
{
    __try { return memcmp(a, b, n); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return 1; }
}

// Walk per region. Skip non-committed/no-access. Optional: only executable.
static PBYTE FindBytesRegion(PBYTE rangeStart, DWORD rangeSize,
                             const BYTE* pattern, DWORD patSize,
                             bool execOnly)
{
    if (rangeSize < patSize) return NULL;
    PBYTE rangeEnd = rangeStart + rangeSize;
    PBYTE p = rangeStart;
    while (p + patSize <= rangeEnd) {
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery(p, &mbi, sizeof(mbi))) { p += 0x1000; continue; }
        PBYTE regionEnd = (PBYTE)mbi.BaseAddress + mbi.RegionSize;
        if (regionEnd > rangeEnd) regionEnd = rangeEnd;

        bool readable = (mbi.State == MEM_COMMIT) &&
                        ((mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) == 0);
        bool executable = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                          PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
        if (!readable || (execOnly && !executable)) {
            p = regionEnd;
            continue;
        }

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
    return FindBytesRegion(base, size, (const BYTE*)str, len, false);
}

// Cari xref code: `push imm32` (0x68 + 4-byte) ATAU `mov reg, imm32` (B8-BF + 4-byte).
// Kembalikan posisi instruksi (untuk push) atau awal mov (untuk mov+push).
static PBYTE FindCodeXref_N(PBYTE base, DWORD size, DWORD imm, int nth)
{
    PBYTE rangeEnd = base + size;
    PBYTE p = base;
    int seen = 0;

    while (p + 5 <= rangeEnd) {
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery(p, &mbi, sizeof(mbi))) { p += 0x1000; continue; }
        PBYTE regionEnd = (PBYTE)mbi.BaseAddress + mbi.RegionSize;
        if (regionEnd > rangeEnd) regionEnd = rangeEnd;

        bool readable = (mbi.State == MEM_COMMIT) &&
                        ((mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) == 0);
        bool executable = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                          PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
        if (!readable || !executable) { p = regionEnd; continue; }

        DWORD scanCount = (DWORD)(regionEnd - p);
        if (scanCount >= 5) {
            DWORD lim = scanCount - 5 + 1;
            for (DWORD i = 0; i < lim; ++i) {
                __try {
                    BYTE op = p[i];
                    bool match = false;
                    // push imm32
                    if (op == 0x68) match = true;
                    // mov eax/ecx/edx/ebx/esp/ebp/esi/edi, imm32
                    else if (op >= 0xB8 && op <= 0xBF) match = true;
                    if (match && *(DWORD*)(p + i + 1) == imm) {
                        if (seen == nth) return p + i;
                        seen++;
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER) { break; }
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
        __except (EXCEPTION_EXECUTE_HANDLER) { return NULL; }
    }
    return NULL;
}

// Scan forward cari epilogue `5D C3` (pop ebp; ret) atau `5D C2 NN NN` (ret imm16).
static PBYTE FindFunctionEpilogue(PBYTE start, DWORD maxScan)
{
    for (DWORD i = 0; i < maxScan; ++i) {
        PBYTE p = start + i;
        __try {
            if (p[0] == 0x5D && (p[1] == 0xC3 || p[1] == 0xC2))
                return p;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) { return NULL; }
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

static bool PatchJumpRel32(PBYTE from, PBYTE to)
{
    INT32 rel = (INT32)((PBYTE)to - (from + 5));
    BYTE patch[5] = { 0xE9, 0, 0, 0, 0 };
    memcpy(patch + 1, &rel, 4);
    return PatchBytes(from, patch, 5);
}

// ---- Patch via string xref ---------------------------------------------
// Verbose: kalau true, log full detail. Kalau false, log ringkas (cocok untuk
// scan banyak ExitProgram-N).
static bool PatchFuncByString(const char* tag, PBYTE base, DWORD size,
                              const char* str, bool verbose)
{
    PBYTE strAddr = FindStrZ(base, size, str);
    if (!strAddr) return false;

    if (verbose) {
        Log("[%s] string '%s' at %p (offset 0x%lX)",
            tag, str, strAddr, (DWORD)(strAddr - base));
        LogHex("at-strAddr-32B", strAddr, 32);
    }

    int xrefIdx = 0, patched = 0;
    while (xrefIdx < 16) {
        PBYTE xrefSite = FindCodeXref_N(base, size, (DWORD)(DWORD_PTR)strAddr, xrefIdx);
        if (!xrefSite) break;
        if (verbose)
            Log("[%s] xref #%d (op=%02X) at %p", tag, xrefIdx, xrefSite[0], xrefSite);

        PBYTE funcStart = FindFuncStartBack(xrefSite, 0x1000);
        if (!funcStart) {
            if (verbose) Log("[%s]   no `55 8B EC` prologue within 4KB above", tag);
        } else {
            PBYTE epilogue = FindFunctionEpilogue(funcStart + 3, 0x2000);
            if (epilogue) {
                if (verbose) {
                    Log("[%s]   prologue %p, epilogue %p (size=%lu)",
                        tag, funcStart, epilogue, (DWORD)(epilogue - funcStart));
                    LogHex("epilogue-bytes", epilogue, 8);
                }
                if (PatchJumpRel32(funcStart, epilogue)) {
                    Log("[%s]   PATCHED jmp %p -> %p", tag, funcStart, epilogue);
                    patched++;
                }
            } else {
                if (verbose) Log("[%s]   no epilogue found, fallback xor-eax-ret", tag);
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

// ---- Worker: scan + patch (retry sampai timeout) -----------------------
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

    // Track patched targets to avoid double work.
    bool got_gameMon = false;
    bool got_npr     = false;
    bool got_ggFail  = false;
    bool got_exitN[64] = {0}; // index by N (1..63)

    for (int attempt = 0; attempt < 240; ++attempt) {
        // Patch SEMUA ExitProgram - N variants (1..50).
        for (int n = 1; n <= 50; ++n) {
            if (got_exitN[n]) continue;
            char buf[32];
            sprintf(buf, "ExitProgram - %d", n);
            char tag[32];
            sprintf(tag, "ExitProg%d", n);
            if (PatchFuncByString(tag, base, size, buf, true))
                got_exitN[n] = true;
        }

        if (!got_gameMon &&
            PatchFuncByString("GameMonErr", base, size, "GameMon Error : %d", true))
            got_gameMon = true;

        if (!got_npr &&
            PatchFuncByString("nProtect", base, size, "[nProtect] - ", true))
            got_npr = true;

        // Sekali saja: dump strings di region 1KB dekat ExitProg23 untuk
        // discovery string lain (debug only, attempt #2 supaya unpacker selesai).
        if (attempt == 2) {
            PBYTE eg23 = FindStrZ(base, size, "ExitProgram - 23");
            if (eg23) {
                Log("dumping strings around ExitProgram-23 region:");
                DumpStringsIn(eg23 - 0x80, 0x400);
            }
        }

        // Hitung total exit patched.
        int exitPatched = 0;
        for (int n = 1; n <= 50; ++n) if (got_exitN[n]) exitPatched++;

        if ((attempt % 8) == 0) {
            Log("attempt #%d: gameMon=%d npr=%d exitN_patched=%d",
                attempt, got_gameMon, got_npr, exitPatched);
        }

        Sleep(250);
    }

    Log("scan worker timeout");
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
        CreateThread(NULL, 0, ScanWorker, NULL, 0, NULL);
        CreateThread(NULL, 0, GGKillLoop, NULL, 0, NULL);
    }
    return TRUE;
}
