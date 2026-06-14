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

// ---- IAT hook (Import Address Table) -----------------------------------
// Handler pengganti ExitProcess: log lalu sleep forever supaya thread caller
// tidak pernah kembali ke logic exit. Process tetap hidup.
typedef VOID (WINAPI *PFN_ExitProcess)(UINT);
typedef BOOL (WINAPI *PFN_TerminateProcess)(HANDLE, UINT);

static LONG WINAPI MyVEH(PEXCEPTION_POINTERS info)
{
    EXCEPTION_RECORD* rec = info->ExceptionRecord;
    CONTEXT* ctx = info->ContextRecord;

    const char* name = "UNKNOWN";
    switch (rec->ExceptionCode) {
        case EXCEPTION_ACCESS_VIOLATION:    name = "ACCESS_VIOLATION";    break;
        case EXCEPTION_ILLEGAL_INSTRUCTION: name = "ILLEGAL_INSTRUCTION"; break;
        case EXCEPTION_STACK_OVERFLOW:      name = "STACK_OVERFLOW";      break;
        case EXCEPTION_BREAKPOINT:          name = "BREAKPOINT";          break;
        case EXCEPTION_INT_DIVIDE_BY_ZERO:  name = "DIV_BY_ZERO";         break;
        case 0xE06D7363:                    name = "C++_EXCEPTION";       break;
    }

    Log("VEH: code=0x%08lX (%s) at %p", rec->ExceptionCode, name, rec->ExceptionAddress);
    if (rec->ExceptionCode == EXCEPTION_ACCESS_VIOLATION && rec->NumberParameters >= 2) {
        const char* op = rec->ExceptionInformation[0] == 0 ? "READ" :
                         rec->ExceptionInformation[0] == 1 ? "WRITE" : "EXEC";
        Log("  AV: %s @ %p", op, (void*)rec->ExceptionInformation[1]);
    }
    Log("  EIP=%p ESP=%p EBP=%p EAX=%p ECX=%p EDX=%p",
        (void*)ctx->Eip, (void*)ctx->Esp, (void*)ctx->Ebp,
        (void*)ctx->Eax, (void*)ctx->Ecx, (void*)ctx->Edx);

    // Dump 16 bytes di EIP supaya kita liat instruksi yang crash.
    PBYTE eip = (PBYTE)ctx->Eip;
    __try {
        Log("  bytes@EIP: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X",
            eip[0],eip[1],eip[2],eip[3],eip[4],eip[5],eip[6],eip[7],
            eip[8],eip[9],eip[10],eip[11],eip[12],eip[13],eip[14],eip[15]);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        Log("  bytes@EIP: <unreadable>");
    }

    // Tetap forward ke handler default supaya WerFault juga jalan.
    return EXCEPTION_CONTINUE_SEARCH;
}

// Kill-switch: kalau file `bypass_off.txt` ada di folder kerja, hook
// auto-bypass dan biarkan exit normal. Berguna saat user mau menutup game.
static bool ShouldAllowExit()
{
    DWORD attr = GetFileAttributesA("bypass_off.txt");
    return attr != INVALID_FILE_ATTRIBUTES;
}

static volatile bool g_exitBlocked = false;

static VOID WINAPI MyExitProcess(UINT uExitCode)
{
    if (ShouldAllowExit()) {
        Log("MyExitProcess: bypass_off.txt found, allowing exit code=%u", uExitCode);
        ExitProcess(uExitCode);
    }
    Log("!!! MyExitProcess intercepted, uExitCode=%u (BLOCKING; create bypass_off.txt to allow)", uExitCode);
    g_exitBlocked = true;
    // Sleep tapi periodik cek kill-switch supaya user bisa unblock kapan saja.
    while (1) {
        Sleep(2000);
        if (ShouldAllowExit()) {
            Log("MyExitProcess: kill-switch detected, releasing");
            ExitProcess(uExitCode);
        }
    }
}

static BOOL WINAPI MyTerminateProcess(HANDLE hProc, UINT uExitCode)
{
    if (hProc == GetCurrentProcess() || hProc == (HANDLE)-1) {
        if (ShouldAllowExit()) {
            Log("MyTerminateProcess: bypass_off.txt found, allowing self-terminate");
            return TerminateProcess(hProc, uExitCode);
        }
        Log("!!! MyTerminateProcess on self intercepted, code=%u (BLOCKING)", uExitCode);
        g_exitBlocked = true;
        while (1) {
            Sleep(2000);
            if (ShouldAllowExit()) {
                Log("MyTerminateProcess: kill-switch detected, releasing");
                return TerminateProcess(hProc, uExitCode);
            }
        }
    }
    // Pass-through untuk handle lain (mis. GameGuard.des).
    return TerminateProcess(hProc, uExitCode);
}

// Hook 1 entry IAT di module hMod yang import nama `funcName` dari `dllName`.
static bool HookIAT(HMODULE hMod, const char* dllName, const char* funcName, void* newFunc)
{
    PBYTE base = (PBYTE)hMod;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    DWORD iatRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!iatRVA) return false;

    PIMAGE_IMPORT_DESCRIPTOR imp = (PIMAGE_IMPORT_DESCRIPTOR)(base + iatRVA);
    while (imp->Name) {
        const char* impName = (const char*)(base + imp->Name);
        if (_stricmp(impName, dllName) == 0) {
            PIMAGE_THUNK_DATA orig = imp->OriginalFirstThunk
                ? (PIMAGE_THUNK_DATA)(base + imp->OriginalFirstThunk)
                : (PIMAGE_THUNK_DATA)(base + imp->FirstThunk);
            PIMAGE_THUNK_DATA iat = (PIMAGE_THUNK_DATA)(base + imp->FirstThunk);

            for (; orig->u1.AddressOfData; orig++, iat++) {
                if (IMAGE_SNAP_BY_ORDINAL(orig->u1.Ordinal)) continue;
                PIMAGE_IMPORT_BY_NAME imn = (PIMAGE_IMPORT_BY_NAME)(base + orig->u1.AddressOfData);
                if (strcmp((const char*)imn->Name, funcName) == 0) {
                    DWORD oldProt = 0, tmp = 0;
                    if (!VirtualProtect(&iat->u1.Function, sizeof(DWORD_PTR),
                                        PAGE_READWRITE, &oldProt)) return false;
                    iat->u1.Function = (DWORD_PTR)newFunc;
                    VirtualProtect(&iat->u1.Function, sizeof(DWORD_PTR), oldProt, &tmp);
                    Log("IAT hook: %s!%s -> %p OK", dllName, funcName, newFunc);
                    return true;
                }
            }
        }
        imp++;
    }
    return false;
}

// Pasang hook untuk fungsi exit yang kemungkinan dipanggil.
static void InstallExitHooks(HMODULE hMain)
{
    // ---- Cara 1: IAT hook di lostsaga.exe ----
    bool any = false;
    if (HookIAT(hMain, "kernel32.dll", "ExitProcess",      (void*)MyExitProcess)) any = true;
    if (HookIAT(hMain, "KERNEL32.dll", "ExitProcess",      (void*)MyExitProcess)) any = true;
    if (HookIAT(hMain, "kernel32.dll", "TerminateProcess", (void*)MyTerminateProcess)) any = true;
    if (HookIAT(hMain, "KERNEL32.dll", "TerminateProcess", (void*)MyTerminateProcess)) any = true;
    if (HookIAT(hMain, "ntdll.dll",    "RtlExitUserProcess", (void*)MyExitProcess)) any = true;
    if (!any) {
        Log("IAT hook: no ExitProcess imports found in lostsaga.exe (game probably uses CRT exit)");
    }

    // ---- Cara 2: Juga hook IAT di module CRT (msvcr100/71) -------------
    // CRT's exit() ujungnya call ExitProcess via msvcr*'s own import.
    HMODULE crt100 = GetModuleHandleA("msvcr100.dll");
    if (crt100) {
        if (HookIAT(crt100, "kernel32.dll", "ExitProcess", (void*)MyExitProcess) ||
            HookIAT(crt100, "KERNEL32.dll", "ExitProcess", (void*)MyExitProcess)) {
            Log("IAT hook in msvcr100.dll OK");
        } else {
            Log("IAT hook in msvcr100.dll: not found");
        }
        HookIAT(crt100, "kernel32.dll", "TerminateProcess", (void*)MyTerminateProcess);
        HookIAT(crt100, "KERNEL32.dll", "TerminateProcess", (void*)MyTerminateProcess);
    }
    HMODULE crt71 = GetModuleHandleA("msvcr71.dll");
    if (crt71) {
        HookIAT(crt71, "kernel32.dll", "ExitProcess", (void*)MyExitProcess);
        HookIAT(crt71, "KERNEL32.dll", "ExitProcess", (void*)MyExitProcess);
    }

    // ---- Cara 3: Patch langsung kernel32!ExitProcess via Copy-On-Write -
    // Ini catch-all: any caller di proses ini yang panggil ExitProcess
    // dengan resolusi langsung ke kernel32 (tanpa lewat IAT) tetap di-block.
    // Patch kena di private copy kernel32 milik proses ini saja.
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    if (k32) {
        FARPROC pExit = GetProcAddress(k32, "ExitProcess");
        if (pExit) {
            // Tulis JMP rel32 ke MyExitProcess di byte ke-0 fungsi ExitProcess.
            // 5 byte: E9 XX XX XX XX
            INT32 rel = (INT32)((PBYTE)MyExitProcess - ((PBYTE)pExit + 5));
            BYTE patch[5] = { 0xE9, 0, 0, 0, 0 };
            memcpy(patch + 1, &rel, 4);
            DWORD oldProt = 0, tmp = 0;
            if (VirtualProtect(pExit, 5, PAGE_EXECUTE_READWRITE, &oldProt)) {
                memcpy(pExit, patch, 5);
                VirtualProtect(pExit, 5, oldProt, &tmp);
                FlushInstructionCache(GetCurrentProcess(), pExit, 5);
                Log("kernel32!ExitProcess patched (JMP -> %p) at %p", MyExitProcess, pExit);
            } else {
                Log("kernel32!ExitProcess patch FAILED: VirtualProtect err=%lu", GetLastError());
            }
        }
    }
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

    // Register VEH ASAP supaya tangkap setiap exception di lostsaga.exe.
    AddVectoredExceptionHandler(1, MyVEH);
    Log("VEH registered");

    // Pasang hook IAT untuk ExitProcess / TerminateProcess SEDINI mungkin
    // supaya semua exit path ke kernel32 di-block, regardless of source.
    InstallExitHooks((HMODULE)base);

    // Track patched targets to avoid double work.
    bool got_gameMon = false;
    bool got_npr     = false;
    bool got_ggFail  = false;
    bool got_exitN[64] = {0}; // index by N (1..63)

    for (int attempt = 0; attempt < 240; ++attempt) {
        // PATCHES DISABLED -- "ExitProgram - N" ternyata DEBUG MARKERS dalam
        // fungsi init normal (string diikuti oleh nama class kayak
        // "ioApplication::OnXxx"), bukan exit reasons. Patch fungsi-fungsi
        // ini malah merusak alur init game. Kita biarkan ExitProcess hook
        // & VEH yang menangani crash/exit; patches dimatikan.
        //
        // for (int n = 1; n <= 50; ++n) { ... }
        // PatchFuncByString("GameMonErr", ...);
        // PatchFuncByString("nProtect",   ...);

        if ((attempt % 8) == 0) {
            Log("attempt #%d: scan worker idle (patches disabled, waiting)",
                attempt);
        }
        Sleep(2000);
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
