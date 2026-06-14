#pragma once

// =====================================================================
// Offsets untuk LostSaga KR build 2025 (sumber: AOB scan publik).
//   nProtect Init Complete   AOB: "nProtect Error : %s:%s\n"
//   ExitProgram - 23         AOB: "ExitProgram - 23"
// Jika offset di bawah tidak cocok dengan build lostsaga.exe yang
// dipakai, game akan crash saat DetourFunction menulis ke alamat salah.
// =====================================================================

#define nInitStart2   0x0147CD76
#define nInitComplete 0x0147CF81

#define n23JE         0x021A7475
#define n23JMP        (n23JE + 0xF1)

#define n24           (n23JMP + 0x62)
#define n24JMP        (n24 + 0x225)
