#pragma once
#include <string>
#include <map>

#include <windows.h>

// Maximum number of bytes to steal
#define MAX_STOLEN_BYTES 20

#define PAGE_SIZE 0x1000
#define TRAMPOLINE_INTERVAL 0x20

#if defined(_WIN64) || defined(__x86_64__) || defined(__ppc64__)
#define MODE 64
#define JMPSIZE 6
#else
uint8_t mode = 32;
uint8_t jmpCount = 7;
#endif

struct INDIRECT_JMP {   //FF25 00000000 => jmp [rip+6]
    UINT8 opcode0;  // FF
    UINT8 opcode1;  // 25
    UINT32 operand; // 00000000
};

// Ensure all structs within this block are packed without padding
#pragma pack(push, 1) // Ensure the struct is packed without padding 
struct JMP_BACK {   // 8+6 = 14 bytes needed
    UINT64 address;     // absolute address in little endian 00 00 00 00 00 00 00 00
    //INDIRECT_JMP jmp; //FF25 F2FFFFFF => jmp [rip-14] => jmp [rip-(8+6)]
    UINT8 opcode0;  // FF
    UINT8 opcode1;  // 25
    UINT32 operand; // F2FFFFFF
};


struct JMP_FRONT {
    UINT8 opcode0;  // FF
    UINT8 opcode1;  // 25
    UINT32 operand; // 00000000
    UINT64 address;
};
#pragma pack(pop) // Restore the previous packing alignment

typedef struct HOOK {
    BYTE* pOriginalFunction;
    BYTE* pHookFunction;
    BYTE* pTrampoline;
    unsigned short countCopiedBytes;
    BYTE copiedBytes[MAX_STOLEN_BYTES];
} Hook;

// Use the C++ map data structure
// Declared as global variable in .cpp file
extern std::map<std::string, Hook*> hookMap;

uint8_t disassemble_and_copy(BYTE* inputBuffer, BYTE* copiedBytes);
Hook* InstallHook(LPCSTR moduleName, LPCSTR functionName, LPVOID pHookFunction);
void RemoveHook(Hook* hook);
void CleanupHooks();