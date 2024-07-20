//#include <string>
//#include <map>

//#include <windows.h>
//#include <winternl.h>

#include "HookingEngine.h"

#include "udis86/Include/udis86.h"


#pragma comment(lib, "ntdll.lib")


// Use the C++ map data structure
std::map<std::string, Hook*> hookMap;

static BYTE* g_trampolineBase = NULL;
static size_t g_currentOffset = 0;



// Function to disassemble and copy instructions ensuring full instructions are copied
uint8_t disassemble_and_copy(BYTE* inputBuffer, BYTE* copiedBytes) {
    ud_t ud_obj;
    uint8_t total_bytes = 0;

    // Initialize the disassembler
    ud_init(&ud_obj);
    ud_set_mode(&ud_obj, MODE); // Set the disassembler mode (32 or 64 bit)
    ud_set_input_buffer(&ud_obj, inputBuffer, MAX_STOLEN_BYTES); // Set input buffer to source (20 bytes to ensure we don't read past)
    ud_set_syntax(&ud_obj, UD_SYN_INTEL); // Set output syntax to Intel

    //printf("sizeof(INDIRECT_JMP): %d %d\n", sizeof(INDIRECT_JMP), JMPSIZE);
    while (total_bytes < JMPSIZE) {
        if (!ud_disassemble(&ud_obj)) {
            fprintf(stderr, "Failed to disassemble instruction\n");
            return 0;
        }
        //if (strcmp(ud_insn_asm(&ud_obj), "invalid")) {
            //insnCount = ud_insn_len(&ud_obj);
        printf("0x%016llx: %s %s\n", ud_insn_off(&ud_obj), ud_insn_hex(&ud_obj), ud_insn_asm(&ud_obj));
        //printf("%s\n", ud_lookup_mnemonic(ud_insn_mnemonic(&ud_obj))); // same output as ud_insn_asm(&ud_obj)
        total_bytes = total_bytes + ud_insn_len(&ud_obj);
        //}

        //insn_len = ud_insn_len(&ud_obj);
        //total_bytes += insn_len;
    }

    // Copy the disassembled instructions
    memcpy(copiedBytes, inputBuffer, total_bytes);

    return total_bytes;
}


// Function to install a hook
Hook* InstallHook(LPCSTR moduleName, LPCSTR functionName, LPVOID pHookFunction) {

    OutputDebugStringW(L"From InstallHook");
    if (!g_trampolineBase) {
        g_trampolineBase = (BYTE*)VirtualAlloc(NULL, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!g_trampolineBase) {
            printf("Failed to allocate memory for trampolines.\n");
            OutputDebugStringW(L"Failed to allocate memory for trampolines.");
            return NULL;
        }
    }

    if (g_currentOffset + TRAMPOLINE_INTERVAL > PAGE_SIZE) {
        printf("Exceeded trampoline memory limit.\n");
        OutputDebugStringW(L"Exceeded trampoline memory limit.");
        return NULL;
    }

    Hook* hook = (Hook*)malloc(sizeof(Hook));
    if (!hook) return NULL;

    // Assign pHookFunction to the hook
    hook->pHookFunction = (BYTE*)pHookFunction;

    // Get the address of the target function
    hook->pOriginalFunction = (BYTE*)GetProcAddress(GetModuleHandleA(moduleName), functionName);
    if (!hook->pOriginalFunction) {
        free(hook);
        return NULL;
    }





    //printf("POriginal: %p, jmpBack: %p\n", hook->pOriginalFunction, jmpBack);

    uint8_t countCopiedBytes = disassemble_and_copy(hook->pOriginalFunction, hook->copiedBytes);
    hook->countCopiedBytes = countCopiedBytes;
    printf("count of copied bytes: %d\n", countCopiedBytes);

    int i = 0;
    while (i < countCopiedBytes)
    {
        printf("%02X ", *(hook->copiedBytes + i));
        i++;
    }
    printf("\n%d\n", i);



    //// Save the original bytes (14 bytes for 64-bit)
    ////memcpy(hook->stolenBytes, hook->pOriginalFunction, 14);
    ////uint8_t countCopiedBytes = disassemble_and_copy(hook->pOriginalFunction, hook->copiedBytes, jmpCount, mode);
    ////hook->countCopiedBytes = countCopiedBytes;

    //// Allocate memory for the trampoline
    //hook->pTrampoline = (BYTE*)VirtualAlloc(NULL, countCopiedBytes + JMPSIZE + 8, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    //if (!hook->pTrampoline) {
    //    free(hook);
    //    return NULL;
    //}

    // Calculate the trampoline address
    hook->pTrampoline = g_trampolineBase + g_currentOffset;
    printf("g_trampolineBase: %p, offset: %X, pTrampoline: %p\n", g_trampolineBase, g_currentOffset, hook->pTrampoline);
    g_currentOffset += TRAMPOLINE_INTERVAL;



    // Copy 'copied bytes' to the trampoline
    memcpy(hook->pTrampoline, hook->copiedBytes, countCopiedBytes);


    JMP_BACK jmpBackStruct;
    // jmpBackStruct.address = (UINT64)jmpBack;
     //jmpBackStruct.opcode0 = 0xFF;
    printf("pHook: %p\n", hook->pHookFunction);
    jmpBackStruct = { (UINT64)hook->pHookFunction , 0xFF, 0x25, 0xFFFFFFF2 };

    BYTE* jmpBack = hook->pOriginalFunction - 8;



    // Jump back from Trampoline to after bytes in Original function
    BYTE* jmpFront = hook->pTrampoline + countCopiedBytes;
    JMP_FRONT jmpFrontStruct;
    jmpFrontStruct = { 0xFF, 0x25, 0x00000000, (UINT64)(hook->pOriginalFunction + countCopiedBytes) };

    memcpy(jmpFront, &jmpFrontStruct, sizeof(jmpFrontStruct));

    printf("pOriginal: %p, afterOriginal: %p\n", hook->pOriginalFunction, (hook->pOriginalFunction + countCopiedBytes));
    printf("after pTrampoline: %p\n", hook->pTrampoline + countCopiedBytes);





    //// Add a JMP from the trampoline to the original function after the stolen bytes
    //DWORD64 originalFuncAfterBytes = (DWORD64)hook->pOriginalFunction + countCopiedBytes;
    //BYTE trampolineJump[JMPSIZE] = {
    //    0x48, 0xB8, // mov rax, ...
    //    0, 0, 0, 0, 0, 0, 0, 0, // address placeholder
    //    0xFF, 0xE0  // jmp rax
    //};
    //memcpy(trampolineJump + 2, &originalFuncAfterBytes, 8);
    //memcpy(hook->pTrampoline + countCopiedBytes, trampolineJump, JMPSIZE);

    //printf("pOriginal: %p\n", hook->pOriginalFunction);
    //i = 0;
    //while (i < countCopiedBytes + JMPSIZE)
    //{
    //    printf("%02X ", *(hook->pTrampoline + i));
    //    i++;
    //}
    //printf("\n%d\n", i);

    //getchar();

    // Write the JMP to the hook function
    DWORD oldProtect;
    VirtualProtect(jmpBack, sizeof(jmpBackStruct), PAGE_EXECUTE_READWRITE, &oldProtect);
    //DWORD64 hookFuncAddr = (DWORD64)pHookFunction;
    //BYTE hookJump[JMPSIZE] = {
    //    0x48, 0xB8, // mov rax, ...
    //    0, 0, 0, 0, 0, 0, 0, 0, // address placeholder
    //    0xFF, 0xE0  // jmp rax
    //};
    //memcpy(hookJump + 2, &hookFuncAddr, 8);
    //memcpy(hook->pOriginalFunction, hookJump, JMPSIZE);
    //VirtualProtect(hook->pOriginalFunction, JMPSIZE, PAGE_EXECUTE_READ, &oldProtect);

    memcpy(jmpBack, &jmpBackStruct, sizeof(jmpBackStruct));

    // getchar();

     // Store the hook in the map
    hookMap[functionName] = hook;

    return hook;
}

// Function to remove a hook
void RemoveHook(Hook* hook) {
    if (!hook) return;

    // Restore the original bytes
    DWORD oldProtect;
    VirtualProtect(hook->pOriginalFunction, hook->countCopiedBytes, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(hook->pOriginalFunction, hook->copiedBytes, hook->countCopiedBytes);
    VirtualProtect(hook->pOriginalFunction, hook->countCopiedBytes, oldProtect, &oldProtect);

    // Free the trampoline memory
    VirtualFree(hook->pTrampoline, 0, MEM_RELEASE);

    // Remove the hook from the map
    std::string key(reinterpret_cast<char*>(hook->pOriginalFunction));
    hookMap.erase(key);

    free(hook);
    printf("%s hook released successfully\n", key.c_str());
}

// Function to cleanup hooks if needed
void CleanupHooks() {
    for (auto& hook : hookMap) {
        delete hook.second;
    }
    hookMap.clear();
}