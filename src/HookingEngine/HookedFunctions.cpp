#include "HookedFunctions.h"

#include <windows.h>

#include "HookingEngine.h"

// Example hook function for MessageBoxA
int WINAPI HookedMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
    //MessageBoxA(NULL, "Hooked!", "Hooked", MB_OK);
    OutputDebugStringW(L"From hooked MessageBoxA");
    // Call the original function using the trampoline
    Hook* hook = hookMap["MessageBoxA"];
    typedef int (WINAPI* MessageBoxAType)(HWND, LPCSTR, LPCSTR, UINT);
    MessageBoxAType originalMessageBoxA = (MessageBoxAType)hook->pTrampoline;
    return originalMessageBoxA(hWnd, lpText, lpCaption, uType);
}

// Example hook function for GetProcAddress
FARPROC WINAPI HookedGetProcAddress(HMODULE hModule, LPCSTR lpProcName) {
    // MessageBoxA(NULL, "GetProcAddress Hooked!", "Hooked", MB_OK);

     // Call the original function using the trampoline
    Hook* hook = hookMap["GetProcAddress"];
    typedef FARPROC(WINAPI* GetProcAddressType)(HMODULE, LPCSTR);
    GetProcAddressType originalGetProcAddress = (GetProcAddressType)hook->pTrampoline;
    return originalGetProcAddress(hModule, lpProcName);
}