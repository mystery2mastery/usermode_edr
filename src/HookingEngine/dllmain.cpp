// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

#include <stdio.h>
#include <tlhelp32.h>

#include "HookingEngine.h"
#include "HookedFunctions.h"
#include "RegisterDllLoad.h"

// Function to check already loaded modules and install hooks if necessary
void InstallHooksForLoadedModules() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        MODULEENTRY32 moduleEntry;
        moduleEntry.dwSize = sizeof(moduleEntry);
        OutputDebugString(L"Already Loaded - Start <-----------------\n");
        if (Module32First(hSnapshot, &moduleEntry)) {
            do {                
                HandleModuleLoad(moduleEntry.szModule);
            } while (Module32Next(hSnapshot, &moduleEntry));
        }
        OutputDebugString(L"Already Loaded - End <------------------\n");
        CloseHandle(hSnapshot);
    }
}


// DLL entry point
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hinstDLL);
        OutputDebugString(L"Injected DLL: DLL_PROCESS_ATTACH\n");
        //RegisterDllNotification();
        // Set up hooks for already loaded DLLs
        //SetupHooks();
        printf("Process Attach");

        // Check already loaded modules and install hooks if necessary
        InstallHooksForLoadedModules();

        // Register for DLL notifications
        RegisterDllNotification();

        break;
    case DLL_PROCESS_DETACH:
        OutputDebugString(L"Injected DLL: DLL_PROCESS_DETACH\n");
        UnregisterDllNotification();
        
        // Cleanup hooks if needed
        CleanupHooks();

        printf("Process Detach");
        break;
    }
    return TRUE;
}
