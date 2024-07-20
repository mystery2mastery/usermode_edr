#include "RegisterDllLoad.h"

#include <windows.h>

#include "HookedFunctions.h"
#include "HookingEngine.h"

//typedef VOID(WINAPI* LDR_DLL_NOTIFICATION_FUNCTION)(ULONG, const LDR_DLL_NOTIFICATION_DATA*, PVOID);
//typedef NTSTATUS(WINAPI* LdrRegisterDllNotification_t)(ULONG, LDR_DLL_NOTIFICATION_FUNCTION, PVOID, PVOID*);
//typedef NTSTATUS(WINAPI* LdrUnregisterDllNotification_t)(PVOID);

LdrRegisterDllNotification_t LdrRegisterDllNotification = NULL;
LdrUnregisterDllNotification_t LdrUnregisterDllNotification = NULL;
PVOID cookie = NULL;

// Function to handle module loading and unloading notifications
VOID HandleModuleLoad(const WCHAR* moduleName) {
    std::wcout << L"Loaded DLL: " << moduleName << std::endl;
    OutputDebugStringW((L"Loaded DLL: " + std::wstring(moduleName)).c_str());

    // Example of setting up hooks for specific DLLs
    if (_wcsicmp(moduleName, L"user32.dll") == 0) {
        InstallHook("user32.dll", "MessageBoxA", HookedMessageBoxA);
        // Install hooks for other functions in user32.dll if needed
    }
}

VOID HandleModuleUnload(const WCHAR* moduleName) {
    std::wcout << L"Unloaded DLL: " << moduleName << std::endl;
    OutputDebugStringW((L"Unloaded DLL: " + std::wstring(moduleName)).c_str());

    // Cleanup hooks if necessary
    auto it = hookMap.find("MessageBoxA");
    if (it != hookMap.end()) {
        delete it->second;
        hookMap.erase(it);
    }
}

// DLL notification callback function
VOID CALLBACK DllNotification(ULONG NotificationReason, const LDR_DLL_NOTIFICATION_DATA* NotificationData, PVOID Context) {
    switch (NotificationReason) {
    case LDR_DLL_NOTIFICATION_REASON_LOADED:
        if (NotificationData && NotificationData->Loaded.BaseDllName) {
            HandleModuleLoad(NotificationData->Loaded.BaseDllName->Buffer);
        }
        break;
    case LDR_DLL_NOTIFICATION_REASON_UNLOADED:
        if (NotificationData && NotificationData->Unloaded.BaseDllName) {
            HandleModuleUnload(NotificationData->Unloaded.BaseDllName->Buffer);
        }
        break;
    default:
        break;
    }
}

// Function to register DLL notification
void RegisterDllNotification() {
    HMODULE hNtDll = GetModuleHandle(L"ntdll.dll");
    if (hNtDll) {
        LdrRegisterDllNotification = (LdrRegisterDllNotification_t)GetProcAddress(hNtDll, "LdrRegisterDllNotification");
        if (LdrRegisterDllNotification) {
            LdrRegisterDllNotification(0, DllNotification, NULL, &cookie);
        }
    }
}

// Function to unregister DLL notification
void UnregisterDllNotification() {
    if (cookie && LdrUnregisterDllNotification) {
        LdrUnregisterDllNotification(cookie);
    }
}


