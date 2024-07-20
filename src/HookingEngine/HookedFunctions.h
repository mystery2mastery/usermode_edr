#pragma once
#include <windows.h>

int WINAPI HookedMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
FARPROC WINAPI HookedGetProcAddress(HMODULE hModule, LPCSTR lpProcName);