/**
 * GNU General Public License, version 2.0.
 *
 * Copyright (c) 2025 Tijme Gommers (@tijme).
 *
 * This source code file is part of Relocatable. Relocatable is 
 * licensed under # GNU General Public License, version 2.0, and 
 * you are free to use, modify, and distribute this file under 
 * its terms. However, any modified versions of this file must 
 * include this same license and copyright notice.
 */

/**
 * Include Relocatable helper functions.
 * 
 * This must be the first statement/code/include in this file, as this file
 * contains the first instructions of the shellcode that will ensure that 
 * the `__main` function is called correctly upon running the shellcode.
 */
#include "../inc/relocatable.c"

#define DEFINE_STRING(name, value) char name[] = value "\0";

/**
 * The main function of your shellcode.
 * 
 * Using `InitRelocatable`, two Windows API functions are at your disposal.
 * Using these two functions, you can further utilize the Windows API.
 * - HMODULE LoadLibraryA([in] LPCSTR lpLibFileName);
 * - FARPROC GetProcAddress([in] HMODULE hModule, [in] LPCSTR lpProcName);
 * 
 * Remember to define variables on the stack in Position Independent Code,
 * thus you need to specify `char* a = 'A'` as `char a[] = { 'A', 0x0 }`.
 */
void __main ();
void* LoadFunction(const char* libraryName, const char* functionName);
void other_function();

void __main () {
    // Define strings
    DEFINE_STRING(StringUser32Dll, "User32.dll");
    DEFINE_STRING(StringMessageBoxA, "MessageBoxA");
    DEFINE_STRING(StringMessageBoxTitle, "Test Title");
    DEFINE_STRING(StringMessageBoxBody, "Test Body");


    void (*MessageBoxA)(HWND, LPCSTR, LPCSTR, UINT) = (void (*)(HWND, LPCSTR, LPCSTR, UINT))
        LoadFunction(StringUser32Dll, StringMessageBoxA);

    if (MessageBoxA) {
        MessageBoxA(NULL, StringMessageBoxBody, StringMessageBoxTitle, MB_OK);
    }

    other_function();
}

void* LoadFunction(const char* libraryName, const char* functionName) {
    PIC_LoadLibraryA LoadLibraryA;
    PIC_GetProcAddress GetProcAddress;
    InitRelocatable(&LoadLibraryA, &GetProcAddress);

    HMODULE library = LoadLibraryA(libraryName);
    if (!library) {
        return NULL;
    }

    return (void*)GetProcAddress(library, functionName);
}

void other_function(){
    DEFINE_STRING(StringKernel32Dll, "Kernel32.dll");
    DEFINE_STRING(StringWinExec, "WinExec");
    DEFINE_STRING(StringCalc, "calc.exe");

    void (*WinExec)(LPCSTR, UINT) = (void (*)(LPCSTR, UINT))
        LoadFunction(StringKernel32Dll, StringWinExec);

    if (WinExec) {
        WinExec(StringCalc, SW_SHOW);
    }
}
