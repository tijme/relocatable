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
void __main () {
    // Initialize Relocatable
    PIC_LoadLibraryA LoadLibraryA;
    PIC_GetProcAddress GetProcAddress;
    InitRelocatable(&LoadLibraryA, &GetProcAddress);

    // Load `User32.dll`
    char StringUser32Dll[] = {'U', 's', 'e', 'r', '3', '2', '.', 'd', 'l', 'l', 0x0 };
    HMODULE User32 = LoadLibraryA(StringUser32Dll);

    // Get `MessageBoxA` address
    char StringMessageBoxA[] = {'M', 'e', 's', 's', 'a', 'g', 'e', 'B', 'o', 'x', 'A', 0x0 };
    void (*MessageBoxA)() = (void (*)) GetProcAddress(User32, StringMessageBoxA);

    // Pop message box
    char StringMessageBoxTitle[] = {'T', 'e', 's', 't', ' ', 'T', 'i', 't', 'l', 'e', 0x0 };
    char StringMessageBoxBody[] = {'T', 'e', 's', 't', ' ', 'B', 'o', 'd', 'y', 0x0 };
    MessageBoxA(NULL, StringMessageBoxTitle, StringMessageBoxBody, MB_OK);
}