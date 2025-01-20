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

#include "../inc/relocatable.c"

#define DEFINE_STRING(name, value) char name[] = value "\0";

// Structure to hold function pointers and modules
typedef struct {
    HMODULE hUser32;
    HMODULE hKernel32;
    void (*MessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);
    void (*WinExec)(LPCSTR, UINT);
} FunctionTable;

// Initialize the FunctionTable
int InitFunctionTable(FunctionTable* table) {
    if (!table) return -1;

    PIC_LoadLibraryA LoadLibraryA;
    PIC_GetProcAddress GetProcAddress;
    InitRelocatable(&LoadLibraryA, &GetProcAddress);

    // Define required strings
    DEFINE_STRING(StringUser32Dll, "User32.dll");
    DEFINE_STRING(StringKernel32Dll, "Kernel32.dll");
    DEFINE_STRING(StringMessageBoxA, "MessageBoxA");
    DEFINE_STRING(StringWinExec, "WinExec");

    // Load User32.dll
    table->hUser32 = LoadLibraryA(StringUser32Dll);
    if (!table->hUser32) return -1;

    // Load Kernel32.dll
    table->hKernel32 = LoadLibraryA(StringKernel32Dll);
    if (!table->hKernel32) return -1;

    // Load MessageBoxA
    table->MessageBoxA = (void (*)(HWND, LPCSTR, LPCSTR, UINT))
        GetProcAddress(table->hUser32, StringMessageBoxA);
    if (!table->MessageBoxA) return -1;

    // Load WinExec
    table->WinExec = (void (*)(LPCSTR, UINT))
        GetProcAddress(table->hKernel32, StringWinExec);
    if (!table->WinExec) return -1;

    return 0;
}


void __main ();
void other_function(FunctionTable* table);

void __main () {
    // Define strings
    DEFINE_STRING(StringMessageBoxTitle, "Test Title");
    DEFINE_STRING(StringMessageBoxBody, "Test Body");

    // Initialize function table
    FunctionTable table;
    if (InitFunctionTable(&table) != 0) {
        // Initialization failed
        return;
    }

    // Call MessageBoxA
    if (table.MessageBoxA) {
        table.MessageBoxA(NULL, StringMessageBoxBody, StringMessageBoxTitle, MB_OK);
    }

    // Call other_function
    other_function(&table);
}

void other_function(FunctionTable* table) {
    DEFINE_STRING(StringCalc, "calc.exe");

    // Call WinExec
    if (table->WinExec) {
        table->WinExec(StringCalc, SW_SHOW);
    }
}
