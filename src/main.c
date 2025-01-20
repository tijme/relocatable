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
 * Windows API.
 * 
 * Contains declarations for all of the functions, macro's & data types in the Windows API.
 * https://docs.microsoft.com/en-us/previous-versions//aa383749(v=vs.85)?redirectedfrom=MSDN
 */
#include <windows.h>

/**
 * A struct of module definitions you would like to use.
 */
struct ModuleTable {
    // Custom (add any module of your preference here)
    HMODULE hKernel32;
    HMODULE hUser32;
};

/**
 * A struct of function definitions you would like to use.
 */
struct FunctionTable {
    // Must always be present (these are initialized by Relocatable)
    HMODULE (*LoadLibraryA)(LPCSTR lpLibFileName);
    FARPROC (*GetProcAddress)(HMODULE hModule, LPCSTR lpProcName);

    // Custom (add any function of your preference here)
    void (*MessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);
    void (*WinExec)(LPCSTR, UINT);
};

/**
 * Include Relocatable helper functions.
 * 
 * This include must be used before any of your own code, as this file
 * contains the first instructions of the shellcode that will ensure that 
 * the `__main` function is called correctly upon running the shellcode.
 */
#include "../inc/relocatable.c"

/**
 * Populate the context tables with modules & functions you would like to use.
 * 
 * @param struct Relocatable* context A 'global' variable capturing Relocatable's entire context (loaded modules & functions)
 */
void PopulateTables(struct Relocatable* context) {
    // Define modules
    DEFINE_STRING(Kernel32ModuleName, "KERNEL32.dll");
    DEFINE_STRING(User32ModuleName, "USER32.dll");

    // Load modules
    context->modules.hKernel32 = context->functions.LoadLibraryA(Kernel32ModuleName);
    context->modules.hUser32 = context->functions.LoadLibraryA(User32ModuleName);

    // Define functions
    DEFINE_STRING(WinExecFunctionName, "WinExec");
    DEFINE_STRING(MessageBoxAFunctionName, "MessageBoxA");

    // Load functions
    context->functions.WinExec = (void (*)(LPCSTR, UINT)) context->functions.GetProcAddress(context->modules.hKernel32, WinExecFunctionName);
    context->functions.MessageBoxA = (void (*)(HWND, LPCSTR, LPCSTR, UINT)) context->functions.GetProcAddress(context->modules.hUser32, MessageBoxAFunctionName);
}

/**
 * The main function of your shellcode.
 * 
 * Using `InitializeRelocatable`, two Windows API functions are at your disposal.
 * Using these two functions, you can further utilize the Windows API.
 * - HMODULE context.functions.LoadLibraryA([in] LPCSTR lpLibFileName);
 * - FARPROC context.functions.GetProcAddress([in] HMODULE hModule, [in] LPCSTR lpProcName);
 */
void __main () {
    struct Relocatable context;
    InitializeRelocatable(&context);

    // Populate module & function tables with your own dependencies
    PopulateTables(&context);

    // Example to pop a message box
    DEFINE_STRING(MessageBoxTitle, "Test Title");
    DEFINE_STRING(MessageBoxBody, "Test Body");
    context.functions.MessageBoxA(NULL, MessageBoxBody, MessageBoxTitle, MB_OK);

    // Example to pop a calculator
    DEFINE_STRING(CalculatorBinary, "calc.exe");
    context.functions.WinExec(CalculatorBinary, SW_SHOW);
}

