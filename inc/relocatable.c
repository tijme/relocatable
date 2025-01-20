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
 * Booleans.
 * 
 * Defines boolean types.
 * https://pubs.opengroup.org/onlinepubs/007904975/basedefs/stdbool.h.html
 */
#include <stdbool.h>

/**
 * Integers.
 * 
 * Defines macros that specify limits of integer types corresponding to types defined in other standard headers.
 * https://pubs.opengroup.org/onlinepubs/009696899/basedefs/stdint.h.html
 */
#include <stdint.h>

/**
 * Windows API.
 * 
 * Contains declarations for all of the functions, macro's & data types in the Windows API.
 * https://docs.microsoft.com/en-us/previous-versions//aa383749(v=vs.85)?redirectedfrom=MSDN
 */
#include <windows.h>

/**
 * Internal NT API's and data structures.
 * 
 * Helper library that contains NT API's and data structures for system services, security and identity.
 * https://docs.microsoft.com/en-us/windows/win32/api/winternl/
 */
#include <winternl.h>

/**
 * Helper Macro Functions
 */
#define DEFINE_STRING(name, value) char name[] = value "\0";

/**
 * The main struct that holds your modules & functions to be used.
 */
struct Relocatable {
    struct ModuleTable modules;
    struct FunctionTable functions;
};

/**
 * The first instruction in the shellcode must jump to the main function.
 */
void RelocatablePrefix() {
    __asm__("call __main");
}

/**
 * Get current Process Environment Block.
 *
 * @return PEB* The current PEB.
 */
void* RelocatableNtGetPeb() {
    #ifdef _M_X64
        return (void*) __readgsqword(0x60);
    #elif _M_IX86
        return (void*) __readfsdword(0x30);
    #else
        #error "This architecture is currently unsupported"
    #endif
}

/**
 * Retrieve the LDR_DATA_TABLE_ENTRY from a given LIST_ENTRY pointer.
 * 
 * @param ptr The LIST_ENTRY pointer to retrieve the data table entry from.
 * @return LDR_DATA_TABLE_ENTRY* The corresponding LDR_DATA_TABLE_ENTRY pointer.
 */
LDR_DATA_TABLE_ENTRY *RelocatableGetDataTableEntry(const LIST_ENTRY *ptr) {
    return (LDR_DATA_TABLE_ENTRY *)((uint8_t *)ptr - offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));
}

/**
 * Compare two null-terminated strings.
 * 
 * @param a First string.
 * @param b Second string.
 * @return true if the strings are equal, false otherwise.
 */
bool RelocatableStrCmp(const char *a, const char *b) {
    while (*a && (*a == *b)) {
        a++, b++;
    }
    
    return *a == *b;
}

/**
 * Retrieve the address of a function from a module in memory by matching
 * both the module name and the function name.
 * 
 * This function and its dependencies are inspired on ShellcodeStdio 
 * from @jackullrich: https://github.com/jackullrich/ShellcodeStdio/tree/master
 * 
 * @param moduleName The name of the module to search for.
 * @param functionName The name of the function to search for.
 * @return void* The address of the function if found, NULL otherwise.
 */
void* RelocatablePreliminaryGetProcAddress(const char *moduleName, const char *functionName) {
    PEB *peb = RelocatableNtGetPeb();
    LIST_ENTRY *first = peb->Ldr->InMemoryOrderModuleList.Flink;
    LIST_ENTRY *ptr = first;

    do {
        LDR_DATA_TABLE_ENTRY *dte = RelocatableGetDataTableEntry(ptr);
        ptr = ptr->Flink;

        uint8_t *base = (uint8_t *)dte->DllBase;
        if (!base) continue;

        IMAGE_DOS_HEADER *dosHdr = (IMAGE_DOS_HEADER *)base;
        IMAGE_NT_HEADERS *ntHdrs = (IMAGE_NT_HEADERS *)(base + dosHdr->e_lfanew);
        DWORD expDirRVA = ntHdrs->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (!expDirRVA) continue;

        IMAGE_EXPORT_DIRECTORY *expDir = (IMAGE_EXPORT_DIRECTORY *)(base + expDirRVA);
        if (!RelocatableStrCmp(moduleName, (char *)(base + expDir->Name))) continue;

        DWORD *nameRVAs = (DWORD *)(base + expDir->AddressOfNames);
        WORD *ordinals = (WORD *)(base + expDir->AddressOfNameOrdinals);
        DWORD *funcRVAs = (DWORD *)(base + expDir->AddressOfFunctions);

        for (DWORD i = 0; i < expDir->NumberOfNames; i++) {
            if (RelocatableStrCmp(functionName, (char *)(base + nameRVAs[i]))) {
                return (void *)(base + funcRVAs[ordinals[i]]);
            }
        }
    } while (ptr != first);
 
    return NULL;
}

/**
 * Initialize Relocatable by resolving the two main Windows APIs it depends on.
 * 
 * @param struct Relocatable* context A 'global' variable capturing Relocatable's entire context (loaded modules & functions)
 */
void InitializeRelocatable(struct Relocatable* context) {
    // Resolve LoadLibraryA and GetProcAddress (assuming `KERNEL32.dll` is loaded)
    DEFINE_STRING(Kernel32ModuleName, "KERNEL32.dll");
    DEFINE_STRING(LoadLibraryAFunctionName, "LoadLibraryA");
    DEFINE_STRING(GetProcAddressFunctionName, "GetProcAddress");

    context->functions.LoadLibraryA = (HMODULE (*)(LPCSTR lpLibFileName)) RelocatablePreliminaryGetProcAddress(Kernel32ModuleName, LoadLibraryAFunctionName);
    context->functions.GetProcAddress = (FARPROC (*)(HMODULE hModule, LPCSTR lpProcName)) RelocatablePreliminaryGetProcAddress(Kernel32ModuleName, GetProcAddressFunctionName);
}