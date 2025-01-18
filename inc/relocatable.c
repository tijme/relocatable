/**
 * Mozilla Public License (MPL) Version 2.0.
 * 
 * Copyright (c) 2025 Tijme Gommers (@tijme).
 * 
 * This source code file is part of Relocatable. Relocatable is 
 * licensed under Mozilla Public License (MPL) Version 2.0, and 
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
 * Definitions of the two primary functions we use to utilize the entire Windows API.
 */
typedef HMODULE (*PIC_LoadLibraryA)(LPCSTR lpLibFileName);
typedef FARPROC (*PIC_GetProcAddress)(HMODULE hModule, LPCSTR lpProcName);

/**
 * The first instruction in the shellcode must jump to the main function.
 */
void prefix() {
    __asm__("call __main");
}

/**
 * Get current Process Environment Block.
 *
 * @return PEB* The current PEB.
 */
void* PIC_NtGetPeb() {
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
LDR_DATA_TABLE_ENTRY *PIC_GetDataTableEntry(const LIST_ENTRY *ptr) {
    int listEntryOffset = offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
    return (LDR_DATA_TABLE_ENTRY *)((BYTE *)ptr - listEntryOffset);
}

/**
 * Retrieve the address of a function from a module in memory by matching
 * both the module name and the function name.
 * 
 * @param moduleName The name of the module to search for.
 * @param functionName The name of the function to search for.
 * @return void* The address of the function if found, NULL otherwise.
 */
void* PIC_PreliminaryGetProcAddress(char moduleName[], char functionName[]) {
    PEB *peb = PIC_NtGetPeb();
    LIST_ENTRY *first = peb->Ldr->InMemoryOrderModuleList.Flink;
    LIST_ENTRY *ptr = first;

    do {
        LDR_DATA_TABLE_ENTRY *dte = PIC_GetDataTableEntry(ptr);
        ptr = ptr->Flink;

        BYTE *baseAddress = (BYTE *) dte->DllBase;
        if (!baseAddress) continue;

        IMAGE_DOS_HEADER *dosHeader = (IMAGE_DOS_HEADER *)baseAddress;
        IMAGE_NT_HEADERS *ntHeaders = (IMAGE_NT_HEADERS *)(baseAddress + dosHeader->e_lfanew);
        DWORD iedRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (!iedRVA) continue;

        IMAGE_EXPORT_DIRECTORY *ied = (IMAGE_EXPORT_DIRECTORY *)(baseAddress + iedRVA);

        // Compare module name byte by byte
        char *currentModuleName = (char *)(baseAddress + ied->Name);

        // Trim any extra padding spaces or null characters
        int i = 0;
        while (moduleName[i] != '\0' && currentModuleName[i] != '\0') {
            if (moduleName[i] != currentModuleName[i]) {
                break;
            }
            i++;
        }

        // Ensure both strings are the same length and match exactly
        if (moduleName[i] != '\0' || currentModuleName[i] != '\0') {
            continue; // Skip if lengths don't match or strings are different
        }

        DWORD *nameRVAs = (DWORD *)(baseAddress + ied->AddressOfNames);
        for (DWORD i = 0; i < ied->NumberOfNames; ++i) {
            char *currentFunctionName = (char *)(baseAddress + nameRVAs[i]);
            
            // Compare function name byte by byte
            bool functionMatch = true;
            for (int j = 0; functionName[j] != '\0' || currentFunctionName[j] != '\0'; j++) {
                if (functionName[j] != currentFunctionName[j]) {
                    functionMatch = false;
                    break;
                }
            }

            if (functionMatch) {
                WORD ordinal = ((WORD *)(baseAddress + ied->AddressOfNameOrdinals))[i];
                DWORD functionRVA = ((DWORD *)(baseAddress + ied->AddressOfFunctions))[ordinal];
                return (void *)(baseAddress + functionRVA);
            }
        }
    } while (ptr != first);
 
    return NULL;
}

void InitRelocatable(PIC_LoadLibraryA* LoadLibraryA, PIC_GetProcAddress* GetProcAddress) {
    // Resolve LoadLibraryA and GetProcAddress (assuming `Kernel32.dll` is loaded)
    char StringKernel32Dll[] = {'K', 'E', 'R', 'N', 'E', 'L', '3', '2', '.', 'd', 'l', 'l', 0x0 };
    char StringLoadLibraryA[] = {'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0x0 };
    char StringGetProcAddress[] = {'G', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's', 0x0 };
    
    *LoadLibraryA = (PIC_LoadLibraryA) PIC_PreliminaryGetProcAddress(StringKernel32Dll, StringLoadLibraryA);
    *GetProcAddress = (PIC_GetProcAddress) PIC_PreliminaryGetProcAddress(StringKernel32Dll, StringGetProcAddress);
}