#pragma once 
#include <Windows.h>
#include <stdio.h>
#include <time.h>
#include "config.h"
#include "peb-lookup.h"
#define FLG_HEAP_ENABLE_TAIL_CHECK   0x10
#define FLG_HEAP_ENABLE_FREE_CHECK   0x20
#define FLG_HEAP_VALIDATE_PARAMETERS 0x40
#define NT_GLOBAL_FLAG_DEBUGGED (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS)


BOOL CheckDebugPresentBit()
{
        BOOL isDebuggerPresent = FALSE;

    // Get a pointer to the PEB
#ifdef _WIN64
    PEB* pPeb = (PEB*)__readgsqword(0x60);
#else
    PEB* pPeb = (PEB*)__readfsdword(0x30);
#endif

    if (pPeb->BeingDebugged) {
        isDebuggerPresent = TRUE;
    }

    return isDebuggerPresent;
}

BOOL CheckNTGlobalFlag()
{
    BOOL isDebuggerPresent = FALSE;

    // Get a pointer to the PEB
    #ifndef _WIN64
    PPEB pPeb = (PPEB)__readfsdword(0x30);
    DWORD dwNtGlobalFlag = *(PDWORD)((PBYTE)pPeb + 0x68);
    #else
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    DWORD dwNtGlobalFlag = *(PDWORD)((PBYTE)pPeb + 0xBC);
    #endif // _WIN64
 
    if (dwNtGlobalFlag & NT_GLOBAL_FLAG_DEBUGGED)
        isDebuggerPresent = TRUE;
        return isDebuggerPresent;
}


#undef FLG_HEAP_ENABLE_TAIL_CHECK
#undef FLG_HEAP_ENABLE_FREE_CHECK
#undef FLG_HEAP_VALIDATE_PARAMETERS
#undef NT_GLOBAL_FLAG_DEBUGGED
