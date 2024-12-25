#pragma once
#include <Windows.h>
#include <stdio.h>
#include "./config.h"
#include "peb-lookup.h"
#include "func-prototype.h"
const char * VMmanufactures_list[] = {"TCGTCGTCGTCG", "Microsoft Hv", "VMwareVMware", "VBoxVBoxVBox"};
const char * HyperVRegKey[] = {"SOFTWARE", "Microsoft", "Virtual Machine", "Guest", "Parameters"};



const int VMlist_length = 6;

EXTERN_C BOOL OpenKeyRecursive(HKEY currentKey, PHKEY saveKey, char** subkeys, int currentidx, int endidx);
EXTERN_C BOOL IsRunningAsAdmin();
BOOL RegKeyDetect(HKEY currentKey, char ** regkey,int regkeylen, char *queryName)
{
    HMODULE kernel32  = (HMODULE)getModuleByName((wchar_t *)aKernel32dll);
    pLoadLibraryA _LoadLibraryA = (pLoadLibraryA) getFuncByName(kernel32, aLoadLibraryA);
    HMODULE advapi32 = _LoadLibraryA(aAdvapi32);
    pRegQueryValueA _RegQueryValueA = (pRegQueryValueA) getFuncByName(advapi32, aRegQueryValueA);
    HKEY hKey; 
    BOOL res = OpenKeyRecursive(currentKey, &hKey, regkey, 0, regkeylen - 1);
    if (res)
    {
        if (queryName == NULL) return TRUE;
        if (_RegQueryValueA(hKey, queryName, NULL, NULL) == ERROR_SUCCESS)
        {
            return TRUE;
        }
        else return FALSE;
    }
    else return FALSE;
}

BOOL HypervisorBitDetect()
{
    unsigned int ECX;
    __asm {
        mov eax, 0x1
        cpuid
        mov ECX, ecx
    }
    if ((ECX >> 31) & 1)
        return TRUE;
    else return FALSE;
}

int VMManufactureDetect()
{
    unsigned int EBX, ECX, EDX ;
    unsigned char nameID[0x10] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    __asm {
        mov eax, 0x40000000
        cpuid
        mov EBX, ebx
        mov ECX, ecx
        mov EDX, edx
    };

    *(unsigned int *)(&nameID[0]) = EBX;
    *(unsigned int *)(&nameID[4]) = ECX;
    *(unsigned int *)(&nameID[8]) = EDX;

    for (int i = 0; i < VMlist_length; ++i)
    {
        if (strncmp((char *) nameID, VMmanufactures_list[i], 12))
        {
            if (!strncmp((char *) nameID, VMmanufactures_list[1], 12))
                return -1;
            else return 1;
        }
    }
    return 0;
}

const char *VMWareRegkey1[] = {"Software", "VMware, Inc."};
const char *VMWareRegkey2[] = {"SOFTWARE", "VMware, Inc."};
const char *VMWareRegkey3[] = {"SYSTEM", "CurrentControlSet", "Services", "vmrawdsk"};
const char *VBoxRegkey1[] = {"HARDWARE", "ACPI", "DSDT"};
const char *VBoxRegkey2[] = {"SOFTWARE", "Oracle", "VirtualBox Guest Additions"};


BOOL VMRegkeyCheck()
{
    if (RegKeyDetect(HKEY_CURRENT_USER, ( char **) VMWareRegkey1, 2, NULL)) return TRUE;
    if (RegKeyDetect(HKEY_LOCAL_MACHINE, (char**)VMWareRegkey2, 2, NULL)) return TRUE;
    if (RegKeyDetect(HKEY_LOCAL_MACHINE, (char**) VMWareRegkey3, 4, NULL)) return TRUE;

    if (RegKeyDetect(HKEY_LOCAL_MACHINE, (char**)VBoxRegkey1, 3, (char *) "VBOX__")) return TRUE;
    if (RegKeyDetect(HKEY_LOCAL_MACHINE, (char**)VBoxRegkey2, 3, NULL)) return TRUE;
    return FALSE;
}

BOOL CheckServicesForKeyword(char **keyword, int listlen) {
    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (hSCManager == NULL) {
        #ifdef DEBUG
        printf("[x] Failed to open service manager.\n");
        #endif
        return FALSE;
    }

    DWORD bytesNeeded = 0, servicesReturned = 0, resumeHandle = 0;
    EnumServicesStatusEx(hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, 
                         NULL, 0, &bytesNeeded, &servicesReturned, &resumeHandle, NULL);

    LPENUM_SERVICE_STATUS_PROCESS services = (LPENUM_SERVICE_STATUS_PROCESS)malloc(bytesNeeded);
    if (services == NULL) {
        #ifdef DEBUG
        printf("[x] Failed to allocate memory for service enumeration.\n");
        #endif
        CloseServiceHandle(hSCManager);
        return FALSE;
    }

    if (!EnumServicesStatusEx(hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, 
                              (LPBYTE)services, bytesNeeded, &bytesNeeded, &servicesReturned, &resumeHandle, NULL)) {
        #ifdef DEBUG
        printf("[x] Failed to enumerate services.\n");
        #endif
        free(services);
        CloseServiceHandle(hSCManager);
        return FALSE;
    }

    for (DWORD i = 0; i < servicesReturned; i++) {
        for(int j = 0; j < listlen; ++j)
            if (strstr(( char *)services[i].lpServiceName, (const char *)keyword[j]) != NULL) {
                return TRUE;
        }
    }

    free(services);
    CloseServiceHandle(hSCManager);
    return FALSE;
}

const char *VMwareServiceList[] = {"vmtoolsd.exe", "VGAuthService.exe", "vmacthlp.exe"};
const char *VboxServiceList[] = {"VBoxService.exe", "VBoxTray.exe"};
BOOL VMServiceCheck()
{
    if (CheckServicesForKeyword((char **)VMwareServiceList, 3) ) return TRUE;
    if (CheckServicesForKeyword((char **)VboxServiceList, 2)) return TRUE;
    return FALSE;
}




BOOL  VMDetect()
{
    #ifdef DEBUG
    printf("[-] Detecting virtual machine environment!\n");
    #endif
    int res = VMManufactureDetect();
    if (res != 0) 
    {
        if (res == 1) return TRUE;
        else
        {
            if (IsRunningAsAdmin()) {
                if (RegKeyDetect(HKEY_LOCAL_MACHINE, (char **)HyperVRegKey, 5, (char *)"VirtualMachineName") || RegKeyDetect(HKEY_LOCAL_MACHINE, (char **)HyperVRegKey, 5, (char *)"VirtualMachineID"))
                    return TRUE;
                else goto SECONDCHECK;
            }
            else {
                #ifdef DEBUG
                printf("[x] No permission given! Continue checking\n");
                #endif
                goto SECONDCHECK;
            }
        }
    }
    SECONDCHECK:
    if (VMRegkeyCheck())
    {
        #ifdef DEBUG
        printf("[x] Registry key found!\n");
        #endif
        return TRUE;
    }
    if (VMServiceCheck())
    {
        #ifdef DEBUG
        printf("[x] Service found!\n");
        #endif
        return TRUE;
    }
    return FALSE;
}
