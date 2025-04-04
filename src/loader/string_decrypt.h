#pragma once
#include <Windows.h>
#include "sysheaders.h"
#include "peb-lookup.h"
#include <stdio.h>

LPVOID getcurProcBaseAddr()
{
	PPEB peb;
#ifdef _WIN64
	peb = (PPEB)__readgsqword(0x60);
#endif
	return (LPVOID)peb->ImageBaseAddress;
}


void DecryptRDataSection()
{
    LPVOID procbase = getcurProcBaseAddr();
    DWORD signature = 0xaabbccdd;
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)procbase;
    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((char*)procbase + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER currentSection = IMAGE_FIRST_SECTION(ntHeaders); 
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i)
    {
        if (*((DWORD64*)currentSection->Name) == 0x61746164722e) {
            // printf("found\n");
            break;
        }
        ++currentSection;
    }
       
    int sectionSize = currentSection->Misc.VirtualSize;
    PVOID addr = (PVOID)((char*)procbase + currentSection->VirtualAddress);
    ULONG oldProtect = PAGE_READONLY;
    
    NTSTATUS check = NtProtectVirtualMemory((HANDLE)0xffffffffffffffff, (PVOID *) &addr, (PSIZE_T)sectionSize, PAGE_READWRITE, (PULONG)&oldProtect);
    if (check)
    {
        exit(0);
    }
    VirtualProtect(addr, sectionSize, PAGE_READWRITE, &oldProtect);
    // printf("Worked\n");
// printf("decrypting\n");
    DWORD* tmp = (DWORD*)addr;
    for (int i = 0; i < 0xa00; i += 4)
    {
        *tmp ^= signature;
        ++tmp;
    }
    oldProtect = PAGE_READWRITE;


    check = NtProtectVirtualMemory((HANDLE)0xffffffffffffffff, (PVOID*)&addr, (PSIZE_T)sectionSize, PAGE_READONLY, (PULONG)&oldProtect);
    if (check == 0)
    {
        printf("[+] Successfully decrypt rdata section!\n");
    }
    //VirtualProtect(addr, sectionSize, PAGE_READONLY, &oldProtect);
}