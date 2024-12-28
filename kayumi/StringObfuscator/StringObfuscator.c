#include <Windows.h>

#include <stdio.h>


void StringObfuscate(char * path)
{
    printf("[*] Target: %s\n", path);
    char* targetpath = path;
    HANDLE hFile = CreateFileA(targetpath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != NULL) printf("[+] Opened file\n");
    HANDLE hFileMapping = CreateFileMappingA(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
    if (hFileMapping) printf("[+] Mapped file\n");
    LPVOID fileBase = MapViewOfFile(hFileMapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
    if (fileBase != NULL) printf("[+] Memory mapped\n");

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileBase;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((char*)fileBase + dosHeader->e_lfanew);

    PIMAGE_SECTION_HEADER currentsection = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i)
    {
        if (*((DWORD64*)currentsection->Name) == 0x656d616e662e)
        {
            printf("[+] Found section\n");
            LPVOID sectionBase = (LPVOID)((char*)fileBase + currentsection->PointerToRawData);
            int sectionSize = (int)currentsection->SizeOfRawData;
            DWORD signature = 0xaabbccdd;
            for (int j = 0; j < sectionSize; j += 4)
                *((DWORD*)((char*)sectionBase + j)) ^= signature;
            break;
        }
        ++currentsection;
    }

    printf("[+] Encrypting completed!\n");
    UnmapViewOfFile(fileBase);
    CloseHandle(hFileMapping);
    CloseHandle(hFile);
}


int main(int argc, char ** argv)
{
    StringObfuscate("C:\\Users\\turbo_granny\\Desktop\\kltn_meodev\\kayumi\\x64\\Debug\\loader.exe");
    StringObfuscate("C:\\Users\\turbo_granny\\Desktop\\kltn_meodev\\kayumi\\x64\\Release\\loader.exe");
}