#include <Windows.h>

#include <stdio.h>


int main(int argc, char ** argv)
{
    char *targetpath = argv[1];
    HANDLE hFile = CreateFileA(targetpath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != NULL) printf("opened file\n");
    HANDLE hFileMapping = CreateFileMappingA(hFile, NULL, PAGE_READWRITE, 0, 0, NULL);
    if (hFileMapping) printf("mapped file\n");
    LPVOID fileBase = MapViewOfFile(hFileMapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
    if (fileBase != NULL) printf("memory mapped\n");

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileBase;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((char*)fileBase + dosHeader->e_lfanew);

    PIMAGE_SECTION_HEADER currentsection = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i)
    {
        if (*((DWORD64*)currentsection->Name) == 0x61746164722e)
        {
            printf("found section\n");
            LPVOID sectionBase = (LPVOID)((char*)fileBase + currentsection->PointerToRawData);
            DWORD signature = 0xaabbccdd;
            for (int j = 0; j < 0xa00; j += 4)
                *((DWORD*)((char*)sectionBase + j)) ^= signature;
            break;
        }
        ++currentsection;
    }
    UnmapViewOfFile(fileBase);
    CloseHandle(hFileMapping);
    CloseHandle(hFile);
}