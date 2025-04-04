#include <Windows.h>
#include <stdio.h>
#include "func-prototype.h"
#include "myheaders.h"



//typedef NTSTATUS(WINAPI* NtAllocateVirtualMemory_t)(
//	HANDLE hProcess,
//	PVOID* BaseAddress,
//	ULONG_PTR ZeroBits,
//	PSIZE_T RegionSize,
//	ULONG AllocationType,
//	ULONG Protect
//	);



int main()
{

	//HMODULE ntdll = GetModuleHandleA("ntdll");
	//pNtAllocateVirtualMemory _NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetProcAddress(ntdll, aNtAllocateVirtualMemory);


	DWORD pid;
	printf("Target pid: ");
	scanf_s("%d", &pid);


	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess == NULL)
	{
		printf("Error open process!\n");
		exit(0);
	}

	PVOID baddr = NULL;
	//LPVOID baddr = VirtualAllocEx(hProcess, NULL, 0x100, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	SIZE_T codesize = 0x100;
	NTSTATUS status = NtAllocateVirtualMemory(hProcess, &baddr, 0, (PULONG) & codesize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (status != 0)
	{

		printf("Failed allocation!\n");
		exit(0);
	}


	printf("[+] Base address: %p\n", baddr);
	BOOL check = WriteProcessMemory(hProcess, baddr, "abcdefgh", 8, NULL);
	if (check)
	{
		printf("Write to memory successfully\n");
	}
	else
	{
		printf("Failed to write to memory\n");
	}
	CloseHandle(hProcess);
}