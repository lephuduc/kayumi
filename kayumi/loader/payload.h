#include "config.h"
#include "resource.h"

int BUFFER_Size;
unsigned char * embeded_payload;

void loadRSRC() {
    HMODULE hModule = GetModuleHandle(NULL);
    HRSRC hRes = FindResource(hModule, MAKEINTRESOURCE(IDR_BIN1), L"BIN");
    if (!hRes)
    {
        #ifdef DEBUG
        printf("Failed to find resource.\n");
        #endif
        return;
    }

    HGLOBAL hResData = LoadResource(hModule, hRes);
    if (!hResData)
    {
        #ifdef DEBUG
        printf("Failed to load resource.\n");
        #endif
        return;
    }

    void* pData = LockResource(hResData);
    if (!pData) return;

    DWORD dataSize = SizeofResource(hModule, hRes);
    if (dataSize == 0) {
#ifdef DEBUG
        printf("Failed to lock resource.\n");
#endif
        return;
    }

    embeded_payload = (unsigned char*)malloc(dataSize);
    
    if (!embeded_payload) {
#ifdef DEBUG
        printf("can't malloc.\n");
#endif
        return;
    }

    memcpy(embeded_payload, pData, dataSize);

#ifdef DEBUG
    printf("Loaded %d\n", dataSize);
#endif

    BUFFER_Size = dataSize;
}