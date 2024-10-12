#include <stdio.h>
#include <Winsock2.h>
#include <process.h>  
#include <stdarg.h>
#include "sockframe.h"

#define kBufferSize 4096

static void AcceptConnections(SOCKET ListeningSocket);
static void PreOnClientConnect(void* ci_); 
static int ShutdownConnection(SOCKET sd);

static unsigned short SockFrame_listenPort;
static SOCKET SockFrame_listenSock;
int __sockFrameDebugMessage = TRUE;

int SockFrame_Connect(SOCK_INFO *si)
{
	int ret;
    // Create a stream socket
    SOCKET sd = socket(AF_INET, SOCK_STREAM, 0);
    if (sd != INVALID_SOCKET) {
        struct sockaddr_in sinRemote;
        sinRemote.sin_family = AF_INET;
        sinRemote.sin_addr.s_addr = si->ip.S_un.S_addr;
        sinRemote.sin_port = htons(si->port);
        ret = connect(sd, (struct sockaddr*)&sinRemote, sizeof(struct sockaddr_in));
		if (ret == SOCKET_ERROR) {
			sd = INVALID_SOCKET;
			SockFrame_DebugOut("failed to connect %s:%d\n" , inet_ntoa(si->ip) , si->port);
			SockFrame_DispLastError();
			return FALSE;
        }
    }
	SockFrame_DebugOut("connect %s:%d\n" , inet_ntoa(si->ip) , si->port);
	si->sock = sd;
    return TRUE;
}
//// LookupAddress /////////////////////////////////////////////////////
// Given an address string, determine if it's a dotted-quad IP address
// or a domain address.  If the latter, ask DNS to resolve it.  In
// either case, return resolved IP address.  If we fail, we return
// INADDR_NONE.

int SockFrame_LookupAddress(SOCK_INFO *si,const char *name)
{
    unsigned int nRemoteAddr = inet_addr(name);
    if (nRemoteAddr == INADDR_NONE) {
        // pcHost isn't a dotted IP, so resolve it through DNS
        struct hostent* pHE = gethostbyname(name);
        if (pHE == 0) {
			SockFrame_DebugOut("DNS lookup failed.\n");
			SockFrame_DispLastError();
            return FALSE;
        }
        nRemoteAddr = *((u_long*)pHE->h_addr_list[0]);
    }
	si->ip.S_un.S_addr = nRemoteAddr;

    return TRUE;
}

int SockFrame_BuildHostPort(SOCK_INFO *si, const char *name)
{
	char *buf;
	char *port;
	int ret;
	
	buf = malloc(strlen(name) + 1);
	strcpy(buf , name);
	port = buf;

	//コロンでデリミタされたポート番号を探す
	while(1){
		//デリミタが見つからないうちに終端に達した
		if(*port == '\0'){
			si->port = 0;
			break;
		}else if(*port == ':'){
			*port = '\0';
			port++;
			//ポート番号取得
			sscanf(port , "%hd" , &(si->port));
			//si->port = htons(si->port);
			break;
		}
		port++;
	}
	//DNSを引く
	ret = SockFrame_LookupAddress(si , buf);
	free(buf);
	return ret;
}
void SockFrame_SetTimeout(SOCK_INFO *ci,int timeout)
{
	int err;
	err = setsockopt( ci->sock , SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));
	err = setsockopt( ci->sock , SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
	SockFrame_DispLastError();
}


int SockFrame_Init()
{
	WORD wVersionRequested;
	WSADATA wsaData;
	int err;
 
	SockFrame_DebugOut("SockFrame init\n");

	SockFrame_listenPort = 0;

	wVersionRequested = MAKEWORD( 2, 2 );
 
	err = WSAStartup( wVersionRequested, &wsaData );
	return err;
}

void SockFrame_Cleanup(void)
{
	ShutdownConnection(SockFrame_listenSock);
	WSACleanup();
    return; 
}
int SockFrame_Listen(unsigned short nPort)
{
    unsigned long nInterfaceAddr = htonl(INADDR_ANY);

    if (nInterfaceAddr != INADDR_NONE) {
        SOCKET sd = socket(AF_INET, SOCK_STREAM, 0);
        if (sd != INVALID_SOCKET) {
            struct sockaddr_in sinInterface;
            sinInterface.sin_family = AF_INET;
            sinInterface.sin_addr.s_addr = nInterfaceAddr;
            sinInterface.sin_port = htons(nPort);
            if (bind(sd, (struct sockaddr*)&sinInterface,sizeof(struct sockaddr_in)) != SOCKET_ERROR) {
                listen(sd, SOMAXCONN);
                SockFrame_listenSock = sd;
				SockFrame_DebugOut("listening on port %d\n",nPort);
				AcceptConnections(sd);
				return TRUE;
            }
            else {
				SockFrame_DispLastError();
            }
        }
    }
    return FALSE;
}

void AcceptConnections(SOCKET ListeningSocket)
{
    struct sockaddr_in sinRemote;
	SOCK_INFO *ci;
//	DWORD nThreadID;
    int nAddrSize = sizeof(sinRemote);

    while (1) {
        SOCKET sd = accept(ListeningSocket, (struct sockaddr*)&sinRemote,
                &nAddrSize);
        if (sd != INVALID_SOCKET) {
			ci = malloc(sizeof(SOCK_INFO));
			ci->ip = sinRemote.sin_addr;
			ci->port = ntohs(sinRemote.sin_port);
			ci->sock =sd;
            //CreateThread(0, 0, PreOnClientConnect, (void*)ci, 0, &nThreadID);
			_beginthread(PreOnClientConnect , 0 , ci);
        }
        else {
			SockFrame_DispLastError();
            return;
        }
    }
}

void PreOnClientConnect(void* ci_) 
{
	SOCK_INFO *ci;
	ci = (SOCK_INFO *)ci_;
	SockFrame_DebugOut("connected from %s:%d\n",inet_ntoa(ci->ip) , ci->port );
	SockFrame_OnClientConnect(ci);
	SockFrame_Shutdown(ci);
	free(ci);
	SockFrame_DebugOut("OnClientConnect finished.\n");
	_endthread();
}
int SockFrame_Shutdown(SOCK_INFO *si)
{
	int ret;
	ret = ShutdownConnection(si->sock);	
	if(ret == TRUE){
		SockFrame_DebugOut("shutdown %s:%d\n" , inet_ntoa(si->ip) , si->port);
	}else{
		SockFrame_DebugOut("failed to shutdown %s:%d\n" , inet_ntoa(si->ip) , si->port);
	}
	si->sock = 0;
	return ret;
}
//// ShutdownConnection ////////////////////////////////////////////////
// Gracefully shuts the connection sd down.  Returns true if we're
// successful, false otherwise.

int ShutdownConnection(SOCKET sd)
{
	int timeout;
    char acReadBuffer[kBufferSize];
    // Disallow any further data sends.  This will tell the other side
    // that we want to go away now.  If we skip this step, we don't
    // shut the connection down nicely.
    if (shutdown(sd, SD_SEND) == SOCKET_ERROR) {
        return FALSE;
    }

    // Receive any extra data still sitting on the socket.  After all
    // data is received, this call will block until the remote host
    // acknowledges the TCP control packet sent by the shutdown above.
    // Then we'll get a 0 back from recv, signalling that the remote
    // host has closed its side of the connection.
#if 0
	timeout = 5000;
	setsockopt( sd , SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
    while (1) {
        int nNewBytes = recv(sd, acReadBuffer, kBufferSize, 0);
        if (nNewBytes == SOCKET_ERROR) {
            return FALSE;
        }
        else if (nNewBytes != 0) {
            SockFrame_DebugOut(" unexpected bytes during shutdown.\n");
        }
        else {
            // Okay, we're done!
            break;
        }
    }
#endif
    // Close the socket.
    if (closesocket(sd) == SOCKET_ERROR) {
        return FALSE;
    }

    return TRUE;
}


void SockFrame_EnableDebugMessage(void)
{
	__sockFrameDebugMessage = TRUE;
}

void SockFrame_DisableDebugMessage(void)
{
	__sockFrameDebugMessage = FALSE;
}
int SockFrame_DebugOut(const char *format,...)
{
	va_list ap;
	int ret;

	if(__sockFrameDebugMessage != TRUE){
		return 0;
	}
	va_start(ap , format);
	ret = vfprintf(stderr,format,ap);
	va_end(ap);

	return ret;
}
