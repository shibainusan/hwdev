#include <stdio.h>
#include <stdbool.h>
#include <process.h> 

#include "sockframe.h"
#include "RingBuf.h"

T_RingBuf ulFifo;
T_RingBuf dlFifo;

const char* newLine = "\n";

void ServerDownlinkThread(void* ci_)
{
	SOCK_INFO* ci = ci_;
	RingBuf_Clear(&dlFifo);
	for (;;) {
		char buf[1024];

		RingBuf_BlockingPopLine(&dlFifo, buf);
		printf("[Local DL]%s\n", buf);
		int ret = _send(ci->sock, buf, strlen(buf), 0);
		if (ret <= 0) {
			break; //client connection lost
		}
		ret = _send(ci->sock, newLine, strlen(newLine), 0);
		if (ret <= 0) {
			break; //client connection lost
		}
	}
	printf("ServerDownlinkThread finised.");
	_endthread();
}

extern void SockFrame_OnClientConnect(SOCK_INFO* ci)
{
	_beginthread(ServerDownlinkThread, 0, ci);
	
	for (;;) {
		char buf[1024];
		int size;
		size = SockFrame_ReceiveLineCRorLF(ci, buf, 1024);
		if (size <= 0) {
			break; //client connection lost
		}
		printf("[Local UL]%s\n", buf);
		RingBuf_PushString(&ulFifo, buf);
		RingBuf_PushString(&ulFifo, newLine);
	}
	RingBuf_UnblockPop(&dlFifo);
}

void ClientDownlinkThread(void* si_)
{
	SOCK_INFO *si = si_;
	for (;;) {
		char buf[1024];
		int size;
		size = SockFrame_ReceiveLineCRorLF(si, buf, 1024);
		if (size <= 0) {
			break; //client connection lost
		}
		printf("[Remote DL]%s\n", buf);
		RingBuf_PushString(&dlFifo, buf);
		RingBuf_PushString(&dlFifo, newLine);
	}
	RingBuf_UnblockPop(&ulFifo);
	printf("ClientDownlinkThread finised.");
	_endthread();
}

void ClientConnectThread(void* ci_)
{
	SOCK_INFO si;

	SockFrame_BuildHostPort(&si, "localhost:56000");
	for (;;) {
		if (FALSE == SockFrame_Connect(&si)) {
			continue;
		}
		_beginthread(ClientDownlinkThread, 0, &si);
		for (;;) {
			char buf[1024];

			RingBuf_BlockingPopLine(&ulFifo, buf);
			printf("[Remote UL]%s", buf);
			int ret = _send(si.sock, buf, strlen(buf), 0);
			if (ret <= 0) { //lost connection
				RingBuf_PushString(&ulFifo, buf); //push back failed data.
				break; 
			}
			ret = _send(si.sock, newLine, strlen(newLine), 0);
			if (ret <= 0) { //lost connection
				RingBuf_PushString(&ulFifo, newLine); //push back failed data.
				break;
			}
		}
	}
	_endthread();
}

int main()
{
	printf("starting TcpSessionKeeper.\n\n");

	RingBuf_Init(&ulFifo);
	RingBuf_Init(&dlFifo);

	SockFrame_Init();
	_beginthread(ClientConnectThread, 0, NULL);
	SockFrame_Listen(8912);
	SockFrame_Cleanup();
}

