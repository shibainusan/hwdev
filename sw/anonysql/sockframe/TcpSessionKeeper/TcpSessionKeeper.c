#include <stdio.h>
#include <stdbool.h>
#include <process.h> 

#include "sockframe.h"
#include "RingBuf.h"

T_RingBuf ulFifo;
T_RingBuf dlFifo;

void ServerDownlinkThread(void* ci_)
{
	SOCK_INFO* ci = ci_;
	RingBuf_Clear(&dlFifo);
	for (;;) {
		char c;

		RingBuf_BlockingPop(&dlFifo, &c);
		printf("[SDL]%c", c);
		int ret = _send(ci->sock, &c, 1, 0);
		if (ret <= 0) {
			break; //client connection lost
		}
	}
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
		printf("[SUL]%s\n", buf);
		RingBuf_PushString(&ulFifo, buf);
		RingBuf_PushString(&ulFifo, "\n");
	}
}

void ClientDownlinkThread(void* si_)
{
	SOCK_INFO *si = si_;
	char c;
	for (;;) {
		int ret = _recv(si->sock, &c, 1, 0);
		if (ret <= 0) {
			break; //session lost
		}
		printf("[CDL]%c", c);
		RingBuf_Push(&dlFifo, c);
	}
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
			char c;
			RingBuf_BlockingPop(&ulFifo, &c);
			printf("[CUL]%c", c);
			int ret = _send(si.sock, &c, 1, 0);
			if (ret <= 0) { //lost connection
				RingBuf_Push(&ulFifo, c); //push back failed data.
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

