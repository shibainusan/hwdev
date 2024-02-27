#include <stdio.h>
#include <stdbool.h>
#include <process.h> 

#include "sockframe.h"
#include "RingBuf.h"
#include "MyCommands.h"

T_RingBuf ulFifo;
T_RingBuf dlFifo;

const char* newLine = "\n";

void ServerDownlinkThread(void* ci_)
{
	SOCK_INFO* ci = ci_;
	RingBuf_Clear(&dlFifo);
	for (;;) {
		char buf[1024];

		if (!RingBuf_BlockingPopLine(&dlFifo, buf)) {
			break;
		}
		//printf("[Local DL]%s\n", buf);
		int ret = _send(ci->sock, buf, strlen(buf), 0);
		if (ret < 0) {
			break; //client connection lost
		}
		ret = _send(ci->sock, newLine, strlen(newLine), 0);
		if (ret < 0) {
			break; //client connection lost
		}
	}
	printf("ServerDownlinkThread finised.\n");
	_endthread();
}



extern void SockFrame_OnClientConnect(SOCK_INFO* ci)
{
	_beginthread(ServerDownlinkThread, 0, ci);
	
	for (;;) {
		char buf[1024];
		int size;
		size = SockFrame_ReceiveLineCRorLF(ci, buf, 1024);
		if (size < 0) {
			break; //client connection lost
		}
		//printf("[Local UL]%s\n", buf);
		if (DoMyCommand(buf)) {

		}
		else {
			RingBuf_PushString(&ulFifo, buf);
			RingBuf_PushString(&ulFifo, newLine);
		}
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
		if (size < 0) {
			break; //client connection lost
		}
		printf("[Remote DL]%s\n", buf);
		RingBuf_PushString(&dlFifo, buf);
		RingBuf_PushString(&dlFifo, newLine);
	}
	RingBuf_UnblockPop(&ulFifo);
	printf("ClientDownlinkThread finised.\n");
	_endthread();
}

static void TryClientConnect(SOCK_INFO *si)
{
	for (;;) {
		if (0 != strlen(remoteHostPort)) {
			break;
		}
		Sleep(100);
	}
	SockFrame_BuildHostPort(si, remoteHostPort);
	for (;;) {
		if (SockFrame_Connect(si)) {
			break;
		}
	}
}

void ClientConnectThread(void* ci_)
{
	SOCK_INFO si;

	for (;;) {
		TryClientConnect(&si);
		_beginthread(ClientDownlinkThread, 0, &si);
		for (;;) {
			char buf[1024];

			if (!RingBuf_BlockingPopLine(&ulFifo, buf)) {
				break;
			}
			printf("[Remote UL]%s\n", buf);
			int ret = _send(si.sock, buf, strlen(buf), 0);
			if (ret < 0) { //lost connection
				RingBuf_PushString(&ulFifo, buf); //push back failed data.
				break; 
			}
			ret = _send(si.sock, newLine, strlen(newLine), 0);
			if (ret < 0) { //lost connection
				RingBuf_PushString(&ulFifo, newLine); //push back failed data.
				break;
			}
		}
		SockFrame_Shutdown(&si);
		printf("Remote client connection lost.\n");
	}
	_endthread();
}

int main()
{
	printf("starting TcpSessionKeeper.\n\n");

	//DoMyCommand("RemoteHostPort 192.168.0.20:56001");
	//DoMyCommand("SendMagicPacket 00-00-91-09-85-40");

	RingBuf_Init(&ulFifo);
	RingBuf_Init(&dlFifo);

	SockFrame_Init();

	const char destMac[] = { 0x12,0x34,0x56,0x78,0x9A,0xBC };
	SendMagicPacketOnAllLocalIP(destMac);

	_beginthread(ClientConnectThread, 0, NULL);
	SockFrame_Listen(55001);
	SockFrame_Cleanup();
}

