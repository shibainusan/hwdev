#include <stdio.h>
#include <windows.h>
#include "sockframe.h"
#include "..\initiator\gunshu.h"
#define COMMAND_BUF 1024

int main(int argc, char **argv)
{

	SockFrame_Init();

	printf("waiting for incomming services.\n");
	SockFrame_Listen(4649);
	SockFrame_Cleanup();
}



void SockFrame_OnClientConnect(SOCK_INFO *ci) 
{
	int ret;
	char com[COMMAND_BUF];

	if( Gunshu_OnClientConnect(ci) != TRUE ){
		return;
	}

	//オウム返しループ
	do{
		ret = SockFrame_ReceiveLine(ci,com,COMMAND_BUF);
		if( ret <= 0 ){
			break;
		}
		printf("%s\n",com);
		SockFrame_SendLine(ci, com);
	}while(1);
}