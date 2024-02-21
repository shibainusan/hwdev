#include <stdio.h>
#include <windows.h>
#include "sockframe.h"
#include "gunshu.h"
#define COMMAND_BUF 1024

static int Command_Est(GUNSHU_SESSION_INFO *gsi);

int Gunshu_OnClientConnect(SOCK_INFO *ci)
{
	char com[COMMAND_BUF];
	int ret;
	GUNSHU_SESSION_INFO gsi;

	ZeroMemory( &gsi , sizeof(GUNSHU_SESSION_INFO));
	gsi.prev = *ci;
	do{
		//�R�}���h�҂�
		ret = SockFrame_ReceiveLine(ci,com,COMMAND_BUF);
		if( ret <= 0){
			printf("OnClientConnect Loop failed:%d\n",ret);
			break;
		}
		//�o�H�m���R�}���h�̏���
		if( strcmp("est" , com) == 0 ){
			if( Command_Est(&gsi) != TRUE){
				break;
			}
		//�]���R�}���h�̏���
		}else if(strcmp("forward", com) == 0){
			return TRUE;
		//manager�ɂ�铮��e�X�g
		}else if(strcmp("test",com) == 0){
			printf("test\n");
			SockFrame_SendLine(ci , "ok");
			break;
		//�o�H����
		}else if(strcmp("path",com) == 0){
			printf("path trace.\n");
			SockFrame_SendLine(ci , "endpoint");
			SockFrame_SendLine(ci , "");
		}else{
			printf("unknown command:%s\n", com);
			break;
		}
	}while(1);

	return FALSE;
}

int Command_Est(GUNSHU_SESSION_INFO *gsi)
{
	char com[COMMAND_BUF];
	int i,ret;
	int numList;

	printf("establish route.\n");

	//Service���X�g������M
	ret = SockFrame_ReceiveLine(&(gsi->prev),com,COMMAND_BUF);
	numList = atoi(com);
	printf("recv %d service list\n",numList);

	//Service���X�g��M
	for( i = 0 ; i < numList ; i++){
		ret = SockFrame_ReceiveLine(&(gsi->prev),com,COMMAND_BUF); 
		printf("%s\n",com);
	}
	//�Ƃ肠����OK��Ԃ��Čo�H�m���I��
	SockFrame_SendLine(&(gsi->prev) , "ok");

	return TRUE;
}