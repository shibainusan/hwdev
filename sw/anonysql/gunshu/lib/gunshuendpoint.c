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
		//コマンド待ち
		ret = SockFrame_ReceiveLine(ci,com,COMMAND_BUF);
		if( ret <= 0){
			printf("OnClientConnect Loop failed:%d\n",ret);
			break;
		}
		//経路確立コマンドの処理
		if( strcmp("est" , com) == 0 ){
			if( Command_Est(&gsi) != TRUE){
				break;
			}
		//転送コマンドの処理
		}else if(strcmp("forward", com) == 0){
			return TRUE;
		//managerによる動作テスト
		}else if(strcmp("test",com) == 0){
			printf("test\n");
			SockFrame_SendLine(ci , "ok");
			break;
		//経路調査
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

	//Serviceリスト件数受信
	ret = SockFrame_ReceiveLine(&(gsi->prev),com,COMMAND_BUF);
	numList = atoi(com);
	printf("recv %d service list\n",numList);

	//Serviceリスト受信
	for( i = 0 ; i < numList ; i++){
		ret = SockFrame_ReceiveLine(&(gsi->prev),com,COMMAND_BUF); 
		printf("%s\n",com);
	}
	//とりあえずOKを返して経路確立終了
	SockFrame_SendLine(&(gsi->prev) , "ok");

	return TRUE;
}