#include <stdio.h>
#include <winsock2.h>
#include "sockframe.h"
#include "listman.h"

#define COMMAND_BUF 1024

int IsCorrectService(const char *hostname);
int IsCorrectServiceName(const char *hostname);

void SockFrame_OnClientConnect(SOCK_INFO *ci) 
{
	char com[COMMAND_BUF];
	char buf[COMMAND_BUF];
	int ret;
	int i;
	int numList;
	ServiceList sl;
	ServiceNode *w;

	//サービスリスト読み込み
	LoadService(&sl);

	SockFrame_SetTimeout(ci,15000);

	//コマンド待ち
	ret = SockFrame_ReceiveLine(ci,com,COMMAND_BUF);

	//登録コマンドの処理
	if( strcmp("reg" , com) == 0 ){
		printf("register host.\n");
		//登録するホスト名待ち
		ret = SockFrame_ReceiveLine(ci,com,COMMAND_BUF);
		//正しいサービス名かチェック
		if( IsCorrectServiceName(com) != TRUE ){
			SockFrame_SendLine(ci,"fail");
			return;
		}
		//もう登録済みか？ 
		if( FindService(&sl , com) == NULL ){
			AddService(&sl , com);
			SaveService(&sl);
		}
		SockFrame_SendLine(ci,"ok");
	//リスト提供コマンドの処理
	}else if(strcmp("list", com) == 0){
		printf("send hostlist.\n");
		//リスト件数を送信
		numList = GetServiceCount(&sl);
		sprintf(buf , "%d" , numList);
		SockFrame_SendLine(ci , buf);
		//リストの内容を送信
		w = TopService(&sl);
		for(i = 0 ; i < numList ; i++){
			if(w == NULL){
				break;
			}
			SockFrame_SendLine(ci , w->name );
			w = w->next;
		}
	}
}

int IsCorrectServiceName(const char *hostname)
{
	SOCK_INFO si;
	int ret;

	ret = SockFrame_BuildHostPort(&si , hostname);
	if( ret != TRUE ){
		return ret;
	}
	return TRUE;
}