#include <stdio.h>
#include <stdlib.h>
#include "sockframe.h"
#include "listman.h"
#include <process.h>  

#define COMMAND_BUF 1024

int IsCorrectService(const char *hostname)
{
	SOCK_INFO si;
	int ret;
	char buf[COMMAND_BUF];

	ret = SockFrame_BuildHostPort(&si , hostname);
	if( ret != TRUE ){
		return ret;
	}
	//テストするサービスに接続
	ret = SockFrame_Connect(&si);
	SockFrame_SetTimeout(&si , 5000);
	if( ret != TRUE ){
		return ret;
	}
	//テストコマンド送信
	SockFrame_SendLine(&si , "test");
	//結果受信
	SockFrame_ReceiveLine(&si , buf,COMMAND_BUF);
	//文字列"ok"を返したか？
	if( strcmp("ok",buf) != 0 ){
		return FALSE;
	}
	return TRUE;
}

void TestServices(void *n)
{
	ServiceList sl;
	ServiceNode *w,*w2;

	do{
		//テスト実行間隔
		Sleep(60 * 1000);
		printf("testing services\n");
		//サービスリスト読み込み
		LoadService(&sl);
		w = TopService(&sl);
		do{
			if(w == NULL){
				break;
			}
			if( IsCorrectService(w->name ) != TRUE){
				printf("invalid service: %s\n",w->name);
				//サービスがテストに失敗したらリストから削除
				w2 = w->next;
				DelService(&sl, w);
				w = w2;
				SaveService(&sl);
			}else{
				printf("ok: %s\n",w->name);
				w = w->next;
			}
		}while(1);
	}while(1);
	_endthread();
}



int main(int argc, char **argv)
{
	
	SockFrame_Init();
	atexit(SockFrame_Cleanup);

	//service巡回スレッド起動
	_beginthread(TestServices , 0 , NULL);
	SockFrame_Listen(23621);
}