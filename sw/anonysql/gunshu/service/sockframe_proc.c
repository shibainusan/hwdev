#include <windows.h>
#include <stdio.h>
#include <process.h>
#include "sockframe.h"

//経路確立後にセッションが有効な期間
#define GUNSHU_SESSION_TIMEOUT (10*60*1000)
#define COMMAND_BUF 1024
#define TRANS_BUFSIZE 4096
#define BUF_SIZE 1024

typedef struct {
	SOCK_INFO prev,next;
} GUNSHU_SESSION_INFO;

typedef struct{
	char managerAddr[BUF_SIZE];
	char myAddr[BUF_SIZE];
	int randomChoice;
} GUNSHU_SERVICE_INFO;

extern GUNSHU_SERVICE_INFO gunshuInfo;

int Command_Est(GUNSHU_SESSION_INFO *gsi);
int Command_Forward(GUNSHU_SESSION_INFO *gsi);
int Command_Path(GUNSHU_SESSION_INFO *gsi);
void DownlinkTrans(void* gsi_);
void UplinkTrans(void* gsi_);

void SockFrame_OnClientConnect(SOCK_INFO *ci)
{
	char com[COMMAND_BUF];
	int ret;
	GUNSHU_SESSION_INFO gsi;

	SockFrame_SetTimeout(ci,GUNSHU_SESSION_TIMEOUT);
	//乱数の初期化
	srand( (unsigned)time( NULL ) );
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
			if( Command_Forward(&gsi) != TRUE ){
				break;
			}
		//managerによる動作テスト
		}else if(strcmp("test",com) == 0){
			printf("test\n");
			SockFrame_SendLine(ci , "ok");
			break;
		//経路調査
		}else if(strcmp("path",com) == 0){
			printf("path trace.\n");
			if( Command_Path(&gsi) != TRUE){
				break;
			}
		}else{
			printf("unknown command:%s\n", com);
			break;
		}
	}while(1);
	if( SockFrame_IsValidSock(&(gsi.next)) == TRUE ){
		SockFrame_Shutdown(&(gsi.next));
	}
}

int Command_Est(GUNSHU_SESSION_INFO *gsi)
{
	char com[COMMAND_BUF];
	char buf[COMMAND_BUF];
	char *nextHost;
	char (*services)[COMMAND_BUF];
	int i,ret;
	int numList;

	services = NULL;
	printf("establish route.\n");

	//Serviceリスト件数受信
	ret = SockFrame_ReceiveLine(&(gsi->prev),com,COMMAND_BUF);
	numList = atoi(com);
	printf("recv %d service list\n",numList);
	if( numList <= 0 ){
		printf("no service available.\n");
		goto FAIL;
	}
	//Serviceリスト受信
	services = malloc(numList * COMMAND_BUF);
	for( i = 0 ; i < numList ; i++){
		ret = SockFrame_ReceiveLine(&(gsi->prev),*(services + i),COMMAND_BUF); 
		printf("%s\n",*(services+i));
	}
	
	//ServiceリストからServiceを一つランダムに選ぶ
	printf(" numlist = %d\n" , numList );
	if( gunshuInfo.randomChoice == TRUE ){
		//ランダム選択有効
		nextHost = services[(rand() % numList)];
	}else{
		//ランダム選択無効
		nextHost = services[0];
	}
	//選んだServiceに接続
	if( SockFrame_BuildHostPort(&(gsi->next) , nextHost) == FALSE){
		goto FAIL;
	}
	if( SockFrame_Connect(&(gsi->next)) == FALSE){
		goto FAIL;
	}
	//セッションのタイムアウトを設定
	SockFrame_SetTimeout(&(gsi->next) , GUNSHU_SESSION_TIMEOUT);
	//経路確立コマンドを次のサービスに転送
	SockFrame_SendLine(&(gsi->next) , "est");
	printf("sending %d service list.\n" , numList -1);
	//サービス数を一つ減らして送る
	SockFrame_SendLine(&(gsi->next) , _itoa(numList - 1 ,buf, 10));
	for(i = 0; i < numList ; i++){
		//送信先のホスト名は送らない
		if( nextHost != services[i] ){
			SockFrame_SendLine(&(gsi->next) , services[i]);
		}
	}
	//結果待ち
	ret = SockFrame_ReceiveLine(&(gsi->next),com,COMMAND_BUF);
	if( strcmp(com , "ok") == 0 ){
		printf("next service response: ok\n");
		SockFrame_SendLine(&(gsi->prev), "ok");
	}else{
		printf("next service response: fail code %d %s\n",ret,com);
		goto FAIL;
	}

	free(services);
	return TRUE;
FAIL:
	SockFrame_SendLine(&(gsi->prev),"fail");
	free(services);
	return FALSE;
}
void DownlinkTrans(void* gsi_)
{	
	int ret;
	BYTE buf[TRANS_BUFSIZE];
	GUNSHU_SESSION_INFO *gsi;

	gsi = (GUNSHU_SESSION_INFO *)gsi_;
	do{
		ret = _recv(gsi->next.sock,buf,TRANS_BUFSIZE,0);
		if( ret <= 0 ){
			printf("failed to recv from next\n");
			break;
		}
		if( SockFrame_Send(&(gsi->prev),buf,ret) <= 0){
			printf("failed to send to prev\n");
			break;
		}
	}while(1);
	printf("exit DownLinkTrans\n");
	_endthread();
}
void UplinkTrans(void* gsi_)
{
	int ret;
	BYTE buf[TRANS_BUFSIZE];
	GUNSHU_SESSION_INFO *gsi;

	gsi = (GUNSHU_SESSION_INFO *)gsi_;

	//prev → next への通信ループ
	do{
		ret = _recv(gsi->prev.sock,buf,TRANS_BUFSIZE,0);
		if( ret <= 0 ){
			printf("failed to recv from prev\n");
			break;
		}
		if( SockFrame_Send(&(gsi->next),buf,ret) <= 0){
			printf("failed to send to next\n");
			break;
		}
	}while(1);
	printf("exit UpLinkTrans\n");
	_endthread();
}
int Command_Forward(GUNSHU_SESSION_INFO *gsi)
{
	int ret;
	HANDLE hThreads[2];
	HANDLE hThread,hThread2;

	printf("forward mode.\n");
	if( SockFrame_IsValidSock(&(gsi->next)) == FALSE || SockFrame_IsValidSock(&(gsi->prev)) == FALSE){
		printf("invalid socket.\n");
		return FALSE;
	}
	//forwardコマンドを次のサービスに転送
	SockFrame_SendLine(&(gsi->next) , "forward");
	
	//next　→　prevへの通信スレッド
	hThread = (HANDLE)_beginthread(DownlinkTrans, 0, (void*)gsi);
	//prev　→　nextへの通信スレッド
	hThread2 = (HANDLE)_beginthread(UplinkTrans, 0,(void*)gsi);
	//スレッド終了待ち
	hThreads[0] = hThread;
	hThreads[1] = hThread2;
	WaitForMultipleObjects(2 , hThreads , FALSE , INFINITE);
	printf("wait finish.\n");
	//通信失敗したらソケットクローズ
	//SockFrame_Shutdown(&(gsi->prev));
	//SockFrame_Shutdown(&(gsi->next));

	return FALSE;
}


int Command_Path(GUNSHU_SESSION_INFO *gsi)
{
	char buf[TRANS_BUFSIZE];

	//次のサービスにpathコマンド転送
	SockFrame_SendLine(&(gsi->next) , "path");
	do{
		//ホスト名受信
		if( SockFrame_ReceiveLine(&(gsi->next) , buf , TRANS_BUFSIZE) > 0){
			//受信したホスト名を前のサービスに転送
			SockFrame_SendLine(&(gsi->prev) ,buf);
		}else{
			//改行のみなら受信ループを抜ける
			break;
		}
	}while(1);
	//自分のアドレスを前のサービスに送る
	SockFrame_SendLine(&(gsi->prev) , gunshuInfo.myAddr);
	//改行のみで終了
	SockFrame_SendLine(&(gsi->prev) , "");

	return TRUE;
}