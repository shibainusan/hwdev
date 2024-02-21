#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "sockframe.h"
#include "gunshu.h"

#define MYAPPNAME "Gunshu Initiator 1.1"
#define SOCK_BUF_SIZE 4096
#define BUF_SIZE 1024

typedef char ServiceName[BUF_SIZE];

static SOCK_INFO managerSock;

void DispLastError(void)
{
	LPVOID lpMsgBuf;
	FormatMessage( FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
				    NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // 既定の言語
					(LPTSTR) &lpMsgBuf, 0, NULL);
	printf("API:%s\n",lpMsgBuf);
	LocalFree(lpMsgBuf);
}

int Gunshu_SetManagerAddr(const char *addr)
{
	//乱数ジェネレータ初期化
	srand( (unsigned)time( NULL ) );

	//DNSで名前解決＆ポート番号分離
	if(SockFrame_BuildHostPort(&managerSock , addr) != TRUE){
		return FALSE;
	}
	return TRUE;
}
int Gunshu_LoadSetting(const char *filename)
{
	int ret;
	char buf[BUF_SIZE];

	//managerのアドレスを取得
	ret = GetPrivateProfileString(MYAPPNAME , "ManagerAddr" , "" , buf , BUF_SIZE , filename);
	if(ret == 0){
		DispLastError();
		return FALSE;
	}

	return Gunshu_SetManagerAddr(buf);
}
//managerに接続してserviceリストを取得する
//siには事前にmanagerのＩＰとポート番号を指定する。
//snにはメモリが確保されるので、呼び出し側でfreeすること。
//失敗時に０以下、成功時にservice個数を返す
int GetServiceList(SOCK_INFO *si, ServiceName **sn)
{
	char buf[BUF_SIZE];
	int numList = 0;
	int i;
	
	//managerに接続
	if( SockFrame_Connect(si) != TRUE){
		printf("failed to connect to manager.\n");
		return FALSE;
	}
	//コマンド発行
	SockFrame_SendLine(si , "list");
	//全リスト件数を得る
	SockFrame_ReceiveLine(si , buf , BUF_SIZE);
	numList = atoi(buf);
	if( numList == 0){
		return 0;
	}
	printf("recv %d service list\n",numList);

	*sn = (ServiceName *)malloc(numList * sizeof(ServiceName));
	//serviceリスト本文受信
	for( i = 0 ; i < numList ; i++){
		SockFrame_ReceiveLine(si , buf , BUF_SIZE);
		if( *buf == '\0'){
			free(*sn);
			*sn = NULL;
			SockFrame_Shutdown(si);
			return 0;
		}
		strcpy((char *)(*sn + i) , buf);
	}
	SockFrame_Shutdown(si);
	return numList;
}

int Gunshu_Connect(SOCK_INFO *si,const char *responderAddr, int limit)
{
	ServiceName *sn,*nextService;
	int ret;
	int i;
	int numService;
	char buf[BUF_SIZE];

	//転送段数0の場合はレスポンダに直接接続
	if(limit == 0){
		nextService = responderAddr;
		numService = 0;
		sn = NULL;
		goto CONNECT;
	}
	ret = GetServiceList(&managerSock , &sn);
	if( ret <= 0){
		return FAIL_GET_SERVICE;
	}
	numService = __min(ret , limit);
	//ランダムに接続するサービスを選択する
	nextService = sn + (rand() % numService);

CONNECT:
	if(SockFrame_BuildHostPort(si , (const char *)nextService) != TRUE){
		return FAIL_RESOLVE_NEXT_SERVICE;
	}
	//サービスに接続
	if( SockFrame_Connect(si) != TRUE){
		return FAIL_CONNNECT_SERVICE;
	}
	//経路確立要求送信
	SockFrame_SendLine(si , "est");
	//serveiceリスト総数送信
	SockFrame_SendLine(si , _itoa(numService ,buf, 10 ));

	//serviceリスト本文送信
	for( i = 0 ; i < numService ; i++){
		//送信先のホスト名は送らない
		if( nextService != sn + i ){
			if( SockFrame_SendLine(si , (const char *)(sn + i)) <= 0){
				free(sn);
				sn = NULL;
				SockFrame_Shutdown(si);
				return FAIL_SEND_SERVICE_LIST;
			}
		}
	}
	//responderアドレス送信
	if( numService > 0 ){
		SockFrame_SendLine(si , responderAddr);	
	}
	//返答待ち
	SockFrame_ReceiveLine(si , buf , BUF_SIZE);
	if( strcmp(buf , "ok" ) != 0){
		free(sn);
		printf("gunshu est failed.\n");
		return RESPONSE_FAIL;
	}
	free(sn);
	//pathコマンドで経路調査
	SockFrame_SendLine(si , "path");
	printf("path:");
	do{
		if( SockFrame_ReceiveLine(si , buf , BUF_SIZE) > 0){
			printf("%s - ",buf);
		}else{
			break;
		}
	}while(1);
	printf("initiator \n");
	//forwardモードへ
	SockFrame_SendLine(si , "forward");
	return TRUE;
}

