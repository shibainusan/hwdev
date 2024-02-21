#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "sockframe.h"

#define MYAPPNAME "Gunshu Service 1.1"
#define INI_FILENAME ".\\gunshuservice.ini"
#define SOCK_BUF_SIZE 4096
#define BUF_SIZE 1024

typedef struct{
	char managerAddr[BUF_SIZE];
	char myAddr[BUF_SIZE];
	int randomChoice;
} GUNSHU_SERVICE_INFO;

GUNSHU_SERVICE_INFO gunshuInfo;

void DispLastError(void)
{
	LPVOID lpMsgBuf;
	FormatMessage( FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
				    NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // 既定の言語
					(LPTSTR) &lpMsgBuf, 0, NULL);
	printf("API:%s\n",lpMsgBuf);
	LocalFree(lpMsgBuf);
}
int RegService()
{
	int ret;
	SOCK_INFO si;
	char buf[SOCK_BUF_SIZE];

	printf("registering.\n");
	//マネージャに接続する
	ret = SockFrame_BuildHostPort(&si , gunshuInfo.managerAddr );
	ret = SockFrame_Connect(&si);
	if( ret != TRUE){
		printf("failed to connect manager.\n");
		return FALSE;
	}
	//自分を登録
	SockFrame_SendLine(&si , "reg");
	//自分のアドレスを送信
	SockFrame_SendLine(&si , gunshuInfo.myAddr);
	//結果待ち
	SockFrame_ReceiveLine(&si , buf , SOCK_BUF_SIZE);
	printf("server response:%s\n",buf);
	SockFrame_Shutdown(&si);
	return TRUE;
}

int main(int argc, char **argv)
{
	int ret;

	printf("starting Gunshu Service.\n\n");
	
	//設定読み込み
	ret = GetPrivateProfileString(MYAPPNAME , "ManagerAddr" , "" , (gunshuInfo.managerAddr) , BUF_SIZE , INI_FILENAME);
	ret = GetPrivateProfileString(MYAPPNAME , "MyAddr" , "" , (gunshuInfo.myAddr) , BUF_SIZE , INI_FILENAME);
	gunshuInfo.randomChoice = GetPrivateProfileInt(MYAPPNAME , "RandomChoice" , FALSE , INI_FILENAME);
	DispLastError();

	SockFrame_Init();

	//サービスをマネージャに登録
	if( RegService() != TRUE ){
		getchar();
		return FALSE;
	}

	//サービス起動
	printf("waiting for other Gunshu services.\n");
	SockFrame_Listen(23622);
	SockFrame_Cleanup();
	getchar();
}