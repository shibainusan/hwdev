#ifndef _GUNSHU_INITIATOR
#define _GUNSHU_INITIATOR

#ifndef _WINDOWS_
#include <Winsock2.h>
#endif

#include "sockframe.h"

typedef struct {
	SOCK_INFO prev,next;
} GUNSHU_SESSION_INFO;

extern int Gunshu_LoadSetting(const char *filename);
extern int Gunshu_SetManagerAddr(const char *addr);

#define FAIL_GET_SERVICE -10
#define FAIL_RESOLVE_NEXT_SERVICE -11
#define FAIL_CONNNECT_SERVICE -12
#define FAIL_SEND_SERVICE_LIST -13
#define RESPONSE_FAIL -14

//匿名通信路セッションを開く
//limitに最大転送段数を設定する。0を指定した場合はManagerにアクセスせず
//レスポンダに直接接続する
extern int Gunshu_Connect(SOCK_INFO *si,const char *responderAddr, int limit);
//call in SockFrame_OnClientConnect();
//gunshu endpointの応答コード
//転送モードに移行し、データ送受信ができる状態になればTRUEを返す
extern int Gunshu_OnClientConnect(SOCK_INFO *ci);
#endif