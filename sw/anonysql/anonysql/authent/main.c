//認証サーバ

#include <stdio.h>
#include "sockframe.h"
#include "minissl.h"

int main()
{
	MiniSSL_INFO si;

	SockFrame_Init();
	//SockFrame_EnableDebugMessage();
	SockFrame_DisableDebugMessage();
	MiniSSL_Init();

	MiniSSL_InitSessionInfo(&si);
	//自分のキーペアを読む
	MiniSSL_SetMyPubPrvKey(&si , "authentprv.key");
	//クライアントACLを読む
	MiniSSL_LoadClientACL();
	//両者認証モード
	si.mode = AUTHENT_CLIENTSERVER;
	//リッスン開始
	MiniSSL_Listen(&si , 19418);
	MiniSSL_FreeSessionInfo(&si);
	MiniSSL_Cleanup();
	SockFrame_Cleanup();
} 