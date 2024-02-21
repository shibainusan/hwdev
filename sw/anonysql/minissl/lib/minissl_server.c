#include <stdio.h>
#include <Winsock2.h>
#include <process.h>  
#include "minissl.h"
#include "sockframe.h"
#include "..\..\aicryptolib\src\include\ok_rsa.h"
#include "..\..\aicryptolib\src\include\ok_x509.h"
#include "..\..\aicryptolib\src\include\ok_des.h"
#include "..\..\aicryptolib\src\include\ok_rand.h"

extern int FindClientKey(int *authority , MiniSSL_INFO *ci);

static void AcceptConnections(SOCKET ListeningSocket , MiniSSL_INFO *ci);
static void PreOnClientConnect(void* ci_); 
static int Server_AuthentServer(MiniSSL_INFO *ci);
static int Server_AuthentClientServer(MiniSSL_INFO *ci, int *authority);
static MiniSSL_INFO *DuplicateInfo(MiniSSL_INFO *si);

static SOCKET MiniSSL_listenSock;

#define BUF_SIZE 4096

int MiniSSL_AuthClient(MiniSSL_INFO *ci, int *authority)
{
	unsigned char mode;
	*authority = 0;
	ci->sessionReady = FALSE;

	//自分の秘密鍵が無い場合はエラー
	if(ci->myPrvKey == NULL || ci->myPubKey == NULL){
		return FALSE;
	}
	
	//認証モードを得る
	SockFrame_Receive(ci->si , &mode , 1);
	//要求する認証モードか？
	if( mode != ci->mode ){
		SockFrame_DebugOut("MiniSSL listen: missmatch auth mode.\n" );
		goto FAIL;
	}
	//サーバを認証
	if( mode == AUTHENT_SERVER ){
		if( Server_AuthentServer(ci) != TRUE ){
			goto FAIL;
		}
		ci->sessionReady = TRUE;
		*authority = 0;
		return TRUE;
	//クライアントとサーバを両者認証
	}else if(mode == AUTHENT_CLIENTSERVER){
		if( Server_AuthentClientServer(ci,authority) != TRUE ){
			goto FAIL;
		}
		ci->sessionReady = TRUE;
		return TRUE;
	}else{
		SockFrame_DebugOut("MiniSSL listen: unknown auth mode.\n" );
		goto FAIL;
	}

FAIL:

	return FALSE;
}

int Server_AuthentServer(MiniSSL_INFO *ci)
{
	unsigned char *p;
	unsigned char buf[BUF_SIZE];
	unsigned char dest[BUF_SIZE];
	unsigned char cRnd[CHALLENGE_SIZE];

	//自分の秘密鍵と公開鍵が無いとエラー
	if( ci->sharedKey == NULL  || ci->myPrvKey == NULL || ci->myPubKey == NULL){
		goto FAIL;
	}
	//session共有情報受信
	memset(buf , 0 , BUF_SIZE);
	SockFrame_Receive(ci->si , buf , RSA_KEY_SIZE);
	//サーバ秘密鍵で復号
	memset(dest , 0 , BUF_SIZE);
	RSAprv_doCrypt(RSA_KEY_SIZE ,buf,dest,ci->myPrvKey);
	//復号結果は右詰なので開始位置を合わせる
	p = (dest + RSA_KEY_SIZE) - (SHARED_KEY_SIZE + IV_SIZE + CHALLENGE_SIZE );
	//共有キー取得
	DESkey_set(ci->sharedKey ,SHARED_KEY_SIZE , p);
	//初期ベクタ取得
	p += SHARED_KEY_SIZE;
	DES_set_iv(ci->sharedKey , p);
	//クライアントチャレンジ取得
	p += IV_SIZE;
	memcpy(cRnd , p , CHALLENGE_SIZE);
	//クライアント共有キーでクライアントチャレンジを暗号化
	DES_cbc_encrypt(ci->sharedKey , CHALLENGE_SIZE , cRnd ,cRnd);
	//送り返す
	SockFrame_Send(ci->si , cRnd , CHALLENGE_SIZE);
	//clientOK待ち
	buf[0] = FALSE;
	SockFrame_Receive(ci->si , buf , 1);
	if( buf[0] != TRUE ){
		goto FAIL;
	}
	//serverOK送る
	SockFrame_SendByte(ci->si ,TRUE);
	SockFrame_DebugOut("server authent ok\n");
	return TRUE;

FAIL:
	SockFrame_SendByte(ci->si ,FALSE);
	SockFrame_DebugOut("server authent failed\n");
	return FALSE;
}
int Server_AuthentClientServer(MiniSSL_INFO *ci, int *authority)
{
	unsigned char *p;
	unsigned char buf[BUF_SIZE];
	unsigned char dest[BUF_SIZE];
	unsigned char cRnd[CHALLENGE_SIZE];
	unsigned char sRnd[CHALLENGE_SIZE];

	//自分の秘密鍵と公開鍵が無いとエラー
	if( ci->sharedKey == NULL  || ci->myPrvKey == NULL || ci->myPubKey == NULL){
		goto FAIL;
	}
	//session共有情報受信
	memset(buf , 0 , BUF_SIZE);
	SockFrame_Receive(ci->si , buf , RSA_KEY_SIZE );
	//サーバ秘密鍵で復号
	memset(dest , 0 , BUF_SIZE);
	RSAprv_doCrypt(RSA_KEY_SIZE,buf,dest,ci->myPrvKey);
	//復号結果は右詰なので実際の開始位置に合わせる
	p = (dest + RSA_KEY_SIZE) - (SHARED_KEY_SIZE + IV_SIZE + CHALLENGE_SIZE + CLIENT_NAME_SIZE + 1);
#if MINISSL_TRACE	
	SockFrame_DebugOut("sharedkey,iv,client challenge to server,client name\n");
	HexDump(p , SHARED_KEY_SIZE + IV_SIZE + CHALLENGE_SIZE + CLIENT_NAME_SIZE + 1 );
#endif
	//共有キー取得
	DESkey_set(ci->sharedKey ,SHARED_KEY_SIZE , p);
	//初期ベクタ取得
	p += SHARED_KEY_SIZE;
	DES_set_iv(ci->sharedKey , p);
	//クライアントチャレンジ取得
	p += IV_SIZE;
	memcpy(cRnd , p , CHALLENGE_SIZE);
	//クライアント名取得
	p += CHALLENGE_SIZE;
	MiniSSL_SetClientName(ci , p);
	//クライアント公開キー検索
	if( FindClientKey(authority , ci) != TRUE ){
		SockFrame_DebugOut("no such client(%s) found in ACL.\n",ci->clientName);
		goto FAIL;
	}

	//セッション共有キーでクライアントチャレンジを暗号化
	memset(dest , 0 , BUF_SIZE);
	DES_cbc_encrypt(ci->sharedKey , CHALLENGE_SIZE , cRnd ,dest);
	//サーバチャレンジ生成
	RAND_bytes(sRnd , CHALLENGE_SIZE);
	memcpy(buf , sRnd , CHALLENGE_SIZE);
#if MINISSL_TRACE
	SockFrame_DebugOut("server challenge to client\n");
	HexDump(buf , CHALLENGE_SIZE);
#endif
	//サーバチャレンジをクライアント公開キーで暗号化
	RSApub_doCrypt(CHALLENGE_SIZE , buf , dest + CHALLENGE_SIZE , ci->targetPubKey);
	//送り返す
	SockFrame_Send(ci->si , dest , CHALLENGE_SIZE + RSA_KEY_SIZE);
	//サーバチャレンジ-レスポンス待ち
	SockFrame_Receive(ci->si , buf , CHALLENGE_SIZE);
	//サーバチャレンジ-レスポンス検証
	memset(dest , 0 , BUF_SIZE);
	DES_cbc_decrypt(ci->sharedKey , CHALLENGE_SIZE , buf ,dest);
#if MINISSL_TRACE
	SockFrame_DebugOut("server challenge-response from client\n");
	HexDump(dest , CHALLENGE_SIZE);
#endif
	//チャレンジ－レスポンスが正しいか？
	if( memcmp(sRnd , dest , CHALLENGE_SIZE) != 0 ){
		SockFrame_DebugOut("invalid challenge-response from client.\n");
		goto FAIL;
	}
	//serverOK送る
	SockFrame_SendByte(ci->si ,TRUE);
	SockFrame_DebugOut("client authent by server: ok\n");
	//clientOK待ち
	buf[0] = FALSE;
	SockFrame_Receive(ci->si , buf , 1);
	if( buf[0] != TRUE ){
		goto FAIL;
	}
	SockFrame_DebugOut("server authent by client: ok\n");

	return TRUE;

FAIL:
	SockFrame_SendByte(ci->si ,FALSE);
	SockFrame_DebugOut("client-server authent failed\n");
	return FALSE;
}


MiniSSL_INFO *DuplicateInfo(MiniSSL_INFO *si)
{
	MiniSSL_INFO *res;

	res = malloc(sizeof(MiniSSL_INFO));
	MiniSSL_InitSessionInfo(res);

	res->myPubKey = RSApubkey_dup(si->myPubKey);
	res->myPrvKey = RSAprvkey_dup(si->myPrvKey);
	res->mode = si->mode;
	return res;

}
void AcceptConnections(SOCKET ListeningSocket,MiniSSL_INFO *ci)
{
    struct sockaddr_in sinRemote;
    int nAddrSize = sizeof(sinRemote);
	MiniSSL_INFO *dupCi;

    while (1) {
        SOCKET sd = accept(ListeningSocket, (struct sockaddr*)&sinRemote,
                &nAddrSize);
        if (sd != INVALID_SOCKET) {
			//基本セッション情報を複製する
			dupCi = DuplicateInfo(ci);
			dupCi->si->ip = sinRemote.sin_addr;
			dupCi->si->port = ntohs(sinRemote.sin_port);
			dupCi->si->sock = sd;
			//ワーカスレッドには基本セッション情報のコピーを渡す
            //CreateThread(0, 0, PreOnClientConnect, (void*)ci, 0, &nThreadID);
			_beginthread(PreOnClientConnect , 0 , dupCi);
        }
        else {
			SockFrame_DispLastError();
            return;
        }
    }
}

void PreOnClientConnect(void* ci_) 
{
	MiniSSL_INFO *ci;
	unsigned char mode;

	int authority;

	ci = (MiniSSL_INFO *)ci_;
	SockFrame_DebugOut("connected from %s:%d\n",inet_ntoa(ci->si->ip) , ci->si->port );
	//認証モードを得る
	SockFrame_Receive(ci->si , &mode , 1);
	//要求する認証モードか？
	if( mode != ci->mode ){
		SockFrame_DebugOut("MiniSSL listen: missmatch auth mode.\n" );
		goto FAIL;
	}
	//サーバを認証
	if( mode == AUTHENT_SERVER ){
		if( Server_AuthentServer(ci) != TRUE ){
			goto FAIL;
		}
		ci->sessionReady = TRUE;
		MiniSSL_OnClientConnect(ci,0);
	//クライアントとサーバを両者認証
	}else if(mode == AUTHENT_CLIENTSERVER){
		if( Server_AuthentClientServer(ci,&authority) != TRUE ){
			goto FAIL;
		}
		ci->sessionReady = TRUE;
		MiniSSL_OnClientConnect(ci,authority);
	}else{
		SockFrame_DebugOut("MiniSSL listen: unknown auth mode.\n" );
		goto FAIL;
	}
FAIL:
	MiniSSL_Shutdown(ci);
	MiniSSL_FreeSessionInfo(ci);
	free(ci);
	_endthread();
	return;
}

int MiniSSL_Listen(MiniSSL_INFO *baseSi,unsigned short nPort)
{
	unsigned long nInterfaceAddr = htonl(INADDR_ANY);

	//自分の秘密鍵が無い場合はエラー
	if(baseSi->myPrvKey == NULL || baseSi->myPubKey == NULL){
		return FALSE;
	}

    if (nInterfaceAddr != INADDR_NONE) {
        SOCKET sd = socket(AF_INET, SOCK_STREAM, 0);
        if (sd != INVALID_SOCKET) {
            struct sockaddr_in sinInterface;
            sinInterface.sin_family = AF_INET;
            sinInterface.sin_addr.s_addr = nInterfaceAddr;
            sinInterface.sin_port = htons(nPort);
            if (bind(sd, (struct sockaddr*)&sinInterface,sizeof(struct sockaddr_in)) != SOCKET_ERROR) {
                listen(sd, SOMAXCONN);
                MiniSSL_listenSock = sd;
				SockFrame_DebugOut("listening on port %d\n",nPort);
				AcceptConnections(sd , baseSi);
				return TRUE;
            }
            else {
				SockFrame_DispLastError();
            }
        }
    }
    return FALSE;
}
