#ifndef _SERVER_SOCK_FRAME
#define _SERVER_SOCK_FRAME

#ifndef _WINDOWS_
#include <Winsock2.h>
#endif

//接続してきたクライアントの情報を保持する構造体
typedef struct tag_SOCK_INFO{
	struct in_addr ip;
	unsigned short port;
	SOCKET sock;
} SOCK_INFO;

//もっとも最近に発生したWinsockエラーを表示する
extern void SockFrame_DispLastError(void);

//初期化関数
extern int SockFrame_Init(void);
extern void SockFrame_Cleanup(void);
extern void SockFrame_EnableDebugMessage(void);
extern void SockFrame_DisableDebugMessage(void);

extern int SockFrame_Shutdown(SOCK_INFO *si);
//siが正常に接続済みかを調べる
extern int SockFrame_IsValidSock(SOCK_INFO *si);
extern int SockFrame_DebugOut(const char *format,...);
//サーバ用関数

//nPortに指定されたポート番号でlistenを開始する。
//エラー時にはFALSEを返す
extern int SockFrame_Listen(unsigned short nPort);
//クライアントが接続してきたときのコールバック関数
//ciにクライアントに関する情報が格納される。
extern void SockFrame_OnClientConnect(SOCK_INFO *ci); 

//クライアント用関数
//ホスト名nameをＤＮＳを使ってＩＰアドレスに変換し、siに格納する
extern int SockFrame_LookupAddress(SOCK_INFO *si, const char *name);
//(hostname):(port number)の形式のnameをＤＮＳでＩＰアドレスに変換し、ＩＰとポートをsiに格納する
extern int SockFrame_BuildHostPort(SOCK_INFO *si, const char *name);
//siに指定されているＩＰとポートに接続する。
//失敗時にはFALSE、成功時にはTRUEを返す
extern int SockFrame_Connect(SOCK_INFO *si);

//データ送受信
//エラーメッセージ表示付きrecv&send
extern int _recv(SOCKET s,char *buf,int len,int flags);
extern int _send(SOCKET s,const char *buf,int len,int flags);
//not implemented
extern int SockFrame_WaitForCode(SOCK_INFO *ci,unsigned char *code,int size);
//送受信タイムアウトをミリセカンド単位で指定する
extern void SockFrame_SetTimeout(SOCK_INFO *ci,int timeout);
//dataにsizeバイト分データを受信するまでブロックする。
//dataにはsizeバイト以上のメモリ領域を確保する。
//エラー時には0もしくは負の数を返す。
extern int SockFrame_Receive(SOCK_INFO *ci,BYTE *data,int size);
//dataにあるデータをsizeバイト分送信するまでブロックする。
//dataにはsizeバイト以上のメモリ領域を確保する。
//エラー時には0もしくは負の数を返す。
extern int SockFrame_Send(SOCK_INFO *ci,const BYTE *data,int size);
//テキストを一行受信する。改行コードは削除される。
//改行とヌル文字を除外した、実際に読み込んだバイト数を返す
//エラー時には0もしくは負の数を返す。
//sizeには十分大きなバイト数を指定する事。（3バイト以上）
//呼び出すと、受信失敗でも先頭がヌル文字に書き換えられる。
extern int SockFrame_ReceiveLine(SOCK_INFO *ci,unsigned char *data,int size);
extern int SockFrame_ReceiveLineCRorLF(SOCK_INFO *ci,unsigned char *data,int size);
//文字列dataを渡すと、改行文字（CRLF）を付加して送信する
//エラー時には0もしくは負の数を返す。
extern int SockFrame_SendLine(SOCK_INFO *ci,const char *data);

extern int SockFrame_SendByte(SOCK_INFO *ci,const BYTE data);
#endif