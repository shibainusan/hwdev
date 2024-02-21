#ifndef _CLIENT_SOCK_FRAME
#define _CLIENT_SOCK_FRAME

//クライアント用関数
#include <Winsock2.h>

//接続してきたクライアントの情報を保持する構造体
typedef struct tag_SERVER_INFO{
	struct in_addr ip;
	int port;
	SOCKET sock;
} SERVER_INFO;

//もっとも最近に発生したWinsockエラーを表示する
extern void SockFrame_DispLastError(void);

//初期化関数
extern int SockFrame_ServerInit(void);
extern void SockFrame_ServerCleanup(void);

//コネクション関数
//nPortに指定されたポート番号でlistenを開始する。
extern int SockFrame_Listen(unsigned short nPort);

extern int SockFrame_BuildServerInfo(SERVER_INFO *si,const char *addrstring);

//データ送受信
//not implemented
extern int SockFrame_WaitForCode(SERVER_INFO *ci,unsigned char *code,int size);
//送受信タイムアウトをミリセカンド単位で指定する
extern void SockFrame_SetTimeout(SERVER_INFO *ci,int timeout);
//dataにsizeバイト分データを受信するまでブロックする。
//dataにはsizeバイト以上のメモリ領域を確保する。
extern int SockFrame_Receive(SERVER_INFO *ci,BYTE *data,int size);
//dataにあるデータをsizeバイト分送信するまでブロックする。
//dataにはsizeバイト以上のメモリ領域を確保する。
extern int SockFrame_Send(SERVER_INFO *ci,const BYTE *data,int size);
//テキストを一行受信する。
//改行とヌル文字を除外した、実際に読み込んだバイト数を返す
//sizeには十分大きなバイト数を指定する事。（3バイト以上）
extern int SockFrame_ReceiveLine(SERVER_INFO *ci,unsigned char *data,int size);
//文字列dataを渡すと、改行文字（CRLF）を付加して送信する
extern int SockFrame_SendLine(SERVER_INFO *ci,const char *data);
#endif