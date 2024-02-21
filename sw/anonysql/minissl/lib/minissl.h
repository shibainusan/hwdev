#ifndef MINISSL_LIB
#define MINISSL_LIB

#include "sockframe.h"
#include "..\..\aicryptolib\src\include\ok_rsa.h"
#include "..\..\aicryptolib\src\include\ok_x509.h"
#include "..\..\aicryptolib\src\include\ok_des.h"

//認証モード
#define AUTHENT_SERVER 0x01
#define AUTHENT_CLIENTSERVER 0x02

#define CLIENT_NAME_SIZE 16
#define MiniSSL_ACL_MAX 32

#define SHARED_KEY_SIZE (64/8)
#define IV_SIZE 8
#define RSA_KEY_SIZE (1024/8)
#define CHALLENGE_SIZE (128/8)
#define MiniSSL_BUF_SIZE 65536	//送受信バッファサイズ
#define RECORD_HEADER 4		//レコードヘッダ

//MiniSSLセッションの情報を保持する構造体
typedef struct tag_MiniSSL_INFO{
	SOCK_INFO *si;
	Key_DES *sharedKey; //セッション共有キー
	Pubkey_RSA *targetPubKey; //接続相手の公開キー
	Pubkey_RSA *myPubKey;
	Prvkey_RSA *myPrvKey;
	char clientName[CLIENT_NAME_SIZE+1];
	int sessionReady; //認証完了フラグ
	int mode; //認証モード
	//int authority;

	unsigned char recvbuf[MiniSSL_BUF_SIZE+SHARED_KEY_SIZE+RECORD_HEADER]; //受信バッファ
	unsigned char *recvpos; //受信バッファ中の位置
	unsigned char *recvbufLimit; //受信バッファ終端位置
	int recvBytes; //レコードレベルの未受信バイト数
	unsigned char sendbuf[MiniSSL_BUF_SIZE+SHARED_KEY_SIZE+RECORD_HEADER];
	unsigned char naglebuf[MiniSSL_BUF_SIZE];
	int nagleByte;
} MiniSSL_INFO;


//初期化関数(共通)
extern int MiniSSL_Init(void);
extern void MiniSSL_Cleanup(void);
//自分の公開鍵と秘密鍵をファイルfilenameから読み込みsiにセットする
extern int MiniSSL_SetMyPubPrvKey(MiniSSL_INFO *si,char *filename);
//セッション情報構造体siを初期化する
extern void MiniSSL_InitSessionInfo(MiniSSL_INFO *si);
extern void MiniSSL_FreeSessionInfo(MiniSSL_INFO *si);
extern int MiniSSL_Shutdown(MiniSSL_INFO *si);

//初期化関数（サーバ用）
//クライアント認証用のアクセスコントロールリストを読み込む
//カレントディレクトリのaclフォルダにアクセスコントロールリストを記述した
//acl.txtと公開キーファイルを置く。
//公開キーはacl.txt内のクライアント名+.keyというファイル名
//acl.txtの書式
//(クライアント名),(権限コード）（改行）
extern int MiniSSL_LoadClientACL(void);
extern int MiniSSL_Listen(MiniSSL_INFO *baseSi,unsigned short port);
//クライアントが接続してきたときのコールバック
extern int MiniSSL_OnClientConnect(MiniSSL_INFO *ci,int authority);
//自前でソケットを用意した場合の認証関数
//ciに自分のキーペアと認証モードをセットする
extern int MiniSSL_AuthClient(MiniSSL_INFO *ci, int *authority);

//初期化関数（クライアント用）
//接続＆認証
extern int MiniSSL_Connect(MiniSSL_INFO *si,unsigned char mode);
//接続は自前。認証のみ
//siにクライアントのソケットをsi->siにセットし、自分のキーペアと認証モードをセットする
extern int MiniSSL_Auth(MiniSSL_INFO *si,unsigned char mode);
//サーバ認証用の公開鍵をファイルfilenameから読み込み、siにセットする
extern int MiniSSL_SetTargetPubKey(MiniSSL_INFO *si, char *filename);
extern int MiniSSL_BuildHostPort(MiniSSL_INFO *si, const char *name);
extern int MiniSSL_SetClientName(MiniSSL_INFO *si, char *name);
//データ送受信
//not implemented
extern int MiniSSL_WaitForCode(MiniSSL_INFO *ci,unsigned char *code,int size);
//dataにsizeバイト分データを受信するまでブロックする。
//dataにはsizeバイト以上のメモリ領域を確保する。
//エラー時には0もしくは負の数を返す。
extern int MiniSSL_Receive(MiniSSL_INFO *ci,BYTE *data,int size);
//dataにあるデータをsizeバイト分送信するまでブロックする。
//dataにはsizeバイト以上のメモリ領域を確保する。
//エラー時には0もしくは負の数を返す。
extern int MiniSSL_Send(MiniSSL_INFO *ci,const BYTE *data,int size);
//dataにあるデータをsizeバイト分内部バッファに格納する（送信はしない）
//dataにはsizeバイト以上のメモリ領域を確保する。
//エラー時には0もしくは負の数を返す。
//バッファのデータはMiniSSL_Flushですべて送信される。
extern int MiniSSL_Put(MiniSSL_INFO *ci,const BYTE *data,int size);
extern int MiniSSL_Flush(MiniSSL_INFO *ci);
//テキストを一行受信する。
//改行とヌル文字を除外した、実際に読み込んだバイト数を返す
//エラー時には0もしくは負の数を返す。
//sizeには十分大きなバイト数を指定する事。（3バイト以上）
//呼び出すと、受信失敗でも先頭がヌル文字に書き換えられる。
extern int MiniSSL_ReceiveLine(MiniSSL_INFO *ci,unsigned char *data,int size);
extern int MiniSSL_ReceiveLineCRorLF(MiniSSL_INFO *ci,unsigned char *data,int size);
//文字列dataを渡すと、改行文字（CRLF）を付加して送信する
//エラー時には0もしくは負の数を返す。
extern int MiniSSL_SendLine(MiniSSL_INFO *ci,const char *data);
extern int MiniSSL_SendByte(MiniSSL_INFO *ci,const BYTE data);

//その他証明書操作ライブラリ
extern Pubkey_RSA *ASN1_read_rsapub(unsigned char *in);
#endif