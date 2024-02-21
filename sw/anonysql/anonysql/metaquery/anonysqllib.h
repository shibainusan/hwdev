#ifndef _ANONYSQLLIB_HEADER
#define _ANONYSQLLIB_HEADER

#include "ok_rsa.h"
#include "..\..\dbtest\metaodbc\odbclib.h"

//SQL文の最大長
#define MAX_SQL_SIZE 4096

#define __BUF_SIZE 512
typedef struct {
	MiniSSL_INFO authConn,dataConn;	//認証サーバの接続とデータサーバの接続
	LNm *accessCert;			//アクセス証明書
	ODBCConnection certStore;	//レコード所有者証明書保存先
	int status;		//接続状況
	int limit;		//転送段数制限
	int authority;	//自分の権限
	Pubkey_RSA *authorityPub; //権限に対応する公開キー
	char dataServerAddr[__BUF_SIZE];	//データサーバのアドレス（DNS名：ポート番号）
	char databaseName[__BUF_SIZE];
	char dataServerName[__BUF_SIZE];
} ANONYSQL_SESSION;
#undef __BUF_SIZE

//どこでコケたかをstatusでチェック
#define ANONYSQL_INVALID_SESSION -1 //セッション初期化失敗
#define ANONYSQL_CONNECT_READY	0	//接続準備OK
#define ANONYSQL_CONNECTED		1	//認証サーバとデータサーバに接続済み（ステートメント実行可）
//以下ステートメント実行中
#define ANONYSQL_ACCESS_CERT	2	//アクセスチケット取得済み
#define ANONYSQL_EXEC			3	//SQL実行済み
#define ANONYSQL_HEADER			4	//ヘッダ取得済み
#define ANONYSQL_FETCH			5	//データフェッチ中
#define ANONYSQL_OWNER_CERT		6	//

//初期化関数。全ての関数呼び出し前に1度だけ呼び出す
extern int AnonysqlInit(void);
//セッション初期化関数。inifileに設定ファイル名を指定する。
extern int AnonysqlInitSession(ANONYSQL_SESSION *as, char *inifile);
//切断されたセッション情報を完全に破棄する。
//再接続するにはinitsessionからやり直す。
extern int AnonysqlFreeSession(ANONYSQL_SESSION *as);
//セッション初期化成功後に認証とデータサーバに接続する。
extern int AnonysqlConnect(ANONYSQL_SESSION *as);
//セッションを一時切断する。再びconnectすることができる。
extern int AnonysqlDisconnect(ANONYSQL_SESSION *as);
//SELECTステートメント実行。
//実行成功後にGetResultColumnNameでコラム情報を取得し
//FetchResultRowで結果行を取得する。
//すべての行を読み出すまで別のステートメントは実行できない
//行読み出しのキャンセルはdisconnectする必要がある
extern int AnonysqlExecSelect(ANONYSQL_SESSION *as, char *sql);
extern int AnonysqlGetResultColumnName(ANONYSQL_SESSION *as, ODBCRecordset *res);
//失敗時は負の数を返す
//成功時にはフェッチした数を返す
extern int AnonysqlFetchResultRow(ANONYSQL_SESSION *as, ODBCRecordset *res);

extern int AnonysqlExecInsert(ANONYSQL_SESSION *as, char *sql, int *affectedRows);
extern int *AnonysqlExecUpdate(ANONYSQL_SESSION *as, char *sql, int *affectedRows, int *matchedRows);
extern int *AnonysqlExecDelete(ANONYSQL_SESSION *as, char *sql, int *affectedRows, int *matchedRows);
//自動コミットモードからBeginTransで明示コミットモードになる
//同一セッション内でcommitするまではデータベースには変更は加えられない
//トランザクション中にセッションが切断された場合はrollbackされる。
extern int AnonysqlBeginTrans(ANONYSQL_SESSION *as);
extern int AnonysqlRollback(ANONYSQL_SESSION *as);
extern int AnonysqlCommit(ANONYSQL_SESSION *as);

#endif