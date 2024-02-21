#ifndef ODBCCONN_LIB
#define ODBCCONN_LIB

#include <sql.h>		   // SDK に付属

typedef struct {
	HENV henv;	//環境ハンドル
	HDBC hdbc;	//接続ハンドル
	HSTMT hstmt;	//ステートメントハンドル
	//int transaction;	//トランザクションネストカウンタ。非トランザクション時は0、トランザクションがネストされるたびにカウントアップ
} ODBCConnection;

#define MAX_COLUMNS 32		//最大コラム数
#define MAX_COLUMN_NAME 256	//最長コラム名
#define MAX_COLUMN_DATA 2048	//最長コラムデータ
#define MAX_TABLE_NAME MAX_COLUMN_NAME

typedef struct {
	int numColumn;	//コラム数
	UCHAR columnName[MAX_COLUMNS][MAX_COLUMN_NAME];	//コラム名
	UDWORD columnSize[MAX_COLUMNS];						//コラムのデータサイズ
	SDWORD columnFetched[MAX_COLUMNS];					//実際にフェッチされたコラムのデータサイズ
	UCHAR data[MAX_COLUMNS][MAX_COLUMN_DATA];			//フェッチされたデータ
} ODBCRecordset;

//ODBCのデータソース名、UID、PWDが書かれた設定ファイルinifileを読み込み
//その情報を元にデータベースに接続する
extern int ConnectDBfromSettingFile(ODBCConnection *dbc,char *inifile);
extern int ConnectDB(ODBCConnection *dbc, UCHAR *source, UCHAR *uid, UCHAR *pwd);
extern void DisconnectDB(ODBCConnection *dbc);
extern void FreeStatementDB(ODBCConnection *dbc);

//有効なDB接続dbc上でSELECTステートメントのSQL文sqlを実行する。
//成功時はステートメントハンドル(hstmt)をdbcにセットしTRUEを返し、
//GetResultColumnNameでコラム名の取得後、FetchResultRowで行データの取得が可能になる。
//失敗時はステートメントハンドルをクローズし、FALSEを返す。
extern int ExecSelect(ODBCConnection *dbc, UCHAR *sql);
//有効なDB接続dbc上でSELECTリクエストを実行後
//レコードセットresに結果のコラム名とコラムのデータサイズを格納する
extern int GetResultColumnName(ODBCConnection *dbc, ODBCRecordset *res);
//有効なデータベース接続dbc上で実行したSELECTリクエストの結果の一行を
//レコードセットresに格納する。
//resのcolumnFetchedに実際にフェッチされたコラムのバイト数、dataにデータが格納される
//この関数の呼出しごとにカーソルは次の行に移動する。
//データ取得に成功の場合はTRUEを返す。
//データ取得に失敗、もしくは結果レコードセットにデータがもう無い場合は
//ステートメントハンドルをクローズし、FALSEを返す。
//この関数の呼び出しでTRUEが返った直後にdbcで違うリクエストを実行する場合は
//FreeStatementDBを呼び出してステートメントハンドルを閉じる必要がある。
extern int FetchResultRow(ODBCConnection *dbc, ODBCRecordset *res);

extern int ExecInsert(ODBCConnection *dbc, UCHAR *sql, int *affectedRows);
extern int ExecInsertIdentity(ODBCConnection *dbc, UCHAR *sql, int *affectedRows, int *newid);
extern int ExecDelete(ODBCConnection *dbc, UCHAR *sql, int *affectedRows);
extern int ExecUpdate(ODBCConnection *dbc, UCHAR *sql, int *affectedRows);

//トランザクションを明示的に開始する。
//初期状態ではautocommitモードなので、1行実行ごとにcommitされる
extern int BeginTransaction(ODBCConnection *dbc);
//明示的に開始したトランザクションを終了し、autocommitモードにする
extern int CommitTransaction(ODBCConnection *dbc);
extern int RollbackTransaction(ODBCConnection *dbc);

extern void PrintSQLerr(ODBCConnection *dbc);
extern void PrintRecordset(ODBCRecordset *r);
extern void PrintColumnName(ODBCRecordset *r);

//レコードの一行rのデータをすべての項目をNULL文字を含めて連結し、バッファretにコピーする
//bufsizeにバッファretの大きさを指定する
//成功時には*outsizeに書き出したバイト数（文字数ではない）を返し、TRUEを返り値として返す
//バッファ不足時は*outsizeは0にセットされ、FALSEを帰り値として返す
extern int SerializeRecord(ODBCRecordset *r, int bufsize, char *ret, int *outsize);
#endif