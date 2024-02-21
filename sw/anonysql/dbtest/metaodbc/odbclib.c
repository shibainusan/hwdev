//ODBCアクセス用ライブラリ

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>
#include <sql.h>		   // SDK に付属
#include <sqlext.h>		// SDK に付属
#include "odbclib.h"

#define BUF_SIZE 256
#define MYAPPNAME "ODBClib 1.0"

static void Space2Null(char *buf);
static void DispLastError(void);
static int ExecDirect(ODBCConnection *dbc, UCHAR *sql);

int ExecDirect(ODBCConnection *dbc, UCHAR *sql)
{
	/* ステートメントハンドルの取得  */
	SQLAllocStmt(dbc->hdbc, &(dbc->hstmt));

	/* SQL ステートメントの実行 */
	if (SQLExecDirect(dbc->hstmt, sql, SQL_NTS) != SQL_SUCCESS) {
		PrintSQLerr(dbc);
		FreeStatementDB(dbc);
		return FALSE;
	}
	FreeStatementDB(dbc);
	return TRUE;
}

int BeginTransaction(ODBCConnection *dbc)
{
	return ExecDirect(dbc , "BEGIN TRANSACTION");
}
int CommitTransaction(ODBCConnection *dbc)
{
	return ExecDirect(dbc , "COMMIT TRANSACTION");
}
int RollbackTransaction(ODBCConnection *dbc)
{
	return ExecDirect(dbc , "ROLLBACK TRANSACTION");
}


void DispLastError(void)
{
	LPVOID lpMsgBuf;
	FormatMessage( FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
				    NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // 既定の言語
					(LPTSTR) &lpMsgBuf, 0, NULL);
	printf("odbclib:%s\n",lpMsgBuf);
	LocalFree(lpMsgBuf);
}

int SerializeRecord(ODBCRecordset *r, int bufsize, char *ret, int *outsize)
{
	int i;
	int c;
	char *org_ret;
	
	org_ret = ret;
	*outsize = 0;

	for( i = 0; i < r->numColumn ; i++){
		//ヌル文字含めてのデータ長
		c = strlen(r->data[i]) + 1;
		bufsize -= c;
		//バッファ不足か？
		if( bufsize < 0 ){
			return FALSE;
		}
		//ヌル文字含めてデータをコピーする
		strcpy(ret , r->data[i]);
		//書き込み先ポインタを進める
		ret += c;
	}
	//書き出したバイト数を計算
	*outsize = ret - org_ret;
	return TRUE;
}

void FreeStatementDB(ODBCConnection *dbc)
{
	SQLFreeStmt(dbc->hstmt, SQL_DROP );
	dbc->hstmt = 0;
}

int ConnectDBfromSettingFile(ODBCConnection *dbc,char *inifile)
{
	int ret;
	UCHAR datasource[BUF_SIZE];
	UCHAR uid[BUF_SIZE];
	UCHAR pwd[BUF_SIZE];

	//設定読み込み
	ret = GetPrivateProfileString(MYAPPNAME , "DataSource" , "" , datasource , BUF_SIZE , inifile);
	ret = GetPrivateProfileString(MYAPPNAME , "UID" , "" , uid , BUF_SIZE , inifile);
	ret = GetPrivateProfileString(MYAPPNAME , "PWD" , "" , pwd , BUF_SIZE , inifile);
	DispLastError();
	//DB接続
	return ConnectDB(dbc , datasource , uid , pwd);
}

int ConnectDB(ODBCConnection *dbc, UCHAR *source, UCHAR *uid, UCHAR *pwd)
{
	RETCODE rc;

	//接続構造体をゼロクリア
	memset(dbc , 0 , sizeof(ODBCConnection));
	//デフォルトで非トランザクションモード
	//dbc->transaction = 0;
	/* 環境および接続ハンドルの取得 */
	SQLAllocEnv(&(dbc->henv));
	SQLAllocConnect(dbc->henv, &(dbc->hdbc));
	/* データソースとの接続		 */
	rc = SQLConnect(dbc->hdbc, source, SQL_NTS, uid, SQL_NTS, pwd, SQL_NTS);
	if (rc != SQL_SUCCESS && rc != SQL_SUCCESS_WITH_INFO) {
		PrintSQLerr( dbc);
		SQLFreeConnect(dbc->hdbc);		   /* Free the connection handle.	  */
		SQLFreeEnv(dbc->henv);			   /* Free the environment handle.	 */
		return FALSE;
	}
	return TRUE;
}

void DisconnectDB(ODBCConnection *dbc)
{
	SQLDisconnect(dbc->hdbc);			/* Disconnect from the data source. */
	SQLFreeConnect(dbc->hdbc);		   /* Free the connection handle.	  */
	SQLFreeEnv(dbc->henv);			   /* Free the environment handle.	 */

	//接続構造体をゼロクリア
	memset(dbc , 0 , sizeof(ODBCConnection));
}

//有効なDB接続dbc上でSELECTステートメントのSQL文sqlを実行する。
//成功時はステートメントハンドル(hstmt)をdbcにセットしTRUEを返し、
//GetResultColumnNameでコラム名の取得後、FetchResultRowで行データの取得が可能になる。
//失敗時はステートメントハンドルをクローズし、FALSEを返す。
int ExecSelect(ODBCConnection *dbc, UCHAR *sql)
{
	/* ステートメントハンドルの取得  */
	SQLAllocStmt(dbc->hdbc, &(dbc->hstmt));

	/* SQL ステートメントの実行 */
	if (SQLExecDirect(dbc->hstmt, sql, SQL_NTS) != SQL_SUCCESS) {
		PrintSQLerr(dbc);
		FreeStatementDB(dbc);
		return FALSE;
	}
	return TRUE;
}

int ExecInsert(ODBCConnection *dbc, UCHAR *sql, int *affectedRows)
{

	*affectedRows = -1;
	/* ステートメントハンドルの取得  */
	SQLAllocStmt(dbc->hdbc, &(dbc->hstmt));

	/* SQL ステートメントの実行 */
	if (SQLExecDirect(dbc->hstmt, sql, SQL_NTS) != SQL_SUCCESS) {
		PrintSQLerr(dbc);
		FreeStatementDB(dbc);
		return FALSE;
	}
	//影響を受けた行数を得る
	SQLRowCount(dbc->hstmt , affectedRows);
	FreeStatementDB(dbc);
	return TRUE;
}
int ExecInsertIdentity(ODBCConnection *dbc, UCHAR *sql, int *affectedRows, int *newid)
{
	int retcode;
	*newid = -1;

	if( ExecInsert(dbc , sql, affectedRows) != TRUE ){
		return FALSE;
	}
	/* ステートメントハンドルの取得  */
	SQLAllocStmt(dbc->hdbc, &(dbc->hstmt));
	/* さっき挿入したレコードのIDを取得 */
	if (SQLExecDirect(dbc->hstmt, "SELECT @@IDENTITY", SQL_NTS) != SQL_SUCCESS) {
		PrintSQLerr(dbc);
		FreeStatementDB(dbc);
		return FALSE;
	}

	retcode = SQLFetch(dbc->hstmt);
	if (retcode == SQL_ERROR) {
		PrintSQLerr(dbc);
		FreeStatementDB(dbc);
		return FALSE;
	}
    if (retcode == SQL_SUCCESS || retcode == SQL_SUCCESS_WITH_INFO){
		SQLGetData(dbc->hstmt, 1, SQL_C_SLONG, newid, sizeof(int), NULL);
	}else{
		PrintSQLerr(dbc);
		FreeStatementDB(dbc);
		return FALSE;
	}

	FreeStatementDB(dbc);
	return TRUE;
}
int ExecDelete(ODBCConnection *dbc, UCHAR *sql, int *affectedRows)
{
	return ExecInsert(dbc , sql , affectedRows);
}
int ExecUpdate(ODBCConnection *dbc, UCHAR *sql, int *affectedRows)
{
	return ExecInsert(dbc , sql , affectedRows);
}

//有効なDB接続dbc上でSELECTリクエストを実行後
//レコードセットresに結果のコラム名とコラムのデータサイズを格納する
int GetResultColumnName(ODBCConnection *dbc, ODBCRecordset *res)
{
	int i;
	SWORD resultcols;
	SWORD   coltype;
	SWORD   colnamelen;
	SWORD   nullable;
	SWORD   scale;

	//コラム数を取得
	SQLNumResultCols(dbc->hstmt, &resultcols);
	res->numColumn = resultcols;

	//各コラムについて処理
	for (i = 0; i < res->numColumn; i++) {
		//コラムの情報問い合わせ
		SQLDescribeCol(dbc->hstmt, (UWORD)(i + 1), res->columnName[i],
				(SWORD)sizeof(res->columnName[i]),
				 &colnamelen, &coltype, &res->columnSize[i], &scale,
				 &nullable);
		//データバッファにバインドする。C文字列に変換。
		SQLBindCol(dbc->hstmt, (UWORD)(i + 1), SQL_C_CHAR, res->data[i],
				 (SWORD)sizeof(res->data[i]), &res->columnFetched[i]);
		//コラム名とサイズを表示
		//printf("%s(%d),", res->columnName[i],res->columnSize[i]);
	}

	return TRUE;
}
void PrintColumnName(ODBCRecordset *r)
{
	int i;

	for( i = 0; i < r->numColumn; i++) {
		printf("%s(%d),", r->columnName[i],r->columnSize[i]);
	}
	printf("\n");
}

//有効なデータベース接続dbc上で実行したSELECTリクエストの結果の一行を
//レコードセットresに格納する。
//resのcolumnFetchedに実際にフェッチされたコラムのバイト数、dataにデータが格納される
//この関数の呼出しごとにカーソルは次の行に移動する。
//データ取得に成功の場合はTRUEを返す。
//データ取得に失敗、もしくは結果レコードセットにデータがもう無い場合は
//ステートメントハンドルをクローズし、FALSEを返す。
//この関数の呼び出しでTRUEが返った直後にdbcで違うリクエストを実行する場合は
//FreeStatementDBを呼び出してステートメントハンドルを閉じる必要がある。
int FetchResultRow(ODBCConnection *dbc, ODBCRecordset *res)
{
	RETCODE rc;	
	int i;

	rc = SQLFetch(dbc->hstmt);
	if (rc == SQL_SUCCESS || rc == SQL_SUCCESS_WITH_INFO) {

		for (i = 0; i < res->numColumn ; i++) {
			//NULL値の場合はヌル文字をセットする
			if (res->columnFetched[i] == SQL_NULL_DATA) {
				lstrcpy(res->data[i], "");
			}
		}
	}else{
		FreeStatementDB(dbc);
		return FALSE;
	}
	return TRUE;
}

void PrintRecordset(ODBCRecordset *r)
{
	int i;
	char buf[MAX_COLUMN_DATA];

	for(i = 0 ; i < r->numColumn ; i++){
		strcpy( buf , r->data[i]);
		Space2Null(buf);
		printf("%s(%d),", buf,r->columnFetched[i]);
	}
	printf("\n");
}

void Space2Null(char *buf)
{
	do{
		if( *buf == '\0' || *buf == ' ' ){
			*buf = '\0';
			break;
		}
		buf++;
	}while(1);
}
/*	  エラー表示					  */
void PrintSQLerr(ODBCConnection *dbc) {
	char errstate[ 1024 ];
	char errmsg[1024 ];
	SDWORD errcode;
	SWORD sz;

	SQLError( dbc->henv, dbc->hdbc, dbc->hstmt,
		errstate, &errcode, errmsg, sizeof( errmsg ), &sz );
	printf( "%s(%d)%*s\n", errstate, errcode, (int)sz, errmsg );
}