#ifndef _ANONYSQL_HEADER
#define _ANONYSQL_HEADER

#include "large_num.h"
#include "ok_rsa.h"
#include "minissl.h"
#include "..\metaquery\anonysqllib.h"

//プロファイラのオン/オフ
#undef PROFILER_ON
//トレースモードのオン/オフ
#undef TRACE_ON
//リクエスト証明書リプレイモード
#define CERT_REPLAY
//レコード所有者証明書の署名アルゴリズム
#undef RECORD_OWNER_CERT_RSA
#define RECORD_OWNER_CERT_DES
//レコード所有者証明書の最大長
#define MAX_RECORD_OWNER_CERT 2048

//delete/updateで一度に処理できる行数
#define MAX_AFFECT_ROWS 2048

//SQL文の最大長
#ifndef MAX_SQL_SIZE
#define MAX_SQL_SIZE 4096
#endif

//権限コード
#define FULL_ACCESS 1
#define SELECT_ONLY 2

//認証サーバへのコマンド
#define REQUEST_SIGN 0x01		//署名要求
#define REQUEST_AUTHORITY 0x02	//権限確認

//データストアサーバへのコマンド
#define SQL_EXEC 0x01				//SQL文実行
#define SQL_BEGIN_TRANS 0x02		//トランザクション開始
#define SQL_COMMIT_TRANS 0x03		//コミット
#define SQL_ROLLBACK_TRANS 0x04		//ロールバック
#define SQL_BYE 0x05				//セッション終了

//データストアサーバからの応答コード
#define OK_RESULT_FOLLOW 0x01		//update,delete成功
#define AUTHENTICATION_FAILED 0x02	//認証エラー
#define AUTHORIZATION_FAILED 0x03	//認可エラー
#define INVALID_SQL 0x04			//SQL構文エラー
#define OK_COLUMN_HEADER_FOLLOW 0x05	//コラムヘッダ送信開始
#define OK_RECORD_OWNER_CERT_FOLLOW 0x06	//insert成功、レコード証明書送信開始
#define RECORD_OWNER_CERT_REQUEST 0x07		//レコード証明書要求
#define RECORD_FOLLOW 0x08					//レコード本体送信開始
#define REOCRD_FINISHED 0x09				//レコード本体送信終了
#define AUTOCOMMIT_ON 0x0A			//自動コミットモードオン
#define AUTOCOMMIT_OFF 0x0B			//自動コミットモードオフ

#define MD5_SIZE (128/8)
#define LN_EQUAL 0

//以下digisign.c
//署名を検証し、正しければTRUE、不正ならばFALSEを返す
//certに署名、hashにハッシュ、keyに公開キーをセットする
extern int CheckCert(LNm *cert, LNm *hash, Pubkey_RSA *key);
//認証サーバにブラインド署名をしてもらう。成功すればTRUE、失敗ならばFALSEを返す。
//認証サーバへの接続：si、署名したいSQL文：sql、署名検証用公開キー、pubKey,署名結果：cert
extern int BlindSign(MiniSSL_INFO *si , unsigned char *sql,Pubkey_RSA *pubKey, LNm *cert);
//sizeバイト数の署名certと平文requestが正しいか検証する。
//\authorityフォルダ内の権限キーを昇順に使って検証する。
//検証に成功した場合は権限コード（正の整数）を返す。
//失敗した場合は負の整数を返す。
extern int VerifyRequest(int size, UCHAR *_cert, UCHAR *request);

extern Pubkey_RSA *LoadAuthorityPubKey(int authority);
extern Prvkey_RSA *LoadAuthorityPrvKey(int authority);

//以下sql.c
//SQL文の種類を判定する。
//SQL_SELECTもしくはSQL_INSERT、SQL_UPDATE、SQL_DELETEのどれかを返す。
//どれでもないときはFALSEを返す
#define SQL_SELECT 0x01
#define SQL_INSERT 0x02
#define SQL_UPDATE 0x03
#define SQL_DELETE 0x04
extern int CheckSQLType(UCHAR *sql);
//insertもしくはinsert into文_sqlからテーブル名tablenameを切り出す
extern int GetTableNameFromInsert(char *_sql, char *tablename);
//deleteもしくはdelete from文_sqlからテーブル名tablenameを切り出す
extern int GetTableNameFromDelete(char *_sql, char *tablename);
//update文_sqlからテーブル名tablenameを切り出す
extern int GetTableNameFromUpdate(char *_sql, char *tablename);
extern int GetSetClauseFromUpdate(char *_sql,char *setclause);
//Where条件を切り出す
extern int GetWhereCondition(char *_sql, char *condition);
//以下certstore.c
extern void SplitRecordOwnerCert(char *cert, char **server, char **database, char **table, int *id, char **sign);
extern int LoadRecordOwnerCerts(ANONYSQL_SESSION *as,char *tablename,int *matchedIDs,int matchedRows,char *certs,int *numCert);
extern int SaveRecordOwnerCert(ODBCConnection *dbc, char *cert, int len);
extern int DeleteRecordOwnerCerts(ANONYSQL_SESSION *as,char *tablename,int *affectedIDs ,int affectedRows);
#endif
