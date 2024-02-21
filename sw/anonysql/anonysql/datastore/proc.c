#include "sockframe.h"
#include "ok_md5.h"
#include "..\..\dbtest\metaodbc\odbclib.h"
#include "minissl.h"
#include "..\authent\anonysql.h"
#include "gunshu.h"
#include "profiler.h"

int ExecSQLProc(MiniSSL_INFO *si, ODBCConnection *dbc);
int InsertProc(MiniSSL_INFO *si, ODBCConnection *dbc, char *sql);
int SelectProc(MiniSSL_INFO *si, ODBCConnection *dbc, char *sql);
int UpdateProc(MiniSSL_INFO *si, ODBCConnection *dbc, char *sql);
int DeleteProc(MiniSSL_INFO *si, ODBCConnection *dbc, char *sql);
int BuildRecordOwnerCert(char *tablename, int id,Prvkey_RSA *key, char *cert);
int CheckRecordOwnerCert(char *cert,char *tablename,int *matchedIDs,int matchedRow);
int VerifyRecordOwnerCertSign(char *cert ,int size, Pubkey_RSA *key);
int *GetMatchedRows(ODBCConnection *dbc, char *tablename, char *condition, int *matchedRow);

#define BUF_SIZE 512
extern char myName[BUF_SIZE];
extern char databaseName[BUF_SIZE];
extern Key_DES recordOwnerCertKey;

int MiniSSL_OnClientConnect(MiniSSL_INFO *ci,int authority)
{
	return TRUE;
}

int ExecSQLProc(MiniSSL_INFO *si, ODBCConnection *dbc)
{
	int authority; //権限コード
	int response; //応答コード
	int reqCertSize;
	int requestSize;
	UCHAR reqCert[LN_MAX];
	UCHAR request[MAX_SQL_SIZE];
	int operation;

	//とりあえず応答コードを認証エラーにしておく
	response = AUTHENTICATION_FAILED;
	//リクエスト署名サイズ受信
	if( MiniSSL_Receive( si , (unsigned char *)&reqCertSize , sizeof(int)) != sizeof(int) ){
		printf("failed to receive size of request cert.\n");
		goto FAIL;
	}
	if( reqCertSize > LN_MAX ){
		printf("too large request cert size:%d\n",reqCertSize);
		goto FAIL;
	}
	//リクエスト署名本体受信
	if( MiniSSL_Receive( si , reqCert , reqCertSize) != reqCertSize ){
		printf("failed to receive request cert.\n");
		goto FAIL;
	}
	//平文リクエストサイズ受信(null文字含めたバイト数)
	if( MiniSSL_Receive( si , (unsigned char *)&requestSize , sizeof(int)) != sizeof(int) ){
		printf("failed to receive size of plaintext request.\n");
		goto FAIL;
	}
	if( requestSize >= MAX_SQL_SIZE ){
		printf("too large plaintext request:%d bytes.\n",requestSize);
		goto FAIL;
	}
	//平文リクエスト本体受信
	if( MiniSSL_Receive( si , request , requestSize) != requestSize ){
		printf("failed to receive plaintext request.\n");
		goto FAIL;
	}
	//リクエスト署名検証&権限コード取得
	authority = VerifyRequest(reqCertSize , reqCert , request);
	authority = FULL_ACCESS;
#if 0
	if( authority <= 0 ){
		//認証エラー
		response = AUTHENTICATION_FAILED;
		printf("invalid request cert.\n");
		goto FAIL;
	}
#endif
	//リクエスト種別判定
	operation = CheckSQLType(request);
	if( operation == FALSE ){
		//SQL構文エラー
		response = INVALID_SQL;
		goto FAIL;
	}
	//リクエストの種別により分岐
	switch(operation){
	case SQL_SELECT:
		//リクエスト実行の権限はあるか？
		if( authority == FULL_ACCESS || authority == SELECT_ONLY){
			return SelectProc(si , dbc , request);
		}else{
			//無いなら認可エラー
			response = AUTHORIZATION_FAILED;
		}
		break;
	case SQL_UPDATE:
		if( authority == FULL_ACCESS ){
			return UpdateProc(si , dbc , request);
		}else{
			response = AUTHORIZATION_FAILED;
		}
		break;
	case SQL_INSERT:
		if( authority == FULL_ACCESS ){
			return InsertProc(si , dbc , request);
		}else{
			response = AUTHORIZATION_FAILED;
		}
		break;
	case SQL_DELETE:
		if( authority == FULL_ACCESS ){
			return DeleteProc(si , dbc , request);
		}else{
			response = AUTHORIZATION_FAILED;
		}
		break;
	default:
		goto FAIL;
		break;
	}

FAIL:
	//エラーコード送信
	MiniSSL_Send(si ,  (const unsigned char *)&response , sizeof(int));
	return FALSE;
}
int SelectProc(MiniSSL_INFO *si, ODBCConnection *dbc, char *sql)
{
	int i;
	int response;
	ODBCRecordset rs;
	int len;
	UCHAR buf[MAX_COLUMNS * MAX_COLUMN_DATA];

	//sql文実行
	if( ExecSelect(dbc ,sql) != TRUE ){
		//SQL構文エラー
		response = INVALID_SQL;
		MiniSSL_Send(si ,  (const unsigned char *)&response , sizeof(int));
		return FALSE;
	}

	//結果コード返送
	response = OK_COLUMN_HEADER_FOLLOW;
	MiniSSL_Put(si ,  (const unsigned char *)&response , sizeof(int));
	//コラムヘッダ取得
	GetResultColumnName(dbc, &rs);
	//全コラム数送信
	MiniSSL_Put(si , (const unsigned char *)&(rs.numColumn) , sizeof(int));
	//コラム情報送信
	for( i = 0 ; i < rs.numColumn ; i++){
		//コラムのデータサイズ送信
		MiniSSL_Put(si , (const unsigned char *)&(rs.columnSize[i]) , sizeof(int));
		//コラム名の長さ送信
		len = strlen(rs.columnName[i]) + 1; //NULL文字分1バイト足す
		MiniSSL_Put(si , (const unsigned char *)&len , sizeof(int));
		//コラム名送信
		MiniSSL_Put(si , rs.columnName[i] , len);
	}
	//if( MiniSSL_Flush(si) < 0 ){
	//	printf("failed to send column header(select)\n");
	//}

	//row送信
	do{
		//1行フェッチ
		if( FetchResultRow(dbc , &rs) != TRUE ){
			//もう結果行が無い場合
			response = REOCRD_FINISHED;
			MiniSSL_Put(si ,  (const unsigned char *)&response , sizeof(int));
			break;
		}
		//1行送る通知
		response = RECORD_FOLLOW;
		MiniSSL_Put(si ,  (const unsigned char *)&response , sizeof(int));
		//1行をシリアル化
		SerializeRecord(&rs, sizeof(buf) , buf , &len);
		//1行のデータサイズ送信
		MiniSSL_Put(si , (const unsigned char *)&len , sizeof(int));
		//本体送信
		MiniSSL_Put(si , buf , len);
	}while(1);
	if( MiniSSL_Flush(si) < 0 ){
		printf("failed to send recordset(select)\n");
	}
	//次のSQL実行に備え、ステートメントハンドルを閉じる
	FreeStatementDB(dbc);
	return TRUE;
}

int DeleteProc(MiniSSL_INFO *si, ODBCConnection *dbc, char *sql)
{
	int response;
	int *matchedIDs = NULL;	//マッチした行のIDの配列
	char tablename[MAX_TABLE_NAME];	
	char condition[MAX_SQL_SIZE];	//Where条件
	char cert[MAX_RECORD_OWNER_CERT];	//レコード所有者署名
	char tempSql[MAX_SQL_SIZE];		//一行DELETE用テンポラリSQL文
	int matchedRow = 0;				//マッチした行数
	int affectedRow = 0;			//実際にDELETEした行数
	int *affectedIDs = NULL;		//実際にDELETEした行のIDの配列
	int numCert,certSize;			//証明書の数、個々の証明書の大きさ
	int id;
	int ret,i;

	//影響を受ける行を調査
	GetTableNameFromDelete(sql, tablename);
	GetWhereCondition(sql, condition);
	matchedIDs = GetMatchedRows(dbc, tablename, condition, &matchedRow);
	affectedIDs = malloc( matchedRow * sizeof(int));
	if( matchedIDs == NULL ){
		response = INVALID_SQL;
		MiniSSL_Send(si ,  (const unsigned char *)&response , sizeof(int));
		return FALSE;
	}
	//クライアントに結果送信
	response = OK_RESULT_FOLLOW;
	MiniSSL_Put(si ,  (const unsigned char *)&response , sizeof(int));
	//マッチした行数
	MiniSSL_Put(si ,  (const unsigned char *)&matchedRow , sizeof(int));
	//マッチしたIDs
	MiniSSL_Put(si , (const unsigned char *)matchedIDs , sizeof(int) * matchedRow);
	if( MiniSSL_Flush(si) < 0 ){
		printf("failed to send matched rows(delete)\n");
	}

	//権限証明書の数を受信
	MiniSSL_Receive( si , (unsigned char *)&numCert , sizeof(int));
	for( i = 0; i < numCert; i++){
		//権限証明書の大きさ受信
		MiniSSL_Receive( si , (unsigned char *)&certSize , sizeof(int));
		if( certSize >= MAX_RECORD_OWNER_CERT ){
			//飛ばす
			continue;
		}
		//本体受信
		if(MiniSSL_Receive( si , (unsigned char *)&cert , certSize) != certSize ){
			continue;
		}
		//証明書の各項目が要求と合っているか？
		id = CheckRecordOwnerCert(cert,tablename,matchedIDs,matchedRow);
		if( id < 0 ){
			continue;
		}
		//署名チェック
		if( VerifyRecordOwnerCertSign(cert ,certSize, si->myPubKey) == TRUE ){
			//削除実行
			sprintf(tempSql , "DELETE %s WHERE id ='%d'", tablename, id);
			if( ExecDelete(dbc,tempSql,&ret) == FALSE ){
				continue;
			}
			affectedIDs[affectedRow] = id;
			affectedRow += ret;
		}
	}
	//影響を受けた行数を送信
	MiniSSL_Put(si ,  (const unsigned char *)&affectedRow , sizeof(int));
	//影響を受けた行のIDを送信
	MiniSSL_Put(si ,  (const unsigned char *)affectedIDs , sizeof(int) * affectedRow);
	if( MiniSSL_Flush(si) < 0 ){
		printf("failed to send affected rows(delete)\n");
	}
	free(matchedIDs);
	free(affectedIDs);
	return TRUE;
FAIL:
	free(matchedIDs);
	free(affectedIDs);
	return FALSE;
}

int *GetMatchedRows(ODBCConnection *dbc, char *tablename, char *condition, int *matchedRow)
{
	int *ids,*pids;
	char sql[MAX_SQL_SIZE];
	ODBCRecordset res;
	
	*matchedRow = 0;
	//select id from (tablename) where (condition)
	sprintf(sql , "SELECT id FROM %s %s" , tablename , condition);
	if( ExecSelect(dbc , sql) != TRUE){
		return NULL;
	}
	//エントリ確保
	ids = malloc(MAX_AFFECT_ROWS*sizeof(int));
	pids = ids;
	GetResultColumnName(dbc, &res);
	while(1){
		if( FetchResultRow(dbc , &res) != TRUE ){
			break;
		}
		(*matchedRow)++;
		//行のID取得
		*pids = atoi(res.data[0]);
		pids++;
		//マッチする行数が多すぎる場合
		if( *matchedRow >= MAX_AFFECT_ROWS){
			//フェッチ中止
			FreeStatementDB(dbc);
			break;
		}
	}
	return ids;
}
int CheckRecordOwnerCert(char *cert,char *tablename,int *matchedIDs,int matchedRow)
{
	char *cserver,*cdatabase,*ctable,*csign;	//cert内の各要素
	int cid;
	int i;

	SplitRecordOwnerCert(cert, &cserver, &cdatabase, &ctable, &cid, &csign);
	//サーバ名は合っている？
	if( strcmp(cserver, myName) != 0){
		return -1; //エラーコード
	}
	//DB名は合っている？
	if( strcmp(cdatabase, databaseName) != 0){
		return -1; //エラーコード
	}
	//テーブル名は合っている？
	if( strcmp(ctable, tablename) != 0){
		return -1; //エラーコード
	}
	//idはmatchedIDs内にある？
	for( i = 0 ; i < matchedRow ; i++){
		if( *(matchedIDs + i) == cid ){
			return cid;
		}
	}

	return -1;
}

int InsertProc(MiniSSL_INFO *si, ODBCConnection *dbc, char *sql)
{
	char cert[MAX_RECORD_OWNER_CERT];
	int response;
	int len;
	int affected;
	int newid;
	char tablename[MAX_TABLE_NAME];

	//sql文実行
	if( ExecInsertIdentity(dbc ,sql, &affected, &newid) != TRUE ){
		//SQL構文エラー
		response = INVALID_SQL;
		MiniSSL_Send(si ,  (const unsigned char *)&response , sizeof(int));
		return FALSE;
	}
	//1行挿入のみ許可,newid検査
	if( affected != 1 || newid <= 0){
		//SQL構文エラー
		response = INVALID_SQL;
		MiniSSL_Send(si ,  (const unsigned char *)&response , sizeof(int));
		return FALSE;
	}
	//sql文からテーブル名抽出
	GetTableNameFromInsert(sql, tablename);
	//権限証明書生成
	len = BuildRecordOwnerCert(tablename, newid, si->myPrvKey, cert);
	//権限証明書送信
	response = OK_RECORD_OWNER_CERT_FOLLOW;
	MiniSSL_Put(si ,  (const unsigned char *)&response , sizeof(int));
	//証明書サイズ送信
	MiniSSL_Put(si ,  (const unsigned char *)&len , sizeof(int));
	//証明書本体送信
	MiniSSL_Put(si ,  cert , len);
	if( MiniSSL_Flush(si) < 0 ){
		printf("failed to send record owner cert(insert)\n");
	}
	return TRUE;
}


//レコード所有者証明書を生成する（DES版）
//certに証明書本体、帰り値に証明書サイズを返す。
//呼び出し前にcertに十分な大きさのメモリを確保すること
//証明書：(マシン名：ヌル終端文字列)（データベース名：ヌル終端文字列）（テーブル名：ヌル終端文字列）（ID：ヌル終端文字列）（署名：バイナリ残り全部）
int BuildRecordOwnerCert(char *tablename, int id, Prvkey_RSA *key,char *cert)
{
	char *p;
	int size;
	unsigned char _hash[MD5_SIZE];
#ifdef RECORD_OWNER_CERT_RSA
	LNm *hash,*sign;
#endif
#ifdef RECORD_OWNER_CERT_DES
	Key_DES deskey;
#endif

	p = cert;
	//ヌル文字含めてバッファにコピー
	size = strlen(myName)+1;
	memcpy(p,myName, size); p += size;
	size = strlen(databaseName)+1;
	memcpy(p,databaseName, size); p += size;
	size = strlen(tablename)+1;
	memcpy(p,tablename, size); p += size;
	p += (sprintf(p , "%d" , id) + 1);
	//size = sprintf(p,"%s,%s,%s,%d",myName,databaseName,tablename,id);

	//ハッシュ計算
	OK_MD5(p - cert ,cert , _hash);
	//署名
#ifdef RECORD_OWNER_CERT_RSA
	hash = LN_alloc();
	LN_set_num_c(hash , MD5_SIZE, _hash);
	sign = LN_alloc();
	LN_exp_mod(hash , key->d ,key->n, sign );
	size = LN_now_byte(sign);
	LN_get_num_c(sign, size , p);
#ifdef TRACE_ON
	printf("owner cert:");
	LN_print(sign);
#endif
	LN_free(hash);
	LN_free(sign);
#endif
#ifdef RECORD_OWNER_CERT_DES
	//暗号化するごとにIVが変わるので退避する
	deskey = recordOwnerCertKey;
	DES_cbc_encrypt(&deskey , MD5_SIZE , _hash , p);
	size = MD5_SIZE;
#endif

	return (p - cert) + size;
}

int VerifyRecordOwnerCertSign(char *cert ,int size, Pubkey_RSA *key)
{
	char *server, *database, *table;
	int id;
	char *_sign;
	unsigned char _hash[MD5_SIZE];
#ifdef RECORD_OWNER_CERT_RSA
	LNm *hash,*sign;
#endif
#ifdef RECORD_OWNER_CERT_DES
	unsigned char sign[MD5_SIZE];
	Key_DES deskey;
#endif
	int ret = FALSE;

	SplitRecordOwnerCert(cert , &server, &database, &table, &id, &_sign);
	//ハッシュ計算
	OK_MD5(_sign - cert ,cert , _hash);

#ifdef RECORD_OWNER_CERT_RSA
	hash = LN_alloc();
	LN_set_num_c(hash , MD5_SIZE, _hash);
	//署名取得
	sign = LN_alloc();
	LN_set_num_c(sign , (cert + size) - _sign, _sign);
	//署名検証
	if( CheckCert(sign , hash, key) == TRUE ){
		ret = TRUE;
	}
	LN_free(sign);
	LN_free(hash);
#endif
#ifdef RECORD_OWNER_CERT_DES
	//署名検証
	deskey = recordOwnerCertKey;
	DES_cbc_decrypt(&deskey , MD5_SIZE , _sign , sign);
	if( memcmp(_hash , sign, MD5_SIZE) == 0 ){
		ret = TRUE;
	}
#endif

	return ret;
}
int UpdateProc(MiniSSL_INFO *si, ODBCConnection *dbc, char *sql)
{
	int response;
	int *matchedIDs = NULL;	//マッチした行のIDの配列
	char tablename[MAX_TABLE_NAME];	
	char condition[MAX_SQL_SIZE];	//Where条件
	char setclause[MAX_SQL_SIZE];	//set節
	char cert[MAX_RECORD_OWNER_CERT];	//レコード所有者署名
	char tempSql[MAX_SQL_SIZE];		//一行UPDATE用テンポラリSQL文
	int matchedRow = 0;				//マッチした行数
	int affectedRow = 0;			//実際にUPDATEした行数
	int *affectedIDs = NULL;		//実際にUPDATEした行のIDの配列
	int numCert,certSize;			//証明書の数、個々の証明書の大きさ
	int id;
	int ret,i;

	//影響を受ける行を調査
	GetTableNameFromUpdate(sql, tablename);
	GetSetClauseFromUpdate(sql, setclause);
	GetWhereCondition(sql, condition);
	matchedIDs = GetMatchedRows(dbc, tablename, condition, &matchedRow);
	affectedIDs = malloc( matchedRow * sizeof(int));
	if( matchedIDs == NULL ){
		response = INVALID_SQL;
		MiniSSL_Send(si ,  (const unsigned char *)&response , sizeof(int));
		return FALSE;
	}
	//クライアントに結果送信
	response = OK_RESULT_FOLLOW;
	MiniSSL_Put(si ,  (const unsigned char *)&response , sizeof(int));
	//マッチした行数
	MiniSSL_Put(si ,  (const unsigned char *)&matchedRow , sizeof(int));
	//マッチしたIDs
	MiniSSL_Put(si , (const unsigned char *)matchedIDs , sizeof(int) * matchedRow);
	if( MiniSSL_Flush(si) < 0 ){
		printf("failed to send matched rows(update)\n");
	}

	//権限証明書の数を受信
	MiniSSL_Receive( si , (unsigned char *)&numCert , sizeof(int));
	for( i = 0; i < numCert; i++){
		//権限証明書の大きさ受信
		MiniSSL_Receive( si , (unsigned char *)&certSize , sizeof(int));
		if( certSize >= MAX_RECORD_OWNER_CERT ){
			//飛ばす
			continue;
		}
		//本体受信
		if(MiniSSL_Receive( si , (unsigned char *)&cert , certSize) != certSize ){
			continue;
		}
		//証明書の各項目が要求と合っているか？
		id = CheckRecordOwnerCert(cert,tablename,matchedIDs,matchedRow);
		if( id < 0 ){
			continue;
		}
		//署名チェック
		if( VerifyRecordOwnerCertSign(cert ,certSize, si->myPubKey) == TRUE ){
			//更新実行
			sprintf(tempSql , "UPDATE %s %s WHERE id ='%d'", tablename,setclause, id);
			if( ExecUpdate(dbc,tempSql,&ret) == FALSE ){
				continue;
			}
			affectedIDs[affectedRow] = id;
			affectedRow += ret;
		}
	}
	//影響を受けた行数を送信
	MiniSSL_Put(si ,  (const unsigned char *)&affectedRow , sizeof(int));
	//影響を受けた行のIDを送信
	MiniSSL_Put(si ,  (const unsigned char *)affectedIDs , sizeof(int) * affectedRow);
	if( MiniSSL_Flush(si) < 0 ){
		printf("failed to send affected rows(update)\n");
	}
	free(matchedIDs);
	free(affectedIDs);
	return TRUE;
FAIL:
	free(matchedIDs);
	free(affectedIDs);
	return FALSE;
}


void SockFrame_OnClientConnect(SOCK_INFO *ci)
{
	MiniSSL_INFO si;
	int authority;
	int command;
	ODBCConnection dbc;
	int response;

	//gunshuの応答コード
	if( Gunshu_OnClientConnect(ci) != TRUE ){
		return;
	}

	printf("gunshu session established.\n");
	MiniSSL_InitSessionInfo(&si);
	//ソケット情報をコピー
	*si.si =  *ci;
	//自分のキーペアを読む
	MiniSSL_SetMyPubPrvKey(&si , "datastoreprv.key");
	//サーバのみ認証モード
	si.mode = AUTHENT_SERVER;

	//サーバ認証に応答
	if( MiniSSL_AuthClient(&si , &authority) == TRUE ){
	}else{
		MiniSSL_FreeSessionInfo(&si);
		return;
	}

	//ODBC接続
	if( ConnectDBfromSettingFile(&dbc , ".\\odbclib.ini") != TRUE){
		PrintSQLerr(&dbc);
		MiniSSL_FreeSessionInfo(&si);
		FreeStatementDB(&dbc);
		return;
	}
	do{
		//コマンド受信
		if( MiniSSL_Receive( &si , (unsigned char *)&command , sizeof(int)) != sizeof(int) ){
			printf("failed to receive command.\n");
			break;
		}

		//リクエスト実行の場合
		if( command == SQL_EXEC ){
			//エラーがあっても継続
			ExecSQLProc(&si,&dbc);
		//トランザクション制御
		}else if( command == SQL_BEGIN_TRANS){
			BeginTransaction(&dbc);
			response = AUTOCOMMIT_OFF;
			MiniSSL_Send(&si ,  (const unsigned char *)&response , sizeof(int));
		}else if( command == SQL_COMMIT_TRANS){
			CommitTransaction(&dbc);
			response = AUTOCOMMIT_ON;
			MiniSSL_Send(&si ,  (const unsigned char *)&response , sizeof(int));
		}else if( command == SQL_ROLLBACK_TRANS){
			RollbackTransaction(&dbc);
			response = AUTOCOMMIT_ON;
			MiniSSL_Send(&si ,  (const unsigned char *)&response , sizeof(int));
		//セッション終了
		}else if( command == SQL_BYE){
			break;
		//その他認識不能なコマンド
		}else{
			printf("unknown command:%d\n" , command);
			//コネクション切断
			break;
		}
	}while(1);

	//ODBC切断
	DisconnectDB(&dbc);

	MiniSSL_FreeSessionInfo(&si);

}