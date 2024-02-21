#include "sockframe.h"
#include "..\..\dbtest\metaodbc\odbclib.h"
#include "minissl.h"
#include "..\..\anonysql\authent\anonysql.h"
#include "anonysqllib.h"
#include "gunshu.h"
#include "large_num.h"

#define BUF_SIZE 512
#define MYAPPNAME "Anonysql client 1.0"

static void MultiplexRecord(int len, char *buf, ODBCRecordset *res);
static int GetMyAuthority(MiniSSL_INFO *si);

//認証サーバから自分の権限コードを取得
//失敗時に負の数、成功時に自分の権限コードを返す
int GetMyAuthority(MiniSSL_INFO *si)
{
	int ret;
	int command;

	command = REQUEST_AUTHORITY;
	if( MiniSSL_Send( si ,  (const unsigned char *)&command , sizeof(int)) != sizeof(int) ){
		printf("failed to send request(getauthority).\n");
		return -1;
	}
	if( MiniSSL_Receive( si , (unsigned char *)&ret , sizeof(int)) != sizeof(int) ){
		printf("failed to recv authority code.\n");
		return -1;
	}
	return ret;
}

int AnonysqlInit(void)
{
	SockFrame_Init();
	MiniSSL_Init();
	return TRUE;
}
int AnonysqlInitSession(ANONYSQL_SESSION *as, char *inifile)
{
	int ret;
	char buf[BUF_SIZE],uid[BUF_SIZE],pwd[BUF_SIZE];

	as->status = ANONYSQL_INVALID_SESSION;
	as->accessCert = LN_alloc();
	//認証サーバへの接続を初期化
	MiniSSL_InitSessionInfo(&as->authConn);
	//データサーバへの接続を初期化
	MiniSSL_InitSessionInfo(&as->dataConn);

	//認証サーバの公開キーをセット
	ret = GetPrivateProfileString(MYAPPNAME , "AuthentServerPubKey" , "" , buf , BUF_SIZE , inifile);
	if( MiniSSL_SetTargetPubKey(&as->authConn , buf) != TRUE ){
		goto FAIL;
	}
	//認証サーバアドレスをセット
	ret = GetPrivateProfileString(MYAPPNAME , "AuthentServerAddr" , "" , buf , BUF_SIZE , inifile);
	if( MiniSSL_BuildHostPort(&as->authConn , buf) != TRUE ){
		goto FAIL;
	}
	//クライアントのキーペアをセット
	ret = GetPrivateProfileString(MYAPPNAME , "MyKey" , "" , buf , BUF_SIZE , inifile);
	if( MiniSSL_SetMyPubPrvKey(&as->authConn , buf) != TRUE ){
		goto FAIL;
	}
	//クライアント名をセット
	ret = GetPrivateProfileString(MYAPPNAME , "MyName" , "" , buf , BUF_SIZE , inifile);
	if( MiniSSL_SetClientName(&as->authConn, buf) != TRUE ){
		goto FAIL;
	}

	//データサーバの公開キーをセット
	ret = GetPrivateProfileString(MYAPPNAME , "DataServerPubKey" , "" , buf , BUF_SIZE , inifile);
	if( MiniSSL_SetTargetPubKey(&as->dataConn , buf) != TRUE ){
		goto FAIL;
	}

	//gunshuマネージャのアドレスをセット
	GetPrivateProfileString(MYAPPNAME , "GunshuManager" , "" , buf , BUF_SIZE , inifile);
	Gunshu_SetManagerAddr(buf);
	//転送段数制限を取得
	as->limit = GetPrivateProfileInt(MYAPPNAME , "GunshuLimit" , 0 , inifile);
	//データサーバ名取得
	GetPrivateProfileString(MYAPPNAME , "DataServerAddr" , "" , buf , BUF_SIZE , inifile);
	strcpy( as->dataServerAddr , buf);
	GetPrivateProfileString(MYAPPNAME , "DataServerName" , "" , buf , BUF_SIZE , inifile);
	strcpy( as->dataServerName , buf);
	GetPrivateProfileString(MYAPPNAME , "DatabaseName" , "" , buf , BUF_SIZE , inifile);
	strcpy( as->databaseName , buf);

	//レコード所有者証明書ストアに接続
	GetPrivateProfileString(MYAPPNAME , "CertStoreDataSource" , "" , buf , BUF_SIZE , inifile);
	GetPrivateProfileString(MYAPPNAME , "CertStoreUID" , "" , uid , BUF_SIZE , inifile);
	GetPrivateProfileString(MYAPPNAME , "CertStorePWD" , "" , pwd , BUF_SIZE , inifile);
	if( ConnectDB(&(as->certStore) , buf , uid , pwd) == TRUE ){
		printf("cert store ready.\n");
	}else{
		printf("cert store fail.\n");
		goto FAIL;
	}

	as->status = ANONYSQL_CONNECT_READY;
	return TRUE;
FAIL:
	LN_free(as->accessCert);
	DisconnectDB(&(as->certStore));
	MiniSSL_FreeSessionInfo(&as->dataConn);
	MiniSSL_FreeSessionInfo(&as->authConn);
	return FALSE;
}
int AnonysqlFreeSession(ANONYSQL_SESSION *as)
{
	as->status = ANONYSQL_INVALID_SESSION;
	LN_free(as->accessCert);
	DisconnectDB(&(as->certStore));
	MiniSSL_FreeSessionInfo(&as->dataConn);
	MiniSSL_FreeSessionInfo(&as->authConn);
	return TRUE;
}
int AnonysqlConnect(ANONYSQL_SESSION *as)
{
	SOCK_INFO si;

	if( as->status != ANONYSQL_CONNECT_READY ){
		printf("session is not ready(AnonysqlConnect). status:%d\n",as->status);
		return FALSE;
	}

	//認証サーバに接続
	if( MiniSSL_Connect(&as->authConn , AUTHENT_CLIENTSERVER) == TRUE ){
		printf("encrypted connection to authent server ready.\n");
	}else{
		printf("authent server fail.\n");
		return FALSE;
	}
	//自分の権限確認
	as->authority = GetMyAuthority(&(as->authConn));
	as->authorityPub = LoadAuthorityPubKey(as->authority);

	//データサーバに接続(gunshu)
	if( Gunshu_Connect( &si , as->dataServerAddr , as->limit ) == TRUE ){
		printf("anonymous connection to data server ready.\n");
	}else{
		printf("anonymous connection to data server fail.\n");
		return FALSE;
	}
	//データサーバに接続(minissl)
	*as->dataConn.si = si;
	if( MiniSSL_Auth( &(as->dataConn) , AUTHENT_SERVER) == TRUE ){
		printf("encrypted connection to data server ready.\n");
	}else{
		printf("encrypted connection to data server fail.\n");
		return FALSE;
	}

	as->status = ANONYSQL_CONNECTED;
	return TRUE;
}
int AnonysqlDisconnect(ANONYSQL_SESSION *as)
{
	if( as->status != ANONYSQL_INVALID_SESSION ){
		as->status = ANONYSQL_CONNECT_READY;
	}
	MiniSSL_Shutdown(&as->dataConn);
	MiniSSL_Shutdown(&as->authConn);
	return TRUE;
}
int PostRequest(ANONYSQL_SESSION *as, char *sql, int *response)
{
	int command;
	unsigned char w[LN_MAX];
	int size;

	if( as->status != ANONYSQL_CONNECTED ){
		printf("cant post request under status(%d).\n",as->status);
		return FALSE;
	}
	//認証サーバにアクセス署名要求
	if( BlindSign(&(as->authConn) , sql , as->authorityPub, as->accessCert) != TRUE ){
		printf("failed to recv access cert.\n");
		return FALSE;
	}
	as->status = ANONYSQL_ACCESS_CERT;

	//SQL実行要求送信
	command = SQL_EXEC;
	if( MiniSSL_Send( &(as->dataConn) ,  (const unsigned char *)&command , sizeof(int)) != sizeof(int) ){
		printf("failed to send request(sqlexec).\n");
		goto FAIL;
	}
	//リクエスト証明書サイズ送信
	size = LN_now_byte(as->accessCert);
	if( MiniSSL_Send( &(as->dataConn) ,  (const unsigned char *)&size , sizeof(int)) != sizeof(int) ){
		goto FAIL;
	}
	//リクエスト署名本体送信
	memset(w , 0 , sizeof(w));
	LN_get_num_c(as->accessCert , size , w);
	if( MiniSSL_Send( &(as->dataConn) ,  (const unsigned char *)w , size) != size ){
		printf("failed to send request cert(sqlexec).\n");
		goto FAIL;
	}
	//リクエスト本文サイズ送信
	size = strlen(sql) + 1;	//NULL文字分1バイト足す
	if( MiniSSL_Send( &(as->dataConn) ,  (const unsigned char *)&size , sizeof(int)) != sizeof(int) ){
		goto FAIL;
	}
	//リクエスト本文送信
	if( MiniSSL_Send( &(as->dataConn) ,  (const unsigned char *)sql , size) != size ){
		printf("failed to send plaintext request(sqlexec).\n");
		goto FAIL;
	}
	//レスポンスコード受信
	if( MiniSSL_Receive( &(as->dataConn) , (unsigned char *)response , sizeof(int)) != sizeof(int) ){
		printf("failed to recv response code(sqlexec).\n");
		goto FAIL;
	}
	//レスポンスコードが認証エラー
	if( *response == AUTHENTICATION_FAILED ){
		printf("authentication failed(sqlexec).\n");
		goto FAIL;
	}else if( *response == AUTHORIZATION_FAILED ){
		printf("authorization failed(sqlexec).\n");
		goto FAIL;
	}else if( *response == INVALID_SQL ){
		printf("invalid sql statement(sqlexec).\n");
		goto FAIL;
	}
	return TRUE;
FAIL:
	as->status = ANONYSQL_CONNECTED;
	return FALSE;
}
int AnonysqlExecSelect(ANONYSQL_SESSION *as, char *sql)
{
	int response;
	//リクエスト署名ゲットしてデータサーバにポスト
	if( PostRequest(as , sql ,&response ) != TRUE ){
		return FALSE;
	}
	//コラムヘッダ受信可能かレスポンスコード判定
	if( response == OK_COLUMN_HEADER_FOLLOW ){
		as->status = ANONYSQL_EXEC;
		return TRUE;
	}
	as->status = ANONYSQL_CONNECTED;
	return FALSE;
}

int AnonysqlGetResultColumnName(ANONYSQL_SESSION *as, ODBCRecordset *res)
{
	int i;
	int size;

	//SQL実行済みか？
	if( as->status == ANONYSQL_EXEC){
	}else{
		goto FAIL;
	}

	res->numColumn = -1;

	//カラム数受信
	if( MiniSSL_Receive( &(as->dataConn) , (unsigned char *)&(res->numColumn) , sizeof(int)) != sizeof(int) ){
		printf("failed to recv numColumn.\n");
		goto FAIL;
	}
	//カラム数が多すぎか？
	if( res->numColumn >= MAX_COLUMNS ){
		printf("too much numColumn(%d).\n",res->numColumn);
		goto FAIL;
	}
	//各カラムの情報を取得
	for( i = 0 ; i < res->numColumn ; i++){
		//カラムのデータサイズ
		MiniSSL_Receive( &(as->dataConn) , (unsigned char *)&(res->columnSize[i]) , sizeof(int));
		//if( res->columnSize[i] >= MAX_COLUMN_DATA ){
		//	printf("too large column data size(%d).\n", res->columnSize[i]);
		//	goto FAIL;
		//}
		//カラム名の大きさ
		MiniSSL_Receive( &(as->dataConn) , (unsigned char *)&size , sizeof(int));
		if( size >= MAX_COLUMN_NAME ){
			printf("too large column name size(%d).\n", size);
			goto FAIL;
		}
		//カラム名本体取得
		if( MiniSSL_Receive( &(as->dataConn) , (unsigned char *)res->columnName[i] , size) != size ){
			printf("failed to recv column name(%d).\n",i);
			goto FAIL;
		}
	}
	as->status = ANONYSQL_HEADER;
	return TRUE;
FAIL:
	as->status = ANONYSQL_CONNECTED;
	return FALSE;
}

void MultiplexRecord(int len, char *buf, ODBCRecordset *res)
{
	int i;
	int c = 0;
	char *data;
	
	data = res->data[c];
	for( i = 0 ; i < len ; i++){
		*data = *buf;	//データコピー
		data++;
		if( *buf == '\0' ){	//ヌル文字の場合は次のカラムに
			//フェッチされたコラムデータを計算
			res->columnFetched[c] = strlen(res->data[c]);
			c++;
			data = res->data[c];
		}
		buf++;
	}

}

int AnonysqlFetchResultRow(ANONYSQL_SESSION *as, ODBCRecordset *res)
{
	int com;
	int len;
	char *buf;

	//ヘッダ取得済みか？フェッチ中か？
	if( as->status == ANONYSQL_HEADER || as->status == ANONYSQL_FETCH ){
	}else{
		return -1; //エラーコード
	}
	//行があるか問い合わせ
	MiniSSL_Receive( &(as->dataConn) , (unsigned char *)&com , sizeof(int));
	if( com >= MAX_COLUMN_DATA ){
		printf("failed to detect end of recordset.\n");
		return -1;	//エラーコード
	}
	if( com == REOCRD_FINISHED ){
		as->status = ANONYSQL_CONNECTED;	//SQL実行可能状態にする
		return 0;	//0行フェッチ
	}
	//行データサイズ取得
	MiniSSL_Receive( &(as->dataConn) , (unsigned char *)&len , sizeof(int));
	if( len >= MAX_COLUMN_DATA * res->numColumn ){
		printf("too large row data(%d).\n",len);
		return -1;	//エラーコード
	}
	buf = malloc(len);
	//行本体取得
	if( MiniSSL_Receive( &(as->dataConn) , buf , len) != len){
		printf("failed to recv row data.\n");
		free(buf);
		return -1;
	}
	MultiplexRecord(len , buf , res);

	free(buf);
	as->status = ANONYSQL_FETCH; 
	return 1;	//1行フェッチ

}

int AnonysqlExecInsert(ANONYSQL_SESSION *as, char *sql, int *affectedRows)
{
	int response;
	int len;
	char *cert;

	//影響を受けた行数を初期化
	*affectedRows = 0;

	if( PostRequest(as , sql ,&response ) != TRUE ){
		return FALSE;
	}
	//挿入成功かレスポンスコード判定
	if( response != OK_RECORD_OWNER_CERT_FOLLOW ){
		as->status = ANONYSQL_CONNECTED;
		return FALSE;
	}
	//レコード所有者証明書の大きさを取得
	MiniSSL_Receive( &(as->dataConn) , (unsigned char *)&len , sizeof(int));
	//レコード所有者証明書本体受信
	cert = malloc(len);
	if( MiniSSL_Receive( &(as->dataConn) , cert , len) != len){
		goto FAIL;
	}
	as->status = ANONYSQL_ACCESS_CERT;

	//レコード所有者証明書を保存
	if( SaveRecordOwnerCert(&(as->certStore) , cert, len) != TRUE ){
		goto FAIL;
	}

	free(cert);
	as->status = ANONYSQL_CONNECTED;
	*affectedRows = 1;
	return TRUE;

FAIL:
	free(cert);
	as->status = ANONYSQL_CONNECTED;
	return FALSE;
}

int *AnonysqlExecUpdate(ANONYSQL_SESSION *as, char *sql, int *affectedRows, int *matchedRows)
{
	int response;
	int certsize;
	char *certs = NULL;
	int numCert;
	int *matchedIDs = NULL;
	int *affectedIDs = NULL;
	char tablename[MAX_TABLE_NAME];

	//影響を受けた行数を初期化
	*affectedRows = 0;
	*matchedRows = 0;

	if( PostRequest(as , sql ,&response ) != TRUE ){
		return NULL;
	}
	//挿入成功かレスポンスコード判定
	if( response != OK_RESULT_FOLLOW ){
		goto FAIL;
	}
	//マッチした行数を取得
	if( MiniSSL_Receive( &(as->dataConn) , (unsigned char *)matchedRows , sizeof(int)) != sizeof(int) ){
		printf("failed to recv matched rows(update).\n");
		goto FAIL;
	}
	if( *matchedRows < 0 ){
		as->status = ANONYSQL_CONNECTED;
		goto FAIL;
	}
	matchedIDs = malloc(*matchedRows * sizeof(int));
	affectedIDs = malloc(*matchedRows * sizeof(int));
	//マッチしたIDを受信する
	if( MiniSSL_Receive( &(as->dataConn) , (unsigned char *)matchedIDs , *matchedRows * sizeof(int)) != ((signed)sizeof(int) * (*matchedRows)) ){
		printf("failed to recv matched ids(update).\n");
		goto FAIL;
	}
	certs = malloc(MAX_RECORD_OWNER_CERT * (*matchedRows));
	GetTableNameFromUpdate(sql , tablename);
	certsize = LoadRecordOwnerCerts(as,tablename, matchedIDs, *matchedRows,certs, &numCert);
	if( certsize < 0 ){
		printf("failed to load record owner certs(update).\n");
		goto FAIL;
	}
	//レコード所有者証明書の数を送信
	MiniSSL_Send( &(as->dataConn) ,  (const unsigned char *)&numCert , sizeof(int));
	//レコード所有者証明書本体送信
	if( MiniSSL_Send( &(as->dataConn) ,  certs , certsize) != certsize ){
		printf("failed to send record owner certs(update).\n");
		goto FAIL;
	}
	//影響を受けた行数受信
	MiniSSL_Receive( &(as->dataConn) , (unsigned char *)affectedRows , sizeof(int));
	if( *affectedRows < 0 ){
		goto FAIL;
	}
	//影響を受けたIDを受信
	if(MiniSSL_Receive( &(as->dataConn) , (unsigned char *)affectedIDs , *affectedRows * sizeof(int)) != *affectedRows * (signed)sizeof(int)){
		printf("failed to recv affected ids(update).\n");
		goto FAIL;
	}
	free(matchedIDs);
	free(certs);
	as->status = ANONYSQL_CONNECTED;
	return affectedIDs;	//成功時はaffectedIDsを返すので開放しない。
FAIL:
	free(matchedIDs);
	free(certs);
	free(affectedIDs);	//失敗時はaffectedIDsを開放する
	as->status = ANONYSQL_CONNECTED;
	return NULL;
}
int *AnonysqlExecDelete(ANONYSQL_SESSION *as, char *sql, int *affectedRows, int *matchedRows)
{
	int response;
	int certsize;
	char *certs = NULL;
	int numCert;
	int *matchedIDs = NULL;
	int *affectedIDs = NULL;
	char tablename[MAX_TABLE_NAME];

	//影響を受けた行数を初期化
	*affectedRows = 0;
	*matchedRows = 0;

	if( PostRequest(as , sql ,&response ) != TRUE ){
		return NULL;
	}
	//挿入成功かレスポンスコード判定
	if( response != OK_RESULT_FOLLOW ){
		goto FAIL;
	}
	//マッチした行数を取得
	if( MiniSSL_Receive( &(as->dataConn) , (unsigned char *)matchedRows , sizeof(int)) != sizeof(int) ){
		printf("failed to recv matched rows(delete).\n");
		goto FAIL;
	}
	if( *matchedRows < 0 ){
		as->status = ANONYSQL_CONNECTED;
		goto FAIL;
	}
	matchedIDs = malloc(*matchedRows * sizeof(int));
	affectedIDs = malloc(*matchedRows * sizeof(int));
	//マッチしたIDを受信する
	if( MiniSSL_Receive( &(as->dataConn) , (unsigned char *)matchedIDs , *matchedRows * sizeof(int)) != ((signed)sizeof(int) * (*matchedRows)) ){
		printf("failed to recv matched ids(delete).\n");
		goto FAIL;
	}
	certs = malloc(MAX_RECORD_OWNER_CERT * (*matchedRows));
	GetTableNameFromDelete(sql , tablename);
	certsize = LoadRecordOwnerCerts(as,tablename, matchedIDs, *matchedRows,certs, &numCert);
	if( certsize < 0 ){
		printf("failed to load record owner certs(delete).\n");
		goto FAIL;
	}
	//レコード所有者証明書の数を送信
	MiniSSL_Send( &(as->dataConn) ,  (const unsigned char *)&numCert , sizeof(int));
	//レコード所有者証明書本体送信
	if( MiniSSL_Send( &(as->dataConn) ,  certs , certsize) != certsize ){
		printf("failed to send record owner certs(delete).\n");
		goto FAIL;
	}
	//影響を受けた行数受信
	MiniSSL_Receive( &(as->dataConn) , (unsigned char *)affectedRows , sizeof(int));
	if( *affectedRows < 0 ){
		goto FAIL;
	}
	//影響を受けたIDを受信
	if(MiniSSL_Receive( &(as->dataConn) , (unsigned char *)affectedIDs , *affectedRows * sizeof(int)) != *affectedRows * (signed)sizeof(int)){
		printf("failed to recv affected ids(delete).\n");
		goto FAIL;
	}
	//削除された行のレコード所有者証明書を破棄する
	if( DeleteRecordOwnerCerts(as, tablename, affectedIDs , *affectedRows) != *affectedRows){
		printf("failed to delete local record owner certs(delete).\n");
		//affectedIDsを呼び出し元に返すのでFAILには飛ばない。
	}
	free(matchedIDs);
	free(certs);
	as->status = ANONYSQL_CONNECTED;
	return affectedIDs;	//成功時はaffectedIDsを返すので開放しない。
FAIL:
	free(matchedIDs);
	free(certs);
	free(affectedIDs);	//失敗時はaffectedIDsを開放する
	as->status = ANONYSQL_CONNECTED;
	return NULL;
}	


int AnonysqlBeginTrans(ANONYSQL_SESSION *as)
{
	//トランザクション開始コード送信
	int command = SQL_BEGIN_TRANS;
	if( MiniSSL_Send( &(as->dataConn) ,  (const unsigned char *)&command , sizeof(int)) != sizeof(int) ){
		printf("failed to send request(begintrans).\n");
		return FALSE;
	}
	//レスポンスコード受信
	if( MiniSSL_Receive( &(as->dataConn) , (unsigned char *)&command , sizeof(int)) != sizeof(int) ){
		printf("failed to recv response code(begintrans).\n");
		return FALSE;
	}
	//レスポンスコードが自動コミットモードオフか？
	if( command != AUTOCOMMIT_OFF ){
		printf("invalid response code(begintrans).\n");
		return FALSE;
	}
	return TRUE;
}
int AnonysqlRollback(ANONYSQL_SESSION *as)
{
	//トランザクションロールバックコード送信
	int command = SQL_ROLLBACK_TRANS;
	if( MiniSSL_Send( &(as->dataConn) ,  (const unsigned char *)&command , sizeof(int)) != sizeof(int) ){
		printf("failed to send request(rollback).\n");
		return FALSE;
	}
	//レスポンスコード受信
	if( MiniSSL_Receive( &(as->dataConn) , (unsigned char *)&command , sizeof(int)) != sizeof(int) ){
		printf("failed to recv response code(rollback).\n");
		return FALSE;
	}
	//レスポンスコードが自動コミットモードオンか？
	if( command != AUTOCOMMIT_ON ){
		printf("invalid response code(rollback).\n");
		return FALSE;
	}
	return TRUE;
}
int AnonysqlCommit(ANONYSQL_SESSION *as)
{
	//トランザクションコミットコード送信
	int command = SQL_COMMIT_TRANS;
	if( MiniSSL_Send( &(as->dataConn) ,  (const unsigned char *)&command , sizeof(int)) != sizeof(int) ){
		printf("failed to send request(commit).\n");
		return FALSE;
	}
	//レスポンスコード受信
	if( MiniSSL_Receive( &(as->dataConn) , (unsigned char *)&command , sizeof(int)) != sizeof(int) ){
		printf("failed to recv response code(commit).\n");
		return FALSE;
	}
	//レスポンスコードが自動コミットモードオンか？
	if( command != AUTOCOMMIT_ON ){
		printf("invalid response code(commit).\n");
		return FALSE;
	}
	return TRUE;
}