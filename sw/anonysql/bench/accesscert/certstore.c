#include <windows.h>
#include <stdio.h>
#include "ok_md5.h"
#include "..\..\anonysql\authent\anonysql.h"
#include "anonysqllib.h"
#include "..\..\dbtest\metaodbc\odbclib.h"

static int Hex2Char(char *hex, char *bin);

void SplitRecordOwnerCert(char *cert, char **server, char **database, char **table, int *id, char **sign)
{
	char *p;

	p = cert;
	*server = cert;
	p += (strlen(p) + 1);
	*database = p;
	p += (strlen(p) + 1);
	*table = p;
	p += (strlen(p) + 1);
	*id = atoi(p);
	p += (strlen(p) + 1);
	*sign = p;
}

//証明書ストアからレコード所有者証明書を取得する
//asより有効な証明書ストアDB接続、サーバ名、DB名を取得する。テーブル名tablename、行IDの配列*matchedIDs
//行IDの数matchedRowsそれぞれの条件に合う証明書をcertsに格納する。
//実際に格納された証明書の数はnumCertに格納される。
//certsには最低でもMAX_RECORD_OWNER_CERT * matchedRows分のメモリを確保しておくこと。
//certsには（証明書１の大きさ：32bit）（証明書１本体）....（証明書ｎの大きさ：32bit）（証明書ｎ本体）という形式で格納される
//成功時はcertsの大きさが返る。失敗時は負の数が返る。
int LoadRecordOwnerCerts(ANONYSQL_SESSION *as,char *tablename,int *matchedIDs,int matchedRows,char *certs,int *numCert)
{
	int i;
	ODBCRecordset res;
	char sql[MAX_SQL_SIZE];
	char *topcert;
	char *org_certs;
	int len,certsize;

	org_certs = certs; //certsの先頭アドレスを退避
	*numCert = 0;
	for( i = 0 ; i < matchedRows ; i++){
		//SELECT cert FROM RecordOwnerCert WHERE tablename = '' AND servername = '' AND recordid = '' AND databasename = ''
		//データベースから署名を取得
		sprintf(sql , "SELECT cert FROM RecordOwnerCert WHERE servername like '%s' AND databasename like '%s' AND tablename like '%s' AND recordid like '%d'" , as->dataServerName,as->databaseName,tablename,matchedIDs[i]);
		if( ExecSelect(&(as->certStore) , sql) != TRUE ){
			FreeStatementDB(&(as->certStore));
			return -1;	//エラーコード
		}
		GetResultColumnName(&(as->certStore) , &res);
		if( FetchResultRow(&(as->certStore) , &res) != TRUE ){
			//証明書が無い場合はスキップ
			continue;
		}
		(*numCert)++;
		//レコード所有者証明書を再構成
		topcert = certs;
		certs += sizeof(int);	//証明書サイズを入れるためint分あけておく
		len = strlen(as->dataServerName) + 1;
		memcpy( certs , as->dataServerName , len ); //ヌル文字含めてコピー
		certs += len;
		len = strlen(as->databaseName) + 1;
		memcpy( certs , as->databaseName , len ); //ヌル文字含めてコピー
		certs += len;
		len = strlen(tablename) + 1;
		memcpy( certs , tablename , len ); //ヌル文字含めてコピー
		certs += len;
		len = sprintf(certs , "%d" , matchedIDs[i]) + 1;
		certs += len;
		//署名のコピー
		len = Hex2Char(res.data[0] , certs);
		certs += len;
		//レコード所有者証明書の大きさ計算
		certsize = (certs - topcert) - sizeof(int);
		memcpy(topcert , &certsize, sizeof(int));
		FreeStatementDB(&(as->certStore));
	}
	//certsの大きさ計算
	return (certs - org_certs);
}
int DeleteRecordOwnerCerts(ANONYSQL_SESSION *as,char *tablename,int *affectedIDs ,int affectedRows)
{
	int i;
	int ret;
	int c = 0;	//削除成功した証明書の数
	char sql[MAX_SQL_SIZE];

	for( i = 0 ; i < affectedRows ; i++){
		sprintf(sql , "DELETE RecordOwnerCert WHERE servername like '%s' AND databasename like '%s' AND tablename like '%s' AND recordid like '%d'" , as->dataServerName,as->databaseName,tablename,affectedIDs[i]);
		if( ExecDelete(&(as->certStore) , sql, &ret) != TRUE ){
			continue;
		}
		c += ret;
	}
	return c;
}

//16進ダンプされた文字列hexをchar型配列binに変換する
int Hex2Char(char *hex, char *bin)
{
	int len,i;
	int res;

	len = strlen(hex) / 2;	//2文字づつ1バイトに変換
	for( i = 0 ; i < len ;i++){
		sscanf(hex, "%02x" , &res);
		*bin = res;
		bin++;
		hex += 2;
	}
	return len;
}

int SaveRecordOwnerCert(ODBCConnection *dbc, char *cert, int len)
{
	//証明書：(マシン名：ヌル終端文字列)（データベース名：ヌル終端文字列）（テーブル名：ヌル終端文字列）（ID：ヌル終端文字列）（署名：バイナリ残り全部）
	//各名前を示すポインタ
	char *table,*machine,*database,*id;
	int affectedRows;
	int certsize;
	unsigned char n;
	char *sql;
	char *p,*b;
	int i;

	sql = malloc(len * 2+256);
	p = cert;
	machine = p;
	p += (strlen(machine) +1);
	database = p;
	p += (strlen(database) + 1);
	table = p;
	p += (strlen(table) + 1);
	id = p;
	p += (strlen(id) + 1);
	//署名の大きさを計算する
	certsize = len - (p - cert);
	//SQL文生成
	strcpy(sql , "INSERT RecordOwnerCert(servername,databasename,tablename,recordid,cert) ");
	b = sql + strlen(sql);
	b = b + sprintf(b , "VALUES('%s','%s','%s','%s','", machine, database, table, id );
	//署名を文字列でダンプする
	for( i = 0 ; i < certsize ; i++){
		n = *p;
		b = b + sprintf(b , "%02x" , n );
		p++;
	}
	//かっこ閉じ
	strcpy(b , "')");
	//署名ストアに保存
	if( ExecInsert(dbc, sql, &affectedRows) != TRUE ){
		free(sql);
		return FALSE;
	}
	free(sql);
	return TRUE;
}

int VerifyRecordOwnerCertSign(char *cert ,int size, Pubkey_RSA *key)
{
	char *server, *database, *table;
	int id;
	char *_sign;
	unsigned char _hash[MD5_SIZE];
	LNm *hash,*sign;
	int ret = FALSE;

	SplitRecordOwnerCert(cert , &server, &database, &table, &id, &_sign);
	//ハッシュ計算
	OK_MD5(_sign - cert ,cert , _hash);
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
	return ret;
}