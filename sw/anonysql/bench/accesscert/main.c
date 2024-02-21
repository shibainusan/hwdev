#include <stdio.h>
#include "sockframe.h"
#include "minissl.h"
#include "..\..\dbtest\metaodbc\odbclib.h"
#include "anonysqllib.h"
#include <pdh.h>
#include "ok_rsa.h"
#include "ok_asn1.h"
#include "ok_md5.h"
#define MD5_SIZE (128/8)

void BeginTime(void);
DWORD EndTime(void);
void PrintCpuUsage();

HQUERY hQuery;
HCOUNTER hUsertime,hCputime;
PDH_FMT_COUNTERVALUE FmtValue;
static DWORD timecount;

int main()
{

	unsigned char *sql = "select * from 天候";
	ANONYSQL_SESSION as;
	int i;
	unsigned char buf[SHARED_KEY_SIZE+IV_SIZE];
	unsigned char data[4096];
	unsigned char _hash[MD5_SIZE];
	LNm *hash,*signedHash;
	Prvkey_RSA *key;
	Key_DES *sharedKey;

	//session共有キー生成
	sharedKey = DESkey_new_();
	memset(buf , 0 , SHARED_KEY_SIZE);
	RAND_bytes(buf , SHARED_KEY_SIZE);
	DESkey_set(sharedKey ,SHARED_KEY_SIZE , buf);
	//iv生成
	RAND_bytes(buf +  SHARED_KEY_SIZE, IV_SIZE);
	DES_set_iv(sharedKey , buf + SHARED_KEY_SIZE);

#if 0
	//ハッシュ生成
	hash = LN_alloc();
	signedHash = LN_alloc();
	OK_MD5(strlen(sql) ,sql, _hash);
	LN_set_num_c(hash , MD5_SIZE, _hash);
	buf = ASN1_read_der("denpaprv.key");
	key = ASN1_read_rsaprv(buf);
#endif

	/* 新規クエリーを作成 */
	PdhOpenQuery(NULL, 0, &hQuery);
	PdhAddCounter(hQuery, "\\Processor(_Total)\\% User Time", 0, &hUsertime);
	PdhAddCounter(hQuery, "\\Processor(_Total)\\% Processor Time", 0, &hCputime);

	BeginTime();
	AnonysqlInit();
	SockFrame_DisableDebugMessage();
	//SockFrame_EnableDebugMessage();
	AnonysqlInitSession(&as , ".\\anonysql.ini");
	printf("init session:%d\n",EndTime());
	BeginTime();
	//AnonysqlConnect(&as);
	printf("connect:%d\n",EndTime());

	//CPU負荷計測開始
	PdhCollectQueryData(hQuery);
	BeginTime();
	for( i = 0 ; i < 1000000 ; i++){
#if 0
		//認証サーバにアクセス署名要求
		if( BlindSign(&(as.authConn) , sql , as.authorityPub, as.accessCert) != TRUE ){
			printf("failed to recv access cert.\n");
			return FALSE;
		}
#endif
#if 0
		LN_exp_mod(hash , key->d ,key->n, signedHash );	//署名
		LN_exp_mod(hash , key->e ,key->n, signedHash );	//署名検証
#endif

		DES_cbc_decrypt(sharedKey , 8 , data ,data);
		
	}
	printf("100accesscert:%d\n",EndTime());
	printf("cpu(total,user):");
	PrintCpuUsage();
	AnonysqlDisconnect(&as);

	SockFrame_Cleanup();
	getchar();
}

void BeginTime(void)
{
	timecount = timeGetTime();
}
DWORD EndTime(void)
{
	return (timeGetTime() - timecount);
}
void PrintCpuUsage()
{
	//CPU負荷計測終了
	PdhCollectQueryData(hQuery);
	//total
	PdhGetFormattedCounterValue(hCputime, PDH_FMT_DOUBLE, NULL, &FmtValue);
	printf("%f,", FmtValue.doubleValue);
	//user
	PdhGetFormattedCounterValue(hUsertime, PDH_FMT_DOUBLE, NULL, &FmtValue);
	printf("%f,", FmtValue.doubleValue);
}