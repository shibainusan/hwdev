//datastoreサーバ
//とりあえずgunshu無し版
#include <stdio.h>
#include "sockframe.h"
#include "minissl.h"

#define MYAPPNAME "Anonysql dataserver 1.0"
#define BUF_SIZE 512
char myName[BUF_SIZE];
char databaseName[BUF_SIZE];
Key_DES recordOwnerCertKey;

int main()
{
	FILE *fp;
	char buf[SHARED_KEY_SIZE];

	SockFrame_Init();
	MiniSSL_Init();

	//サーバ名取得
	if( GetPrivateProfileString(MYAPPNAME , "MyName" , "" , myName , BUF_SIZE , ".\\anonysql.ini") <= 0){
		printf("failed to load anonysql.ini(MyName)\n");
		return FALSE;
	}
	//データベース名取得
	if( GetPrivateProfileString(MYAPPNAME , "DatabaseName" , "" , databaseName , BUF_SIZE , ".\\anonysql.ini") <= 0){
		printf("failed to load anonysql.ini(DatabaseName)\n");
		return FALSE;
	}

	//レコード所有者証明書署名用DESキー読み込み
	fp = fopen(".\\recordownerdes.key","rb");
	if( fp == NULL ){
		printf("failed to load DES key.\n");
	}else{
		fread(buf , SHARED_KEY_SIZE , 1 , fp);
		DESkey_set(&recordOwnerCertKey , SHARED_KEY_SIZE , buf);
		fread(buf , IV_SIZE , 1 , fp);
		DES_set_iv(&recordOwnerCertKey , buf);
		fclose(fp);
	}

	//リッスン開始
	SockFrame_Listen(19419);
	MiniSSL_Cleanup();
	SockFrame_Cleanup();
} 