#include <stdio.h>
#include "sockframe.h"
#include "minissl.h"
#include "..\..\dbtest\metaodbc\odbclib.h"
#include "..\..\anonysql\metaquery\anonysqllib.h"
#include "..\..\anonysql\authent\anonysql.h"
#include "profiler.h"

void DumpIDs(int *ids, int numids);

void InsertTestData(ANONYSQL_SESSION *as, int nrows)
{
	UCHAR sqlstr[4096];
	int affectedRows = 0;
	int i;
	
	for( i = 0 ; i < nrows ; i++){
		sprintf(sqlstr,"insert into test values('iwatekeniwateguntakizawamura','2003/10/12 10:52:10','555')");
		if( AnonysqlExecInsert(as , sqlstr , &affectedRows) != TRUE ){
			exit(-1);
		}
	}
}

void TestInsert(ANONYSQL_SESSION *as)
{
	unsigned char *sql = "insert into test values('iwatekeniwateguntakizawamura','2003/10/12 10:52:10','666')";
	int i;
	int affected = 0;
	int nrows = 1024;
	int j;

	printf("nrows,time,cpu total,cpu user\n");
	//連続insert
	//CPU負荷計測開始
	for( j = 1 ; j < 4 ; j++){
		printf("%d,",nrows);
		StartProfile();
		BeginTime();
		for( i = 0 ; i < nrows ; i++){
			if( AnonysqlExecInsert(as,sql,&affected) != TRUE){
				printf("failed\n");
				exit(-1);
			}
		}
		PrintEndTime();
		PrintCpuUsage();
		printf("\n");
	}
}
void TestSelect(ANONYSQL_SESSION *as)
{
	int i;
	unsigned char sqlstr[4096];
	ODBCRecordset res;
	int matched = 0;
	int nrows = 100;
	
	printf("nrows,requests,matched,time,cpu total,cpu user\n");
	for( nrows = 1 ; nrows <= 2048 ; nrows *= 2 ){
		matched = 0;
		StartProfile();
		BeginTime();
		printf("%d,%d,",nrows, (4096/nrows) );
		sprintf(sqlstr,"select * from test where id <= %d" , nrows);
		for( i = 0 ; i < (4096 / nrows) ; i++ ){
			if( AnonysqlExecSelect(as,sqlstr) != TRUE){
				exit(-1);
			}
			AnonysqlGetResultColumnName(as,&res);
			do{
				//すべての行をフェッチ
				if( AnonysqlFetchResultRow(as , &res) <= 0 ){
					break;
				}
				matched++;
			}while(1);
		}
		printf("%d,",matched);
		PrintEndTime();
		PrintCpuUsage();
		printf("\n");
	}
	getchar();
}
void TestDelete(ANONYSQL_SESSION *as)
{
	int *affectedIDs = NULL;
	unsigned char sqlstr[4096];
	int affected,matched,matchedRows;
	int nrows;
	int i;
	int base = 0;
	
	//連続delete
	printf("nrows,requests,matched,time,cpu total,cpu user\n");
	for( nrows = 1 ; nrows <= 2048 ; nrows *= 2 ){
		InsertTestData(as,2048);
		matched = 0;
		StartProfile();
		BeginTime();
		printf("%d,%d,",nrows, (2048/nrows) );
		for( i = 0 ; i < (2048 / nrows) ; i++ ){
			sprintf(sqlstr,"delete from test where id > %d and id <= %d" , nrows*i+base, nrows*(i+1)+base);
			affectedIDs = AnonysqlExecDelete(as,sqlstr,&affected,&matchedRows);
			if( affectedIDs == NULL){
				exit(-1);
			}
			matched+=affected;
		}
		printf("%d,",matched);
		PrintEndTime();
		PrintCpuUsage();
		printf("\n");
		free(affectedIDs);
		base += 2048;
	}
}
void TestUpdate(ANONYSQL_SESSION *as)
{
	int i;
	unsigned char sqlstr[4096];
	int nrows;
	int matched;
	int affectedRows,matchedRows;
	int *affectedIDs;

	printf("nrows,requests,matched,time,cpu total,cpu user\n");
	for( nrows = 1 ; nrows <= 2048 ; nrows *= 2 ){
		matched = 0;
		StartProfile();
		BeginTime();
		printf("%d,%d,",nrows, (2048/nrows) );
		for( i = 0 ; i < (2048 / nrows) ; i++ ){
			sprintf(sqlstr,"update test set moji='IWATEKENIWATEGUNTAKIZAWAMURA',jikan='2003/11/9 16:00:00',suuji='999' where id <= %d" , nrows);
			affectedIDs = AnonysqlExecUpdate(as , sqlstr, &affectedRows, &matchedRows);
			if(affectedIDs == NULL){
				exit(-1);
			}
			matched+=affectedRows;
		}
		printf("%d,",matched);
		PrintEndTime();
		PrintCpuUsage();
		printf("\n");
		free(affectedIDs);
	}
	getchar();
}

int main()
{
	ANONYSQL_SESSION as;
	char *sql = "select";

	InitProfiler();
	AnonysqlInit();
	AnonysqlInitSession(&as , ".\\anonysql.ini");
	AnonysqlConnect(&as);

	//認証サーバにリクエスト証明書要求
	if( BlindSign(&(as.authConn) , sql , as.authorityPub, as.accessCert) != TRUE ){
		printf("failed to recv access cert.\n");
		exit(-1);
	}

	//TestInsert(&as);
	//TestSelect(&as);
	//TestUpdate(&as);
	TestDelete(&as);
	
	AnonysqlDisconnect(&as);
	SockFrame_Cleanup();
	getchar();
	return 0;
}
void DumpIDs(int *ids, int numids)
{
	int i;
	for( i = 0 ; i < numids ; i++){
		printf("%d,",*ids);
		ids++;
	}

}

void SockFrame_OnClientConnect(SOCK_INFO *ci)
{
}