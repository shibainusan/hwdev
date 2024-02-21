#include <windows.h>
#include <stdio.h>
#include "..\anonysql\profiler.h"
#include "..\..\dbtest\metaodbc\odbclib.h"

void InsertTestData(ODBCConnection *dbc, int nrows)
{
	UCHAR   sqlstr[4096];
	int affectedRows = 0;
	int newid;
	int i;
	
	for( i = 0 ; i < nrows ; i++){
		sprintf(sqlstr,"insert into test values('iwatekeniwateguntakizawamura','2003/10/12 10:52:10','555')");
		if( ExecInsertIdentity(dbc , sqlstr , &affectedRows, &newid) != TRUE ){
			exit(-1);
		}
	}
}

int main()
{
	UCHAR   sqlstr[4096];
	int outsize;
	int affectedRows = 0;
	int matched = 0;
	ODBCConnection dbc;
	ODBCRecordset record;
	char statement[10];
	int newid = 0;
	int i,j;
	int nrows;
	int base =0;

	InitProfiler();
	ConnectDBfromSettingFile(&dbc , ".\\odbclib.ini");
	//ConnectDB(&dbc,"jiko","jiko","jiko");

goto _DELETE;

	//連続insert
	//CPU負荷計測開始
	nrows = 1024;
	printf("nrows,time,cpu total,cpu user\n");
	for( j = 1 ; j < 4 ; j++){
		printf("%d,",nrows);
		strcpy(sqlstr,"insert into test values('iwatekeniwateguntakizawamura','2003/10/12 10:52:10','555')");
		StartProfile();
		BeginTime();
		for( i = 0 ; i < nrows ; i++){
			if( ExecInsertIdentity(&dbc , sqlstr , &affectedRows, &newid) != TRUE ){
				exit(-1);
			}
		}
		PrintEndTime();
		PrintCpuUsage();
		printf("\n");
		Sleep(1000);
	}


SELECT:
	//連続Select
	printf("nrows,requests,matched,time,cpu total,cpu user\n");
	for( nrows = 1 ; nrows <= 2048 ; nrows *= 2 ){
		matched = 0;
		StartProfile();
		BeginTime();
		printf("%d,%d,",nrows, (16384/nrows) );
		for( i = 0 ; i < (16384 / nrows) ; i++ ){
			sprintf(sqlstr,"select * from test where id <= %d" , nrows);
			if( ExecSelect(&dbc , sqlstr) != TRUE){
				exit(-1);
			}
			GetResultColumnName(&dbc,&record);
			do{
				//すべての行をフェッチ
				if( FetchResultRow(&dbc,&record) != TRUE ){
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
	//getchar();

UPDATE:
	//連続update
	printf("nrows,requests,matched,time,cpu total,cpu user\n");
	for( nrows = 1 ; nrows <= 2048 ; nrows *= 2 ){
		matched = 0;
		StartProfile();
		BeginTime();
		printf("%d,%d,",nrows, (4096/nrows) );
		for( i = 0 ; i < (4096 / nrows) ; i++ ){
			sprintf(sqlstr,"update test set moji='IWATEKENIWATEGUNTAKIZAWAMURA',jikan='2003/11/9 16:00:00',suuji='999' where id <= %d" , nrows);
			if( ExecUpdate(&dbc , sqlstr, &affectedRows) != TRUE){
				exit(-1);
			}
			matched+=affectedRows;
		}
		printf("%d,",matched);
		PrintEndTime();
		PrintCpuUsage();
		printf("\n");
	}
	getchar();

_DELETE:
	//連続delete

	printf("nrows,requests,matched,time,cpu total,cpu user\n");
	for( nrows = 1 ; nrows <= 2048 ; nrows *= 2 ){
		matched = 0;
		InsertTestData(&dbc,2048);
		StartProfile();
		BeginTime();
		printf("%d,%d,",nrows, (2048/nrows) );
		for( i = 0 ; i < (2048 / nrows) ; i++ ){
			sprintf(sqlstr,"delete from test where id > %d and id <= %d" , nrows*i+base , nrows*(i+1)+base);
			if( ExecDelete(&dbc , sqlstr, &affectedRows) != TRUE){
				exit(-1);
			}
			matched+=affectedRows;
		}
		printf("%d,",matched);
		PrintEndTime();
		PrintCpuUsage();
		printf("\n");
		base += 2048;
	}
	getchar();

#if 0
	while(TRUE) {
		printf( "SQL> " );
		gets( sqlstr );
		if( *sqlstr == 0 ) break;

		strcpy(statement , sqlstr);

		//ステートメントの種類判別
		if( _strnicmp(statement , "select", strlen("select")) == 0){
			ExecSelect(&dbc , sqlstr);
			//検索結果のコラム名を取得
			GetResultColumnName(&dbc,&record);
			PrintColumnName(&record);
			do{
				//すべての行をフェッチして表示
				if( FetchResultRow(&dbc,&record) != TRUE ){
					break;
				}
				PrintRecordset(&record);
				SerializeRecord(&record , 4096 , sr , &outsize);
			}while(1);

		}else if(_strnicmp(statement , "insert", strlen("insert")) == 0){
			ExecInsertIdentity(&dbc , sqlstr , &affectedRows, &newid);
			//影響を受けた行数を表示する
			printf("affected rows:%d, newid:%d \n",affectedRows,newid);
		}else if(_strnicmp(statement , "update", strlen("update")) == 0){
			ExecUpdate(&dbc , sqlstr , &affectedRows);
			printf("affected rows:%d\n",affectedRows);
		}else if(_strnicmp(statement , "delete", strlen("delete")) == 0){
			ExecDelete(&dbc , sqlstr , &affectedRows);
			printf("affected rows:%d\n",affectedRows);
		//トランザクション関係
		}else if(_strnicmp(statement , "begin", strlen("begin")) == 0){
			BeginTransaction(&dbc);
		}else if(_strnicmp(statement , "commit", strlen("commit")) == 0){
			CommitTransaction(&dbc);
		}else if(_strnicmp(statement , "rollback", strlen("rollback")) == 0){
			RollbackTransaction(&dbc);
		}else{
			printf("unknwon statement\n");
		}
	}
#endif
	DisconnectDB(&dbc);
}
