/************************************************************************/
/*	  ODBC API サンプルプログラム(2)								  */
/*			  sample2.c						  1998.02.12 J.Baba	*/
/************************************************************************/
/*
	  動的ＳＱＬ（DynamicSQL）の操作例です。
	このプログラムは、固定した SQL 文でなく、実行時に入力した、不特定の
	SQL 文を実行させる事が出来ます。

	ODBC SDK に付属のサンプル(*1)を手直ししたものです。
	VisualC++(4.0/5.0)でコンパイル可能です。

		cl -c sample2.c
		link sample2 odbc32.lib

	入力ループを付加しています。
	不審な方は、SDK のオリジナルを参照して下さい。

	(*1) ODBC SDK 2.10 「Interactive Ad Hoc Query Example」より
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>
#include <sql.h>		   // SDK に付属
#include <sqlext.h>		// SDK に付属
#include "odbclib.h"

void main( int argc, char *argv[] ) {
	UCHAR   sqlstr[ 1024 ];
	char sr[4096];
	int outsize;
	int affectedRows;
	ODBCConnection dbc;
	ODBCRecordset record;
	char statement[10];
	int newid;

	ConnectDBfromSettingFile(&dbc , ".\\odbclib.ini");
	//ConnectDB(&dbc,"jiko","jiko","jiko");

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
	DisconnectDB(&dbc);
}

/************************************************************/
/* 次に示す関数は完璧ではありません						 */
/* しかし、ODBC 関数を理解する上では、支障は無いでしょう	*/
/************************************************************/

#define MAX_NUM_PRECISION 20

/* 数値に必要な文字列の最大を定義する								 */
/*   =  max(precision) + leading sign + E + exp sign + max exp length */
/*   =  15			 + 1			+ 1 + 1		+ 2			  */
/*   =  15 + 5														*/

#define MAX_NUM_STRING_SIZE (MAX_NUM_PRECISION + 5)
#define MAX_DATE_STRING_SIZE 24

UDWORD  display_size(SWORD coltype, UDWORD collen, UCHAR *colname )
{
	switch (coltype) {

	  case SQL_CHAR:
	  case SQL_VARCHAR:
		return collen;

	  case SQL_SMALLINT:
		return 8;

	  case SQL_INTEGER:
		return 20;

	  case SQL_DECIMAL:
	  case SQL_NUMERIC:
	  case SQL_REAL:
	  case SQL_FLOAT:
	  case SQL_DOUBLE:
		return MAX_NUM_STRING_SIZE;

	  case SQL_TIMESTAMP:	   // 追加 J.Baba
		return MAX_DATE_STRING_SIZE;

	  /* 注意 この関数は、core data type しかサポートしていない */
	  default:
		printf("Unknown datatype, %d\n", coltype);
		return(0);
	 }
}



