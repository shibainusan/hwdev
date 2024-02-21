#include <stdio.h>
#include "sockframe.h"
#include "minissl.h"
#include "..\..\dbtest\metaodbc\odbclib.h"
#include "anonysqllib.h"

void DumpIDs(int *ids, int numids);

int main()
{
	unsigned char *sql = "select * from “VŒó";
	ANONYSQL_SESSION as;
	ODBCRecordset res;
	UCHAR   sqlstr[ 1024 ];
	UCHAR ret[1024];
	int affected,matched;
	int *affectedIDs = NULL;

	AnonysqlInit();
	SockFrame_EnableDebugMessage();
	AnonysqlInitSession(&as , ".\\anonysql.ini");
	do{
		printf( "SQL> " );
		gets( sqlstr );
		if( *sqlstr == 0 ) break;
	//	GetSetClauseFromUpdate(sqlstr , ret);
	//	printf("'%s'\n",ret);
	//	continue;
		if( strcmp( sqlstr , "con" ) == 0 ){
			AnonysqlConnect(&as);
			continue;
		}
		if( strcmp( sqlstr , "dis" ) == 0 ){
			AnonysqlDisconnect(&as);
			continue;
		}
		if( strcmp( sqlstr , "begin" ) == 0 ){
			AnonysqlBeginTrans(&as);
			continue;
		}
		if( strcmp( sqlstr , "commit" ) == 0 ){
			AnonysqlCommit(&as);
			continue;
		}
		if( strcmp( sqlstr , "rollback" ) == 0 ){
			AnonysqlRollback(&as);
			continue;
		}
		if(_strnicmp(sqlstr , "select", strlen("select")) == 0){
			if( AnonysqlExecSelect(&as,sqlstr) == TRUE ){
				AnonysqlGetResultColumnName(&as,&res);
				PrintColumnName(&res);
				do{
					if( AnonysqlFetchResultRow(&as , &res) <= 0 ){
						break;
					}
					PrintRecordset(&res);
				}while(1);
			}
			continue;
		}
		if(_strnicmp(sqlstr , "insert", strlen("insert")) == 0){
			if( AnonysqlExecInsert(&as,sqlstr,&affected) == TRUE ){
				printf("affected:%d\n",affected);
			}
			continue;
		}
		if(_strnicmp(sqlstr , "delete", strlen("delete")) == 0){
			affectedIDs = AnonysqlExecDelete(&as,sqlstr,&affected,&matched);
			if( affectedIDs == NULL ){
				printf("matched:%d affected:%d\n",matched, affected);
			}else{
				printf("matched:%d affected:%d(",matched, affected);
				DumpIDs(affectedIDs,affected);
				printf(")\n");
				free(affectedIDs);
			}
			
			continue;
		}
		if(_strnicmp(sqlstr , "update", strlen("update")) == 0){
			affectedIDs = AnonysqlExecUpdate(&as,sqlstr,&affected,&matched);
			if( affectedIDs == NULL ){
				printf("matched:%d affected:%d\n",matched, affected);
			}else{
				printf("matched:%d affected:%d(",matched, affected);
				DumpIDs(affectedIDs,affected);
				printf(")\n");
				free(affectedIDs);
			}
			continue;
		}
		printf("ERROR:unknown command\n");
	}while(1);
	//AnonysqlRollback(&as);

	SockFrame_Cleanup();
}
void DumpIDs(int *ids, int numids)
{
	int i;
	for( i = 0 ; i < numids ; i++){
		printf("%d,",*ids);
		ids++;
	}

}