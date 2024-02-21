#include <stdio.h>
#include <stdlib.h>
#include "minissl.h"
#include "..\authent\anonysql.h"

//SQL文の種類を判定する。
//SQL_SELECTもしくはSQL_INSERT、SQL_UPDATE、SQL_DELETEのどれかを返す。
//どれでもないときはFALSEを返す
int CheckSQLType(UCHAR *sql)
{
	//大文字小文字区別なしで部分文字列を比較
	if( _strnicmp(sql , "SELECT" , strlen("SELECT")) == 0){
		return SQL_SELECT;
	}
	if( _strnicmp(sql , "INSERT" , strlen("INSERT")) == 0){
		return SQL_INSERT;
	}
	if( _strnicmp(sql , "UPDATE" , strlen("UPDATE")) == 0){
		return SQL_UPDATE;
	}
	if( _strnicmp(sql , "DELETE" , strlen("DELETE")) == 0){
		return SQL_DELETE;
	}
	return FALSE;
}
//insert文から対象となるテーブル名を取得する
int GetTableNameFromInsert(char *_sql, char *tablename)
{
	char *token;
	char seps[] = " ,\t\n(";
	char *sql;

	*tablename = '\0';
	sql = _strdup(_sql);
	token = strtok( sql, seps );
	while( token != NULL ){
		//"insert"か"insert into"の次にテーブル名がある
		//最初にinsertが来ないとエラー
		if( stricmp("insert", token) == 0 ){
			token = strtok( NULL, seps );
			if( stricmp("into", token) == 0){
				//intoが省略されてない場合,次のトークンにテーブル名ある
				token = strtok(NULL , seps);
				if( token == NULL ){
					break;
				}else{
					strcpy( tablename , token);
					free(sql);
					return TRUE;
				}
			}else{
				//intoが省略されている場合
				strcpy( tablename , token);
				free(sql);
				return TRUE;
			}
		}else{
			break;
		}
	}
	free(sql);
	return FALSE;
}
int GetTableNameFromDelete(char *_sql, char *tablename)
{
	char *token;
	char seps[] = " ,\t\n(";
	char *sql;

	*tablename = '\0';
	sql = _strdup(_sql);
	token = strtok( sql, seps );
	while( token != NULL ){
		//"delete"か"delete from"の次にテーブル名がある
		//最初にdeleteが来ないとエラー
		if( stricmp("delete", token) == 0 ){
			token = strtok( NULL, seps );
			if( stricmp("from", token) == 0){
				//fromが省略されてない場合,次のトークンにテーブル名ある
				token = strtok(NULL , seps);
				if( token == NULL ){
					break;
				}else{
					strcpy( tablename , token);
					free(sql);
					return TRUE;
				}
			}else{
				//fromが省略されている場合
				strcpy( tablename , token);
				free(sql);
				return TRUE;
			}
		}else{
			break;
		}
	}
	free(sql);
	return FALSE;
}
int GetTableNameFromUpdate(char *_sql, char *tablename)
{
	char *token;
	char seps[] = " ,\t\n(";
	char *sql;

	*tablename = '\0';
	sql = _strdup(_sql);
	token = strtok( sql, seps );
	while( token != NULL ){
		//"update"の次にテーブル名がある
		//最初にdeleteが来ないとエラー
		if( stricmp("update", token) == 0 ){
			token = strtok( NULL, seps );
			//次のトークンにテーブル名ある
			if( token == NULL ){
				break;
			}else{
				strcpy( tablename , token);
				free(sql);
				return TRUE;
			}
		}else{
			break;
		}
	}
	free(sql);
	return FALSE;
}
int GetSetClauseFromUpdate(char *_sql,char *setclause)
{
	char *token;
	char seps[] = " ,\t\n()";
	char *sql;
	char *topset;
	int size;

	*setclause = '\0';
	sql = _strdup(_sql);

	if( strtok( sql , seps) == NULL ){	//UPDATE読み飛ばし
		goto FAIL;
	}
	if( strtok( NULL , seps) == NULL ){	//テーブル名読み飛ばし
		goto FAIL;
	}
	topset = strtok(NULL, seps);	//SET先頭
	if( topset == NULL ){
		goto FAIL;
	}
	if( stricmp("set", topset) != 0 ){
		goto FAIL;
	}
	token = strtok(NULL , seps);
	while( token != NULL ){
		//Where検索
		if( stricmp("where", token) == 0 ){
			size = token - topset;
			memcpy( setclause , _sql + (topset - sql) , size);
			*(setclause + size) = '\0';
			free(sql);
			return TRUE;
		}
		token = strtok(NULL , seps);
	}
	//whereが無い場合
	strcpy(setclause , _sql + (topset - sql));
	free(sql);
	return TRUE;
FAIL:
	free(sql);
	return FALSE;
}
int GetWhereCondition(char *_sql, char *condition)
{
	char *token;
	char seps[] = " ,\t\n(";
	char *sql;
	int c;

	*condition = '\0';
	sql = _strdup(_sql);
	token = strtok( sql, seps );
	while( token != NULL ){
		//where節か？
		if( stricmp("where", token) == 0 ){
			//whereは何文字目？
			c = token - sql;
			strcpy( condition , _sql + c);
			free(sql);
			return TRUE;
		}
		token = strtok( NULL, seps );
	}
	free(sql);
	return FALSE;
}
