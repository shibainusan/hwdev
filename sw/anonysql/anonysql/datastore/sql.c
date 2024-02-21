#include <stdio.h>
#include <stdlib.h>
#include "minissl.h"
#include "..\authent\anonysql.h"

//SQL���̎�ނ𔻒肷��B
//SQL_SELECT��������SQL_INSERT�ASQL_UPDATE�ASQL_DELETE�̂ǂꂩ��Ԃ��B
//�ǂ�ł��Ȃ��Ƃ���FALSE��Ԃ�
int CheckSQLType(UCHAR *sql)
{
	//�啶����������ʂȂ��ŕ�����������r
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
//insert������ΏۂƂȂ�e�[�u�������擾����
int GetTableNameFromInsert(char *_sql, char *tablename)
{
	char *token;
	char seps[] = " ,\t\n(";
	char *sql;

	*tablename = '\0';
	sql = _strdup(_sql);
	token = strtok( sql, seps );
	while( token != NULL ){
		//"insert"��"insert into"�̎��Ƀe�[�u����������
		//�ŏ���insert�����Ȃ��ƃG���[
		if( stricmp("insert", token) == 0 ){
			token = strtok( NULL, seps );
			if( stricmp("into", token) == 0){
				//into���ȗ�����ĂȂ��ꍇ,���̃g�[�N���Ƀe�[�u��������
				token = strtok(NULL , seps);
				if( token == NULL ){
					break;
				}else{
					strcpy( tablename , token);
					free(sql);
					return TRUE;
				}
			}else{
				//into���ȗ�����Ă���ꍇ
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
		//"delete"��"delete from"�̎��Ƀe�[�u����������
		//�ŏ���delete�����Ȃ��ƃG���[
		if( stricmp("delete", token) == 0 ){
			token = strtok( NULL, seps );
			if( stricmp("from", token) == 0){
				//from���ȗ�����ĂȂ��ꍇ,���̃g�[�N���Ƀe�[�u��������
				token = strtok(NULL , seps);
				if( token == NULL ){
					break;
				}else{
					strcpy( tablename , token);
					free(sql);
					return TRUE;
				}
			}else{
				//from���ȗ�����Ă���ꍇ
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
		//"update"�̎��Ƀe�[�u����������
		//�ŏ���delete�����Ȃ��ƃG���[
		if( stricmp("update", token) == 0 ){
			token = strtok( NULL, seps );
			//���̃g�[�N���Ƀe�[�u��������
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

	if( strtok( sql , seps) == NULL ){	//UPDATE�ǂݔ�΂�
		goto FAIL;
	}
	if( strtok( NULL , seps) == NULL ){	//�e�[�u�����ǂݔ�΂�
		goto FAIL;
	}
	topset = strtok(NULL, seps);	//SET�擪
	if( topset == NULL ){
		goto FAIL;
	}
	if( stricmp("set", topset) != 0 ){
		goto FAIL;
	}
	token = strtok(NULL , seps);
	while( token != NULL ){
		//Where����
		if( stricmp("where", token) == 0 ){
			size = token - topset;
			memcpy( setclause , _sql + (topset - sql) , size);
			*(setclause + size) = '\0';
			free(sql);
			return TRUE;
		}
		token = strtok(NULL , seps);
	}
	//where�������ꍇ
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
		//where�߂��H
		if( stricmp("where", token) == 0 ){
			//where�͉������ځH
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
