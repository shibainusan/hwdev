/************************************************************************/
/*	  ODBC API �T���v���v���O����(2)								  */
/*			  sample2.c						  1998.02.12 J.Baba	*/
/************************************************************************/
/*
	  ���I�r�p�k�iDynamicSQL�j�̑����ł��B
	���̃v���O�����́A�Œ肵�� SQL ���łȂ��A���s���ɓ��͂����A�s�����
	SQL �������s�����鎖���o���܂��B

	ODBC SDK �ɕt���̃T���v��(*1)���蒼���������̂ł��B
	VisualC++(4.0/5.0)�ŃR���p�C���\�ł��B

		cl -c sample2.c
		link sample2 odbc32.lib

	���̓��[�v��t�����Ă��܂��B
	�s�R�ȕ��́ASDK �̃I���W�i�����Q�Ƃ��ĉ������B

	(*1) ODBC SDK 2.10 �uInteractive Ad Hoc Query Example�v���
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>
#include <sql.h>		   // SDK �ɕt��
#include <sqlext.h>		// SDK �ɕt��
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

		//�X�e�[�g�����g�̎�ޔ���
		if( _strnicmp(statement , "select", strlen("select")) == 0){
			ExecSelect(&dbc , sqlstr);
			//�������ʂ̃R���������擾
			GetResultColumnName(&dbc,&record);
			PrintColumnName(&record);
			do{
				//���ׂĂ̍s���t�F�b�`���ĕ\��
				if( FetchResultRow(&dbc,&record) != TRUE ){
					break;
				}
				PrintRecordset(&record);
				SerializeRecord(&record , 4096 , sr , &outsize);
			}while(1);

		}else if(_strnicmp(statement , "insert", strlen("insert")) == 0){
			ExecInsertIdentity(&dbc , sqlstr , &affectedRows, &newid);
			//�e�����󂯂��s����\������
			printf("affected rows:%d, newid:%d \n",affectedRows,newid);
		}else if(_strnicmp(statement , "update", strlen("update")) == 0){
			ExecUpdate(&dbc , sqlstr , &affectedRows);
			printf("affected rows:%d\n",affectedRows);
		}else if(_strnicmp(statement , "delete", strlen("delete")) == 0){
			ExecDelete(&dbc , sqlstr , &affectedRows);
			printf("affected rows:%d\n",affectedRows);
		//�g�����U�N�V�����֌W
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
/* ���Ɏ����֐��͊����ł͂���܂���						 */
/* �������AODBC �֐��𗝉������ł́A�x��͖����ł��傤	*/
/************************************************************/

#define MAX_NUM_PRECISION 20

/* ���l�ɕK�v�ȕ�����̍ő���`����								 */
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

	  case SQL_TIMESTAMP:	   // �ǉ� J.Baba
		return MAX_DATE_STRING_SIZE;

	  /* ���� ���̊֐��́Acore data type �����T�|�[�g���Ă��Ȃ� */
	  default:
		printf("Unknown datatype, %d\n", coltype);
		return(0);
	 }
}



