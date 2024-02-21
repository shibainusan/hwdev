//ODBC�A�N�Z�X�p���C�u����

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <windows.h>
#include <sql.h>		   // SDK �ɕt��
#include <sqlext.h>		// SDK �ɕt��
#include "odbclib.h"

#define BUF_SIZE 256
#define MYAPPNAME "ODBClib 1.0"

static void Space2Null(char *buf);
static void DispLastError(void);
static int ExecDirect(ODBCConnection *dbc, UCHAR *sql);

int ExecDirect(ODBCConnection *dbc, UCHAR *sql)
{
	/* �X�e�[�g�����g�n���h���̎擾  */
	SQLAllocStmt(dbc->hdbc, &(dbc->hstmt));

	/* SQL �X�e�[�g�����g�̎��s */
	if (SQLExecDirect(dbc->hstmt, sql, SQL_NTS) != SQL_SUCCESS) {
		PrintSQLerr(dbc);
		FreeStatementDB(dbc);
		return FALSE;
	}
	FreeStatementDB(dbc);
	return TRUE;
}

int BeginTransaction(ODBCConnection *dbc)
{
	return ExecDirect(dbc , "BEGIN TRANSACTION");
}
int CommitTransaction(ODBCConnection *dbc)
{
	return ExecDirect(dbc , "COMMIT TRANSACTION");
}
int RollbackTransaction(ODBCConnection *dbc)
{
	return ExecDirect(dbc , "ROLLBACK TRANSACTION");
}


void DispLastError(void)
{
	LPVOID lpMsgBuf;
	FormatMessage( FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
				    NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // ����̌���
					(LPTSTR) &lpMsgBuf, 0, NULL);
	printf("odbclib:%s\n",lpMsgBuf);
	LocalFree(lpMsgBuf);
}

int SerializeRecord(ODBCRecordset *r, int bufsize, char *ret, int *outsize)
{
	int i;
	int c;
	char *org_ret;
	
	org_ret = ret;
	*outsize = 0;

	for( i = 0; i < r->numColumn ; i++){
		//�k�������܂߂Ẵf�[�^��
		c = strlen(r->data[i]) + 1;
		bufsize -= c;
		//�o�b�t�@�s�����H
		if( bufsize < 0 ){
			return FALSE;
		}
		//�k�������܂߂ăf�[�^���R�s�[����
		strcpy(ret , r->data[i]);
		//�������ݐ�|�C���^��i�߂�
		ret += c;
	}
	//�����o�����o�C�g�����v�Z
	*outsize = ret - org_ret;
	return TRUE;
}

void FreeStatementDB(ODBCConnection *dbc)
{
	SQLFreeStmt(dbc->hstmt, SQL_DROP );
	dbc->hstmt = 0;
}

int ConnectDBfromSettingFile(ODBCConnection *dbc,char *inifile)
{
	int ret;
	UCHAR datasource[BUF_SIZE];
	UCHAR uid[BUF_SIZE];
	UCHAR pwd[BUF_SIZE];

	//�ݒ�ǂݍ���
	ret = GetPrivateProfileString(MYAPPNAME , "DataSource" , "" , datasource , BUF_SIZE , inifile);
	ret = GetPrivateProfileString(MYAPPNAME , "UID" , "" , uid , BUF_SIZE , inifile);
	ret = GetPrivateProfileString(MYAPPNAME , "PWD" , "" , pwd , BUF_SIZE , inifile);
	DispLastError();
	//DB�ڑ�
	return ConnectDB(dbc , datasource , uid , pwd);
}

int ConnectDB(ODBCConnection *dbc, UCHAR *source, UCHAR *uid, UCHAR *pwd)
{
	RETCODE rc;

	//�ڑ��\���̂��[���N���A
	memset(dbc , 0 , sizeof(ODBCConnection));
	//�f�t�H���g�Ŕ�g�����U�N�V�������[�h
	//dbc->transaction = 0;
	/* ������ѐڑ��n���h���̎擾 */
	SQLAllocEnv(&(dbc->henv));
	SQLAllocConnect(dbc->henv, &(dbc->hdbc));
	/* �f�[�^�\�[�X�Ƃ̐ڑ�		 */
	rc = SQLConnect(dbc->hdbc, source, SQL_NTS, uid, SQL_NTS, pwd, SQL_NTS);
	if (rc != SQL_SUCCESS && rc != SQL_SUCCESS_WITH_INFO) {
		PrintSQLerr( dbc);
		SQLFreeConnect(dbc->hdbc);		   /* Free the connection handle.	  */
		SQLFreeEnv(dbc->henv);			   /* Free the environment handle.	 */
		return FALSE;
	}
	return TRUE;
}

void DisconnectDB(ODBCConnection *dbc)
{
	SQLDisconnect(dbc->hdbc);			/* Disconnect from the data source. */
	SQLFreeConnect(dbc->hdbc);		   /* Free the connection handle.	  */
	SQLFreeEnv(dbc->henv);			   /* Free the environment handle.	 */

	//�ڑ��\���̂��[���N���A
	memset(dbc , 0 , sizeof(ODBCConnection));
}

//�L����DB�ڑ�dbc���SELECT�X�e�[�g�����g��SQL��sql�����s����B
//�������̓X�e�[�g�����g�n���h��(hstmt)��dbc�ɃZ�b�g��TRUE��Ԃ��A
//GetResultColumnName�ŃR�������̎擾��AFetchResultRow�ōs�f�[�^�̎擾���\�ɂȂ�B
//���s���̓X�e�[�g�����g�n���h�����N���[�Y���AFALSE��Ԃ��B
int ExecSelect(ODBCConnection *dbc, UCHAR *sql)
{
	/* �X�e�[�g�����g�n���h���̎擾  */
	SQLAllocStmt(dbc->hdbc, &(dbc->hstmt));

	/* SQL �X�e�[�g�����g�̎��s */
	if (SQLExecDirect(dbc->hstmt, sql, SQL_NTS) != SQL_SUCCESS) {
		PrintSQLerr(dbc);
		FreeStatementDB(dbc);
		return FALSE;
	}
	return TRUE;
}

int ExecInsert(ODBCConnection *dbc, UCHAR *sql, int *affectedRows)
{

	*affectedRows = -1;
	/* �X�e�[�g�����g�n���h���̎擾  */
	SQLAllocStmt(dbc->hdbc, &(dbc->hstmt));

	/* SQL �X�e�[�g�����g�̎��s */
	if (SQLExecDirect(dbc->hstmt, sql, SQL_NTS) != SQL_SUCCESS) {
		PrintSQLerr(dbc);
		FreeStatementDB(dbc);
		return FALSE;
	}
	//�e�����󂯂��s���𓾂�
	SQLRowCount(dbc->hstmt , affectedRows);
	FreeStatementDB(dbc);
	return TRUE;
}
int ExecInsertIdentity(ODBCConnection *dbc, UCHAR *sql, int *affectedRows, int *newid)
{
	int retcode;
	*newid = -1;

	if( ExecInsert(dbc , sql, affectedRows) != TRUE ){
		return FALSE;
	}
	/* �X�e�[�g�����g�n���h���̎擾  */
	SQLAllocStmt(dbc->hdbc, &(dbc->hstmt));
	/* �������}���������R�[�h��ID���擾 */
	if (SQLExecDirect(dbc->hstmt, "SELECT @@IDENTITY", SQL_NTS) != SQL_SUCCESS) {
		PrintSQLerr(dbc);
		FreeStatementDB(dbc);
		return FALSE;
	}

	retcode = SQLFetch(dbc->hstmt);
	if (retcode == SQL_ERROR) {
		PrintSQLerr(dbc);
		FreeStatementDB(dbc);
		return FALSE;
	}
    if (retcode == SQL_SUCCESS || retcode == SQL_SUCCESS_WITH_INFO){
		SQLGetData(dbc->hstmt, 1, SQL_C_SLONG, newid, sizeof(int), NULL);
	}else{
		PrintSQLerr(dbc);
		FreeStatementDB(dbc);
		return FALSE;
	}

	FreeStatementDB(dbc);
	return TRUE;
}
int ExecDelete(ODBCConnection *dbc, UCHAR *sql, int *affectedRows)
{
	return ExecInsert(dbc , sql , affectedRows);
}
int ExecUpdate(ODBCConnection *dbc, UCHAR *sql, int *affectedRows)
{
	return ExecInsert(dbc , sql , affectedRows);
}

//�L����DB�ڑ�dbc���SELECT���N�G�X�g�����s��
//���R�[�h�Z�b�gres�Ɍ��ʂ̃R�������ƃR�����̃f�[�^�T�C�Y���i�[����
int GetResultColumnName(ODBCConnection *dbc, ODBCRecordset *res)
{
	int i;
	SWORD resultcols;
	SWORD   coltype;
	SWORD   colnamelen;
	SWORD   nullable;
	SWORD   scale;

	//�R���������擾
	SQLNumResultCols(dbc->hstmt, &resultcols);
	res->numColumn = resultcols;

	//�e�R�����ɂ��ď���
	for (i = 0; i < res->numColumn; i++) {
		//�R�����̏��₢���킹
		SQLDescribeCol(dbc->hstmt, (UWORD)(i + 1), res->columnName[i],
				(SWORD)sizeof(res->columnName[i]),
				 &colnamelen, &coltype, &res->columnSize[i], &scale,
				 &nullable);
		//�f�[�^�o�b�t�@�Ƀo�C���h����BC������ɕϊ��B
		SQLBindCol(dbc->hstmt, (UWORD)(i + 1), SQL_C_CHAR, res->data[i],
				 (SWORD)sizeof(res->data[i]), &res->columnFetched[i]);
		//�R�������ƃT�C�Y��\��
		//printf("%s(%d),", res->columnName[i],res->columnSize[i]);
	}

	return TRUE;
}
void PrintColumnName(ODBCRecordset *r)
{
	int i;

	for( i = 0; i < r->numColumn; i++) {
		printf("%s(%d),", r->columnName[i],r->columnSize[i]);
	}
	printf("\n");
}

//�L���ȃf�[�^�x�[�X�ڑ�dbc��Ŏ��s����SELECT���N�G�X�g�̌��ʂ̈�s��
//���R�[�h�Z�b�gres�Ɋi�[����B
//res��columnFetched�Ɏ��ۂɃt�F�b�`���ꂽ�R�����̃o�C�g���Adata�Ƀf�[�^���i�[�����
//���̊֐��̌ďo�����ƂɃJ�[�\���͎��̍s�Ɉړ�����B
//�f�[�^�擾�ɐ����̏ꍇ��TRUE��Ԃ��B
//�f�[�^�擾�Ɏ��s�A�������͌��ʃ��R�[�h�Z�b�g�Ƀf�[�^�����������ꍇ��
//�X�e�[�g�����g�n���h�����N���[�Y���AFALSE��Ԃ��B
//���̊֐��̌Ăяo����TRUE���Ԃ��������dbc�ňႤ���N�G�X�g�����s����ꍇ��
//FreeStatementDB���Ăяo���ăX�e�[�g�����g�n���h�������K�v������B
int FetchResultRow(ODBCConnection *dbc, ODBCRecordset *res)
{
	RETCODE rc;	
	int i;

	rc = SQLFetch(dbc->hstmt);
	if (rc == SQL_SUCCESS || rc == SQL_SUCCESS_WITH_INFO) {

		for (i = 0; i < res->numColumn ; i++) {
			//NULL�l�̏ꍇ�̓k���������Z�b�g����
			if (res->columnFetched[i] == SQL_NULL_DATA) {
				lstrcpy(res->data[i], "");
			}
		}
	}else{
		FreeStatementDB(dbc);
		return FALSE;
	}
	return TRUE;
}

void PrintRecordset(ODBCRecordset *r)
{
	int i;
	char buf[MAX_COLUMN_DATA];

	for(i = 0 ; i < r->numColumn ; i++){
		strcpy( buf , r->data[i]);
		Space2Null(buf);
		printf("%s(%d),", buf,r->columnFetched[i]);
	}
	printf("\n");
}

void Space2Null(char *buf)
{
	do{
		if( *buf == '\0' || *buf == ' ' ){
			*buf = '\0';
			break;
		}
		buf++;
	}while(1);
}
/*	  �G���[�\��					  */
void PrintSQLerr(ODBCConnection *dbc) {
	char errstate[ 1024 ];
	char errmsg[1024 ];
	SDWORD errcode;
	SWORD sz;

	SQLError( dbc->henv, dbc->hdbc, dbc->hstmt,
		errstate, &errcode, errmsg, sizeof( errmsg ), &sz );
	printf( "%s(%d)%*s\n", errstate, errcode, (int)sz, errmsg );
}