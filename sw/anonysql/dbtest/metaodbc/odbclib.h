#ifndef ODBCCONN_LIB
#define ODBCCONN_LIB

#include <sql.h>		   // SDK �ɕt��

typedef struct {
	HENV henv;	//���n���h��
	HDBC hdbc;	//�ڑ��n���h��
	HSTMT hstmt;	//�X�e�[�g�����g�n���h��
	//int transaction;	//�g�����U�N�V�����l�X�g�J�E���^�B��g�����U�N�V��������0�A�g�����U�N�V�������l�X�g����邽�тɃJ�E���g�A�b�v
} ODBCConnection;

#define MAX_COLUMNS 32		//�ő�R������
#define MAX_COLUMN_NAME 256	//�Œ��R������
#define MAX_COLUMN_DATA 2048	//�Œ��R�����f�[�^
#define MAX_TABLE_NAME MAX_COLUMN_NAME

typedef struct {
	int numColumn;	//�R������
	UCHAR columnName[MAX_COLUMNS][MAX_COLUMN_NAME];	//�R������
	UDWORD columnSize[MAX_COLUMNS];						//�R�����̃f�[�^�T�C�Y
	SDWORD columnFetched[MAX_COLUMNS];					//���ۂɃt�F�b�`���ꂽ�R�����̃f�[�^�T�C�Y
	UCHAR data[MAX_COLUMNS][MAX_COLUMN_DATA];			//�t�F�b�`���ꂽ�f�[�^
} ODBCRecordset;

//ODBC�̃f�[�^�\�[�X���AUID�APWD�������ꂽ�ݒ�t�@�C��inifile��ǂݍ���
//���̏������Ƀf�[�^�x�[�X�ɐڑ�����
extern int ConnectDBfromSettingFile(ODBCConnection *dbc,char *inifile);
extern int ConnectDB(ODBCConnection *dbc, UCHAR *source, UCHAR *uid, UCHAR *pwd);
extern void DisconnectDB(ODBCConnection *dbc);
extern void FreeStatementDB(ODBCConnection *dbc);

//�L����DB�ڑ�dbc���SELECT�X�e�[�g�����g��SQL��sql�����s����B
//�������̓X�e�[�g�����g�n���h��(hstmt)��dbc�ɃZ�b�g��TRUE��Ԃ��A
//GetResultColumnName�ŃR�������̎擾��AFetchResultRow�ōs�f�[�^�̎擾���\�ɂȂ�B
//���s���̓X�e�[�g�����g�n���h�����N���[�Y���AFALSE��Ԃ��B
extern int ExecSelect(ODBCConnection *dbc, UCHAR *sql);
//�L����DB�ڑ�dbc���SELECT���N�G�X�g�����s��
//���R�[�h�Z�b�gres�Ɍ��ʂ̃R�������ƃR�����̃f�[�^�T�C�Y���i�[����
extern int GetResultColumnName(ODBCConnection *dbc, ODBCRecordset *res);
//�L���ȃf�[�^�x�[�X�ڑ�dbc��Ŏ��s����SELECT���N�G�X�g�̌��ʂ̈�s��
//���R�[�h�Z�b�gres�Ɋi�[����B
//res��columnFetched�Ɏ��ۂɃt�F�b�`���ꂽ�R�����̃o�C�g���Adata�Ƀf�[�^���i�[�����
//���̊֐��̌ďo�����ƂɃJ�[�\���͎��̍s�Ɉړ�����B
//�f�[�^�擾�ɐ����̏ꍇ��TRUE��Ԃ��B
//�f�[�^�擾�Ɏ��s�A�������͌��ʃ��R�[�h�Z�b�g�Ƀf�[�^�����������ꍇ��
//�X�e�[�g�����g�n���h�����N���[�Y���AFALSE��Ԃ��B
//���̊֐��̌Ăяo����TRUE���Ԃ��������dbc�ňႤ���N�G�X�g�����s����ꍇ��
//FreeStatementDB���Ăяo���ăX�e�[�g�����g�n���h�������K�v������B
extern int FetchResultRow(ODBCConnection *dbc, ODBCRecordset *res);

extern int ExecInsert(ODBCConnection *dbc, UCHAR *sql, int *affectedRows);
extern int ExecInsertIdentity(ODBCConnection *dbc, UCHAR *sql, int *affectedRows, int *newid);
extern int ExecDelete(ODBCConnection *dbc, UCHAR *sql, int *affectedRows);
extern int ExecUpdate(ODBCConnection *dbc, UCHAR *sql, int *affectedRows);

//�g�����U�N�V�����𖾎��I�ɊJ�n����B
//������Ԃł�autocommit���[�h�Ȃ̂ŁA1�s���s���Ƃ�commit�����
extern int BeginTransaction(ODBCConnection *dbc);
//�����I�ɊJ�n�����g�����U�N�V�������I�����Aautocommit���[�h�ɂ���
extern int CommitTransaction(ODBCConnection *dbc);
extern int RollbackTransaction(ODBCConnection *dbc);

extern void PrintSQLerr(ODBCConnection *dbc);
extern void PrintRecordset(ODBCRecordset *r);
extern void PrintColumnName(ODBCRecordset *r);

//���R�[�h�̈�sr�̃f�[�^�����ׂĂ̍��ڂ�NULL�������܂߂ĘA�����A�o�b�t�@ret�ɃR�s�[����
//bufsize�Ƀo�b�t�@ret�̑傫�����w�肷��
//�������ɂ�*outsize�ɏ����o�����o�C�g���i�������ł͂Ȃ��j��Ԃ��ATRUE��Ԃ�l�Ƃ��ĕԂ�
//�o�b�t�@�s������*outsize��0�ɃZ�b�g����AFALSE���A��l�Ƃ��ĕԂ�
extern int SerializeRecord(ODBCRecordset *r, int bufsize, char *ret, int *outsize);
#endif