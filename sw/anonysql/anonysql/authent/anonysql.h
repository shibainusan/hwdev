#ifndef _ANONYSQL_HEADER
#define _ANONYSQL_HEADER

#include "large_num.h"
#include "ok_rsa.h"
#include "minissl.h"
#include "..\metaquery\anonysqllib.h"

//�v���t�@�C���̃I��/�I�t
#undef PROFILER_ON
//�g���[�X���[�h�̃I��/�I�t
#undef TRACE_ON
//���N�G�X�g�ؖ������v���C���[�h
#define CERT_REPLAY
//���R�[�h���L�ҏؖ����̏����A���S���Y��
#undef RECORD_OWNER_CERT_RSA
#define RECORD_OWNER_CERT_DES
//���R�[�h���L�ҏؖ����̍ő咷
#define MAX_RECORD_OWNER_CERT 2048

//delete/update�ň�x�ɏ����ł���s��
#define MAX_AFFECT_ROWS 2048

//SQL���̍ő咷
#ifndef MAX_SQL_SIZE
#define MAX_SQL_SIZE 4096
#endif

//�����R�[�h
#define FULL_ACCESS 1
#define SELECT_ONLY 2

//�F�؃T�[�o�ւ̃R�}���h
#define REQUEST_SIGN 0x01		//�����v��
#define REQUEST_AUTHORITY 0x02	//�����m�F

//�f�[�^�X�g�A�T�[�o�ւ̃R�}���h
#define SQL_EXEC 0x01				//SQL�����s
#define SQL_BEGIN_TRANS 0x02		//�g�����U�N�V�����J�n
#define SQL_COMMIT_TRANS 0x03		//�R�~�b�g
#define SQL_ROLLBACK_TRANS 0x04		//���[���o�b�N
#define SQL_BYE 0x05				//�Z�b�V�����I��

//�f�[�^�X�g�A�T�[�o����̉����R�[�h
#define OK_RESULT_FOLLOW 0x01		//update,delete����
#define AUTHENTICATION_FAILED 0x02	//�F�؃G���[
#define AUTHORIZATION_FAILED 0x03	//�F�G���[
#define INVALID_SQL 0x04			//SQL�\���G���[
#define OK_COLUMN_HEADER_FOLLOW 0x05	//�R�����w�b�_���M�J�n
#define OK_RECORD_OWNER_CERT_FOLLOW 0x06	//insert�����A���R�[�h�ؖ������M�J�n
#define RECORD_OWNER_CERT_REQUEST 0x07		//���R�[�h�ؖ����v��
#define RECORD_FOLLOW 0x08					//���R�[�h�{�̑��M�J�n
#define REOCRD_FINISHED 0x09				//���R�[�h�{�̑��M�I��
#define AUTOCOMMIT_ON 0x0A			//�����R�~�b�g���[�h�I��
#define AUTOCOMMIT_OFF 0x0B			//�����R�~�b�g���[�h�I�t

#define MD5_SIZE (128/8)
#define LN_EQUAL 0

//�ȉ�digisign.c
//���������؂��A���������TRUE�A�s���Ȃ��FALSE��Ԃ�
//cert�ɏ����Ahash�Ƀn�b�V���Akey�Ɍ��J�L�[���Z�b�g����
extern int CheckCert(LNm *cert, LNm *hash, Pubkey_RSA *key);
//�F�؃T�[�o�Ƀu���C���h���������Ă��炤�B���������TRUE�A���s�Ȃ��FALSE��Ԃ��B
//�F�؃T�[�o�ւ̐ڑ��Fsi�A����������SQL���Fsql�A�������ؗp���J�L�[�ApubKey,�������ʁFcert
extern int BlindSign(MiniSSL_INFO *si , unsigned char *sql,Pubkey_RSA *pubKey, LNm *cert);
//size�o�C�g���̏���cert�ƕ���request�������������؂���B
//\authority�t�H���_���̌����L�[�������Ɏg���Č��؂���B
//���؂ɐ��������ꍇ�͌����R�[�h�i���̐����j��Ԃ��B
//���s�����ꍇ�͕��̐�����Ԃ��B
extern int VerifyRequest(int size, UCHAR *_cert, UCHAR *request);

extern Pubkey_RSA *LoadAuthorityPubKey(int authority);
extern Prvkey_RSA *LoadAuthorityPrvKey(int authority);

//�ȉ�sql.c
//SQL���̎�ނ𔻒肷��B
//SQL_SELECT��������SQL_INSERT�ASQL_UPDATE�ASQL_DELETE�̂ǂꂩ��Ԃ��B
//�ǂ�ł��Ȃ��Ƃ���FALSE��Ԃ�
#define SQL_SELECT 0x01
#define SQL_INSERT 0x02
#define SQL_UPDATE 0x03
#define SQL_DELETE 0x04
extern int CheckSQLType(UCHAR *sql);
//insert��������insert into��_sql����e�[�u����tablename��؂�o��
extern int GetTableNameFromInsert(char *_sql, char *tablename);
//delete��������delete from��_sql����e�[�u����tablename��؂�o��
extern int GetTableNameFromDelete(char *_sql, char *tablename);
//update��_sql����e�[�u����tablename��؂�o��
extern int GetTableNameFromUpdate(char *_sql, char *tablename);
extern int GetSetClauseFromUpdate(char *_sql,char *setclause);
//Where������؂�o��
extern int GetWhereCondition(char *_sql, char *condition);
//�ȉ�certstore.c
extern void SplitRecordOwnerCert(char *cert, char **server, char **database, char **table, int *id, char **sign);
extern int LoadRecordOwnerCerts(ANONYSQL_SESSION *as,char *tablename,int *matchedIDs,int matchedRows,char *certs,int *numCert);
extern int SaveRecordOwnerCert(ODBCConnection *dbc, char *cert, int len);
extern int DeleteRecordOwnerCerts(ANONYSQL_SESSION *as,char *tablename,int *affectedIDs ,int affectedRows);
#endif
