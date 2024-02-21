#ifndef _ANONYSQLLIB_HEADER
#define _ANONYSQLLIB_HEADER

#include "ok_rsa.h"
#include "..\..\dbtest\metaodbc\odbclib.h"

//SQL���̍ő咷
#define MAX_SQL_SIZE 4096

#define __BUF_SIZE 512
typedef struct {
	MiniSSL_INFO authConn,dataConn;	//�F�؃T�[�o�̐ڑ��ƃf�[�^�T�[�o�̐ڑ�
	LNm *accessCert;			//�A�N�Z�X�ؖ���
	ODBCConnection certStore;	//���R�[�h���L�ҏؖ����ۑ���
	int status;		//�ڑ���
	int limit;		//�]���i������
	int authority;	//�����̌���
	Pubkey_RSA *authorityPub; //�����ɑΉ�������J�L�[
	char dataServerAddr[__BUF_SIZE];	//�f�[�^�T�[�o�̃A�h���X�iDNS���F�|�[�g�ԍ��j
	char databaseName[__BUF_SIZE];
	char dataServerName[__BUF_SIZE];
} ANONYSQL_SESSION;
#undef __BUF_SIZE

//�ǂ��ŃR�P������status�Ń`�F�b�N
#define ANONYSQL_INVALID_SESSION -1 //�Z�b�V�������������s
#define ANONYSQL_CONNECT_READY	0	//�ڑ�����OK
#define ANONYSQL_CONNECTED		1	//�F�؃T�[�o�ƃf�[�^�T�[�o�ɐڑ��ς݁i�X�e�[�g�����g���s�j
//�ȉ��X�e�[�g�����g���s��
#define ANONYSQL_ACCESS_CERT	2	//�A�N�Z�X�`�P�b�g�擾�ς�
#define ANONYSQL_EXEC			3	//SQL���s�ς�
#define ANONYSQL_HEADER			4	//�w�b�_�擾�ς�
#define ANONYSQL_FETCH			5	//�f�[�^�t�F�b�`��
#define ANONYSQL_OWNER_CERT		6	//

//�������֐��B�S�Ă̊֐��Ăяo���O��1�x�����Ăяo��
extern int AnonysqlInit(void);
//�Z�b�V�����������֐��Binifile�ɐݒ�t�@�C�������w�肷��B
extern int AnonysqlInitSession(ANONYSQL_SESSION *as, char *inifile);
//�ؒf���ꂽ�Z�b�V�����������S�ɔj������B
//�Đڑ�����ɂ�initsession�����蒼���B
extern int AnonysqlFreeSession(ANONYSQL_SESSION *as);
//�Z�b�V����������������ɔF�؂ƃf�[�^�T�[�o�ɐڑ�����B
extern int AnonysqlConnect(ANONYSQL_SESSION *as);
//�Z�b�V�������ꎞ�ؒf����B�Ă�connect���邱�Ƃ��ł���B
extern int AnonysqlDisconnect(ANONYSQL_SESSION *as);
//SELECT�X�e�[�g�����g���s�B
//���s�������GetResultColumnName�ŃR���������擾��
//FetchResultRow�Ō��ʍs���擾����B
//���ׂĂ̍s��ǂݏo���܂ŕʂ̃X�e�[�g�����g�͎��s�ł��Ȃ�
//�s�ǂݏo���̃L�����Z����disconnect����K�v������
extern int AnonysqlExecSelect(ANONYSQL_SESSION *as, char *sql);
extern int AnonysqlGetResultColumnName(ANONYSQL_SESSION *as, ODBCRecordset *res);
//���s���͕��̐���Ԃ�
//�������ɂ̓t�F�b�`��������Ԃ�
extern int AnonysqlFetchResultRow(ANONYSQL_SESSION *as, ODBCRecordset *res);

extern int AnonysqlExecInsert(ANONYSQL_SESSION *as, char *sql, int *affectedRows);
extern int *AnonysqlExecUpdate(ANONYSQL_SESSION *as, char *sql, int *affectedRows, int *matchedRows);
extern int *AnonysqlExecDelete(ANONYSQL_SESSION *as, char *sql, int *affectedRows, int *matchedRows);
//�����R�~�b�g���[�h����BeginTrans�Ŗ����R�~�b�g���[�h�ɂȂ�
//����Z�b�V��������commit����܂ł̓f�[�^�x�[�X�ɂ͕ύX�͉������Ȃ�
//�g�����U�N�V�������ɃZ�b�V�������ؒf���ꂽ�ꍇ��rollback�����B
extern int AnonysqlBeginTrans(ANONYSQL_SESSION *as);
extern int AnonysqlRollback(ANONYSQL_SESSION *as);
extern int AnonysqlCommit(ANONYSQL_SESSION *as);

#endif