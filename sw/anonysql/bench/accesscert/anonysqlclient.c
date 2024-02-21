#include "sockframe.h"
#include "..\..\dbtest\metaodbc\odbclib.h"
#include "minissl.h"
#include "..\..\anonysql\authent\anonysql.h"
#include "anonysqllib.h"
#include "gunshu.h"
#include "large_num.h"

#define BUF_SIZE 512
#define MYAPPNAME "Anonysql client 1.0"

static void MultiplexRecord(int len, char *buf, ODBCRecordset *res);
static int GetMyAuthority(MiniSSL_INFO *si);

//�F�؃T�[�o���玩���̌����R�[�h���擾
//���s���ɕ��̐��A�������Ɏ����̌����R�[�h��Ԃ�
int GetMyAuthority(MiniSSL_INFO *si)
{
	int ret;
	int command;

	command = REQUEST_AUTHORITY;
	if( MiniSSL_Send( si ,  (const unsigned char *)&command , sizeof(int)) != sizeof(int) ){
		printf("failed to send request(getauthority).\n");
		return -1;
	}
	if( MiniSSL_Receive( si , (unsigned char *)&ret , sizeof(int)) != sizeof(int) ){
		printf("failed to recv authority code.\n");
		return -1;
	}
	return ret;
}

int AnonysqlInit(void)
{
	SockFrame_Init();
	MiniSSL_Init();
	return TRUE;
}
int AnonysqlInitSession(ANONYSQL_SESSION *as, char *inifile)
{
	int ret;
	char buf[BUF_SIZE],uid[BUF_SIZE],pwd[BUF_SIZE];

	as->status = ANONYSQL_INVALID_SESSION;
	as->accessCert = LN_alloc();
	//�F�؃T�[�o�ւ̐ڑ���������
	MiniSSL_InitSessionInfo(&as->authConn);
	//�f�[�^�T�[�o�ւ̐ڑ���������
	MiniSSL_InitSessionInfo(&as->dataConn);

	//�F�؃T�[�o�̌��J�L�[���Z�b�g
	ret = GetPrivateProfileString(MYAPPNAME , "AuthentServerPubKey" , "" , buf , BUF_SIZE , inifile);
	if( MiniSSL_SetTargetPubKey(&as->authConn , buf) != TRUE ){
		goto FAIL;
	}
	//�F�؃T�[�o�A�h���X���Z�b�g
	ret = GetPrivateProfileString(MYAPPNAME , "AuthentServerAddr" , "" , buf , BUF_SIZE , inifile);
	if( MiniSSL_BuildHostPort(&as->authConn , buf) != TRUE ){
		goto FAIL;
	}
	//�N���C�A���g�̃L�[�y�A���Z�b�g
	ret = GetPrivateProfileString(MYAPPNAME , "MyKey" , "" , buf , BUF_SIZE , inifile);
	if( MiniSSL_SetMyPubPrvKey(&as->authConn , buf) != TRUE ){
		goto FAIL;
	}
	//�N���C�A���g�����Z�b�g
	ret = GetPrivateProfileString(MYAPPNAME , "MyName" , "" , buf , BUF_SIZE , inifile);
	if( MiniSSL_SetClientName(&as->authConn, buf) != TRUE ){
		goto FAIL;
	}

	//�f�[�^�T�[�o�̌��J�L�[���Z�b�g
	ret = GetPrivateProfileString(MYAPPNAME , "DataServerPubKey" , "" , buf , BUF_SIZE , inifile);
	if( MiniSSL_SetTargetPubKey(&as->dataConn , buf) != TRUE ){
		goto FAIL;
	}

	//gunshu�}�l�[�W���̃A�h���X���Z�b�g
	GetPrivateProfileString(MYAPPNAME , "GunshuManager" , "" , buf , BUF_SIZE , inifile);
	Gunshu_SetManagerAddr(buf);
	//�]���i���������擾
	as->limit = GetPrivateProfileInt(MYAPPNAME , "GunshuLimit" , 0 , inifile);
	//�f�[�^�T�[�o���擾
	GetPrivateProfileString(MYAPPNAME , "DataServerAddr" , "" , buf , BUF_SIZE , inifile);
	strcpy( as->dataServerAddr , buf);
	GetPrivateProfileString(MYAPPNAME , "DataServerName" , "" , buf , BUF_SIZE , inifile);
	strcpy( as->dataServerName , buf);
	GetPrivateProfileString(MYAPPNAME , "DatabaseName" , "" , buf , BUF_SIZE , inifile);
	strcpy( as->databaseName , buf);

	//���R�[�h���L�ҏؖ����X�g�A�ɐڑ�
	GetPrivateProfileString(MYAPPNAME , "CertStoreDataSource" , "" , buf , BUF_SIZE , inifile);
	GetPrivateProfileString(MYAPPNAME , "CertStoreUID" , "" , uid , BUF_SIZE , inifile);
	GetPrivateProfileString(MYAPPNAME , "CertStorePWD" , "" , pwd , BUF_SIZE , inifile);
	if( ConnectDB(&(as->certStore) , buf , uid , pwd) == TRUE ){
		printf("cert store ready.\n");
	}else{
		printf("cert store fail.\n");
		goto FAIL;
	}

	as->status = ANONYSQL_CONNECT_READY;
	return TRUE;
FAIL:
	LN_free(as->accessCert);
	DisconnectDB(&(as->certStore));
	MiniSSL_FreeSessionInfo(&as->dataConn);
	MiniSSL_FreeSessionInfo(&as->authConn);
	return FALSE;
}
int AnonysqlFreeSession(ANONYSQL_SESSION *as)
{
	as->status = ANONYSQL_INVALID_SESSION;
	LN_free(as->accessCert);
	DisconnectDB(&(as->certStore));
	MiniSSL_FreeSessionInfo(&as->dataConn);
	MiniSSL_FreeSessionInfo(&as->authConn);
	return TRUE;
}
int AnonysqlConnect(ANONYSQL_SESSION *as)
{
	SOCK_INFO si;

	if( as->status != ANONYSQL_CONNECT_READY ){
		printf("session is not ready(AnonysqlConnect). status:%d\n",as->status);
		return FALSE;
	}

	//�F�؃T�[�o�ɐڑ�
	if( MiniSSL_Connect(&as->authConn , AUTHENT_CLIENTSERVER) == TRUE ){
		printf("encrypted connection to authent server ready.\n");
	}else{
		printf("authent server fail.\n");
		return FALSE;
	}
	//�����̌����m�F
	as->authority = GetMyAuthority(&(as->authConn));
	as->authorityPub = LoadAuthorityPubKey(as->authority);

	//�f�[�^�T�[�o�ɐڑ�(gunshu)
	if( Gunshu_Connect( &si , as->dataServerAddr , as->limit ) == TRUE ){
		printf("anonymous connection to data server ready.\n");
	}else{
		printf("anonymous connection to data server fail.\n");
		return FALSE;
	}
	//�f�[�^�T�[�o�ɐڑ�(minissl)
	*as->dataConn.si = si;
	if( MiniSSL_Auth( &(as->dataConn) , AUTHENT_SERVER) == TRUE ){
		printf("encrypted connection to data server ready.\n");
	}else{
		printf("encrypted connection to data server fail.\n");
		return FALSE;
	}

	as->status = ANONYSQL_CONNECTED;
	return TRUE;
}
int AnonysqlDisconnect(ANONYSQL_SESSION *as)
{
	if( as->status != ANONYSQL_INVALID_SESSION ){
		as->status = ANONYSQL_CONNECT_READY;
	}
	MiniSSL_Shutdown(&as->dataConn);
	MiniSSL_Shutdown(&as->authConn);
	return TRUE;
}
int PostRequest(ANONYSQL_SESSION *as, char *sql, int *response)
{
	int command;
	unsigned char w[LN_MAX];
	int size;

	if( as->status != ANONYSQL_CONNECTED ){
		printf("cant post request under status(%d).\n",as->status);
		return FALSE;
	}
	//�F�؃T�[�o�ɃA�N�Z�X�����v��
	if( BlindSign(&(as->authConn) , sql , as->authorityPub, as->accessCert) != TRUE ){
		printf("failed to recv access cert.\n");
		return FALSE;
	}
	as->status = ANONYSQL_ACCESS_CERT;

	//SQL���s�v�����M
	command = SQL_EXEC;
	if( MiniSSL_Send( &(as->dataConn) ,  (const unsigned char *)&command , sizeof(int)) != sizeof(int) ){
		printf("failed to send request(sqlexec).\n");
		goto FAIL;
	}
	//���N�G�X�g�ؖ����T�C�Y���M
	size = LN_now_byte(as->accessCert);
	if( MiniSSL_Send( &(as->dataConn) ,  (const unsigned char *)&size , sizeof(int)) != sizeof(int) ){
		goto FAIL;
	}
	//���N�G�X�g�����{�̑��M
	memset(w , 0 , sizeof(w));
	LN_get_num_c(as->accessCert , size , w);
	if( MiniSSL_Send( &(as->dataConn) ,  (const unsigned char *)w , size) != size ){
		printf("failed to send request cert(sqlexec).\n");
		goto FAIL;
	}
	//���N�G�X�g�{���T�C�Y���M
	size = strlen(sql) + 1;	//NULL������1�o�C�g����
	if( MiniSSL_Send( &(as->dataConn) ,  (const unsigned char *)&size , sizeof(int)) != sizeof(int) ){
		goto FAIL;
	}
	//���N�G�X�g�{�����M
	if( MiniSSL_Send( &(as->dataConn) ,  (const unsigned char *)sql , size) != size ){
		printf("failed to send plaintext request(sqlexec).\n");
		goto FAIL;
	}
	//���X�|���X�R�[�h��M
	if( MiniSSL_Receive( &(as->dataConn) , (unsigned char *)response , sizeof(int)) != sizeof(int) ){
		printf("failed to recv response code(sqlexec).\n");
		goto FAIL;
	}
	//���X�|���X�R�[�h���F�؃G���[
	if( *response == AUTHENTICATION_FAILED ){
		printf("authentication failed(sqlexec).\n");
		goto FAIL;
	}else if( *response == AUTHORIZATION_FAILED ){
		printf("authorization failed(sqlexec).\n");
		goto FAIL;
	}else if( *response == INVALID_SQL ){
		printf("invalid sql statement(sqlexec).\n");
		goto FAIL;
	}
	return TRUE;
FAIL:
	as->status = ANONYSQL_CONNECTED;
	return FALSE;
}
int AnonysqlExecSelect(ANONYSQL_SESSION *as, char *sql)
{
	int response;
	//���N�G�X�g�����Q�b�g���ăf�[�^�T�[�o�Ƀ|�X�g
	if( PostRequest(as , sql ,&response ) != TRUE ){
		return FALSE;
	}
	//�R�����w�b�_��M�\�����X�|���X�R�[�h����
	if( response == OK_COLUMN_HEADER_FOLLOW ){
		as->status = ANONYSQL_EXEC;
		return TRUE;
	}
	as->status = ANONYSQL_CONNECTED;
	return FALSE;
}

int AnonysqlGetResultColumnName(ANONYSQL_SESSION *as, ODBCRecordset *res)
{
	int i;
	int size;

	//SQL���s�ς݂��H
	if( as->status == ANONYSQL_EXEC){
	}else{
		goto FAIL;
	}

	res->numColumn = -1;

	//�J��������M
	if( MiniSSL_Receive( &(as->dataConn) , (unsigned char *)&(res->numColumn) , sizeof(int)) != sizeof(int) ){
		printf("failed to recv numColumn.\n");
		goto FAIL;
	}
	//�J�����������������H
	if( res->numColumn >= MAX_COLUMNS ){
		printf("too much numColumn(%d).\n",res->numColumn);
		goto FAIL;
	}
	//�e�J�����̏����擾
	for( i = 0 ; i < res->numColumn ; i++){
		//�J�����̃f�[�^�T�C�Y
		MiniSSL_Receive( &(as->dataConn) , (unsigned char *)&(res->columnSize[i]) , sizeof(int));
		//if( res->columnSize[i] >= MAX_COLUMN_DATA ){
		//	printf("too large column data size(%d).\n", res->columnSize[i]);
		//	goto FAIL;
		//}
		//�J�������̑傫��
		MiniSSL_Receive( &(as->dataConn) , (unsigned char *)&size , sizeof(int));
		if( size >= MAX_COLUMN_NAME ){
			printf("too large column name size(%d).\n", size);
			goto FAIL;
		}
		//�J�������{�̎擾
		if( MiniSSL_Receive( &(as->dataConn) , (unsigned char *)res->columnName[i] , size) != size ){
			printf("failed to recv column name(%d).\n",i);
			goto FAIL;
		}
	}
	as->status = ANONYSQL_HEADER;
	return TRUE;
FAIL:
	as->status = ANONYSQL_CONNECTED;
	return FALSE;
}

void MultiplexRecord(int len, char *buf, ODBCRecordset *res)
{
	int i;
	int c = 0;
	char *data;
	
	data = res->data[c];
	for( i = 0 ; i < len ; i++){
		*data = *buf;	//�f�[�^�R�s�[
		data++;
		if( *buf == '\0' ){	//�k�������̏ꍇ�͎��̃J������
			//�t�F�b�`���ꂽ�R�����f�[�^���v�Z
			res->columnFetched[c] = strlen(res->data[c]);
			c++;
			data = res->data[c];
		}
		buf++;
	}

}

int AnonysqlFetchResultRow(ANONYSQL_SESSION *as, ODBCRecordset *res)
{
	int com;
	int len;
	char *buf;

	//�w�b�_�擾�ς݂��H�t�F�b�`�����H
	if( as->status == ANONYSQL_HEADER || as->status == ANONYSQL_FETCH ){
	}else{
		return -1; //�G���[�R�[�h
	}
	//�s�����邩�₢���킹
	MiniSSL_Receive( &(as->dataConn) , (unsigned char *)&com , sizeof(int));
	if( com >= MAX_COLUMN_DATA ){
		printf("failed to detect end of recordset.\n");
		return -1;	//�G���[�R�[�h
	}
	if( com == REOCRD_FINISHED ){
		as->status = ANONYSQL_CONNECTED;	//SQL���s�\��Ԃɂ���
		return 0;	//0�s�t�F�b�`
	}
	//�s�f�[�^�T�C�Y�擾
	MiniSSL_Receive( &(as->dataConn) , (unsigned char *)&len , sizeof(int));
	if( len >= MAX_COLUMN_DATA * res->numColumn ){
		printf("too large row data(%d).\n",len);
		return -1;	//�G���[�R�[�h
	}
	buf = malloc(len);
	//�s�{�̎擾
	if( MiniSSL_Receive( &(as->dataConn) , buf , len) != len){
		printf("failed to recv row data.\n");
		free(buf);
		return -1;
	}
	MultiplexRecord(len , buf , res);

	free(buf);
	as->status = ANONYSQL_FETCH; 
	return 1;	//1�s�t�F�b�`

}

int AnonysqlExecInsert(ANONYSQL_SESSION *as, char *sql, int *affectedRows)
{
	int response;
	int len;
	char *cert;

	//�e�����󂯂��s����������
	*affectedRows = 0;

	if( PostRequest(as , sql ,&response ) != TRUE ){
		return FALSE;
	}
	//�}�����������X�|���X�R�[�h����
	if( response != OK_RECORD_OWNER_CERT_FOLLOW ){
		as->status = ANONYSQL_CONNECTED;
		return FALSE;
	}
	//���R�[�h���L�ҏؖ����̑傫�����擾
	MiniSSL_Receive( &(as->dataConn) , (unsigned char *)&len , sizeof(int));
	//���R�[�h���L�ҏؖ����{�̎�M
	cert = malloc(len);
	if( MiniSSL_Receive( &(as->dataConn) , cert , len) != len){
		goto FAIL;
	}
	as->status = ANONYSQL_ACCESS_CERT;

	//���R�[�h���L�ҏؖ�����ۑ�
	if( SaveRecordOwnerCert(&(as->certStore) , cert, len) != TRUE ){
		goto FAIL;
	}

	free(cert);
	as->status = ANONYSQL_CONNECTED;
	*affectedRows = 1;
	return TRUE;

FAIL:
	free(cert);
	as->status = ANONYSQL_CONNECTED;
	return FALSE;
}

int *AnonysqlExecUpdate(ANONYSQL_SESSION *as, char *sql, int *affectedRows, int *matchedRows)
{
	int response;
	int certsize;
	char *certs = NULL;
	int numCert;
	int *matchedIDs = NULL;
	int *affectedIDs = NULL;
	char tablename[MAX_TABLE_NAME];

	//�e�����󂯂��s����������
	*affectedRows = 0;
	*matchedRows = 0;

	if( PostRequest(as , sql ,&response ) != TRUE ){
		return NULL;
	}
	//�}�����������X�|���X�R�[�h����
	if( response != OK_RESULT_FOLLOW ){
		goto FAIL;
	}
	//�}�b�`�����s�����擾
	if( MiniSSL_Receive( &(as->dataConn) , (unsigned char *)matchedRows , sizeof(int)) != sizeof(int) ){
		printf("failed to recv matched rows(update).\n");
		goto FAIL;
	}
	if( *matchedRows < 0 ){
		as->status = ANONYSQL_CONNECTED;
		goto FAIL;
	}
	matchedIDs = malloc(*matchedRows * sizeof(int));
	affectedIDs = malloc(*matchedRows * sizeof(int));
	//�}�b�`����ID����M����
	if( MiniSSL_Receive( &(as->dataConn) , (unsigned char *)matchedIDs , *matchedRows * sizeof(int)) != ((signed)sizeof(int) * (*matchedRows)) ){
		printf("failed to recv matched ids(update).\n");
		goto FAIL;
	}
	certs = malloc(MAX_RECORD_OWNER_CERT * (*matchedRows));
	GetTableNameFromUpdate(sql , tablename);
	certsize = LoadRecordOwnerCerts(as,tablename, matchedIDs, *matchedRows,certs, &numCert);
	if( certsize < 0 ){
		printf("failed to load record owner certs(update).\n");
		goto FAIL;
	}
	//���R�[�h���L�ҏؖ����̐��𑗐M
	MiniSSL_Send( &(as->dataConn) ,  (const unsigned char *)&numCert , sizeof(int));
	//���R�[�h���L�ҏؖ����{�̑��M
	if( MiniSSL_Send( &(as->dataConn) ,  certs , certsize) != certsize ){
		printf("failed to send record owner certs(update).\n");
		goto FAIL;
	}
	//�e�����󂯂��s����M
	MiniSSL_Receive( &(as->dataConn) , (unsigned char *)affectedRows , sizeof(int));
	if( *affectedRows < 0 ){
		goto FAIL;
	}
	//�e�����󂯂�ID����M
	if(MiniSSL_Receive( &(as->dataConn) , (unsigned char *)affectedIDs , *affectedRows * sizeof(int)) != *affectedRows * (signed)sizeof(int)){
		printf("failed to recv affected ids(update).\n");
		goto FAIL;
	}
	free(matchedIDs);
	free(certs);
	as->status = ANONYSQL_CONNECTED;
	return affectedIDs;	//��������affectedIDs��Ԃ��̂ŊJ�����Ȃ��B
FAIL:
	free(matchedIDs);
	free(certs);
	free(affectedIDs);	//���s����affectedIDs���J������
	as->status = ANONYSQL_CONNECTED;
	return NULL;
}
int *AnonysqlExecDelete(ANONYSQL_SESSION *as, char *sql, int *affectedRows, int *matchedRows)
{
	int response;
	int certsize;
	char *certs = NULL;
	int numCert;
	int *matchedIDs = NULL;
	int *affectedIDs = NULL;
	char tablename[MAX_TABLE_NAME];

	//�e�����󂯂��s����������
	*affectedRows = 0;
	*matchedRows = 0;

	if( PostRequest(as , sql ,&response ) != TRUE ){
		return NULL;
	}
	//�}�����������X�|���X�R�[�h����
	if( response != OK_RESULT_FOLLOW ){
		goto FAIL;
	}
	//�}�b�`�����s�����擾
	if( MiniSSL_Receive( &(as->dataConn) , (unsigned char *)matchedRows , sizeof(int)) != sizeof(int) ){
		printf("failed to recv matched rows(delete).\n");
		goto FAIL;
	}
	if( *matchedRows < 0 ){
		as->status = ANONYSQL_CONNECTED;
		goto FAIL;
	}
	matchedIDs = malloc(*matchedRows * sizeof(int));
	affectedIDs = malloc(*matchedRows * sizeof(int));
	//�}�b�`����ID����M����
	if( MiniSSL_Receive( &(as->dataConn) , (unsigned char *)matchedIDs , *matchedRows * sizeof(int)) != ((signed)sizeof(int) * (*matchedRows)) ){
		printf("failed to recv matched ids(delete).\n");
		goto FAIL;
	}
	certs = malloc(MAX_RECORD_OWNER_CERT * (*matchedRows));
	GetTableNameFromDelete(sql , tablename);
	certsize = LoadRecordOwnerCerts(as,tablename, matchedIDs, *matchedRows,certs, &numCert);
	if( certsize < 0 ){
		printf("failed to load record owner certs(delete).\n");
		goto FAIL;
	}
	//���R�[�h���L�ҏؖ����̐��𑗐M
	MiniSSL_Send( &(as->dataConn) ,  (const unsigned char *)&numCert , sizeof(int));
	//���R�[�h���L�ҏؖ����{�̑��M
	if( MiniSSL_Send( &(as->dataConn) ,  certs , certsize) != certsize ){
		printf("failed to send record owner certs(delete).\n");
		goto FAIL;
	}
	//�e�����󂯂��s����M
	MiniSSL_Receive( &(as->dataConn) , (unsigned char *)affectedRows , sizeof(int));
	if( *affectedRows < 0 ){
		goto FAIL;
	}
	//�e�����󂯂�ID����M
	if(MiniSSL_Receive( &(as->dataConn) , (unsigned char *)affectedIDs , *affectedRows * sizeof(int)) != *affectedRows * (signed)sizeof(int)){
		printf("failed to recv affected ids(delete).\n");
		goto FAIL;
	}
	//�폜���ꂽ�s�̃��R�[�h���L�ҏؖ�����j������
	if( DeleteRecordOwnerCerts(as, tablename, affectedIDs , *affectedRows) != *affectedRows){
		printf("failed to delete local record owner certs(delete).\n");
		//affectedIDs���Ăяo�����ɕԂ��̂�FAIL�ɂ͔�΂Ȃ��B
	}
	free(matchedIDs);
	free(certs);
	as->status = ANONYSQL_CONNECTED;
	return affectedIDs;	//��������affectedIDs��Ԃ��̂ŊJ�����Ȃ��B
FAIL:
	free(matchedIDs);
	free(certs);
	free(affectedIDs);	//���s����affectedIDs���J������
	as->status = ANONYSQL_CONNECTED;
	return NULL;
}	


int AnonysqlBeginTrans(ANONYSQL_SESSION *as)
{
	//�g�����U�N�V�����J�n�R�[�h���M
	int command = SQL_BEGIN_TRANS;
	if( MiniSSL_Send( &(as->dataConn) ,  (const unsigned char *)&command , sizeof(int)) != sizeof(int) ){
		printf("failed to send request(begintrans).\n");
		return FALSE;
	}
	//���X�|���X�R�[�h��M
	if( MiniSSL_Receive( &(as->dataConn) , (unsigned char *)&command , sizeof(int)) != sizeof(int) ){
		printf("failed to recv response code(begintrans).\n");
		return FALSE;
	}
	//���X�|���X�R�[�h�������R�~�b�g���[�h�I�t���H
	if( command != AUTOCOMMIT_OFF ){
		printf("invalid response code(begintrans).\n");
		return FALSE;
	}
	return TRUE;
}
int AnonysqlRollback(ANONYSQL_SESSION *as)
{
	//�g�����U�N�V�������[���o�b�N�R�[�h���M
	int command = SQL_ROLLBACK_TRANS;
	if( MiniSSL_Send( &(as->dataConn) ,  (const unsigned char *)&command , sizeof(int)) != sizeof(int) ){
		printf("failed to send request(rollback).\n");
		return FALSE;
	}
	//���X�|���X�R�[�h��M
	if( MiniSSL_Receive( &(as->dataConn) , (unsigned char *)&command , sizeof(int)) != sizeof(int) ){
		printf("failed to recv response code(rollback).\n");
		return FALSE;
	}
	//���X�|���X�R�[�h�������R�~�b�g���[�h�I�����H
	if( command != AUTOCOMMIT_ON ){
		printf("invalid response code(rollback).\n");
		return FALSE;
	}
	return TRUE;
}
int AnonysqlCommit(ANONYSQL_SESSION *as)
{
	//�g�����U�N�V�����R�~�b�g�R�[�h���M
	int command = SQL_COMMIT_TRANS;
	if( MiniSSL_Send( &(as->dataConn) ,  (const unsigned char *)&command , sizeof(int)) != sizeof(int) ){
		printf("failed to send request(commit).\n");
		return FALSE;
	}
	//���X�|���X�R�[�h��M
	if( MiniSSL_Receive( &(as->dataConn) , (unsigned char *)&command , sizeof(int)) != sizeof(int) ){
		printf("failed to recv response code(commit).\n");
		return FALSE;
	}
	//���X�|���X�R�[�h�������R�~�b�g���[�h�I�����H
	if( command != AUTOCOMMIT_ON ){
		printf("invalid response code(commit).\n");
		return FALSE;
	}
	return TRUE;
}