#include "sockframe.h"
#include "ok_md5.h"
#include "..\..\dbtest\metaodbc\odbclib.h"
#include "minissl.h"
#include "..\authent\anonysql.h"
#include "gunshu.h"
#include "profiler.h"

int ExecSQLProc(MiniSSL_INFO *si, ODBCConnection *dbc);
int InsertProc(MiniSSL_INFO *si, ODBCConnection *dbc, char *sql);
int SelectProc(MiniSSL_INFO *si, ODBCConnection *dbc, char *sql);
int UpdateProc(MiniSSL_INFO *si, ODBCConnection *dbc, char *sql);
int DeleteProc(MiniSSL_INFO *si, ODBCConnection *dbc, char *sql);
int BuildRecordOwnerCert(char *tablename, int id,Prvkey_RSA *key, char *cert);
int CheckRecordOwnerCert(char *cert,char *tablename,int *matchedIDs,int matchedRow);
int VerifyRecordOwnerCertSign(char *cert ,int size, Pubkey_RSA *key);
int *GetMatchedRows(ODBCConnection *dbc, char *tablename, char *condition, int *matchedRow);

#define BUF_SIZE 512
extern char myName[BUF_SIZE];
extern char databaseName[BUF_SIZE];
extern Key_DES recordOwnerCertKey;

int MiniSSL_OnClientConnect(MiniSSL_INFO *ci,int authority)
{
	return TRUE;
}

int ExecSQLProc(MiniSSL_INFO *si, ODBCConnection *dbc)
{
	int authority; //�����R�[�h
	int response; //�����R�[�h
	int reqCertSize;
	int requestSize;
	UCHAR reqCert[LN_MAX];
	UCHAR request[MAX_SQL_SIZE];
	int operation;

	//�Ƃ肠���������R�[�h��F�؃G���[�ɂ��Ă���
	response = AUTHENTICATION_FAILED;
	//���N�G�X�g�����T�C�Y��M
	if( MiniSSL_Receive( si , (unsigned char *)&reqCertSize , sizeof(int)) != sizeof(int) ){
		printf("failed to receive size of request cert.\n");
		goto FAIL;
	}
	if( reqCertSize > LN_MAX ){
		printf("too large request cert size:%d\n",reqCertSize);
		goto FAIL;
	}
	//���N�G�X�g�����{�̎�M
	if( MiniSSL_Receive( si , reqCert , reqCertSize) != reqCertSize ){
		printf("failed to receive request cert.\n");
		goto FAIL;
	}
	//�������N�G�X�g�T�C�Y��M(null�����܂߂��o�C�g��)
	if( MiniSSL_Receive( si , (unsigned char *)&requestSize , sizeof(int)) != sizeof(int) ){
		printf("failed to receive size of plaintext request.\n");
		goto FAIL;
	}
	if( requestSize >= MAX_SQL_SIZE ){
		printf("too large plaintext request:%d bytes.\n",requestSize);
		goto FAIL;
	}
	//�������N�G�X�g�{�̎�M
	if( MiniSSL_Receive( si , request , requestSize) != requestSize ){
		printf("failed to receive plaintext request.\n");
		goto FAIL;
	}
	//���N�G�X�g��������&�����R�[�h�擾
	authority = VerifyRequest(reqCertSize , reqCert , request);
	authority = FULL_ACCESS;
#if 0
	if( authority <= 0 ){
		//�F�؃G���[
		response = AUTHENTICATION_FAILED;
		printf("invalid request cert.\n");
		goto FAIL;
	}
#endif
	//���N�G�X�g��ʔ���
	operation = CheckSQLType(request);
	if( operation == FALSE ){
		//SQL�\���G���[
		response = INVALID_SQL;
		goto FAIL;
	}
	//���N�G�X�g�̎�ʂɂ�蕪��
	switch(operation){
	case SQL_SELECT:
		//���N�G�X�g���s�̌����͂��邩�H
		if( authority == FULL_ACCESS || authority == SELECT_ONLY){
			return SelectProc(si , dbc , request);
		}else{
			//�����Ȃ�F�G���[
			response = AUTHORIZATION_FAILED;
		}
		break;
	case SQL_UPDATE:
		if( authority == FULL_ACCESS ){
			return UpdateProc(si , dbc , request);
		}else{
			response = AUTHORIZATION_FAILED;
		}
		break;
	case SQL_INSERT:
		if( authority == FULL_ACCESS ){
			return InsertProc(si , dbc , request);
		}else{
			response = AUTHORIZATION_FAILED;
		}
		break;
	case SQL_DELETE:
		if( authority == FULL_ACCESS ){
			return DeleteProc(si , dbc , request);
		}else{
			response = AUTHORIZATION_FAILED;
		}
		break;
	default:
		goto FAIL;
		break;
	}

FAIL:
	//�G���[�R�[�h���M
	MiniSSL_Send(si ,  (const unsigned char *)&response , sizeof(int));
	return FALSE;
}
int SelectProc(MiniSSL_INFO *si, ODBCConnection *dbc, char *sql)
{
	int i;
	int response;
	ODBCRecordset rs;
	int len;
	UCHAR buf[MAX_COLUMNS * MAX_COLUMN_DATA];

	//sql�����s
	if( ExecSelect(dbc ,sql) != TRUE ){
		//SQL�\���G���[
		response = INVALID_SQL;
		MiniSSL_Send(si ,  (const unsigned char *)&response , sizeof(int));
		return FALSE;
	}

	//���ʃR�[�h�ԑ�
	response = OK_COLUMN_HEADER_FOLLOW;
	MiniSSL_Put(si ,  (const unsigned char *)&response , sizeof(int));
	//�R�����w�b�_�擾
	GetResultColumnName(dbc, &rs);
	//�S�R���������M
	MiniSSL_Put(si , (const unsigned char *)&(rs.numColumn) , sizeof(int));
	//�R������񑗐M
	for( i = 0 ; i < rs.numColumn ; i++){
		//�R�����̃f�[�^�T�C�Y���M
		MiniSSL_Put(si , (const unsigned char *)&(rs.columnSize[i]) , sizeof(int));
		//�R�������̒������M
		len = strlen(rs.columnName[i]) + 1; //NULL������1�o�C�g����
		MiniSSL_Put(si , (const unsigned char *)&len , sizeof(int));
		//�R���������M
		MiniSSL_Put(si , rs.columnName[i] , len);
	}
	//if( MiniSSL_Flush(si) < 0 ){
	//	printf("failed to send column header(select)\n");
	//}

	//row���M
	do{
		//1�s�t�F�b�`
		if( FetchResultRow(dbc , &rs) != TRUE ){
			//�������ʍs�������ꍇ
			response = REOCRD_FINISHED;
			MiniSSL_Put(si ,  (const unsigned char *)&response , sizeof(int));
			break;
		}
		//1�s����ʒm
		response = RECORD_FOLLOW;
		MiniSSL_Put(si ,  (const unsigned char *)&response , sizeof(int));
		//1�s���V���A����
		SerializeRecord(&rs, sizeof(buf) , buf , &len);
		//1�s�̃f�[�^�T�C�Y���M
		MiniSSL_Put(si , (const unsigned char *)&len , sizeof(int));
		//�{�̑��M
		MiniSSL_Put(si , buf , len);
	}while(1);
	if( MiniSSL_Flush(si) < 0 ){
		printf("failed to send recordset(select)\n");
	}
	//����SQL���s�ɔ����A�X�e�[�g�����g�n���h�������
	FreeStatementDB(dbc);
	return TRUE;
}

int DeleteProc(MiniSSL_INFO *si, ODBCConnection *dbc, char *sql)
{
	int response;
	int *matchedIDs = NULL;	//�}�b�`�����s��ID�̔z��
	char tablename[MAX_TABLE_NAME];	
	char condition[MAX_SQL_SIZE];	//Where����
	char cert[MAX_RECORD_OWNER_CERT];	//���R�[�h���L�ҏ���
	char tempSql[MAX_SQL_SIZE];		//��sDELETE�p�e���|����SQL��
	int matchedRow = 0;				//�}�b�`�����s��
	int affectedRow = 0;			//���ۂ�DELETE�����s��
	int *affectedIDs = NULL;		//���ۂ�DELETE�����s��ID�̔z��
	int numCert,certSize;			//�ؖ����̐��A�X�̏ؖ����̑傫��
	int id;
	int ret,i;

	//�e�����󂯂�s�𒲍�
	GetTableNameFromDelete(sql, tablename);
	GetWhereCondition(sql, condition);
	matchedIDs = GetMatchedRows(dbc, tablename, condition, &matchedRow);
	affectedIDs = malloc( matchedRow * sizeof(int));
	if( matchedIDs == NULL ){
		response = INVALID_SQL;
		MiniSSL_Send(si ,  (const unsigned char *)&response , sizeof(int));
		return FALSE;
	}
	//�N���C�A���g�Ɍ��ʑ��M
	response = OK_RESULT_FOLLOW;
	MiniSSL_Put(si ,  (const unsigned char *)&response , sizeof(int));
	//�}�b�`�����s��
	MiniSSL_Put(si ,  (const unsigned char *)&matchedRow , sizeof(int));
	//�}�b�`����IDs
	MiniSSL_Put(si , (const unsigned char *)matchedIDs , sizeof(int) * matchedRow);
	if( MiniSSL_Flush(si) < 0 ){
		printf("failed to send matched rows(delete)\n");
	}

	//�����ؖ����̐�����M
	MiniSSL_Receive( si , (unsigned char *)&numCert , sizeof(int));
	for( i = 0; i < numCert; i++){
		//�����ؖ����̑傫����M
		MiniSSL_Receive( si , (unsigned char *)&certSize , sizeof(int));
		if( certSize >= MAX_RECORD_OWNER_CERT ){
			//��΂�
			continue;
		}
		//�{�̎�M
		if(MiniSSL_Receive( si , (unsigned char *)&cert , certSize) != certSize ){
			continue;
		}
		//�ؖ����̊e���ڂ��v���ƍ����Ă��邩�H
		id = CheckRecordOwnerCert(cert,tablename,matchedIDs,matchedRow);
		if( id < 0 ){
			continue;
		}
		//�����`�F�b�N
		if( VerifyRecordOwnerCertSign(cert ,certSize, si->myPubKey) == TRUE ){
			//�폜���s
			sprintf(tempSql , "DELETE %s WHERE id ='%d'", tablename, id);
			if( ExecDelete(dbc,tempSql,&ret) == FALSE ){
				continue;
			}
			affectedIDs[affectedRow] = id;
			affectedRow += ret;
		}
	}
	//�e�����󂯂��s���𑗐M
	MiniSSL_Put(si ,  (const unsigned char *)&affectedRow , sizeof(int));
	//�e�����󂯂��s��ID�𑗐M
	MiniSSL_Put(si ,  (const unsigned char *)affectedIDs , sizeof(int) * affectedRow);
	if( MiniSSL_Flush(si) < 0 ){
		printf("failed to send affected rows(delete)\n");
	}
	free(matchedIDs);
	free(affectedIDs);
	return TRUE;
FAIL:
	free(matchedIDs);
	free(affectedIDs);
	return FALSE;
}

int *GetMatchedRows(ODBCConnection *dbc, char *tablename, char *condition, int *matchedRow)
{
	int *ids,*pids;
	char sql[MAX_SQL_SIZE];
	ODBCRecordset res;
	
	*matchedRow = 0;
	//select id from (tablename) where (condition)
	sprintf(sql , "SELECT id FROM %s %s" , tablename , condition);
	if( ExecSelect(dbc , sql) != TRUE){
		return NULL;
	}
	//�G���g���m��
	ids = malloc(MAX_AFFECT_ROWS*sizeof(int));
	pids = ids;
	GetResultColumnName(dbc, &res);
	while(1){
		if( FetchResultRow(dbc , &res) != TRUE ){
			break;
		}
		(*matchedRow)++;
		//�s��ID�擾
		*pids = atoi(res.data[0]);
		pids++;
		//�}�b�`����s������������ꍇ
		if( *matchedRow >= MAX_AFFECT_ROWS){
			//�t�F�b�`���~
			FreeStatementDB(dbc);
			break;
		}
	}
	return ids;
}
int CheckRecordOwnerCert(char *cert,char *tablename,int *matchedIDs,int matchedRow)
{
	char *cserver,*cdatabase,*ctable,*csign;	//cert���̊e�v�f
	int cid;
	int i;

	SplitRecordOwnerCert(cert, &cserver, &cdatabase, &ctable, &cid, &csign);
	//�T�[�o���͍����Ă���H
	if( strcmp(cserver, myName) != 0){
		return -1; //�G���[�R�[�h
	}
	//DB���͍����Ă���H
	if( strcmp(cdatabase, databaseName) != 0){
		return -1; //�G���[�R�[�h
	}
	//�e�[�u�����͍����Ă���H
	if( strcmp(ctable, tablename) != 0){
		return -1; //�G���[�R�[�h
	}
	//id��matchedIDs���ɂ���H
	for( i = 0 ; i < matchedRow ; i++){
		if( *(matchedIDs + i) == cid ){
			return cid;
		}
	}

	return -1;
}

int InsertProc(MiniSSL_INFO *si, ODBCConnection *dbc, char *sql)
{
	char cert[MAX_RECORD_OWNER_CERT];
	int response;
	int len;
	int affected;
	int newid;
	char tablename[MAX_TABLE_NAME];

	//sql�����s
	if( ExecInsertIdentity(dbc ,sql, &affected, &newid) != TRUE ){
		//SQL�\���G���[
		response = INVALID_SQL;
		MiniSSL_Send(si ,  (const unsigned char *)&response , sizeof(int));
		return FALSE;
	}
	//1�s�}���̂݋���,newid����
	if( affected != 1 || newid <= 0){
		//SQL�\���G���[
		response = INVALID_SQL;
		MiniSSL_Send(si ,  (const unsigned char *)&response , sizeof(int));
		return FALSE;
	}
	//sql������e�[�u�������o
	GetTableNameFromInsert(sql, tablename);
	//�����ؖ�������
	len = BuildRecordOwnerCert(tablename, newid, si->myPrvKey, cert);
	//�����ؖ������M
	response = OK_RECORD_OWNER_CERT_FOLLOW;
	MiniSSL_Put(si ,  (const unsigned char *)&response , sizeof(int));
	//�ؖ����T�C�Y���M
	MiniSSL_Put(si ,  (const unsigned char *)&len , sizeof(int));
	//�ؖ����{�̑��M
	MiniSSL_Put(si ,  cert , len);
	if( MiniSSL_Flush(si) < 0 ){
		printf("failed to send record owner cert(insert)\n");
	}
	return TRUE;
}


//���R�[�h���L�ҏؖ����𐶐�����iDES�Łj
//cert�ɏؖ����{�́A�A��l�ɏؖ����T�C�Y��Ԃ��B
//�Ăяo���O��cert�ɏ\���ȑ傫���̃��������m�ۂ��邱��
//�ؖ����F(�}�V�����F�k���I�[������)�i�f�[�^�x�[�X���F�k���I�[������j�i�e�[�u�����F�k���I�[������j�iID�F�k���I�[������j�i�����F�o�C�i���c��S���j
int BuildRecordOwnerCert(char *tablename, int id, Prvkey_RSA *key,char *cert)
{
	char *p;
	int size;
	unsigned char _hash[MD5_SIZE];
#ifdef RECORD_OWNER_CERT_RSA
	LNm *hash,*sign;
#endif
#ifdef RECORD_OWNER_CERT_DES
	Key_DES deskey;
#endif

	p = cert;
	//�k�������܂߂ăo�b�t�@�ɃR�s�[
	size = strlen(myName)+1;
	memcpy(p,myName, size); p += size;
	size = strlen(databaseName)+1;
	memcpy(p,databaseName, size); p += size;
	size = strlen(tablename)+1;
	memcpy(p,tablename, size); p += size;
	p += (sprintf(p , "%d" , id) + 1);
	//size = sprintf(p,"%s,%s,%s,%d",myName,databaseName,tablename,id);

	//�n�b�V���v�Z
	OK_MD5(p - cert ,cert , _hash);
	//����
#ifdef RECORD_OWNER_CERT_RSA
	hash = LN_alloc();
	LN_set_num_c(hash , MD5_SIZE, _hash);
	sign = LN_alloc();
	LN_exp_mod(hash , key->d ,key->n, sign );
	size = LN_now_byte(sign);
	LN_get_num_c(sign, size , p);
#ifdef TRACE_ON
	printf("owner cert:");
	LN_print(sign);
#endif
	LN_free(hash);
	LN_free(sign);
#endif
#ifdef RECORD_OWNER_CERT_DES
	//�Í������邲�Ƃ�IV���ς��̂őޔ�����
	deskey = recordOwnerCertKey;
	DES_cbc_encrypt(&deskey , MD5_SIZE , _hash , p);
	size = MD5_SIZE;
#endif

	return (p - cert) + size;
}

int VerifyRecordOwnerCertSign(char *cert ,int size, Pubkey_RSA *key)
{
	char *server, *database, *table;
	int id;
	char *_sign;
	unsigned char _hash[MD5_SIZE];
#ifdef RECORD_OWNER_CERT_RSA
	LNm *hash,*sign;
#endif
#ifdef RECORD_OWNER_CERT_DES
	unsigned char sign[MD5_SIZE];
	Key_DES deskey;
#endif
	int ret = FALSE;

	SplitRecordOwnerCert(cert , &server, &database, &table, &id, &_sign);
	//�n�b�V���v�Z
	OK_MD5(_sign - cert ,cert , _hash);

#ifdef RECORD_OWNER_CERT_RSA
	hash = LN_alloc();
	LN_set_num_c(hash , MD5_SIZE, _hash);
	//�����擾
	sign = LN_alloc();
	LN_set_num_c(sign , (cert + size) - _sign, _sign);
	//��������
	if( CheckCert(sign , hash, key) == TRUE ){
		ret = TRUE;
	}
	LN_free(sign);
	LN_free(hash);
#endif
#ifdef RECORD_OWNER_CERT_DES
	//��������
	deskey = recordOwnerCertKey;
	DES_cbc_decrypt(&deskey , MD5_SIZE , _sign , sign);
	if( memcmp(_hash , sign, MD5_SIZE) == 0 ){
		ret = TRUE;
	}
#endif

	return ret;
}
int UpdateProc(MiniSSL_INFO *si, ODBCConnection *dbc, char *sql)
{
	int response;
	int *matchedIDs = NULL;	//�}�b�`�����s��ID�̔z��
	char tablename[MAX_TABLE_NAME];	
	char condition[MAX_SQL_SIZE];	//Where����
	char setclause[MAX_SQL_SIZE];	//set��
	char cert[MAX_RECORD_OWNER_CERT];	//���R�[�h���L�ҏ���
	char tempSql[MAX_SQL_SIZE];		//��sUPDATE�p�e���|����SQL��
	int matchedRow = 0;				//�}�b�`�����s��
	int affectedRow = 0;			//���ۂ�UPDATE�����s��
	int *affectedIDs = NULL;		//���ۂ�UPDATE�����s��ID�̔z��
	int numCert,certSize;			//�ؖ����̐��A�X�̏ؖ����̑傫��
	int id;
	int ret,i;

	//�e�����󂯂�s�𒲍�
	GetTableNameFromUpdate(sql, tablename);
	GetSetClauseFromUpdate(sql, setclause);
	GetWhereCondition(sql, condition);
	matchedIDs = GetMatchedRows(dbc, tablename, condition, &matchedRow);
	affectedIDs = malloc( matchedRow * sizeof(int));
	if( matchedIDs == NULL ){
		response = INVALID_SQL;
		MiniSSL_Send(si ,  (const unsigned char *)&response , sizeof(int));
		return FALSE;
	}
	//�N���C�A���g�Ɍ��ʑ��M
	response = OK_RESULT_FOLLOW;
	MiniSSL_Put(si ,  (const unsigned char *)&response , sizeof(int));
	//�}�b�`�����s��
	MiniSSL_Put(si ,  (const unsigned char *)&matchedRow , sizeof(int));
	//�}�b�`����IDs
	MiniSSL_Put(si , (const unsigned char *)matchedIDs , sizeof(int) * matchedRow);
	if( MiniSSL_Flush(si) < 0 ){
		printf("failed to send matched rows(update)\n");
	}

	//�����ؖ����̐�����M
	MiniSSL_Receive( si , (unsigned char *)&numCert , sizeof(int));
	for( i = 0; i < numCert; i++){
		//�����ؖ����̑傫����M
		MiniSSL_Receive( si , (unsigned char *)&certSize , sizeof(int));
		if( certSize >= MAX_RECORD_OWNER_CERT ){
			//��΂�
			continue;
		}
		//�{�̎�M
		if(MiniSSL_Receive( si , (unsigned char *)&cert , certSize) != certSize ){
			continue;
		}
		//�ؖ����̊e���ڂ��v���ƍ����Ă��邩�H
		id = CheckRecordOwnerCert(cert,tablename,matchedIDs,matchedRow);
		if( id < 0 ){
			continue;
		}
		//�����`�F�b�N
		if( VerifyRecordOwnerCertSign(cert ,certSize, si->myPubKey) == TRUE ){
			//�X�V���s
			sprintf(tempSql , "UPDATE %s %s WHERE id ='%d'", tablename,setclause, id);
			if( ExecUpdate(dbc,tempSql,&ret) == FALSE ){
				continue;
			}
			affectedIDs[affectedRow] = id;
			affectedRow += ret;
		}
	}
	//�e�����󂯂��s���𑗐M
	MiniSSL_Put(si ,  (const unsigned char *)&affectedRow , sizeof(int));
	//�e�����󂯂��s��ID�𑗐M
	MiniSSL_Put(si ,  (const unsigned char *)affectedIDs , sizeof(int) * affectedRow);
	if( MiniSSL_Flush(si) < 0 ){
		printf("failed to send affected rows(update)\n");
	}
	free(matchedIDs);
	free(affectedIDs);
	return TRUE;
FAIL:
	free(matchedIDs);
	free(affectedIDs);
	return FALSE;
}


void SockFrame_OnClientConnect(SOCK_INFO *ci)
{
	MiniSSL_INFO si;
	int authority;
	int command;
	ODBCConnection dbc;
	int response;

	//gunshu�̉����R�[�h
	if( Gunshu_OnClientConnect(ci) != TRUE ){
		return;
	}

	printf("gunshu session established.\n");
	MiniSSL_InitSessionInfo(&si);
	//�\�P�b�g�����R�s�[
	*si.si =  *ci;
	//�����̃L�[�y�A��ǂ�
	MiniSSL_SetMyPubPrvKey(&si , "datastoreprv.key");
	//�T�[�o�̂ݔF�؃��[�h
	si.mode = AUTHENT_SERVER;

	//�T�[�o�F�؂ɉ���
	if( MiniSSL_AuthClient(&si , &authority) == TRUE ){
	}else{
		MiniSSL_FreeSessionInfo(&si);
		return;
	}

	//ODBC�ڑ�
	if( ConnectDBfromSettingFile(&dbc , ".\\odbclib.ini") != TRUE){
		PrintSQLerr(&dbc);
		MiniSSL_FreeSessionInfo(&si);
		FreeStatementDB(&dbc);
		return;
	}
	do{
		//�R�}���h��M
		if( MiniSSL_Receive( &si , (unsigned char *)&command , sizeof(int)) != sizeof(int) ){
			printf("failed to receive command.\n");
			break;
		}

		//���N�G�X�g���s�̏ꍇ
		if( command == SQL_EXEC ){
			//�G���[�������Ă��p��
			ExecSQLProc(&si,&dbc);
		//�g�����U�N�V��������
		}else if( command == SQL_BEGIN_TRANS){
			BeginTransaction(&dbc);
			response = AUTOCOMMIT_OFF;
			MiniSSL_Send(&si ,  (const unsigned char *)&response , sizeof(int));
		}else if( command == SQL_COMMIT_TRANS){
			CommitTransaction(&dbc);
			response = AUTOCOMMIT_ON;
			MiniSSL_Send(&si ,  (const unsigned char *)&response , sizeof(int));
		}else if( command == SQL_ROLLBACK_TRANS){
			RollbackTransaction(&dbc);
			response = AUTOCOMMIT_ON;
			MiniSSL_Send(&si ,  (const unsigned char *)&response , sizeof(int));
		//�Z�b�V�����I��
		}else if( command == SQL_BYE){
			break;
		//���̑��F���s�\�ȃR�}���h
		}else{
			printf("unknown command:%d\n" , command);
			//�R�l�N�V�����ؒf
			break;
		}
	}while(1);

	//ODBC�ؒf
	DisconnectDB(&dbc);

	MiniSSL_FreeSessionInfo(&si);

}