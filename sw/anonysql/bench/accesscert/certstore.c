#include <windows.h>
#include <stdio.h>
#include "ok_md5.h"
#include "..\..\anonysql\authent\anonysql.h"
#include "anonysqllib.h"
#include "..\..\dbtest\metaodbc\odbclib.h"

static int Hex2Char(char *hex, char *bin);

void SplitRecordOwnerCert(char *cert, char **server, char **database, char **table, int *id, char **sign)
{
	char *p;

	p = cert;
	*server = cert;
	p += (strlen(p) + 1);
	*database = p;
	p += (strlen(p) + 1);
	*table = p;
	p += (strlen(p) + 1);
	*id = atoi(p);
	p += (strlen(p) + 1);
	*sign = p;
}

//�ؖ����X�g�A���烌�R�[�h���L�ҏؖ������擾����
//as���L���ȏؖ����X�g�ADB�ڑ��A�T�[�o���ADB�����擾����B�e�[�u����tablename�A�sID�̔z��*matchedIDs
//�sID�̐�matchedRows���ꂼ��̏����ɍ����ؖ�����certs�Ɋi�[����B
//���ۂɊi�[���ꂽ�ؖ����̐���numCert�Ɋi�[�����B
//certs�ɂ͍Œ�ł�MAX_RECORD_OWNER_CERT * matchedRows���̃��������m�ۂ��Ă������ƁB
//certs�ɂ́i�ؖ����P�̑傫���F32bit�j�i�ؖ����P�{�́j....�i�ؖ������̑傫���F32bit�j�i�ؖ������{�́j�Ƃ����`���Ŋi�[�����
//��������certs�̑傫�����Ԃ�B���s���͕��̐����Ԃ�B
int LoadRecordOwnerCerts(ANONYSQL_SESSION *as,char *tablename,int *matchedIDs,int matchedRows,char *certs,int *numCert)
{
	int i;
	ODBCRecordset res;
	char sql[MAX_SQL_SIZE];
	char *topcert;
	char *org_certs;
	int len,certsize;

	org_certs = certs; //certs�̐擪�A�h���X��ޔ�
	*numCert = 0;
	for( i = 0 ; i < matchedRows ; i++){
		//SELECT cert FROM RecordOwnerCert WHERE tablename = '' AND servername = '' AND recordid = '' AND databasename = ''
		//�f�[�^�x�[�X���珐�����擾
		sprintf(sql , "SELECT cert FROM RecordOwnerCert WHERE servername like '%s' AND databasename like '%s' AND tablename like '%s' AND recordid like '%d'" , as->dataServerName,as->databaseName,tablename,matchedIDs[i]);
		if( ExecSelect(&(as->certStore) , sql) != TRUE ){
			FreeStatementDB(&(as->certStore));
			return -1;	//�G���[�R�[�h
		}
		GetResultColumnName(&(as->certStore) , &res);
		if( FetchResultRow(&(as->certStore) , &res) != TRUE ){
			//�ؖ����������ꍇ�̓X�L�b�v
			continue;
		}
		(*numCert)++;
		//���R�[�h���L�ҏؖ������č\��
		topcert = certs;
		certs += sizeof(int);	//�ؖ����T�C�Y�����邽��int�������Ă���
		len = strlen(as->dataServerName) + 1;
		memcpy( certs , as->dataServerName , len ); //�k�������܂߂ăR�s�[
		certs += len;
		len = strlen(as->databaseName) + 1;
		memcpy( certs , as->databaseName , len ); //�k�������܂߂ăR�s�[
		certs += len;
		len = strlen(tablename) + 1;
		memcpy( certs , tablename , len ); //�k�������܂߂ăR�s�[
		certs += len;
		len = sprintf(certs , "%d" , matchedIDs[i]) + 1;
		certs += len;
		//�����̃R�s�[
		len = Hex2Char(res.data[0] , certs);
		certs += len;
		//���R�[�h���L�ҏؖ����̑傫���v�Z
		certsize = (certs - topcert) - sizeof(int);
		memcpy(topcert , &certsize, sizeof(int));
		FreeStatementDB(&(as->certStore));
	}
	//certs�̑傫���v�Z
	return (certs - org_certs);
}
int DeleteRecordOwnerCerts(ANONYSQL_SESSION *as,char *tablename,int *affectedIDs ,int affectedRows)
{
	int i;
	int ret;
	int c = 0;	//�폜���������ؖ����̐�
	char sql[MAX_SQL_SIZE];

	for( i = 0 ; i < affectedRows ; i++){
		sprintf(sql , "DELETE RecordOwnerCert WHERE servername like '%s' AND databasename like '%s' AND tablename like '%s' AND recordid like '%d'" , as->dataServerName,as->databaseName,tablename,affectedIDs[i]);
		if( ExecDelete(&(as->certStore) , sql, &ret) != TRUE ){
			continue;
		}
		c += ret;
	}
	return c;
}

//16�i�_���v���ꂽ������hex��char�^�z��bin�ɕϊ�����
int Hex2Char(char *hex, char *bin)
{
	int len,i;
	int res;

	len = strlen(hex) / 2;	//2�����Â�1�o�C�g�ɕϊ�
	for( i = 0 ; i < len ;i++){
		sscanf(hex, "%02x" , &res);
		*bin = res;
		bin++;
		hex += 2;
	}
	return len;
}

int SaveRecordOwnerCert(ODBCConnection *dbc, char *cert, int len)
{
	//�ؖ����F(�}�V�����F�k���I�[������)�i�f�[�^�x�[�X���F�k���I�[������j�i�e�[�u�����F�k���I�[������j�iID�F�k���I�[������j�i�����F�o�C�i���c��S���j
	//�e���O�������|�C���^
	char *table,*machine,*database,*id;
	int affectedRows;
	int certsize;
	unsigned char n;
	char *sql;
	char *p,*b;
	int i;

	sql = malloc(len * 2+256);
	p = cert;
	machine = p;
	p += (strlen(machine) +1);
	database = p;
	p += (strlen(database) + 1);
	table = p;
	p += (strlen(table) + 1);
	id = p;
	p += (strlen(id) + 1);
	//�����̑傫�����v�Z����
	certsize = len - (p - cert);
	//SQL������
	strcpy(sql , "INSERT RecordOwnerCert(servername,databasename,tablename,recordid,cert) ");
	b = sql + strlen(sql);
	b = b + sprintf(b , "VALUES('%s','%s','%s','%s','", machine, database, table, id );
	//�����𕶎���Ń_���v����
	for( i = 0 ; i < certsize ; i++){
		n = *p;
		b = b + sprintf(b , "%02x" , n );
		p++;
	}
	//��������
	strcpy(b , "')");
	//�����X�g�A�ɕۑ�
	if( ExecInsert(dbc, sql, &affectedRows) != TRUE ){
		free(sql);
		return FALSE;
	}
	free(sql);
	return TRUE;
}

int VerifyRecordOwnerCertSign(char *cert ,int size, Pubkey_RSA *key)
{
	char *server, *database, *table;
	int id;
	char *_sign;
	unsigned char _hash[MD5_SIZE];
	LNm *hash,*sign;
	int ret = FALSE;

	SplitRecordOwnerCert(cert , &server, &database, &table, &id, &_sign);
	//�n�b�V���v�Z
	OK_MD5(_sign - cert ,cert , _hash);
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
	return ret;
}