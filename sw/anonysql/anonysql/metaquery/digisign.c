#include <stdio.h>
#include "ok_rsa.h"
#include "ok_asn1.h"
#include "ok_md5.h"
#include "ok_rand.h"
#include "large_num.h"
#include "minissl.h"
#include "anonysqllib.h"
#include "..\authent\anonysql.h"

static void gcd(const LNm *_a ,const LNm *_b , LNm *ret);
static void GenerateBlindFactor(LNm *bf, LNm *n);
static int DoSign(MiniSSL_INFO *si , unsigned char *hash, int hashSize, unsigned char *signedHash, int *signedHashSize);

Prvkey_RSA *LoadAuthorityPrvKey(int authority)
{
	unsigned char *buf;
	char filename[256];
	Prvkey_RSA *ret;

	//�閧�L�[�ǂݍ���
	sprintf(filename, ".\\authority\\%d.key",authority);
	buf = ASN1_read_der(filename);
	if( buf == NULL ){
		printf("failed to load %s\n",filename);
		return NULL;
	}
	ret = ASN1_read_rsaprv(buf);
//	free(buf);
	return ret;
}

int DoSign(MiniSSL_INFO *si , unsigned char *hash, int hashSize, unsigned char *signedHash, int *signedHashSize)
{
	int command = REQUEST_SIGN;

	//�����v���R�}���h���M
	if(MiniSSL_Put(si , (const unsigned char *)&command , sizeof(int)) != sizeof(int)){
		return FALSE;
	}
	//�n�b�V���T�C�Y���M
	if(MiniSSL_Put(si , (const unsigned char *)&hashSize , sizeof(int)) != sizeof(int)){
		return FALSE;
	}
	//�n�b�V���{�̑��M
	if(MiniSSL_Put(si , hash , hashSize) != hashSize){
		return FALSE;
	}
	if(MiniSSL_Flush(si) != sizeof(int)+sizeof(int)+hashSize){
		return FALSE;
	}

	//���������n�b�V���T�C�Y��M
	if( MiniSSL_Receive(si , (unsigned char *)signedHashSize , sizeof(int)) != sizeof(int)){
		return FALSE;
	}
	if( *signedHashSize >= LN_MAX ){
		printf("too large signed hash size:%d\n",*signedHashSize);
		return FALSE;
	}
	//���������n�b�V���{�̎�M
	if( MiniSSL_Receive(si , signedHash , *signedHashSize) != *signedHashSize){
		return FALSE;
	}

	return TRUE;
}

int BlindSign(MiniSSL_INFO *si , unsigned char *sql ,Pubkey_RSA *pubKey, LNm *cert)
{
	unsigned char hash[MD5_SIZE];
	unsigned char blindedHash[LN_MAX];
	unsigned char signedHash[LN_MAX];
	int signedHashSize;
	LNm *bf,*ebf,*ubf,*lhash,*lblindedHash;
	int ret = FALSE;
	int sendBytes;

	//�ϐ��̏������ƃ[���N���A
	ubf = LN_alloc();
	lhash = LN_alloc();
	bf = LN_alloc();
	ebf = LN_alloc();
	lblindedHash = LN_alloc();
	memset(blindedHash , 0 , sizeof(blindedHash));

	//�n�b�V������
	OK_MD5(strlen(sql) ,sql, hash);

	//blinding factor����
	GenerateBlindFactor(bf , pubKey->n);
#ifdef TRACE_ON 
	printf("bf: "); LN_print(bf); 
#endif
	//blinding factor�����J�L�[�ňÍ���
	LN_exp_mod(bf , pubKey->e ,pubKey->n, ebf );
#ifdef TRACE_ON 
	printf("encrypted bf: "); LN_print(ebf);
#endif
	//�o�C�i����̃n�b�V�������Z�ł���悤��LNm�^�ɂ���
	LN_set_num_c(lhash , MD5_SIZE, hash);
#ifdef TRACE_ON 
	printf("lhash:"); LN_print(lhash);
#endif
	//�n�b�V�����u���C���h��(hash*rand^e mod n)
	LN_mul_mod( ebf , lhash , pubKey->n , lblindedHash);
#ifdef TRACE_ON 
	printf("toserver: "); LN_print(lblindedHash);
#endif
	sendBytes = LN_now_byte(lblindedHash);
	//���M�̂��߂�LNm����o�C�i����ɕϊ�
	LN_get_num_c(lblindedHash , sendBytes , blindedHash);

	//�F�؃T�[�o�ɑ����ď��������炤
	if( DoSign(si , blindedHash , sendBytes, signedHash , &signedHashSize) != TRUE ){
		goto FAIL;
	}
	//��M�����o�C�i�����LNm�^��
	LN_set_num_c(lblindedHash , signedHashSize , signedHash);

#ifdef TRACE_ON 
	printf("fromserver: "); LN_print(lblindedHash);
#endif

	//blinding factor�̋t���𓾂�
	LN_mod_inverse(bf ,pubKey->n , ubf);

#ifdef TRACE_ON 
	printf("invbf: "); LN_print(ubf);
	//�t�������������e�X�g
	LN_mul_mod(ubf , bf , pubKey->n , cert);
	printf("bf*invbf=1: "); LN_print(cert);
#endif

	//unblinding �u���C���h����
	LN_mul_mod(lblindedHash , ubf ,  pubKey->n , cert); 
#ifdef TRACE_ON
	printf("cert: "); LN_print(cert);
#endif

	//��������
	if( CheckCert(cert , lhash ,  pubKey) != TRUE){
		printf("invalid request cert.\n");
		goto FAIL;
	}else{
		SockFrame_DebugOut("cert check ok.\n");
	}
	ret = TRUE;

FAIL:
	LN_free(bf);
	LN_free(ebf);
	LN_free(ubf);
	LN_free(lhash);
	LN_free(lblindedHash);
	return ret;
}


int CheckCert(LNm *cert, LNm *hash, Pubkey_RSA *key)
{
	LNm *w;
	int ret;

	w = LN_alloc();
	//���������J�L�[�ŕ��������ăn�b�V���𓾂�
	LN_exp_mod(cert , key->e ,key->n, w );
	//���n�b�V���Ə������瓾���n�b�V�����r
	if( LN_cmp( w , hash) == LN_EQUAL ){
		ret = TRUE;
	}else{
		ret = FALSE;
	}

	LN_free(w);
	return ret;
}


//blinding factor����
void GenerateBlindFactor(LNm *bf, LNm *n)
{
	LNm *ret;
	unsigned char c = 1;
	unsigned char d = 1;
	LNm *one;
	unsigned char rand[MD5_SIZE];

	ret = LN_alloc();
	//��r�̂��߂̒萔�h�P�h��p��
	one = LN_alloc();
	LN_set_num_c(one , 1 , &c);

	do{
#if 1
		//�u���C���h�����p�̔閧�̗�������
		RAND_bytes(rand , MD5_SIZE);
		LN_set_num_c(bf , MD5_SIZE, rand);
#else
		//�u���C���h�t�@�N�^���P�ɂ���ƕ��ʂ̏����ɂȂ�
		memset(rand , 0 , sizeof(rand));
		LN_set_num_c(bf , 1, &d);
#endif
		
		//bf��n��菬�����K�v����(bf < n)
		if( LN_cmp( bf , n ) != -1 ){
			break;
		}
		//n��blinding factor�݂͌��ɑf�ł���K�v����
		gcd(n , bf , ret);
		//LN_print(rer);
		if( LN_cmp( ret , one ) == LN_EQUAL ){
			break;
		}
	}while(1);

	LN_free(one);
	LN_free(ret);
}

//a��b�̍ő���񐔂�ret�Ɋi�[
//���[�N���b�h�̌ݏ��@
void gcd(const LNm *_a ,const LNm *_b , LNm *ret)
{
	LNm *r,*a,*b;
	LNm *zero;

	r = LN_alloc();
	zero = LN_alloc();
	LN_clean(zero);

	//a > b
//	if( LN_cmp(_a ,_b ) == 1 ){
		//_a��_b�͂��̊֐����ł͂�����Ȃ��̂�const�C������B
		a = LN_clone((LNm *)_a);
		b = LN_clone((LNm *)_b);
//	}else{ //a < b
//		b = LN_clone(_a);
//		a = LN_clone(_b);
//	}
	//r > 0
	while(1){
		// r = a % b
		LN_mod(a , b , r);
		if( LN_cmp(r , zero) == 0 ){
			break;
		}
		// a = b
		LN_copy(b, a);
		// b = r
		LN_copy(r , b);
	}
	LN_copy(b , ret);
	LN_free(a);
	LN_free(b);
	LN_free(r);
	LN_free(zero);
}


Pubkey_RSA *LoadAuthorityPubKey(int authority)
{
	unsigned char *buf;
	char filename[256];
	Pubkey_RSA *ret;

	//�閧�L�[�ǂݍ���
	sprintf(filename, ".\\authority\\%d.key",authority);
	buf = ASN1_read_der(filename);
	if( buf == NULL ){
		//SockFrame_DebugOut("failed to load %s\n",filename);
		return NULL;
	}
	ret = ASN1_read_rsapub(buf);

	return ret;
}

//size�o�C�g���̏���cert�ƕ���request�������������؂���B
//\authority�t�H���_���̌����L�[�������Ɏg���Č��؂���B
//���؂ɐ��������ꍇ�͌����R�[�h�i���̐����j��Ԃ��B
//���s�����ꍇ�͕��̐�����Ԃ��B
int VerifyRequest(int size, UCHAR *_cert, UCHAR *request)
{
	int count = 1;
	Pubkey_RSA *pub;
	LNm *hash;
	LNm *cert;
	unsigned char buf[MD5_SIZE];

	//�n�b�V������
	OK_MD5(strlen(request) ,request, buf);
	//char����LNm�^�ɕϊ�
	hash = LN_alloc();
	LN_set_num_c(hash , MD5_SIZE, buf);
	cert = LN_alloc();
	LN_set_num_c(cert , size, _cert);

	do{
		pub = LoadAuthorityPubKey(count);
		if( pub == NULL ){
			//�S�ẴL�[�Ō��؂Ɏ��s
			break;
		}
		//��������
		if( CheckCert(cert,hash,pub) == TRUE ){
			LN_free(cert);
			LN_free(hash);
			RSAkey_free((Key*)pub);
			return count;
		}
		RSAkey_free((Key*)pub);
		count++;
	}while(1);

	LN_free(cert);
	LN_free(hash);
	return -1;
}



