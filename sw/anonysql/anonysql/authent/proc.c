#include "sockframe.h"
#include "minissl.h"
#include "anonysql.h"
#include "..\..\aicryptolib\src\include\ok_rsa.h"
#include "..\..\aicryptolib\src\include\ok_x509.h"
#include "..\..\aicryptolib\src\include\ok_asn1.h"

static int RequestSignProc(MiniSSL_INFO *ci ,int authority);

int MiniSSL_OnClientConnect(MiniSSL_INFO *ci,int authority)
{
	int command;
	printf("Client Name:%s\n",ci->clientName );

	do{
		//�R�}���h��M
		if( MiniSSL_Receive( ci , (unsigned char *)&command , sizeof(int)) != sizeof(int) ){
			printf("failed to receive command.\n");
			break;
		}
		//�����v���̏ꍇ
		if( command == REQUEST_SIGN ){
			if( RequestSignProc(ci , authority) != TRUE ){
				//break;
			}
		//�����m�F�̏ꍇ
		}else if( command == REQUEST_AUTHORITY ){
			//�����R�[�h��ԑ�
			if( MiniSSL_Send(ci ,  (const unsigned char *)&authority , sizeof(int)) != sizeof(int) ){
				//break;
			}
		//���̑��F���s�\�ȃR�}���h
		}else{
			printf("unknown command:%d\n" , (unsigned int)command);
			break;
		}
	}while(1);


	return TRUE;
}


//�����v���̏ꍇ
int RequestSignProc(MiniSSL_INFO *ci ,int authority)
{
	int size;
	LNm *hash;
	LNm *signedHash;
	Prvkey_RSA *authorityKey;
	unsigned char w[LN_MAX];

	hash = LN_alloc();
	signedHash = LN_alloc();

	//�n�b�V���T�C�Y��M
	if( MiniSSL_Receive( ci , (unsigned char *)&size , sizeof(int)) != sizeof(int) ){
		printf("failed to receive size of hash.\n");
		goto FAIL;
	}
	//�n�b�V���T�C�Y�̃`�F�b�N
	if( size > LN_MAX ){
		printf("too large hash size:%d\n",size);
		goto FAIL;
	}
	//�n�b�V���{�̎�M
	if( MiniSSL_Receive( ci , w , size) != size ){
		printf("failed to receive hash.\n");
		goto FAIL;
	}
	//�o�C�i���񂩂�LNm�^��
	LN_set_num_c(hash , size, w);
#ifdef TRACE_ON
	printf("recvhash: "); LN_print(hash);
#endif
	//�T�[�o�閧���ŏ���
	//LN_exp_mod(hash , ci->myPrvKey->d ,ci->myPrvKey->n, signedHash );
	//��������閧�������[�h����
	authorityKey = LoadAuthorityPrvKey(authority);
	if( authorityKey == NULL){
		goto FAIL;
	}
	//����
	LN_exp_mod(hash , authorityKey->d ,authorityKey->n, signedHash );
	RSAkey_free((Key*)authorityKey);

#ifdef TRACE_ON
	printf("signedhash: "); LN_print(signedHash);
#endif

	//���������n�b�V���̃o�C�g���𓾂�
	size = LN_now_byte(signedHash);
	//���M���鏐�������n�b�V���̃o�C�g���𑗂�
	if( MiniSSL_Put(ci , (const unsigned char *)&size , sizeof(int)) != sizeof(int)){
		goto FAIL;
	}
	//���������n�b�V���{�̂𑗂�
	memset(w , 0 , sizeof(w));
	LN_get_num_c(signedHash , size , w);
	if( MiniSSL_Put(ci , w , size) != size ){
		goto FAIL;
	}
	if(MiniSSL_Flush(ci) != sizeof(int)+size){
		return FALSE;
	}
	
	SockFrame_DebugOut("%s: sign ok.\n",ci->clientName);
	LN_free(hash);
	LN_free(signedHash);
	return TRUE;

FAIL:

	printf("%s: sign failed.\n",ci->clientName);
	LN_free(hash);
	LN_free(signedHash);
	return FALSE;
}

void SockFrame_OnClientConnect(SOCK_INFO *ci)
{
}