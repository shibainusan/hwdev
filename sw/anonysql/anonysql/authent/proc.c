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
		//コマンド受信
		if( MiniSSL_Receive( ci , (unsigned char *)&command , sizeof(int)) != sizeof(int) ){
			printf("failed to receive command.\n");
			break;
		}
		//署名要求の場合
		if( command == REQUEST_SIGN ){
			if( RequestSignProc(ci , authority) != TRUE ){
				//break;
			}
		//権限確認の場合
		}else if( command == REQUEST_AUTHORITY ){
			//権限コードを返送
			if( MiniSSL_Send(ci ,  (const unsigned char *)&authority , sizeof(int)) != sizeof(int) ){
				//break;
			}
		//その他認識不能なコマンド
		}else{
			printf("unknown command:%d\n" , (unsigned int)command);
			break;
		}
	}while(1);


	return TRUE;
}


//署名要求の場合
int RequestSignProc(MiniSSL_INFO *ci ,int authority)
{
	int size;
	LNm *hash;
	LNm *signedHash;
	Prvkey_RSA *authorityKey;
	unsigned char w[LN_MAX];

	hash = LN_alloc();
	signedHash = LN_alloc();

	//ハッシュサイズ受信
	if( MiniSSL_Receive( ci , (unsigned char *)&size , sizeof(int)) != sizeof(int) ){
		printf("failed to receive size of hash.\n");
		goto FAIL;
	}
	//ハッシュサイズのチェック
	if( size > LN_MAX ){
		printf("too large hash size:%d\n",size);
		goto FAIL;
	}
	//ハッシュ本体受信
	if( MiniSSL_Receive( ci , w , size) != size ){
		printf("failed to receive hash.\n");
		goto FAIL;
	}
	//バイナリ列からLNm型に
	LN_set_num_c(hash , size, w);
#ifdef TRACE_ON
	printf("recvhash: "); LN_print(hash);
#endif
	//サーバ秘密鍵で署名
	//LN_exp_mod(hash , ci->myPrvKey->d ,ci->myPrvKey->n, signedHash );
	//署名する秘密鍵をロードする
	authorityKey = LoadAuthorityPrvKey(authority);
	if( authorityKey == NULL){
		goto FAIL;
	}
	//署名
	LN_exp_mod(hash , authorityKey->d ,authorityKey->n, signedHash );
	RSAkey_free((Key*)authorityKey);

#ifdef TRACE_ON
	printf("signedhash: "); LN_print(signedHash);
#endif

	//署名したハッシュのバイト数を得る
	size = LN_now_byte(signedHash);
	//送信する署名したハッシュのバイト数を送る
	if( MiniSSL_Put(ci , (const unsigned char *)&size , sizeof(int)) != sizeof(int)){
		goto FAIL;
	}
	//署名したハッシュ本体を送る
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