#include <stdio.h>
#include <Winsock2.h>
#include <process.h>  
#include "minissl.h"
#include "sockframe.h"
#include "..\..\aicryptolib\src\include\ok_rsa.h"
#include "..\..\aicryptolib\src\include\ok_x509.h"
#include "..\..\aicryptolib\src\include\ok_des.h"
#include "..\..\aicryptolib\src\include\ok_rand.h"

static int Client_AuthentServer(MiniSSL_INFO *ci);
static int Client_AuthentClientServer(MiniSSL_INFO *ci);

#define BUF_SIZE 4096

int Client_AuthentServer(MiniSSL_INFO *ci)
{

	unsigned char buf[BUF_SIZE];
	unsigned char dest[BUF_SIZE];
	unsigned char cRnd[CHALLENGE_SIZE];

	//����̌��J�L�[�������ƃG���[
	if( ci->targetPubKey == NULL || ci->sharedKey == NULL ){
		SockFrame_DebugOut("no server public key found\n");
		return FALSE;
	}
	//�F�؃��[�h���M
	SockFrame_SendByte(ci->si ,AUTHENT_SERVER);
	//session���L�L�[����
	memset(buf , 0 , BUF_SIZE);
	RAND_bytes(buf , SHARED_KEY_SIZE);
	DESkey_set(ci->sharedKey ,SHARED_KEY_SIZE , buf);
	//iv����
	RAND_bytes(buf +  SHARED_KEY_SIZE, IV_SIZE);
	DES_set_iv(ci->sharedKey , buf + SHARED_KEY_SIZE);
	//�`�������W����
	RAND_bytes(buf +  SHARED_KEY_SIZE + IV_SIZE, CHALLENGE_SIZE);
	memcpy(cRnd , buf +  SHARED_KEY_SIZE + IV_SIZE, CHALLENGE_SIZE);
	//session���L�����T�[�o���J���ňÍ���
	memset(dest , 0 , BUF_SIZE);
	RSApub_doCrypt(SHARED_KEY_SIZE + IV_SIZE + CHALLENGE_SIZE , buf , dest , ci->targetPubKey);
	//session���L�����T�[�o�ɑ��M
	SockFrame_Send(ci->si , dest , RSA_KEY_SIZE);
	//�ԓ��҂�
	SockFrame_Receive(ci->si ,buf , CHALLENGE_SIZE);
	//�`�������W����
	DES_cbc_decrypt(ci->sharedKey , CHALLENGE_SIZE , buf ,dest);
	//�`�������W�|���X�|���X�����������H
	if( memcmp(cRnd , dest , CHALLENGE_SIZE) != 0 ){
		SockFrame_DebugOut("invalid challenge-response from server.\n");
		goto FAIL;
	}

	//clientOK���M
	SockFrame_SendByte(ci->si ,TRUE);
	//serverOK�҂�
	buf[0] = FALSE;
	SockFrame_Receive(ci->si , buf , 1);
	if( buf[0] != TRUE ){
		goto FAIL;
	}
	SockFrame_DebugOut("server authent ok.\n");
	return TRUE;

FAIL:
	SockFrame_DebugOut("server authent failed.\n");
	SockFrame_SendByte(ci->si ,FALSE);
	return FALSE;

}
int Client_AuthentClientServer(MiniSSL_INFO *ci)
{
	unsigned char *p;
	unsigned char buf[BUF_SIZE];
	unsigned char dest[BUF_SIZE];
	unsigned char cRnd[CHALLENGE_SIZE];
	unsigned char sRnd[CHALLENGE_SIZE];

	//����̌��J�L�[�Ǝ����̔閧�L�[�������ƃG���[
	if( ci->targetPubKey == NULL || ci->myPrvKey == NULL || ci->myPubKey == NULL || ci->sharedKey == NULL ){
		SockFrame_DebugOut("no server public key found\n");
		return FALSE;
	}
	//�F�؃��[�h���M
	SockFrame_SendByte(ci->si ,AUTHENT_CLIENTSERVER);
	//session���L�L�[����
	memset(buf , 0 , BUF_SIZE);
	RAND_bytes(buf , SHARED_KEY_SIZE);
	DESkey_set(ci->sharedKey ,SHARED_KEY_SIZE , buf);
	//iv����
	RAND_bytes(buf +  SHARED_KEY_SIZE, IV_SIZE);
	DES_set_iv(ci->sharedKey , buf + SHARED_KEY_SIZE);
	//�`�������W����
	RAND_bytes(buf +  SHARED_KEY_SIZE + IV_SIZE, CHALLENGE_SIZE);
	memcpy(cRnd , buf +  SHARED_KEY_SIZE + IV_SIZE, CHALLENGE_SIZE);
	//�N���C�A���g���ݒ�
	memcpy(buf +  SHARED_KEY_SIZE + IV_SIZE + CHALLENGE_SIZE , ci->clientName, sizeof(ci->clientName));
		
	//session���L�����T�[�o���J���ňÍ���
	memset(dest , 0 , BUF_SIZE);
	RSApub_doCrypt(SHARED_KEY_SIZE + IV_SIZE + CHALLENGE_SIZE + CLIENT_NAME_SIZE + 1  , buf , dest , ci->targetPubKey);
	//session���L�����T�[�o�ɑ��M
	SockFrame_Send(ci->si , dest , RSA_KEY_SIZE );
	//�ԓ��҂�
	memset(buf , 0 , BUF_SIZE);
	SockFrame_Receive(ci->si ,buf , CHALLENGE_SIZE + RSA_KEY_SIZE);
	//�N���C�A���g�`�������W-���X�|���X����
	memset(dest , 0 , BUF_SIZE);
	DES_cbc_decrypt(ci->sharedKey , CHALLENGE_SIZE , buf ,dest);
#if MINISSL_TRACE
	SockFrame_DebugOut("client challenge-response from server\n");
	HexDump(dest , CHALLENGE_SIZE);
#endif
	//�N���C�A���g�`�������W�|���X�|���X�����������H
	if( memcmp(cRnd , dest , CHALLENGE_SIZE) != 0 ){
		SockFrame_DebugOut("invalid challenge-response from server.\n");
		goto FAIL;
	}
	//�T�[�o�`�������W��閧���ŕ���
	memset(dest , 0 , BUF_SIZE);
	RSAprv_doCrypt(RSA_KEY_SIZE ,buf + CHALLENGE_SIZE,dest,ci->myPrvKey);
	//�������ʂ͉E�l�Ȃ̂Ŏ��ۂ̊J�n�ʒu�ɍ��킹��
	p = (dest + RSA_KEY_SIZE) - CHALLENGE_SIZE;
#if MINISSL_TRACE	
	SockFrame_DebugOut("server challenge to client\n");
	HexDump(p , CHALLENGE_SIZE);
#endif
	//�T�[�o�`�������W�擾
	memcpy(sRnd , p, CHALLENGE_SIZE);
	//�Z�b�V�������L�L�[�ŃN���C�A���g�`�������W���Í���
	memset(dest , 0 , BUF_SIZE);
	DES_cbc_encrypt(ci->sharedKey , CHALLENGE_SIZE , sRnd ,dest);
	//����Ԃ�
	SockFrame_Send(ci->si , dest , CHALLENGE_SIZE);

	//serverOK�҂�
	buf[0] = FALSE;
	SockFrame_Receive(ci->si , buf , 1);
	if( buf[0] != TRUE ){
		goto FAIL;
	}
	//clientOK���M
	SockFrame_SendByte(ci->si ,TRUE);
	SockFrame_DebugOut("client-server authent ok.\n");
	return TRUE;

FAIL:
	SockFrame_DebugOut("client-server authent failed.\n");
	SockFrame_SendByte(ci->si ,FALSE);
	return FALSE;
}
int MiniSSL_Auth(MiniSSL_INFO *si,unsigned char mode)
{
	si->mode = mode;
	if( mode == AUTHENT_SERVER ){
		SockFrame_DebugOut("authent mode: server only\n");
		if( Client_AuthentServer(si) != TRUE){
			goto FAIL;
		}
	}else if(mode == AUTHENT_CLIENTSERVER){
		SockFrame_DebugOut("authent mode: client-server\n");
		if( Client_AuthentClientServer(si) != TRUE ){
			goto FAIL;
		}
	}
	si->sessionReady = TRUE;
	return TRUE;
FAIL:
	MiniSSL_Shutdown(si);
	return FALSE;
}
int MiniSSL_Connect(MiniSSL_INFO *si,unsigned char mode)
{
	if( SockFrame_Connect(si->si) != TRUE ){
		goto FAIL;
	}
	return MiniSSL_Auth(si,mode);
FAIL:
	MiniSSL_Shutdown(si);
	return FALSE;
}