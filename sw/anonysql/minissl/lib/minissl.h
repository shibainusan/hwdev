#ifndef MINISSL_LIB
#define MINISSL_LIB

#include "sockframe.h"
#include "..\..\aicryptolib\src\include\ok_rsa.h"
#include "..\..\aicryptolib\src\include\ok_x509.h"
#include "..\..\aicryptolib\src\include\ok_des.h"

//�F�؃��[�h
#define AUTHENT_SERVER 0x01
#define AUTHENT_CLIENTSERVER 0x02

#define CLIENT_NAME_SIZE 16
#define MiniSSL_ACL_MAX 32

#define SHARED_KEY_SIZE (64/8)
#define IV_SIZE 8
#define RSA_KEY_SIZE (1024/8)
#define CHALLENGE_SIZE (128/8)
#define MiniSSL_BUF_SIZE 65536	//����M�o�b�t�@�T�C�Y
#define RECORD_HEADER 4		//���R�[�h�w�b�_

//MiniSSL�Z�b�V�����̏���ێ�����\����
typedef struct tag_MiniSSL_INFO{
	SOCK_INFO *si;
	Key_DES *sharedKey; //�Z�b�V�������L�L�[
	Pubkey_RSA *targetPubKey; //�ڑ�����̌��J�L�[
	Pubkey_RSA *myPubKey;
	Prvkey_RSA *myPrvKey;
	char clientName[CLIENT_NAME_SIZE+1];
	int sessionReady; //�F�؊����t���O
	int mode; //�F�؃��[�h
	//int authority;

	unsigned char recvbuf[MiniSSL_BUF_SIZE+SHARED_KEY_SIZE+RECORD_HEADER]; //��M�o�b�t�@
	unsigned char *recvpos; //��M�o�b�t�@���̈ʒu
	unsigned char *recvbufLimit; //��M�o�b�t�@�I�[�ʒu
	int recvBytes; //���R�[�h���x���̖���M�o�C�g��
	unsigned char sendbuf[MiniSSL_BUF_SIZE+SHARED_KEY_SIZE+RECORD_HEADER];
	unsigned char naglebuf[MiniSSL_BUF_SIZE];
	int nagleByte;
} MiniSSL_INFO;


//�������֐�(����)
extern int MiniSSL_Init(void);
extern void MiniSSL_Cleanup(void);
//�����̌��J���Ɣ閧�����t�@�C��filename����ǂݍ���si�ɃZ�b�g����
extern int MiniSSL_SetMyPubPrvKey(MiniSSL_INFO *si,char *filename);
//�Z�b�V�������\����si������������
extern void MiniSSL_InitSessionInfo(MiniSSL_INFO *si);
extern void MiniSSL_FreeSessionInfo(MiniSSL_INFO *si);
extern int MiniSSL_Shutdown(MiniSSL_INFO *si);

//�������֐��i�T�[�o�p�j
//�N���C�A���g�F�ؗp�̃A�N�Z�X�R���g���[�����X�g��ǂݍ���
//�J�����g�f�B���N�g����acl�t�H���_�ɃA�N�Z�X�R���g���[�����X�g���L�q����
//acl.txt�ƌ��J�L�[�t�@�C����u���B
//���J�L�[��acl.txt���̃N���C�A���g��+.key�Ƃ����t�@�C����
//acl.txt�̏���
//(�N���C�A���g��),(�����R�[�h�j�i���s�j
extern int MiniSSL_LoadClientACL(void);
extern int MiniSSL_Listen(MiniSSL_INFO *baseSi,unsigned short port);
//�N���C�A���g���ڑ����Ă����Ƃ��̃R�[���o�b�N
extern int MiniSSL_OnClientConnect(MiniSSL_INFO *ci,int authority);
//���O�Ń\�P�b�g��p�ӂ����ꍇ�̔F�؊֐�
//ci�Ɏ����̃L�[�y�A�ƔF�؃��[�h���Z�b�g����
extern int MiniSSL_AuthClient(MiniSSL_INFO *ci, int *authority);

//�������֐��i�N���C�A���g�p�j
//�ڑ����F��
extern int MiniSSL_Connect(MiniSSL_INFO *si,unsigned char mode);
//�ڑ��͎��O�B�F�؂̂�
//si�ɃN���C�A���g�̃\�P�b�g��si->si�ɃZ�b�g���A�����̃L�[�y�A�ƔF�؃��[�h���Z�b�g����
extern int MiniSSL_Auth(MiniSSL_INFO *si,unsigned char mode);
//�T�[�o�F�ؗp�̌��J�����t�@�C��filename����ǂݍ��݁Asi�ɃZ�b�g����
extern int MiniSSL_SetTargetPubKey(MiniSSL_INFO *si, char *filename);
extern int MiniSSL_BuildHostPort(MiniSSL_INFO *si, const char *name);
extern int MiniSSL_SetClientName(MiniSSL_INFO *si, char *name);
//�f�[�^����M
//not implemented
extern int MiniSSL_WaitForCode(MiniSSL_INFO *ci,unsigned char *code,int size);
//data��size�o�C�g���f�[�^����M����܂Ńu���b�N����B
//data�ɂ�size�o�C�g�ȏ�̃������̈���m�ۂ���B
//�G���[���ɂ�0�������͕��̐���Ԃ��B
extern int MiniSSL_Receive(MiniSSL_INFO *ci,BYTE *data,int size);
//data�ɂ���f�[�^��size�o�C�g�����M����܂Ńu���b�N����B
//data�ɂ�size�o�C�g�ȏ�̃������̈���m�ۂ���B
//�G���[���ɂ�0�������͕��̐���Ԃ��B
extern int MiniSSL_Send(MiniSSL_INFO *ci,const BYTE *data,int size);
//data�ɂ���f�[�^��size�o�C�g�������o�b�t�@�Ɋi�[����i���M�͂��Ȃ��j
//data�ɂ�size�o�C�g�ȏ�̃������̈���m�ۂ���B
//�G���[���ɂ�0�������͕��̐���Ԃ��B
//�o�b�t�@�̃f�[�^��MiniSSL_Flush�ł��ׂđ��M�����B
extern int MiniSSL_Put(MiniSSL_INFO *ci,const BYTE *data,int size);
extern int MiniSSL_Flush(MiniSSL_INFO *ci);
//�e�L�X�g����s��M����B
//���s�ƃk�����������O�����A���ۂɓǂݍ��񂾃o�C�g����Ԃ�
//�G���[���ɂ�0�������͕��̐���Ԃ��B
//size�ɂ͏\���傫�ȃo�C�g�����w�肷�鎖�B�i3�o�C�g�ȏ�j
//�Ăяo���ƁA��M���s�ł��擪���k�������ɏ�����������B
extern int MiniSSL_ReceiveLine(MiniSSL_INFO *ci,unsigned char *data,int size);
extern int MiniSSL_ReceiveLineCRorLF(MiniSSL_INFO *ci,unsigned char *data,int size);
//������data��n���ƁA���s�����iCRLF�j��t�����đ��M����
//�G���[���ɂ�0�������͕��̐���Ԃ��B
extern int MiniSSL_SendLine(MiniSSL_INFO *ci,const char *data);
extern int MiniSSL_SendByte(MiniSSL_INFO *ci,const BYTE data);

//���̑��ؖ������색�C�u����
extern Pubkey_RSA *ASN1_read_rsapub(unsigned char *in);
#endif