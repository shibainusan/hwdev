#ifndef _CLIENT_SOCK_FRAME
#define _CLIENT_SOCK_FRAME

//�N���C�A���g�p�֐�
#include <Winsock2.h>

//�ڑ����Ă����N���C�A���g�̏���ێ�����\����
typedef struct tag_SERVER_INFO{
	struct in_addr ip;
	int port;
	SOCKET sock;
} SERVER_INFO;

//�����Ƃ��ŋ߂ɔ�������Winsock�G���[��\������
extern void SockFrame_DispLastError(void);

//�������֐�
extern int SockFrame_ServerInit(void);
extern void SockFrame_ServerCleanup(void);

//�R�l�N�V�����֐�
//nPort�Ɏw�肳�ꂽ�|�[�g�ԍ���listen���J�n����B
extern int SockFrame_Listen(unsigned short nPort);

extern int SockFrame_BuildServerInfo(SERVER_INFO *si,const char *addrstring);

//�f�[�^����M
//not implemented
extern int SockFrame_WaitForCode(SERVER_INFO *ci,unsigned char *code,int size);
//����M�^�C���A�E�g���~���Z�J���h�P�ʂŎw�肷��
extern void SockFrame_SetTimeout(SERVER_INFO *ci,int timeout);
//data��size�o�C�g���f�[�^����M����܂Ńu���b�N����B
//data�ɂ�size�o�C�g�ȏ�̃������̈���m�ۂ���B
extern int SockFrame_Receive(SERVER_INFO *ci,BYTE *data,int size);
//data�ɂ���f�[�^��size�o�C�g�����M����܂Ńu���b�N����B
//data�ɂ�size�o�C�g�ȏ�̃������̈���m�ۂ���B
extern int SockFrame_Send(SERVER_INFO *ci,const BYTE *data,int size);
//�e�L�X�g����s��M����B
//���s�ƃk�����������O�����A���ۂɓǂݍ��񂾃o�C�g����Ԃ�
//size�ɂ͏\���傫�ȃo�C�g�����w�肷�鎖�B�i3�o�C�g�ȏ�j
extern int SockFrame_ReceiveLine(SERVER_INFO *ci,unsigned char *data,int size);
//������data��n���ƁA���s�����iCRLF�j��t�����đ��M����
extern int SockFrame_SendLine(SERVER_INFO *ci,const char *data);
#endif