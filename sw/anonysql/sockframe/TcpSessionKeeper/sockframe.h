#ifndef _SERVER_SOCK_FRAME
#define _SERVER_SOCK_FRAME

#ifndef _WINDOWS_
#include <Winsock2.h>
#endif

//�ڑ����Ă����N���C�A���g�̏���ێ�����\����
typedef struct tag_SOCK_INFO{
	struct in_addr ip;
	unsigned short port;
	SOCKET sock;
} SOCK_INFO;

//�����Ƃ��ŋ߂ɔ�������Winsock�G���[��\������
extern void SockFrame_DispLastError(void);

//�������֐�
extern int SockFrame_Init(void);
extern void SockFrame_Cleanup(void);
extern void SockFrame_EnableDebugMessage(void);
extern void SockFrame_DisableDebugMessage(void);

extern int SockFrame_Shutdown(SOCK_INFO *si);
//si������ɐڑ��ς݂��𒲂ׂ�
extern int SockFrame_IsValidSock(SOCK_INFO *si);
extern int SockFrame_DebugOut(const char *format,...);
//�T�[�o�p�֐�

//nPort�Ɏw�肳�ꂽ�|�[�g�ԍ���listen���J�n����B
//�G���[���ɂ�FALSE��Ԃ�
extern int SockFrame_Listen(unsigned short nPort);
//�N���C�A���g���ڑ����Ă����Ƃ��̃R�[���o�b�N�֐�
//ci�ɃN���C�A���g�Ɋւ����񂪊i�[�����B
extern void SockFrame_OnClientConnect(SOCK_INFO *ci); 

//�N���C�A���g�p�֐�
//�z�X�g��name���c�m�r���g���Ăh�o�A�h���X�ɕϊ����Asi�Ɋi�[����
extern int SockFrame_LookupAddress(SOCK_INFO *si, const char *name);
//(hostname):(port number)�̌`����name���c�m�r�łh�o�A�h���X�ɕϊ����A�h�o�ƃ|�[�g��si�Ɋi�[����
extern int SockFrame_BuildHostPort(SOCK_INFO *si, const char *name);
//si�Ɏw�肳��Ă���h�o�ƃ|�[�g�ɐڑ�����B
//���s���ɂ�FALSE�A�������ɂ�TRUE��Ԃ�
extern int SockFrame_Connect(SOCK_INFO *si);

//�f�[�^����M
//�G���[���b�Z�[�W�\���t��recv&send
extern int _recv(SOCKET s,char *buf,int len,int flags);
extern int _send(SOCKET s,const char *buf,int len,int flags);
//not implemented
extern int SockFrame_WaitForCode(SOCK_INFO *ci,unsigned char *code,int size);
//����M�^�C���A�E�g���~���Z�J���h�P�ʂŎw�肷��
extern void SockFrame_SetTimeout(SOCK_INFO *ci,int timeout);
//data��size�o�C�g���f�[�^����M����܂Ńu���b�N����B
//data�ɂ�size�o�C�g�ȏ�̃������̈���m�ۂ���B
//�G���[���ɂ�0�������͕��̐���Ԃ��B
extern int SockFrame_Receive(SOCK_INFO *ci,BYTE *data,int size);
//data�ɂ���f�[�^��size�o�C�g�����M����܂Ńu���b�N����B
//data�ɂ�size�o�C�g�ȏ�̃������̈���m�ۂ���B
//�G���[���ɂ�0�������͕��̐���Ԃ��B
extern int SockFrame_Send(SOCK_INFO *ci,const BYTE *data,int size);
//�e�L�X�g����s��M����B���s�R�[�h�͍폜�����B
//���s�ƃk�����������O�����A���ۂɓǂݍ��񂾃o�C�g����Ԃ�
//�G���[���ɂ�0�������͕��̐���Ԃ��B
//size�ɂ͏\���傫�ȃo�C�g�����w�肷�鎖�B�i3�o�C�g�ȏ�j
//�Ăяo���ƁA��M���s�ł��擪���k�������ɏ�����������B
extern int SockFrame_ReceiveLine(SOCK_INFO *ci,unsigned char *data,int size);
extern int SockFrame_ReceiveLineCRorLF(SOCK_INFO *ci,unsigned char *data,int size);
//������data��n���ƁA���s�����iCRLF�j��t�����đ��M����
//�G���[���ɂ�0�������͕��̐���Ԃ��B
extern int SockFrame_SendLine(SOCK_INFO *ci,const char *data);

extern int SockFrame_SendByte(SOCK_INFO *ci,const BYTE data);
#endif