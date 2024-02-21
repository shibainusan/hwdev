//�F�؃T�[�o

#include <stdio.h>
#include "sockframe.h"
#include "minissl.h"

int main()
{
	MiniSSL_INFO si;

	SockFrame_Init();
	//SockFrame_EnableDebugMessage();
	SockFrame_DisableDebugMessage();
	MiniSSL_Init();

	MiniSSL_InitSessionInfo(&si);
	//�����̃L�[�y�A��ǂ�
	MiniSSL_SetMyPubPrvKey(&si , "authentprv.key");
	//�N���C�A���gACL��ǂ�
	MiniSSL_LoadClientACL();
	//���ҔF�؃��[�h
	si.mode = AUTHENT_CLIENTSERVER;
	//���b�X���J�n
	MiniSSL_Listen(&si , 19418);
	MiniSSL_FreeSessionInfo(&si);
	MiniSSL_Cleanup();
	SockFrame_Cleanup();
} 