#include <stdio.h>
#include <stdlib.h>
#include "sockframe.h"
#include "listman.h"
#include <process.h>  

#define COMMAND_BUF 1024

int IsCorrectService(const char *hostname)
{
	SOCK_INFO si;
	int ret;
	char buf[COMMAND_BUF];

	ret = SockFrame_BuildHostPort(&si , hostname);
	if( ret != TRUE ){
		return ret;
	}
	//�e�X�g����T�[�r�X�ɐڑ�
	ret = SockFrame_Connect(&si);
	SockFrame_SetTimeout(&si , 5000);
	if( ret != TRUE ){
		return ret;
	}
	//�e�X�g�R�}���h���M
	SockFrame_SendLine(&si , "test");
	//���ʎ�M
	SockFrame_ReceiveLine(&si , buf,COMMAND_BUF);
	//������"ok"��Ԃ������H
	if( strcmp("ok",buf) != 0 ){
		return FALSE;
	}
	return TRUE;
}

void TestServices(void *n)
{
	ServiceList sl;
	ServiceNode *w,*w2;

	do{
		//�e�X�g���s�Ԋu
		Sleep(60 * 1000);
		printf("testing services\n");
		//�T�[�r�X���X�g�ǂݍ���
		LoadService(&sl);
		w = TopService(&sl);
		do{
			if(w == NULL){
				break;
			}
			if( IsCorrectService(w->name ) != TRUE){
				printf("invalid service: %s\n",w->name);
				//�T�[�r�X���e�X�g�Ɏ��s�����烊�X�g����폜
				w2 = w->next;
				DelService(&sl, w);
				w = w2;
				SaveService(&sl);
			}else{
				printf("ok: %s\n",w->name);
				w = w->next;
			}
		}while(1);
	}while(1);
	_endthread();
}



int main(int argc, char **argv)
{
	
	SockFrame_Init();
	atexit(SockFrame_Cleanup);

	//service����X���b�h�N��
	_beginthread(TestServices , 0 , NULL);
	SockFrame_Listen(23621);
}