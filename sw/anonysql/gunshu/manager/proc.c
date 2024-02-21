#include <stdio.h>
#include <winsock2.h>
#include "sockframe.h"
#include "listman.h"

#define COMMAND_BUF 1024

int IsCorrectService(const char *hostname);
int IsCorrectServiceName(const char *hostname);

void SockFrame_OnClientConnect(SOCK_INFO *ci) 
{
	char com[COMMAND_BUF];
	char buf[COMMAND_BUF];
	int ret;
	int i;
	int numList;
	ServiceList sl;
	ServiceNode *w;

	//�T�[�r�X���X�g�ǂݍ���
	LoadService(&sl);

	SockFrame_SetTimeout(ci,15000);

	//�R�}���h�҂�
	ret = SockFrame_ReceiveLine(ci,com,COMMAND_BUF);

	//�o�^�R�}���h�̏���
	if( strcmp("reg" , com) == 0 ){
		printf("register host.\n");
		//�o�^����z�X�g���҂�
		ret = SockFrame_ReceiveLine(ci,com,COMMAND_BUF);
		//�������T�[�r�X�����`�F�b�N
		if( IsCorrectServiceName(com) != TRUE ){
			SockFrame_SendLine(ci,"fail");
			return;
		}
		//�����o�^�ς݂��H 
		if( FindService(&sl , com) == NULL ){
			AddService(&sl , com);
			SaveService(&sl);
		}
		SockFrame_SendLine(ci,"ok");
	//���X�g�񋟃R�}���h�̏���
	}else if(strcmp("list", com) == 0){
		printf("send hostlist.\n");
		//���X�g�����𑗐M
		numList = GetServiceCount(&sl);
		sprintf(buf , "%d" , numList);
		SockFrame_SendLine(ci , buf);
		//���X�g�̓��e�𑗐M
		w = TopService(&sl);
		for(i = 0 ; i < numList ; i++){
			if(w == NULL){
				break;
			}
			SockFrame_SendLine(ci , w->name );
			w = w->next;
		}
	}
}

int IsCorrectServiceName(const char *hostname)
{
	SOCK_INFO si;
	int ret;

	ret = SockFrame_BuildHostPort(&si , hostname);
	if( ret != TRUE ){
		return ret;
	}
	return TRUE;
}