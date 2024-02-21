#include <windows.h>
#include <stdio.h>
#include <process.h>
#include "sockframe.h"

//�o�H�m����ɃZ�b�V�������L���Ȋ���
#define GUNSHU_SESSION_TIMEOUT (10*60*1000)
#define COMMAND_BUF 1024
#define TRANS_BUFSIZE 4096
#define BUF_SIZE 1024

typedef struct {
	SOCK_INFO prev,next;
} GUNSHU_SESSION_INFO;

typedef struct{
	char managerAddr[BUF_SIZE];
	char myAddr[BUF_SIZE];
	int randomChoice;
} GUNSHU_SERVICE_INFO;

extern GUNSHU_SERVICE_INFO gunshuInfo;

int Command_Est(GUNSHU_SESSION_INFO *gsi);
int Command_Forward(GUNSHU_SESSION_INFO *gsi);
int Command_Path(GUNSHU_SESSION_INFO *gsi);
void DownlinkTrans(void* gsi_);
void UplinkTrans(void* gsi_);

void SockFrame_OnClientConnect(SOCK_INFO *ci)
{
	char com[COMMAND_BUF];
	int ret;
	GUNSHU_SESSION_INFO gsi;

	SockFrame_SetTimeout(ci,GUNSHU_SESSION_TIMEOUT);
	//�����̏�����
	srand( (unsigned)time( NULL ) );
	ZeroMemory( &gsi , sizeof(GUNSHU_SESSION_INFO));
	gsi.prev = *ci;
	do{
		//�R�}���h�҂�
		ret = SockFrame_ReceiveLine(ci,com,COMMAND_BUF);
		if( ret <= 0){
			printf("OnClientConnect Loop failed:%d\n",ret);
			break;
		}
		//�o�H�m���R�}���h�̏���
		if( strcmp("est" , com) == 0 ){
			if( Command_Est(&gsi) != TRUE){
				break;
			}
		//�]���R�}���h�̏���
		}else if(strcmp("forward", com) == 0){
			if( Command_Forward(&gsi) != TRUE ){
				break;
			}
		//manager�ɂ�铮��e�X�g
		}else if(strcmp("test",com) == 0){
			printf("test\n");
			SockFrame_SendLine(ci , "ok");
			break;
		//�o�H����
		}else if(strcmp("path",com) == 0){
			printf("path trace.\n");
			if( Command_Path(&gsi) != TRUE){
				break;
			}
		}else{
			printf("unknown command:%s\n", com);
			break;
		}
	}while(1);
	if( SockFrame_IsValidSock(&(gsi.next)) == TRUE ){
		SockFrame_Shutdown(&(gsi.next));
	}
}

int Command_Est(GUNSHU_SESSION_INFO *gsi)
{
	char com[COMMAND_BUF];
	char buf[COMMAND_BUF];
	char *nextHost;
	char (*services)[COMMAND_BUF];
	int i,ret;
	int numList;

	services = NULL;
	printf("establish route.\n");

	//Service���X�g������M
	ret = SockFrame_ReceiveLine(&(gsi->prev),com,COMMAND_BUF);
	numList = atoi(com);
	printf("recv %d service list\n",numList);
	if( numList <= 0 ){
		printf("no service available.\n");
		goto FAIL;
	}
	//Service���X�g��M
	services = malloc(numList * COMMAND_BUF);
	for( i = 0 ; i < numList ; i++){
		ret = SockFrame_ReceiveLine(&(gsi->prev),*(services + i),COMMAND_BUF); 
		printf("%s\n",*(services+i));
	}
	
	//Service���X�g����Service��������_���ɑI��
	printf(" numlist = %d\n" , numList );
	if( gunshuInfo.randomChoice == TRUE ){
		//�����_���I��L��
		nextHost = services[(rand() % numList)];
	}else{
		//�����_���I�𖳌�
		nextHost = services[0];
	}
	//�I��Service�ɐڑ�
	if( SockFrame_BuildHostPort(&(gsi->next) , nextHost) == FALSE){
		goto FAIL;
	}
	if( SockFrame_Connect(&(gsi->next)) == FALSE){
		goto FAIL;
	}
	//�Z�b�V�����̃^�C���A�E�g��ݒ�
	SockFrame_SetTimeout(&(gsi->next) , GUNSHU_SESSION_TIMEOUT);
	//�o�H�m���R�}���h�����̃T�[�r�X�ɓ]��
	SockFrame_SendLine(&(gsi->next) , "est");
	printf("sending %d service list.\n" , numList -1);
	//�T�[�r�X��������炵�đ���
	SockFrame_SendLine(&(gsi->next) , _itoa(numList - 1 ,buf, 10));
	for(i = 0; i < numList ; i++){
		//���M��̃z�X�g���͑���Ȃ�
		if( nextHost != services[i] ){
			SockFrame_SendLine(&(gsi->next) , services[i]);
		}
	}
	//���ʑ҂�
	ret = SockFrame_ReceiveLine(&(gsi->next),com,COMMAND_BUF);
	if( strcmp(com , "ok") == 0 ){
		printf("next service response: ok\n");
		SockFrame_SendLine(&(gsi->prev), "ok");
	}else{
		printf("next service response: fail code %d %s\n",ret,com);
		goto FAIL;
	}

	free(services);
	return TRUE;
FAIL:
	SockFrame_SendLine(&(gsi->prev),"fail");
	free(services);
	return FALSE;
}
void DownlinkTrans(void* gsi_)
{	
	int ret;
	BYTE buf[TRANS_BUFSIZE];
	GUNSHU_SESSION_INFO *gsi;

	gsi = (GUNSHU_SESSION_INFO *)gsi_;
	do{
		ret = _recv(gsi->next.sock,buf,TRANS_BUFSIZE,0);
		if( ret <= 0 ){
			printf("failed to recv from next\n");
			break;
		}
		if( SockFrame_Send(&(gsi->prev),buf,ret) <= 0){
			printf("failed to send to prev\n");
			break;
		}
	}while(1);
	printf("exit DownLinkTrans\n");
	_endthread();
}
void UplinkTrans(void* gsi_)
{
	int ret;
	BYTE buf[TRANS_BUFSIZE];
	GUNSHU_SESSION_INFO *gsi;

	gsi = (GUNSHU_SESSION_INFO *)gsi_;

	//prev �� next �ւ̒ʐM���[�v
	do{
		ret = _recv(gsi->prev.sock,buf,TRANS_BUFSIZE,0);
		if( ret <= 0 ){
			printf("failed to recv from prev\n");
			break;
		}
		if( SockFrame_Send(&(gsi->next),buf,ret) <= 0){
			printf("failed to send to next\n");
			break;
		}
	}while(1);
	printf("exit UpLinkTrans\n");
	_endthread();
}
int Command_Forward(GUNSHU_SESSION_INFO *gsi)
{
	int ret;
	HANDLE hThreads[2];
	HANDLE hThread,hThread2;

	printf("forward mode.\n");
	if( SockFrame_IsValidSock(&(gsi->next)) == FALSE || SockFrame_IsValidSock(&(gsi->prev)) == FALSE){
		printf("invalid socket.\n");
		return FALSE;
	}
	//forward�R�}���h�����̃T�[�r�X�ɓ]��
	SockFrame_SendLine(&(gsi->next) , "forward");
	
	//next�@���@prev�ւ̒ʐM�X���b�h
	hThread = (HANDLE)_beginthread(DownlinkTrans, 0, (void*)gsi);
	//prev�@���@next�ւ̒ʐM�X���b�h
	hThread2 = (HANDLE)_beginthread(UplinkTrans, 0,(void*)gsi);
	//�X���b�h�I���҂�
	hThreads[0] = hThread;
	hThreads[1] = hThread2;
	WaitForMultipleObjects(2 , hThreads , FALSE , INFINITE);
	printf("wait finish.\n");
	//�ʐM���s������\�P�b�g�N���[�Y
	//SockFrame_Shutdown(&(gsi->prev));
	//SockFrame_Shutdown(&(gsi->next));

	return FALSE;
}


int Command_Path(GUNSHU_SESSION_INFO *gsi)
{
	char buf[TRANS_BUFSIZE];

	//���̃T�[�r�X��path�R�}���h�]��
	SockFrame_SendLine(&(gsi->next) , "path");
	do{
		//�z�X�g����M
		if( SockFrame_ReceiveLine(&(gsi->next) , buf , TRANS_BUFSIZE) > 0){
			//��M�����z�X�g����O�̃T�[�r�X�ɓ]��
			SockFrame_SendLine(&(gsi->prev) ,buf);
		}else{
			//���s�݂̂Ȃ��M���[�v�𔲂���
			break;
		}
	}while(1);
	//�����̃A�h���X��O�̃T�[�r�X�ɑ���
	SockFrame_SendLine(&(gsi->prev) , gunshuInfo.myAddr);
	//���s�݂̂ŏI��
	SockFrame_SendLine(&(gsi->prev) , "");

	return TRUE;
}