#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "sockframe.h"
#include "gunshu.h"

#define MYAPPNAME "Gunshu Initiator 1.1"
#define SOCK_BUF_SIZE 4096
#define BUF_SIZE 1024

typedef char ServiceName[BUF_SIZE];

static SOCK_INFO managerSock;

void DispLastError(void)
{
	LPVOID lpMsgBuf;
	FormatMessage( FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
				    NULL, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // ����̌���
					(LPTSTR) &lpMsgBuf, 0, NULL);
	printf("API:%s\n",lpMsgBuf);
	LocalFree(lpMsgBuf);
}

int Gunshu_SetManagerAddr(const char *addr)
{
	//�����W�F�l���[�^������
	srand( (unsigned)time( NULL ) );

	//DNS�Ŗ��O�������|�[�g�ԍ�����
	if(SockFrame_BuildHostPort(&managerSock , addr) != TRUE){
		return FALSE;
	}
	return TRUE;
}
int Gunshu_LoadSetting(const char *filename)
{
	int ret;
	char buf[BUF_SIZE];

	//manager�̃A�h���X���擾
	ret = GetPrivateProfileString(MYAPPNAME , "ManagerAddr" , "" , buf , BUF_SIZE , filename);
	if(ret == 0){
		DispLastError();
		return FALSE;
	}

	return Gunshu_SetManagerAddr(buf);
}
//manager�ɐڑ�����service���X�g���擾����
//si�ɂ͎��O��manager�̂h�o�ƃ|�[�g�ԍ����w�肷��B
//sn�ɂ̓��������m�ۂ����̂ŁA�Ăяo������free���邱�ƁB
//���s���ɂO�ȉ��A��������service����Ԃ�
int GetServiceList(SOCK_INFO *si, ServiceName **sn)
{
	char buf[BUF_SIZE];
	int numList = 0;
	int i;
	
	//manager�ɐڑ�
	if( SockFrame_Connect(si) != TRUE){
		printf("failed to connect to manager.\n");
		return FALSE;
	}
	//�R�}���h���s
	SockFrame_SendLine(si , "list");
	//�S���X�g�����𓾂�
	SockFrame_ReceiveLine(si , buf , BUF_SIZE);
	numList = atoi(buf);
	if( numList == 0){
		return 0;
	}
	printf("recv %d service list\n",numList);

	*sn = (ServiceName *)malloc(numList * sizeof(ServiceName));
	//service���X�g�{����M
	for( i = 0 ; i < numList ; i++){
		SockFrame_ReceiveLine(si , buf , BUF_SIZE);
		if( *buf == '\0'){
			free(*sn);
			*sn = NULL;
			SockFrame_Shutdown(si);
			return 0;
		}
		strcpy((char *)(*sn + i) , buf);
	}
	SockFrame_Shutdown(si);
	return numList;
}

int Gunshu_Connect(SOCK_INFO *si,const char *responderAddr, int limit)
{
	ServiceName *sn,*nextService;
	int ret;
	int i;
	int numService;
	char buf[BUF_SIZE];

	//�]���i��0�̏ꍇ�̓��X�|���_�ɒ��ڐڑ�
	if(limit == 0){
		nextService = responderAddr;
		numService = 0;
		sn = NULL;
		goto CONNECT;
	}
	ret = GetServiceList(&managerSock , &sn);
	if( ret <= 0){
		return FAIL_GET_SERVICE;
	}
	numService = __min(ret , limit);
	//�����_���ɐڑ�����T�[�r�X��I������
	nextService = sn + (rand() % numService);

CONNECT:
	if(SockFrame_BuildHostPort(si , (const char *)nextService) != TRUE){
		return FAIL_RESOLVE_NEXT_SERVICE;
	}
	//�T�[�r�X�ɐڑ�
	if( SockFrame_Connect(si) != TRUE){
		return FAIL_CONNNECT_SERVICE;
	}
	//�o�H�m���v�����M
	SockFrame_SendLine(si , "est");
	//serveice���X�g�������M
	SockFrame_SendLine(si , _itoa(numService ,buf, 10 ));

	//service���X�g�{�����M
	for( i = 0 ; i < numService ; i++){
		//���M��̃z�X�g���͑���Ȃ�
		if( nextService != sn + i ){
			if( SockFrame_SendLine(si , (const char *)(sn + i)) <= 0){
				free(sn);
				sn = NULL;
				SockFrame_Shutdown(si);
				return FAIL_SEND_SERVICE_LIST;
			}
		}
	}
	//responder�A�h���X���M
	if( numService > 0 ){
		SockFrame_SendLine(si , responderAddr);	
	}
	//�ԓ��҂�
	SockFrame_ReceiveLine(si , buf , BUF_SIZE);
	if( strcmp(buf , "ok" ) != 0){
		free(sn);
		printf("gunshu est failed.\n");
		return RESPONSE_FAIL;
	}
	free(sn);
	//path�R�}���h�Ōo�H����
	SockFrame_SendLine(si , "path");
	printf("path:");
	do{
		if( SockFrame_ReceiveLine(si , buf , BUF_SIZE) > 0){
			printf("%s - ",buf);
		}else{
			break;
		}
	}while(1);
	printf("initiator \n");
	//forward���[�h��
	SockFrame_SendLine(si , "forward");
	return TRUE;
}

