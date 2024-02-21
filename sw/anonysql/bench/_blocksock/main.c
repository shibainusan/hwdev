#include <windows.h>
#include <stdio.h>
#include <pdh.h>
#include "sockframe.h"
#include "CpuUsageForNT.h"

#define SO_MAX_MSG_SIZE   0x2003  

#define MB (1024*1024)

int TOTAL_SIZE;// 1024*1024*16	//16MB

static DWORD timecount;
int blocksize;

void ClientProc(char *server);
void ServerProc(int port);
void BeginTime(void);
DWORD EndTime(void);
void PrintCpuUsage();
char *MakeDummy(int blocksize);

char *Split(char *buf, char delimiter)
{
	if( buf == NULL ){
		return NULL;
	}
	do{
		if( *buf == '\0'){
			break;
		}
		if( *buf == delimiter ){
			*buf = '\0';
			return (buf + 1);
		}
		buf++;
	}while(1);

	return NULL;
}

int main(int argc,char **argv)
{
	int i;
	int port;

	if( argc <= 1 ){
		printf("usage:\n");
		printf("blocksock.exe s \n");
		printf("blocksock.exe c (servername:port) (totalsize in KB) (blocksize in byte)\n");
		return 0;
	}

	SockFrame_Init();
	SockFrame_DisableDebugMessage();
	//SockFrame_EnableDebugMessage();

	if( strcmp(argv[1] , "s") == 0 ){
		printf("totalsize,blocksize,c2s,s2c\n");
		port = atoi(argv[2]);
		ServerProc(port);
	}
	if( strcmp(argv[1], "c" ) == 0 ){
		TOTAL_SIZE = atoi(argv[3])*1024;
		blocksize = atoi(argv[4]);
		printf("totalsize,blocksize,session,c2s,s2c\n");
//		for( i = 0 ; i <= 10 ; i++){
			printf("%d,%d,",(TOTAL_SIZE/1024),blocksize);
			ClientProc(argv[2]);
//		}
	}

	SockFrame_Cleanup();
}

void ClientProc(char *server)
{
	char *data;
	int i,ret,size;
	int ack = 10;
	SOCK_INFO si;

	//ダミーデータ用意
	data = MakeDummy(blocksize);
	//セッション確立時間計測
	BeginTime();
	SockFrame_BuildHostPort(&si, server);
	if(SockFrame_Connect(&si) != TRUE){
		printf("connect failed\n");
		return;
	}

	/*SockFrame_SetTimeout(&si , 1000*30);
	size = sizeof(i);
	ret = getsockopt(si.sock, SOL_SOCKET, SO_MAX_MSG_SIZE, &i, &size);
	SockFrame_DispLastError();
	printf("SO_MAX_MSG_SIZE:%d %d\n",i,ret);
	ret = getsockopt(si.sock, SOL_SOCKET, SO_SNDBUF, &i, &size);
	SockFrame_DispLastError();
	printf("SO_SNDBUF:%d %d\n",i,ret);*/

	printf("%d,",EndTime());
	//ブロックサイズ送信
	SockFrame_Send(&si , (unsigned char *)&TOTAL_SIZE, sizeof(int));
	SockFrame_Send(&si , (unsigned char *)&blocksize, sizeof(int));

	//一方向転送
	//c→s
	BeginTime();
	for( i = 0 ; i < TOTAL_SIZE ; i += blocksize){
		SockFrame_Send(&si , data , blocksize);
	}
	//ack待ち
	SockFrame_Receive(&si , (unsigned char *)&ack , sizeof(int));
	printf("%d,",EndTime());

	//s→c
	BeginTime();
	for( i = 0 ; i < TOTAL_SIZE ; i += blocksize){
		SockFrame_Receive(&si , data , blocksize);
	}
	//ack送信
	SockFrame_Send(&si , (const unsigned char *)&ack , sizeof(int));
	printf("%d,",EndTime());

	//getchar();
	printf("\n");
	Sleep(1000);
}

void ServerProc(int port)
{
	SockFrame_Listen(port);
}
void SockFrame_OnClientConnect(SOCK_INFO *ci)
{
	char *data;
	int i;
	int ack = 10;

	//ブロックサイズ受信
	SockFrame_Receive(ci , (unsigned char *)&TOTAL_SIZE, sizeof(int));
	SockFrame_Receive(ci , (unsigned char *)&blocksize, sizeof(int));

	printf("%d,%d,",(TOTAL_SIZE/1024),blocksize);

	//ダミーデータ用意
	data = MakeDummy(blocksize);

	BeginTime();
	//一方向転送
	//c→s
	for( i = 0 ; i < TOTAL_SIZE ; i += blocksize){
		SockFrame_Receive(ci , data , blocksize);
	}
	//ack送信
	SockFrame_Send(ci , (const unsigned char *)&ack , sizeof(int));
	printf("%d,",EndTime());

	BeginTime();
	//s→c
	for( i = 0 ; i < TOTAL_SIZE ; i += blocksize){
		SockFrame_Send(ci , data , blocksize);
	}
	//ack受信
	SockFrame_Receive(ci , (unsigned char *)&ack , sizeof(int));
	printf("%d,",EndTime());

	printf("\n");
	free(data);

}
void BeginTime(void)
{
	timecount = timeGetTime();
}
DWORD EndTime(void)
{
	return (timeGetTime() - timecount);
}


char *MakeDummy(int size)
{
	char *ret;
	int i;
	char c = 0;

	//ダミーデータ用意
	ret = malloc(size);
	for( i = 0 ; i < size ; i++){
		*(ret + i) = c;
		c++;
	}
	return ret;
}

