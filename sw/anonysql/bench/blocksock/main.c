#include <windows.h>
#include <stdio.h>
#include <pdh.h>
#include "sockframe.h"
#include "CpuUsageForNT.h"

#define SO_MAX_MSG_SIZE   0x2003  

#define MB (1024*1024)

int TOTAL_SIZE;// 1024*1024*16	//16MB
int PING_PONG_SIZE;// 1024*1024*4	//4MB

static DWORD timecount;
int blocksize;

HQUERY hQuery;
HCOUNTER hUsertime,hCputime;
PDH_FMT_COUNTERVALUE FmtValue;

void ClientProc(char *server);
void ServerProc(void);
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


	if( argc <= 1 ){
		printf("usage:\n");
		printf("blocksock.exe s \n");
		printf("blocksock.exe c (servername:port) (totalsize in MB) (blocksize in byte)\n");
		return 0;
	}

	/* 新規クエリーを作成 */
	PdhOpenQuery(NULL, 0, &hQuery);
	PdhAddCounter(hQuery, "\\Processor(_Total)\\% User Time", 0, &hUsertime);
	PdhAddCounter(hQuery, "\\Processor(_Total)\\% Processor Time", 0, &hCputime);

	SockFrame_Init();
	SockFrame_DisableDebugMessage();
	//SockFrame_EnableDebugMessage();

	if( strcmp(argv[1] , "s") == 0 ){
		printf("totalsize,blocksize,c2s,s2c,cpu total,cpu user,totalsize,blocksize,pingpong,cpu total,cpu user\n");
		ServerProc();
	}
	if( strcmp(argv[1], "c" ) == 0 ){
		blocksize = 1;
		printf("totalsize,blocksize,session,c2s,s2c,cpu total,cpu user,totalsize,blocksize,pingpong,cpu total,cpu user\n");
		for( i = 0 ; i <= 10 ; i++){
			if( blocksize == 1 ){
				TOTAL_SIZE = 1*MB;
				PING_PONG_SIZE = 256*1024;
			}else if( blocksize == 4 ){
				TOTAL_SIZE = 4*MB;
				PING_PONG_SIZE = 512*1024;
			}else if( blocksize == 16 ){
				TOTAL_SIZE = 16*MB;
				PING_PONG_SIZE = 1*MB;
			}else if( blocksize == 64 ){
				TOTAL_SIZE = 48*MB;
				PING_PONG_SIZE = 4*MB;
			}else{
				TOTAL_SIZE = 80*MB;
				PING_PONG_SIZE = 32*MB;
			}
			
			//TOTAL_SIZE = TOTAL_SIZE / 64;
			//PING_PONG_SIZE = PING_PONG_SIZE /64;

			printf("%d,%d,",(TOTAL_SIZE/1024),blocksize);
			ClientProc(argv[2]);
			blocksize = blocksize * 4;
			
		}
	}

	SockFrame_Cleanup();
	PdhCloseQuery(hQuery);
}

void ClientProc(char *server)
{
	char *data;
	int i,ret,size;
	int ack = 10;
	SOCK_INFO si;

	//ダミーデータ用意
	data = MakeDummy(blocksize);

	//CPU負荷計測開始
	PdhCollectQueryData(hQuery);

	//セッション確立時間計測
	BeginTime();
	SockFrame_BuildHostPort(&si, server);
	SockFrame_Connect(&si);

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
	SockFrame_Send(&si , (unsigned char *)&PING_PONG_SIZE, sizeof(int));
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

	//CPU負荷計測終了
	PrintCpuUsage();

	//ping-pong
	printf("%d,%d,",(PING_PONG_SIZE/1024) , blocksize);
	//CPU負荷計測開始
	PdhCollectQueryData(hQuery);
	BeginTime();
	//c→s、s→c
	for( i = 0 ; i < PING_PONG_SIZE ; i += blocksize){
		
		SockFrame_Send(&si , data , blocksize);
		SockFrame_Receive(&si , data , blocksize);
	}
	printf("%d,",EndTime());
	//CPU負荷計測終了
	PrintCpuUsage();

	//getchar();
	printf("\n");
	Sleep(1000);
}

void ServerProc(void)
{
	SockFrame_Listen(5555);
}
void SockFrame_OnClientConnect(SOCK_INFO *ci)
{
	char *data;
	int i;
	int ack = 10;

	//ブロックサイズ受信
	SockFrame_Receive(ci , (unsigned char *)&TOTAL_SIZE, sizeof(int));
	SockFrame_Receive(ci , (unsigned char *)&PING_PONG_SIZE, sizeof(int));
	SockFrame_Receive(ci , (unsigned char *)&blocksize, sizeof(int));

	printf("%d,%d,",(TOTAL_SIZE/1024),blocksize);

	//ダミーデータ用意
	data = MakeDummy(blocksize);

	//CPU負荷計測開始
	PdhCollectQueryData(hQuery);
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
	//CPU負荷計測終了
	PrintCpuUsage();

	//ping-pong
	printf("%d,%d,",(PING_PONG_SIZE/1024) , blocksize);
	//CPU負荷計測開始
	PdhCollectQueryData(hQuery);
	BeginTime();
	//c→s、s→c
	for( i = 0 ; i < PING_PONG_SIZE ; i += blocksize){
		SockFrame_Receive(ci , data , blocksize);
		SockFrame_Send(ci , data , blocksize);
	}
	printf("%d,",EndTime());
	//CPU負荷計測終了
	PrintCpuUsage();

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

void PrintCpuUsage()
{
	//CPU負荷計測終了
	PdhCollectQueryData(hQuery);
	//total
	PdhGetFormattedCounterValue(hCputime, PDH_FMT_DOUBLE, NULL, &FmtValue);
	printf("%f,", FmtValue.doubleValue);
	//user
	PdhGetFormattedCounterValue(hUsertime, PDH_FMT_DOUBLE, NULL, &FmtValue);
	printf("%f,", FmtValue.doubleValue);
}