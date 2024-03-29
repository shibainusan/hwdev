#include <windows.h>
#include <stdio.h>
#include <pdh.h>
#include "minissl.h"

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

int main(int argc,char **argv)
{
	int i;

	if( argc <= 1 ){
		printf("usage:\n");
		printf("minisslblock.exe s \n");
		printf("minisslblock.exe c (servername:port)\n");
		return 0;
	}

	/* VKNG[ðì¬ */
	PdhOpenQuery(NULL, 0, &hQuery);
	PdhAddCounter(hQuery, "\\Processor(_Total)\\% User Time", 0, &hUsertime);
	PdhAddCounter(hQuery, "\\Processor(_Total)\\% Processor Time", 0, &hCputime);

	SockFrame_Init();
	MiniSSL_Init();
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
				PING_PONG_SIZE = 64*1024;
			}else if( blocksize == 4 ){
				TOTAL_SIZE = 2*MB;
				PING_PONG_SIZE = 128*1024;
			}else if( blocksize == 16 ){
				TOTAL_SIZE = 8*MB;
				PING_PONG_SIZE = 512*1024;
			}else if( blocksize == 64 ){
				TOTAL_SIZE = 10*MB;
				PING_PONG_SIZE = 1*MB;
			}else{
				TOTAL_SIZE = 16*MB;
				PING_PONG_SIZE = 8*MB;
			}
			
			TOTAL_SIZE = TOTAL_SIZE;
			PING_PONG_SIZE = PING_PONG_SIZE;

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
	MiniSSL_INFO si;

	//_~[f[^pÓ
	data = MakeDummy(blocksize);

	//CPU×vªJn
	PdhCollectQueryData(hQuery);

	//ZbVm§Ôvª
	BeginTime();
	MiniSSL_InitSessionInfo(&si);
	SockFrame_BuildHostPort(si.si, server);
	SockFrame_Connect(si.si);
	//¼ÒFØ
	MiniSSL_SetClientName(&si , "benchclient");
	MiniSSL_SetMyPubPrvKey(&si , "benchclientprv.key");
	MiniSSL_SetTargetPubKey(&si , "serverpub.key");
	MiniSSL_Auth(&si,AUTHENT_CLIENTSERVER);
	printf("%d,",EndTime());

	//ubNTCYM
	MiniSSL_Send(&si , (unsigned char *)&TOTAL_SIZE, sizeof(int));
	MiniSSL_Send(&si , (unsigned char *)&PING_PONG_SIZE, sizeof(int));
	MiniSSL_Send(&si , (unsigned char *)&blocksize, sizeof(int));

	//êûü]
	//c¨s
	BeginTime();
	for( i = 0 ; i < TOTAL_SIZE ; i += blocksize){
		MiniSSL_Send(&si , data , blocksize);
	}
	//ackÒ¿
	MiniSSL_Receive(&si , (unsigned char *)&ack , sizeof(int));
	printf("%d,",EndTime());

	//s¨c
	BeginTime();
	for( i = 0 ; i < TOTAL_SIZE ; i += blocksize){
		MiniSSL_Receive(&si , data , blocksize);
	}
	//ackM
	MiniSSL_Send(&si , (const unsigned char *)&ack , sizeof(int));
	printf("%d,",EndTime());

	//CPU×vªI¹
	PrintCpuUsage();

	//ping-pong
	printf("%d,%d,",(PING_PONG_SIZE/1024) , blocksize);
	//CPU×vªJn
	PdhCollectQueryData(hQuery);
	BeginTime();
	//c¨sAs¨c
	for( i = 0 ; i < PING_PONG_SIZE ; i += blocksize){
		
		MiniSSL_Send(&si , data , blocksize);
		MiniSSL_Receive(&si , data , blocksize);
	}
	printf("%d,",EndTime());
	//CPU×vªI¹
	PrintCpuUsage();

	MiniSSL_FreeSessionInfo(&si);
	//getchar();
	printf("\n");
	Sleep(1000);
}

void ServerProc(void)
{
	//NCAgACLÇÝÝ
	MiniSSL_LoadClientACL();
	SockFrame_Listen(5555);
}
void SockFrame_OnClientConnect(SOCK_INFO *ci)
{
	char *data;
	int i;
	int ack = 10;
	MiniSSL_INFO si;
	int authority;


	//CPU×vªJn
	PdhCollectQueryData(hQuery);

	MiniSSL_InitSessionInfo(&si);
	MiniSSL_SetMyPubPrvKey(&si , "serverprv.key");
	*si.si = *ci;
	si.mode = AUTHENT_CLIENTSERVER;
	MiniSSL_AuthClient(&si , &authority);

	//ubNTCYóM
	MiniSSL_Receive(&si , (unsigned char *)&TOTAL_SIZE, sizeof(int));
	MiniSSL_Receive(&si , (unsigned char *)&PING_PONG_SIZE, sizeof(int));
	MiniSSL_Receive(&si , (unsigned char *)&blocksize, sizeof(int));
	//_~[f[^pÓ
	data = MakeDummy(blocksize);

	printf("%d,%d,",(TOTAL_SIZE/1024),blocksize);

	BeginTime();
	//êûü]
	//c¨s
	for( i = 0 ; i < TOTAL_SIZE ; i += blocksize){
		MiniSSL_Receive(&si , data , blocksize);
	}
	//ackM
	MiniSSL_Send(&si , (const unsigned char *)&ack , sizeof(int));
	printf("%d,",EndTime());

	BeginTime();
	//s¨c
	for( i = 0 ; i < TOTAL_SIZE ; i += blocksize){
		MiniSSL_Send(&si , data , blocksize);
	}
	//ackóM
	MiniSSL_Receive(&si , (unsigned char *)&ack , sizeof(int));
	printf("%d,",EndTime());
	//CPU×vªI¹
	PrintCpuUsage();

	//ping-pong
	printf("%d,%d,",(PING_PONG_SIZE/1024) , blocksize);
	//CPU×vªJn
	PdhCollectQueryData(hQuery);
	BeginTime();
	//c¨sAs¨c
	for( i = 0 ; i < PING_PONG_SIZE ; i += blocksize){
		MiniSSL_Receive(&si , data , blocksize);
		MiniSSL_Send(&si , data , blocksize);
	}
	printf("%d,",EndTime());
	//CPU×vªI¹
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

	//_~[f[^pÓ
	ret = malloc(size);
	for( i = 0 ; i < size ; i++){
		*(ret + i) = c;
		c++;
	}
	return ret;
}

void PrintCpuUsage()
{
	//CPU×vªI¹
	PdhCollectQueryData(hQuery);
	//total
	PdhGetFormattedCounterValue(hCputime, PDH_FMT_DOUBLE, NULL, &FmtValue);
	printf("%f,", FmtValue.doubleValue);
	//user
	PdhGetFormattedCounterValue(hUsertime, PDH_FMT_DOUBLE, NULL, &FmtValue);
	printf("%f,", FmtValue.doubleValue);
}

int MiniSSL_OnClientConnect(MiniSSL_INFO *ci,int authority)
{
	return 1;
}