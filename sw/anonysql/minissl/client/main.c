#include "minissl.h"

#define BUF_SIZE 9999

int main(int argc, char **argv)
{
	char org[BUF_SIZE];
	int n;

	MiniSSL_INFO si;
	
	SockFrame_Init();
	MiniSSL_Init();
	MiniSSL_InitSessionInfo(&si);
	MiniSSL_SetTargetPubKey(&si , "serverpub.key");
	MiniSSL_BuildHostPort(&si , "geisha:9898");
	MiniSSL_SetMyPubPrvKey(&si , "denpaprv.key");
	MiniSSL_SetClientName(&si, "denpa");

	MiniSSL_Connect(&si , AUTHENT_CLIENTSERVER);
	//MiniSSL_Connect(&si , AUTHENT_SERVER);
	
	do{
		gets(org);
		n = strlen(org) + 1;
		MiniSSL_Send(&si , &n , 4);
		MiniSSL_Send(&si, org , n);
		//MiniSSL_Send(&si, org + n - 9 , 9);
		//MiniSSL_SendLine(&si , org);
	}while(1);
	
	MiniSSL_Shutdown(&si);
	MiniSSL_FreeSessionInfo(&si);
	SockFrame_Cleanup();
}