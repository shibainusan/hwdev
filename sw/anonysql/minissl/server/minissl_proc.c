#include "minissl.h"
#include "sockframe.h"

#define BUF_SIZE 4096

void SockFrame_OnClientConnect(SOCK_INFO *ci)
{
	char org[BUF_SIZE];

	int i;
	MiniSSL_INFO si;
	int authority;

	MiniSSL_InitSessionInfo(&si);
	*si.si =  *ci;
	MiniSSL_SetMyPubPrvKey(&si , "prv.key");
	MiniSSL_LoadClientACL();
	si.mode = AUTHENT_CLIENTSERVER;

	if( MiniSSL_AuthClient(&si , &authority) == TRUE ){
	}else{
		MiniSSL_FreeSessionInfo(&si);
		return;
	}

	do{
#if 1
		if( MiniSSL_Receive(&si , &i , 4) <= 0 ){
			break;
		
		}
		MiniSSL_Receive(&si , org , i);
		//MiniSSL_Receive(ci , org , i-9);
		//MiniSSL_Receive(ci , org+i-9 , 9);

#endif
	/*	if( MiniSSL_ReceiveLine(ci , org , BUF_SIZE) <=  0){
			break;
		}*/
		printf("%s\n" , org);
	}while(1);

	MiniSSL_FreeSessionInfo(&si);
	return;
}

int MiniSSL_OnClientConnect(MiniSSL_INFO *ci,int authority)
{
	char org[BUF_SIZE];

	int i;

	do{
#if 1
		if( MiniSSL_Receive(ci , &i , 4) <= 0 ){
			break;
		
		}
		MiniSSL_Receive(ci , org , i);
		//MiniSSL_Receive(ci , org , i-9);
		//MiniSSL_Receive(ci , org+i-9 , 9);

#endif
	/*	if( MiniSSL_ReceiveLine(ci , org , BUF_SIZE) <=  0){
			break;
		}*/
		printf("%s\n" , org);
	}while(1);
	return TRUE;
}