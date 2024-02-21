#include "minissl.h"

#define BUF_SIZE 256

int main(int argc, char **argv)
{
	MiniSSL_INFO si;

	SockFrame_Init();
	MiniSSL_Init();
#if 0
	MiniSSL_InitSessionInfo(&si);
	MiniSSL_SetMyPubPrvKey(&si , "prv.key");
	MiniSSL_LoadClientACL();
	si.mode = AUTHENT_CLIENTSERVER;


	MiniSSL_Listen(&si , 9898);
	MiniSSL_FreeSessionInfo(&si);
#endif
	SockFrame_Listen(9898);
	MiniSSL_Cleanup();
	SockFrame_Cleanup();
}