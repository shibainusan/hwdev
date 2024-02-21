#include "sockframe.h"
#include "minissl.h"

int MiniSSL_OnClientConnect(MiniSSL_INFO *ci,int authority)
{
	return TRUE;
}

void SockFrame_OnClientConnect(SOCK_INFO *ci)
{
}