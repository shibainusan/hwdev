#include "minissl.h"
#include "sockframe.h"

void SockFrame_OnClientConnect(SOCK_INFO *ci)
{
}

int MiniSSL_OnClientConnect(MiniSSL_INFO *ci,int authority)
{
	return TRUE;
}