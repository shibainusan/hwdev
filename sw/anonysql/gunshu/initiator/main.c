#include <stdio.h>
#include <windows.h>
#include "sockframe.h"
#include "gunshu.h"

#define INI_FILENAME ".\\gunshuinitiator.ini"

int main(int argc, char **argv)
{
	SOCK_INFO si;
	char buf[4000];

	SockFrame_Init();
	Gunshu_LoadSetting(INI_FILENAME);
	Gunshu_Connect(&si , "geisha:4649", 3);

	do{
		gets(buf);	
		SockFrame_SendLine(&si , buf);
		SockFrame_ReceiveLine(&si , buf , 4000);
		printf("%s\n",buf);
	}while(1);

	SockFrame_Shutdown(&si);
	SockFrame_Cleanup();
}