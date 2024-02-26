#include <stdio.h>
#include <Winsock2.h>
#include "sockframe.h"

void HexDump(const BYTE *in , int size)
{
	int i;
	unsigned int n;
	for( i = 0 ; i < size ; i++){
		n = *in;
		SockFrame_DebugOut("%02X",n);
		in++;
	}
	SockFrame_DebugOut("\n");
}

int _send(SOCKET s,const char *buf,int len,int flags)
{
	int ret;
	ret = send(s,buf,len,flags);

	if( ret < 0 ){
		SockFrame_DispLastError();
	}

	return ret;
}

int _recv(SOCKET s,char *buf,int len,int flags)
{
	int ret;
	ret = recv(s,buf,len,flags);

	if( ret < 0 ){
		SockFrame_DispLastError();
	}

	return ret;
}

int SockFrame_IsValidSock(SOCK_INFO *si)
{
	int ret;
	int optval,optlen;

	optlen = sizeof(optval);
	ret = getsockopt(si->sock , SOL_SOCKET , SO_ERROR ,(char *) &optval , &optlen);
	if( ret != 0 ){
		return FALSE;
	}else{
		return TRUE;
	}
}

void SockFrame_DispLastError(void)
{
	LPVOID lpMsgBuf;
	FormatMessage( FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
				    NULL, WSAGetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // 既定の言語
					(LPTSTR) &lpMsgBuf, 0, NULL);
	SockFrame_DebugOut("WSAERR:%s\n",lpMsgBuf);
	LocalFree(lpMsgBuf);
}


//データ送受信
int SockFrame_WaitForCode(SOCK_INFO *ci,unsigned char *code,int size)
{
	return FALSE;
}
int SockFrame_ReceiveInt(SOCK_INFO *ci,int *n)
{
	return FALSE;

}

int SockFrame_ReceiveLine(SOCK_INFO *ci,unsigned char *data,int size)
{
	int ret;
	//ヌル文字用に1バイト減らす
	int left = size - 1;
	int count = 0;
	data[0] = '\0';

	ret = _recv(ci->sock , data , 1,0);

	if( ret <= 0){
		return ret;
	}else{
		count++;
		left--;
		data++;
	}
	while(1){
		ret = _recv(ci->sock , data , 1,0);
		if( ret <= 0){
			return ret;
		}else{
			//改行か？
			if( *data == 0xA && *(data-1) == 0xD){
				//改行ならヌル文字追加して文字数を返す
				*(data -1) = '\0';
				return count - 1;
			}

			left--;
			data++;
			count++;
			//バッファに収まるか？
			if( left <= 0){
				//バッファあふれでヌル文字追加
				*(data + size) = '\0';
				return size - 1;
			}
		}
	}	
}
int SockFrame_ReceiveLineCRorLF(SOCK_INFO *ci,unsigned char *data,int size)
{
	int ret;
	//ヌル文字用に1バイト減らす
	int left = size - 1;
	int count = 0;
	data[0] = '\0';

	while(1){
		ret = _recv(ci->sock , data , 1,0);
		if( ret <= 0){
			return -1; //connection closed
		}else{
			//改行か？
			if( *data == 0xA || *(data) == 0xD){
				//改行ならヌル文字追加して文字数を返す
				*(data) = '\0';
				return count;
			}

			left--;
			data++;
			count++;
			//バッファに収まるか？
			if( left <= 0){
				//バッファあふれでヌル文字追加
				*(data + size) = '\0';
				return size - 1;
			}
		}
	}	
}
int SockFrame_Receive(SOCK_INFO *ci,BYTE *data,int size)
{
	int ret;
	int left = size;
	BYTE *org = data;

	while(1){
		ret = _recv(ci->sock , data , left,0);
		if( ret <= 0){
			return ret;
		}else{
			left -= ret;
			data += ret;
			if( left <= 0){
#ifdef SOCK_TRACE
				SockFrame_DebugOut("%d recv\n" , data - org);
				HexDump(org , size);
#endif
				return size;
			}
		}
	}
}

int SockFrame_SendLine(SOCK_INFO *ci,const char *data)
{
	int ret;
	char crlf[] = {0xD, 0xA};
	ret = SockFrame_Send(ci , data , strlen(data));
	if( ret < 0 ){
		return ret;
	}

	ret += SockFrame_Send(ci , crlf , 2);
	return (ret - 2);
}
int SockFrame_Send(SOCK_INFO *ci,const BYTE *data,int size)
{
	int ret;
	int left = size;
	const BYTE *org = data;

	while(1){
		ret = _send(ci->sock , data , left,0);
		if( ret <= 0){
			return ret;
		}else{
			left -= ret;
			data += ret;
			if( left <= 0){
#ifdef SOCK_TRACE
				SockFrame_DebugOut("%d sent\n",data - org);
				HexDump(org , size);
#endif
				return size;
			}
		}
	}
}

int SockFrame_SendByte(SOCK_INFO *ci,const BYTE data)
{
	return SockFrame_Send(ci , &data , 1);
}