#include <stdio.h>
#include <Winsock2.h>
#include <process.h>  
#include "minissl.h"
#include "sockframe.h"
#include "..\..\aicryptolib\src\include\ok_rsa.h"
#include "..\..\aicryptolib\src\include\ok_x509.h"
#include "..\..\aicryptolib\src\include\ok_des.h"
#include "..\..\aicryptolib\src\include\ok_rand.h"

int MiniSSL_Init(void)
{

	return RAND_init();
}
void MiniSSL_Cleanup(void)
{
	RAND_cleanup();
}

int MiniSSL_BuildHostPort(MiniSSL_INFO *si, const char *name)
{
	return SockFrame_BuildHostPort(si->si , name);
}
int MiniSSL_Shutdown(MiniSSL_INFO *si)
{
	si->sessionReady = FALSE;
	return SockFrame_Shutdown(si->si);
}

int MiniSSL_IsValidSock(MiniSSL_INFO *si)
{
	int ret;
	int optval,optlen;

	optlen = sizeof(optval);
	ret = getsockopt(si->si->sock , SOL_SOCKET , SO_ERROR ,(char *) &optval , &optlen);
	if( ret != 0 ){
		return FALSE;
	}else{
		return TRUE;
	}
}

int MiniSSL_ReceiveLine(MiniSSL_INFO *ci,unsigned char *data,int size)
{
	int ret;
	//ヌル文字用に1バイト減らす
	int left = size - 1;
	int count = 0;
	data[0] = '\0';

	ret = MiniSSL_Receive(ci , data , 1);

	if( ret <= 0){
		return ret;
	}else{
		count++;
		left--;
		data++;
	}
	while(1){
		ret = MiniSSL_Receive(ci , data , 1);
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
				*(data -1) = '\0';
				return size - 1;
			}
		}
	}	
}
int MiniSSL_ReceiveLineCRorLF(MiniSSL_INFO *ci,unsigned char *data,int size)
{
	int ret;
	//ヌル文字用に1バイト減らす
	int left = size - 1;
	int count = 0;
	data[0] = '\0';

	while(1){
		ret = MiniSSL_Receive(ci , data , 1);
		if( ret <= 0){
			return ret;
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
int MiniSSL_Receive(MiniSSL_INFO *ci,BYTE *data,int size)
{
	int left = size;
	int bytesInBuf;
	int recordSize;

	if( size <= 0 ){
		return 0;
	}
	do{
		//バッファに未読み出しのデータがあるか？
		bytesInBuf = ci->recvbufLimit - ci->recvpos;
		if( bytesInBuf > 0){			
			if( bytesInBuf >= left ){
				//バッファにあるデータで間に合う場合
				memcpy(data , ci->recvpos ,  left);
				ci->recvpos += left;
				return size;
			}else{
				//バッファを全部使ってもまだ足りない
				memcpy( data , ci->recvpos , bytesInBuf);
				data += bytesInBuf;
				left -= bytesInBuf;
			}
		}
		//レコード終端か？
		if( ci->recvBytes <= 0 ){
			//データ長取得（レコードヘッダ）
			if( SockFrame_Receive(ci->si , (unsigned char *)&(ci->recvBytes) , sizeof(ci->recvBytes)) != sizeof(ci->recvBytes)){
				goto FAIL;
			}
		}
		//バッファ読み取りカーソルを先頭にする
		ci->recvpos = ci->recvbuf;
		//バッファに収まる場合
		if( ci->recvBytes < MiniSSL_BUF_SIZE ){
			//バッファ内読み取り上限の設定
			ci->recvbufLimit = ci->recvbuf + ci->recvBytes;	
			//実際のレコードサイズは8の倍数
			recordSize = (ci->recvBytes/SHARED_KEY_SIZE + 1)*SHARED_KEY_SIZE;
			
			if( SockFrame_Receive(ci->si , ci->recvbuf , recordSize) != recordSize){
				goto FAIL;
			}
			ci->recvBytes -= recordSize;
			//復号
			DES_cbc_decrypt(ci->sharedKey , recordSize , ci->recvbuf , ci->recvbuf);
		//バッファに収まらない場合
		}else{
			//バッファ一杯に読み込む
			ci->recvbufLimit = ci->recvbuf + MiniSSL_BUF_SIZE;
			if( SockFrame_Receive(ci->si , ci->recvbuf , MiniSSL_BUF_SIZE) != MiniSSL_BUF_SIZE){
				goto FAIL;
			}
			ci->recvBytes -= MiniSSL_BUF_SIZE;
			//復号
			DES_cbc_decrypt(ci->sharedKey , MiniSSL_BUF_SIZE , ci->recvbuf , ci->recvbuf);
		}
	}while(1);

FAIL:
	ci->recvBytes = 0;
	return -1;
}

int MiniSSL_SendLine(MiniSSL_INFO *ci,const char *data)
{
	int ret;
	char crlf[] = {0xD, 0xA};
	ret = MiniSSL_Send(ci , data , strlen(data));
	if( ret < 0 ){
		return ret;
	}

	ret += MiniSSL_Send(ci , crlf , 2);
	return (ret - 2);
}
int MiniSSL_Send(MiniSSL_INFO *ci,const BYTE *data,int size)
{
	int offset;
	int numBlock = (size/MiniSSL_BUF_SIZE);
	int left;
	int i;

	if( size <= 0 ){
		return 0;
	}
	//実サイズ送信準備
	offset = RECORD_HEADER;
	memcpy(ci->sendbuf , &size , RECORD_HEADER);
	//ブロック送信
	for( i = 0 ; i < numBlock ; i++){
		DES_cbc_encrypt(ci->sharedKey , MiniSSL_BUF_SIZE , data ,ci->sendbuf + offset);
		if( SockFrame_Send(ci->si , ci->sendbuf , MiniSSL_BUF_SIZE + offset) != MiniSSL_BUF_SIZE + offset){
			return -1;
		}
		data += MiniSSL_BUF_SIZE;
		//実サイズ（レコードヘッダ）は一回だけ送る
		offset = 0;
	}
	//あまりの処理
	left = size % MiniSSL_BUF_SIZE;
	if( left != 0){
		memcpy(ci->sendbuf + offset, data , left);
		//leftを8の倍数にする
		left = (left/SHARED_KEY_SIZE + 1)*SHARED_KEY_SIZE;
		DES_cbc_encrypt(ci->sharedKey , left , ci->sendbuf + offset,ci->sendbuf + offset);
		if( SockFrame_Send(ci->si , ci->sendbuf , left + offset) != left + offset){
			return -1;
		}
	}
	return size;
}

int MiniSSL_SendByte(MiniSSL_INFO *ci,const BYTE data)
{
	return MiniSSL_Send(ci , &data , 1);
}

int MiniSSL_Put(MiniSSL_INFO *ci,const BYTE *data,int size)
{
	int ret;
	//内部バッファより大きい場合はフラッシュ
	if( size >= MiniSSL_BUF_SIZE - ci->nagleByte){
		ret = MiniSSL_Flush(ci);
		if( ret < 0 ){
			return ret;
		}
		return MiniSSL_Send(ci , data , size);
	}
	//内部バッファに収まる場合
	memcpy(ci->naglebuf + ci->nagleByte , data , size);
	ci->nagleByte += size;
	return size;
}
int MiniSSL_Flush(MiniSSL_INFO *ci)
{
	int ret;
	ret = MiniSSL_Send(ci , ci->naglebuf , ci->nagleByte);
	ci->nagleByte = 0;
	return ret;
}