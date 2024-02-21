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
	//�k�������p��1�o�C�g���炷
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
			//���s���H
			if( *data == 0xA && *(data-1) == 0xD){
				//���s�Ȃ�k�������ǉ����ĕ�������Ԃ�
				*(data -1) = '\0';
				return count - 1;
			}

			left--;
			data++;
			count++;
			//�o�b�t�@�Ɏ��܂邩�H
			if( left <= 0){
				//�o�b�t�@���ӂ�Ńk�������ǉ�
				*(data -1) = '\0';
				return size - 1;
			}
		}
	}	
}
int MiniSSL_ReceiveLineCRorLF(MiniSSL_INFO *ci,unsigned char *data,int size)
{
	int ret;
	//�k�������p��1�o�C�g���炷
	int left = size - 1;
	int count = 0;
	data[0] = '\0';

	while(1){
		ret = MiniSSL_Receive(ci , data , 1);
		if( ret <= 0){
			return ret;
		}else{
			//���s���H
			if( *data == 0xA || *(data) == 0xD){
				//���s�Ȃ�k�������ǉ����ĕ�������Ԃ�
				*(data) = '\0';
				return count;
			}

			left--;
			data++;
			count++;
			//�o�b�t�@�Ɏ��܂邩�H
			if( left <= 0){
				//�o�b�t�@���ӂ�Ńk�������ǉ�
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
		//�o�b�t�@�ɖ��ǂݏo���̃f�[�^�����邩�H
		bytesInBuf = ci->recvbufLimit - ci->recvpos;
		if( bytesInBuf > 0){			
			if( bytesInBuf >= left ){
				//�o�b�t�@�ɂ���f�[�^�ŊԂɍ����ꍇ
				memcpy(data , ci->recvpos ,  left);
				ci->recvpos += left;
				return size;
			}else{
				//�o�b�t�@��S���g���Ă��܂�����Ȃ�
				memcpy( data , ci->recvpos , bytesInBuf);
				data += bytesInBuf;
				left -= bytesInBuf;
			}
		}
		//���R�[�h�I�[���H
		if( ci->recvBytes <= 0 ){
			//�f�[�^���擾�i���R�[�h�w�b�_�j
			if( SockFrame_Receive(ci->si , (unsigned char *)&(ci->recvBytes) , sizeof(ci->recvBytes)) != sizeof(ci->recvBytes)){
				goto FAIL;
			}
		}
		//�o�b�t�@�ǂݎ��J�[�\����擪�ɂ���
		ci->recvpos = ci->recvbuf;
		//�o�b�t�@�Ɏ��܂�ꍇ
		if( ci->recvBytes < MiniSSL_BUF_SIZE ){
			//�o�b�t�@���ǂݎ�����̐ݒ�
			ci->recvbufLimit = ci->recvbuf + ci->recvBytes;	
			//���ۂ̃��R�[�h�T�C�Y��8�̔{��
			recordSize = (ci->recvBytes/SHARED_KEY_SIZE + 1)*SHARED_KEY_SIZE;
			
			if( SockFrame_Receive(ci->si , ci->recvbuf , recordSize) != recordSize){
				goto FAIL;
			}
			ci->recvBytes -= recordSize;
			//����
			DES_cbc_decrypt(ci->sharedKey , recordSize , ci->recvbuf , ci->recvbuf);
		//�o�b�t�@�Ɏ��܂�Ȃ��ꍇ
		}else{
			//�o�b�t�@��t�ɓǂݍ���
			ci->recvbufLimit = ci->recvbuf + MiniSSL_BUF_SIZE;
			if( SockFrame_Receive(ci->si , ci->recvbuf , MiniSSL_BUF_SIZE) != MiniSSL_BUF_SIZE){
				goto FAIL;
			}
			ci->recvBytes -= MiniSSL_BUF_SIZE;
			//����
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
	//���T�C�Y���M����
	offset = RECORD_HEADER;
	memcpy(ci->sendbuf , &size , RECORD_HEADER);
	//�u���b�N���M
	for( i = 0 ; i < numBlock ; i++){
		DES_cbc_encrypt(ci->sharedKey , MiniSSL_BUF_SIZE , data ,ci->sendbuf + offset);
		if( SockFrame_Send(ci->si , ci->sendbuf , MiniSSL_BUF_SIZE + offset) != MiniSSL_BUF_SIZE + offset){
			return -1;
		}
		data += MiniSSL_BUF_SIZE;
		//���T�C�Y�i���R�[�h�w�b�_�j�͈�񂾂�����
		offset = 0;
	}
	//���܂�̏���
	left = size % MiniSSL_BUF_SIZE;
	if( left != 0){
		memcpy(ci->sendbuf + offset, data , left);
		//left��8�̔{���ɂ���
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
	//�����o�b�t�@���傫���ꍇ�̓t���b�V��
	if( size >= MiniSSL_BUF_SIZE - ci->nagleByte){
		ret = MiniSSL_Flush(ci);
		if( ret < 0 ){
			return ret;
		}
		return MiniSSL_Send(ci , data , size);
	}
	//�����o�b�t�@�Ɏ��܂�ꍇ
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