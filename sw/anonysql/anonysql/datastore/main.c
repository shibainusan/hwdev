//datastore�T�[�o
//�Ƃ肠����gunshu������
#include <stdio.h>
#include "sockframe.h"
#include "minissl.h"

#define MYAPPNAME "Anonysql dataserver 1.0"
#define BUF_SIZE 512
char myName[BUF_SIZE];
char databaseName[BUF_SIZE];
Key_DES recordOwnerCertKey;

int main()
{
	FILE *fp;
	char buf[SHARED_KEY_SIZE];

	SockFrame_Init();
	MiniSSL_Init();

	//�T�[�o���擾
	if( GetPrivateProfileString(MYAPPNAME , "MyName" , "" , myName , BUF_SIZE , ".\\anonysql.ini") <= 0){
		printf("failed to load anonysql.ini(MyName)\n");
		return FALSE;
	}
	//�f�[�^�x�[�X���擾
	if( GetPrivateProfileString(MYAPPNAME , "DatabaseName" , "" , databaseName , BUF_SIZE , ".\\anonysql.ini") <= 0){
		printf("failed to load anonysql.ini(DatabaseName)\n");
		return FALSE;
	}

	//���R�[�h���L�ҏؖ��������pDES�L�[�ǂݍ���
	fp = fopen(".\\recordownerdes.key","rb");
	if( fp == NULL ){
		printf("failed to load DES key.\n");
	}else{
		fread(buf , SHARED_KEY_SIZE , 1 , fp);
		DESkey_set(&recordOwnerCertKey , SHARED_KEY_SIZE , buf);
		fread(buf , IV_SIZE , 1 , fp);
		DES_set_iv(&recordOwnerCertKey , buf);
		fclose(fp);
	}

	//���b�X���J�n
	SockFrame_Listen(19419);
	MiniSSL_Cleanup();
	SockFrame_Cleanup();
} 