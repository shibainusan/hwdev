#include <stdio.h>
#include "minissl.h"
#include "sockframe.h"
#include "..\..\aicryptolib\src\include\ok_rsa.h"
#include "..\..\aicryptolib\src\include\ok_x509.h"
#include "..\..\aicryptolib\src\include\ok_asn1.h"
#include "..\..\aicryptolib\src\include\ok_des.h"

#define BUF_SIZE 1024

typedef struct tag_MiniSSL_ACL{
	char name[CLIENT_NAME_SIZE + 1];
	int authority;
	Pubkey_RSA *key;
	struct tag_MiniSSL_ACL *next, *prev;
} MiniSSL_ACL;

static MiniSSL_ACL workACL[MiniSSL_ACL_MAX];
static MiniSSL_ACL *freeACL;	//空きリスト先頭
static MiniSSL_ACL *topACL;	//使用済みリスト先頭

static void InitACL(void);
static int AddACL(const char *name , int authority);
static int DelACL(MiniSSL_ACL *w);
static const MiniSSL_ACL *TopACL(void);
static const MiniSSL_ACL *FindACL(const char *name);

int FindClientKey(int *authority , MiniSSL_INFO *ci);

int MiniSSL_SetClientName(MiniSSL_INFO *si, char *name)
{
	if(strlen(name) > CLIENT_NAME_SIZE || strlen(name) <= 0 ){
		return FALSE;
	}
	strcpy(si->clientName , name);
	return TRUE;
}

int FindClientKey(int *authority , MiniSSL_INFO *ci)
{
	const MiniSSL_ACL *w;

	w = FindACL(ci->clientName);
	if( w == NULL ){
		*authority = 0;
		ci->targetPubKey = NULL;
		return FALSE;
	}

	ci->targetPubKey = RSApubkey_dup(w->key);
	*authority =  w->authority;
	return TRUE;
}

void InitACL(void)
{
	int i;
	freeACL = workACL;
	topACL = NULL;

	workACL[0].prev = NULL;
	workACL[0].next = (workACL + 1);

	for( i = 1 ; i < MiniSSL_ACL_MAX - 1 ; i++){
		workACL[i].prev = (workACL + i - 1);
		workACL[i].next = (workACL + i + 1);

	}
	workACL[MiniSSL_ACL_MAX-1].prev = (workACL + MiniSSL_ACL_MAX - 2);
	workACL[MiniSSL_ACL_MAX-1].next = NULL;

	for( i = 0 ; i < MiniSSL_ACL_MAX ; i++){
		workACL[i].key = NULL;
		workACL[i].authority = 0;
		workACL[i].name[0] = '\0';
	}
}

int AddACL(const char *name , int authority)
{
	MiniSSL_ACL *w;
	unsigned char *buf;
	char filename[CLIENT_NAME_SIZE*2];

	//ACLに空きがあるか？
	if( freeACL == NULL ){
		return FALSE;
	}
	w = freeACL->next;
	freeACL->next = topACL;
	freeACL->prev = NULL;
	if( topACL == NULL ){

	}else{
		topACL->prev = freeACL;
	}
	topACL = freeACL;
	freeACL = w;
	freeACL->prev = NULL;

	topACL->authority = authority;
	strcpy(topACL->name , name);
	//公開キー読み込み
	strcpy(filename , ".\\acl\\");
	strcat(filename , name);
	strcat(filename , ".key");
	buf = ASN1_read_der(filename);
	if( buf == NULL ){
		SockFrame_DebugOut("failed to load %s\n",filename);
		return FALSE;
	}
	topACL->key = ASN1_read_rsapub(buf);

	return TRUE;
}
int DelACL(MiniSSL_ACL *w)
{
	if( w == NULL ){
		return TRUE;
	}
	RSAkey_free((Key *)w->key);
	w->authority = 0;
	w->name[0] = '\0';

	if(w->prev == NULL && w->next == NULL){
		goto LINK_FREE;
	}

	if(w->prev == NULL ){
		//先頭ACLを削除
		w->next->prev = NULL;
		topACL = w->next;
	}else{
		//中間ACLを削除
		w->prev->next = w->next;
	}

	if(w->next == NULL){
		//最後尾ACLを削除
		w->prev->next = NULL;
	}else{
		//中間ACLを削除
		w->next->prev = w->prev;
	}

LINK_FREE:
	w->prev = NULL;
	w->next = freeACL;
	freeACL->prev = w;
	freeACL = w;
	
	return TRUE;
}

const MiniSSL_ACL *TopACL()
{
	return topACL;
}

//ACL内にnameで指定するクライアントがあるか検索し、そのACLへの参照を返す
//ない場合はNULLを返す
const MiniSSL_ACL *FindACL(const char *name)
{
	MiniSSL_ACL *w;

	w = topACL;
	do{
		if( w == NULL ){
			return NULL;
		}
		if( strcmp(name , w->name) == 0 ){
			return w;
		}
		w = w->next;
	}while(1);
}

int MiniSSL_LoadClientACL()
{
	FILE *fp;
	char buf[BUF_SIZE];
	char *name;
	char *authority;
	int auth;
	int line = 0;

	fp = fopen(".\\acl\\acl.txt" , "rt");
	if( fp == NULL ){
		SockFrame_DebugOut("ACL(.\\acl\\acl.txt) not found.\n");
		return FALSE;
	}

	InitACL();
	do{
		//ACLを一行ずつ処理する
		if( fgets(buf ,BUF_SIZE ,fp) == NULL ){
			break;
		}
		line++;
		//クライアント名を読む　デリミタはカンマと改行
		name = strtok(buf , ",\n");
		//権限コードを読む
		authority = strtok(NULL , ",\n");
		if( authority == NULL ){
			SockFrame_DebugOut("authority code not found in line %d.\n",line);
			return FALSE;
		}
		sscanf(authority , "%d" , &auth);
		if( AddACL(name , auth) != TRUE ){
			SockFrame_DebugOut("failed to load key file or ACL full in %d.\n",line);
			return FALSE;
		}
	}while(1);
	SockFrame_DebugOut("%d client ACL loaded\n",line);
	return TRUE;
}

void MiniSSL_InitSessionInfo(MiniSSL_INFO *si)
{
	si->sharedKey = DESkey_new_();
	si->si = malloc(sizeof(SOCK_INFO));
	si->myPrvKey = NULL;
	si->myPubKey = NULL;
	si->targetPubKey = NULL;
	memset(si->clientName , 0 , sizeof(si->clientName));
	si->sessionReady = FALSE;
	si->recvbufLimit = si->recvbuf;
	si->recvpos = si->recvbuf;
	si->recvBytes = 0;
	si->mode = 0;
	si->nagleByte = 0;
}
void MiniSSL_FreeSessionInfo(MiniSSL_INFO *si)
{
	free(si->si);
	si->si = NULL;
	DESkey_free(si->sharedKey );
	RSAkey_free((Key *)si->myPrvKey);
	RSAkey_free((Key *)si->myPubKey);
	RSAkey_free((Key *)si->targetPubKey);
	memset(si->clientName , 0 , sizeof(si->clientName));
	si->recvpos = si->recvbuf;
	si->recvbufLimit = si->recvbuf;
	si->recvBytes = 0;
	si->sessionReady = FALSE;
	si->mode = 0;
}
int MiniSSL_SetMyPubPrvKey(MiniSSL_INFO *si,char *filename)
{
	unsigned char *buf;
	buf = ASN1_read_der(filename);
	if( buf == NULL ){
		SockFrame_DebugOut("failed to load my prvkey(%s).\n" , filename);
		return FALSE;
	}
	si->myPrvKey = ASN1_read_rsaprv(buf);

	if( si->myPrvKey == NULL ){
		SockFrame_DebugOut("invalid prvkey file(%s)\n" , filename);
		return FALSE;
	}
	si->myPubKey = RSApubkey_new();
	RSAprv_2pub(si->myPrvKey , si->myPubKey);

	return TRUE;
}

/*-----------------------------------------
  ASN.1 to struct Pubkey_RSA
-----------------------------------------*/
Pubkey_RSA *ASN1_read_rsapub(unsigned char *in)
{
	Pubkey_RSA 	*ret;
	unsigned char	*cp;
	int	i,err=-1;

	if(in == NULL) return NULL;
	if(*in != 0x30){
		OK_set_error(ERR_ST_BADFORMAT,ERR_LC_ASN1,ERR_PT_ASN1RSA,NULL);
		return NULL;}

	/* if this DER contains less 40 byte (512 bit) integer, 
	 * it must not be RSA private key!! 
	 */
	cp = ASN1_step(in,1);
	if((cp[0]!=0x02)||(cp[1]<0x40)){
		OK_set_error(ERR_ST_BADFORMAT,ERR_LC_ASN1,ERR_PT_ASN1RSA,NULL);
		return NULL;}

	if((ret=RSApubkey_new())==NULL) goto done;

	/* check PKCS#1 Private key version. it must be 0. */
	//cp = ASN1_next(in);
	//if((ret->version=ASN1_integer(cp,&i)) != 0){
	//	OK_set_error(ERR_ST_UNSUPPORTED_VER,ERR_LC_ASN1,ERR_PT_ASN1RSA,NULL);
	//	goto done;
	//}

	cp = ASN1_next(in);
	if(ASN1_int2LNm(cp,ret->n,&i)) goto done;
	cp = ASN1_next(cp);
	if(ASN1_int2LNm(cp,ret->e,&i)) goto done;

	ret->size    = LN_now_byte(ret->n);
	err=0;
done:
	if(err&&ret){RSAkey_free((Key*)ret);ret=NULL;}
	return(ret);
}
int MiniSSL_SetTargetPubKey(MiniSSL_INFO *si, char *filename)
{
	unsigned char *buf;
	buf = ASN1_read_der(filename);
	if( buf == NULL ){
		return FALSE;
	}
	si->targetPubKey = ASN1_read_rsapub(buf);

	return TRUE;
}