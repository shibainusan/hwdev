
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "ok_rsa.h"
#include "ok_asn1.h"
#include "ok_md5.h"
#include "ok_rand.h"
#include "large_num.h"

#define MD5_SIZE (128/8)
#define KEY_SIZE (1024/8)

//aとbの最大公約数をretに格納
void gcd(LNm *_a , LNm *_b , LNm *ret)
{
	LNm *r,*a,*b;
	LNm *zero;

	r = LN_alloc();
	zero = LN_alloc();
	LN_clean(zero);

	//a > b
//	if( LN_cmp(_a ,_b ) == 1 ){
		a = LN_clone(_a);
		b = LN_clone(_b);
//	}else{ //a < b
//		b = LN_clone(_a);
//		a = LN_clone(_b);
//	}
	//r > 0
	while(1){
		// r = a % b
		LN_mod(a , b , r);
		if( LN_cmp(r , zero) == 0 ){
			break;
		}
		// a = b
		LN_copy(b, a);
		// b = r
		LN_copy(r , b);
	}
	LN_copy(b , ret);
	LN_free(a);
	LN_free(b);
	LN_free(r);
	LN_free(zero);
}
int SetPrvKey(Prvkey_RSA *myPrvKey,char *filename)
{
	unsigned char *buf;
	buf = ASN1_read_der(filename);
	if( buf == NULL ){
		printf("failed to load my prvkey(%s).\n" , filename);
		return FALSE;
	}
	myPrvKey = ASN1_read_rsaprv(buf);
	free(buf);
	if( myPrvKey == NULL ){
		printf("invalid prvkey file(%s)\n" , filename);
		return FALSE;
	}
	return TRUE;
}
void anana()
{
	unsigned char ba[4],bb[4];
	LNm *a,*b;
	a = LN_alloc();
	b = LN_alloc();

}
int main(int argc,char **argv){

	unsigned char *sql = "select * from jiko where";
	unsigned char hash[MD5_SIZE];
	unsigned char rand[KEY_SIZE];
	LNm *lhash;
	LNm *lrand;
	LNm *lrandinv;
	LNm *blind;
	LNm *toServer;
	LNm *fromServer;
	LNm *ret;
	Prvkey_RSA *prv;
	Pubkey_RSA *pub;
	unsigned char bf[KEY_SIZE];
 	unsigned char s[KEY_SIZE];
	unsigned char b[KEY_SIZE];
	unsigned char *buf;

	anana();

	RAND_init();
	lhash = LN_alloc();
	lrand = LN_alloc();
	lrandinv = LN_alloc();
	blind = LN_alloc();
	toServer = LN_alloc();
	fromServer = LN_alloc();
	ret = LN_alloc();

	buf = ASN1_read_der("prv.key");
	prv = ASN1_read_rsaprv(buf);
	free(buf);
	pub = RSApubkey_new();
	RSAprv_2pub(prv , pub);

	//ハッシュ生成
	OK_MD5(strlen(sql) ,sql, hash);
	LN_set_num_c(lhash , MD5_SIZE , hash);
	//普通の署名
	LN_exp_mod(lhash , prv->d ,prv->n, ret );
	printf("normal signB: ");
	LN_print(ret);

	printf("prv->n\n");
	LN_print(prv->n);
	//blinding factor生成
	do{
		RAND_bytes(rand , MD5_SIZE);
		LN_set_num_c(lrand , MD5_SIZE, rand);
		gcd(pub->n , lrand , ret);
		if( 
	}while(1);

	//blinding factorを公開キーで暗号化
	LN_exp_mod(lrand , pub->e ,pub->n, blind );
	printf("blind\n");
	LN_print(blind);
	//hash*rand^e mod n
	LN_mul_mod( blind , lhash , pub->n , toServer);
	printf("toServer\n");
	LN_print(toServer);

	//秘密鍵で署名
	LN_exp_mod(toServer , prv->d ,prv->n, fromServer );
	printf("fromServer\n");
	LN_print(fromServer);
	//逆元を得る
	LN_mod_inverse(lrand , pub->n , lrandinv);
	//ブラインド解除
	LN_mul_mod(  fromServer , lrandinv ,  pub->n , ret); 
	LN_print(ret);
	
	RAND_cleanup();
	return 0;

}

int MiniSSL_BlindingRequest(const Pubkey_RSA *serverPubKey,const char *plaintext,char *blindFactor,char *blindedHash)
{
}

int MiniSSL_UnblindingSignature(const Pubkey_RSA *serverPrvKey,const char *blindedSign , char *blindFactor , char *sign)
{
}
