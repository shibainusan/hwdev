//RSAキーペア生成プログラム
#include <stdio.h>
#include <string.h>

#include "ok_rsa.h"
#include "ok_asn1.h"
#include "ok_rand.h"

/*-----------------------------------------
  ASN.1 to struct Pubkey_RSA
-----------------------------------------*/
Pubkey_RSA *ASN1_read_rsapub(unsigned char *in){
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
	cp = ASN1_step(in,2);
	if((cp[0]!=0x02)||(cp[1]<0x40)){
		OK_set_error(ERR_ST_BADFORMAT,ERR_LC_ASN1,ERR_PT_ASN1RSA,NULL);
		return NULL;}

	if((ret=RSApubkey_new())==NULL) goto done;

	/* check PKCS#1 Private key version. it must be 0. */
	cp = ASN1_next(in);
	if(ASN1_integer(cp,&i) != 0){
		OK_set_error(ERR_ST_UNSUPPORTED_VER,ERR_LC_ASN1,ERR_PT_ASN1RSA,NULL);
		goto done;
	}

	cp = ASN1_next(cp);
	if(ASN1_int2LNm(cp,ret->n,&i)) goto done;
	cp = ASN1_next(cp);
	if(ASN1_int2LNm(cp,ret->e,&i)) goto done;

	ret->size    = LN_now_byte(ret->n);
	err=0;
done:
	if(err&&ret){RSAkey_free((Key*)ret);ret=NULL;}
	return(ret);
}

int rsa_keygen(int keysize)
{

	unsigned char buf[4096];
	int ret;
	Pubkey_RSA	   *pub;
	Prvkey_RSA	   *prv;

	prv=RSAprvkey_new();
	pub=RSApubkey_new();
	RSAprv_generate(prv,keysize/2/8);
	RSAprv_2pub(prv,pub);

	ASN1_write_der(prv->der , "prv.key");

	ASN1_write_der(RSApub_toDER(pub , buf ,&ret ) , "pub.key");

	RSAkey_free(prv);
	RSAkey_free(pub);
	
	return 0;
}

int des_keygen()
{
#define DES_SIZE 8
#define IV_SIZE 8
	FILE *fp;
	unsigned char buf[DES_SIZE + IV_SIZE];

	fp=fopen("des.key" , "wb"); 
	RAND_bytes(buf , DES_SIZE + IV_SIZE);
	fwrite(buf , DES_SIZE + IV_SIZE , 1 , fp);
	fclose(fp);
}

int main(int argc,char **argv)
{
	Pubkey_RSA *p;
	Prvkey_RSA *p2;
	unsigned char *buf;
	unsigned char b[] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25};
	LNm *ln;

	RAND_init();	
	printf("generating 1024bit rsa keypair.\n");
	rsa_keygen(1024);
	printf("generating 56bit DES key and IV.");
	des_keygen();
	printf("ok\n");
	RAND_cleanup();
	getchar();
#if 0
	ln = LN_alloc();
	LN_set_num_c(ln , 25 , b);
	buf = ASN1_read_der("prv.key");
	p2 = ASN1_read_rsaprv(buf);
	buf = ASN1_read_der("pub.key");
	p = ASN1_read_rsapub(buf);
#endif
}

