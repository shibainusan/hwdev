/*
 * rsa test functions.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ok_rsa.h"
#include "ok_asn1.h"

int test_rsa_pubprv(){
    unsigned short sn1[]={
	0xed3e,0x206e,0x179f,0x7c27,0x6d0d,0x834c,0xf64b,0xe264,
	0x4b9d,0x6f0d,0xbbbd,0x2956,0xdd70,0x3f64,0x7f40,0x660b,
	0xbe87,0xcb3c,0x656a,0xd501,0xf647,0x1759,0xe62f,0xece6,
	0x3735,0xadfa,0x037f,0x1c8c,0xee5e,0x00eb,0x9580,0x1fab};
	unsigned short se[]={
	0x0001,0x0001};
	unsigned short sd1[]={
	0x1726,0x57cd,0xc65a,0x56a8,0x1639,0x1a55,0xd936,0xc069,
	0x9f03,0x46c1,0xe54e,0xe908,0xc3e4,0xdf1a,0xb45c,0x1958,
	0xddea,0x70f7,0xa236,0x9533,0xe67f,0x4aff,0xc4b3,0xa724,
	0x1dd2,0x1572,0x1e9d,0x01ad,0x0ec0,0x58cb,0x368d,0xe311};
 	unsigned char  in[130],cry[130],out[130],*cp,*ct;
	LNm *e,*d,*n;
	Pubkey_RSA	   *key;
	Prvkey_RSA	   *prv;
 	int i;

	n=LN_alloc_s(32,sn1);
	d=LN_alloc_s(32,sd1);
	e=LN_alloc_s(2,se);
	key =(Pubkey_RSA*)MALLOC(sizeof(Pubkey_RSA));
	prv =(Prvkey_RSA*)MALLOC(sizeof(Prvkey_RSA));
	key->size=prv->size=64;

    LN_print(n);
    LN_print(e);
    LN_print(d);

    OK_RSA_set_pubkey(key,n,e);
    OK_RSA_set_prvkey(prv,n,d);

	strcpy(in,"This is test.");
    memset(cry,0,130);
    memset(out,0,130);

    RSApub_doCrypt(strlen(in),in,cry,key);
    RSAprv_doCrypt(prv->size,cry,out,prv);

    cp = (char*)memchr(out,'T',prv->size);
	if(strcmp(in,cp)){
		printf("error : test_rsa_pubprv -- 1\n");
		for(i=0;i<prv->size;i++) printf("%.2x ",cry[i]);printf("\n");
		for(i=0;i<prv->size;i++) printf("%.2x ",out[i]);printf("\n");
		return -1;
	}else{
		printf("test_rsa_pubprv ok -- 1\n");
	}

    memset(in,0,130);
    RSAprv_doCrypt(strlen(cp),cp,cry,prv);
    RSApub_doCrypt(prv->size,cry,in,key);

    ct = (char*)memchr(in,'T',prv->size);
	if(strcmp(cp,ct)){
		printf("error : test_rsa_pubprv -- 2\n");
		return -1;
	}

	printf("test_rsa_pubprv ok -- 2\n");

    FREE(key); FREE(prv);
	LN_free(d);	LN_free(e);	LN_free(n);
	return 0;
}

int test_rsa_keygen(){
	unsigned short se[]={
		0x0001,0x0001};
	Pubkey_RSA	   *key,*d1;
	Prvkey_RSA	   *prv,*d2;
	LNm *in,*cry,*out;
	int i,j;

	prv=RSAprvkey_new();
	in =LN_alloc();
	cry=LN_alloc();
	out=LN_alloc();

	/* test 1 */
	LN_set_num_s(prv->e,2,se);
	LN_set_rand(in,48,(unsigned short)rand());
	for(j=32;j<129;j+=32){
		for(i=0;i<5;i++){
			LN_prime(j,prv->p,0);
			LN_prime(j,prv->q,0);
			prv->p->num[LN_MAX-1]&=0xfffffffe;	/* p1=p-1 */
			prv->q->num[LN_MAX-1]&=0xfffffffe;	/* q1=q-1 */
			LN_multi(prv->p,prv->q,prv->n);
			LN_mod_inverse(prv->e,prv->n,prv->d);
			prv->p->num[LN_MAX-1]|=0x00000001;
			prv->q->num[LN_MAX-1]|=0x00000001;
			LN_multi(prv->p,prv->q,prv->n);

			LN_exp_mod(in ,prv->e,prv->n,cry);
			LN_exp_mod(cry,prv->d,prv->n,out);

			if(LN_cmp(in,out)){
				printf("error -- test gen RSA prvkey (%d)\n",i);
				LN_print(in);
				LN_print(out);
				return -1;
			}else
				printf("test gen RSA prvkey (%d bit)-- %d\n",j*16,i);
	    }
	}
	RSAkey_free((Key*)prv);

	/* test 2 */
	/* test for getting new RSA prvkey */
	for(j=32;j<129;j+=32){
	    for(i=0;i<5;i++){
			prv=RSAprvkey_new();
			key=RSApubkey_new();

			RSAprv_generate(prv,j);
			RSAprv_2pub(prv,key);
			d1 =RSApubkey_dup(key);
			d2 =RSAprvkey_dup(prv);

			LN_exp_mod(in ,d1->e,d1->n,cry);
			LN_exp_mod(cry,d2->d,d2->n,out);

			if(LN_cmp(in,out)){
				printf("error -- test gen RSA prvkey (%d)\n",i);
				LN_print(in);
				LN_print(out);
				return -1;
			}

			RSAkey_free((Key*)prv);RSAkey_free((Key*)key);
			RSAkey_free((Key*)d1); RSAkey_free((Key*)d2);
			printf("test RSAprvkey_new() (%d bit) -- %d\n",j*16,i);
	    }
	}

	LN_free(in); LN_free(cry); LN_free(out);
	return 0;
}

int test_rsa_der_asn1(){
	Prvkey_RSA *prv,*prv2;
	Pubkey_RSA *pub;
	char *cp;
	int i;

    for(i=0;i<10;i++){
		prv=RSAprvkey_new();

		RSAprv_generate(prv,32);
		prv2=ASN1_read_rsaprv(prv->der);
		/* prv2->der pointer is same as original one.. */
		prv2->der=NULL;

		if(LN_cmp(prv->n,prv2->n)){cp="n:"; goto error;}
		if(LN_cmp(prv->e,prv2->e)){cp="e:";goto error;}
		if(LN_cmp(prv->d,prv2->d)){cp="d:";goto error;}
		if(LN_cmp(prv->p,prv2->p)){cp="p:";goto error;}
		if(LN_cmp(prv->q,prv2->q)){cp="q:";goto error;}
		if(LN_cmp(prv->e1,prv2->e1)){cp="e1:";goto error;}
		if(LN_cmp(prv->e2,prv2->e2)){cp="e2:";goto error;}
		if(LN_cmp(prv->cof,prv2->cof)){cp="cof:";goto error;}

		printf("test rsa DER encode & decode -- ok (%d)\n",i);
		RSAkey_free((Key*)prv);RSAkey_free((Key*)prv2);
	}

	/* compare two keys test */
    for(i=0;i<10;i++){
		prv =RSAprvkey_new();
		prv2=RSAprvkey_new();
		pub =RSApubkey_new();

		RSAprv_generate(prv,16);
		RSAprv_generate(prv2,16);
		RSAprv_2pub(prv,pub);

		if(Key_cmp((Key*)prv,(Key*)prv)){
			printf("test rsa compare two keys -- error (%d)\n",i);
			return -1;
		}
		if(!Key_cmp((Key*)prv,(Key*)prv2)){
			printf("test rsa compare two keys -- error (%d)\n",i);
			LN_print(prv->p);
			LN_print(prv2->p);
			return -1;
		}
		if(Key_cmp((Key*)pub,(Key*)pub)){
			printf("test rsa compare two keys -- error (%d)\n",i);
			return -1;
		}
		if(Key_pair_cmp((Key*)prv,(Key*)pub)){
			printf("test rsa compare prv & pub key -- error!\n");
			return -1;
		}

		printf("test rsa compare two keys -- ok (%d)\n",i);
		Key_free((Key*)prv); Key_free((Key*)pub);
		Key_free((Key*)prv2);
	}


	return 0;
error:
	printf("%s error -- test rsa DER encode & decode (%d)\n",cp,i);
	return -1;
}
