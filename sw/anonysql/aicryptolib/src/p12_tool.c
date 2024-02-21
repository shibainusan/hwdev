/* p12_tool.c */
/*
 * Copyright (C) 1998-2002
 * Akira Iwata & Takuto Okuno
 * Akira Iwata Laboratory,
 * Nagoya Institute of Technology in Japan.
 *
 * All rights reserved.
 *
 * This software is written by Takuto Okuno(usapato@anet.ne.jp)
 * And if you want to contact us, send an email to Kimitake Wakayama
 * (wakayama@elcom.nitech.ac.jp)
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. All advertising materials mentioning features or use of this software must
 *    display the following acknowledgment:
 *    "This product includes software developed by Akira Iwata Laboratory,
 *    Nagoya Institute of Technology in Japan (http://mars.elcom.nitech.ac.jp/)."
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Akira Iwata Laboratory,
 *     Nagoya Institute of Technology in Japan (http://mars.elcom.nitech.ac.jp/)."
 *
 *   THIS SOFTWARE IS PROVIDED "AS IS" WITHOUT EXPRESS OR IMPLIED WARRANTY.
 *   AKIRA IWATA LABORATORY DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS
 *   SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS,
 *   IN NO EVENT SHALL AKIRA IWATA LABORATORY BE LIABLE FOR ANY SPECIAL,
 *   INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
 *   FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 *   NEGLIGENCE OR OTHER TORTUOUS ACTION, ARISING OUT OF OR IN CONNECTION
 *   WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 */
#include "aiconfig.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "large_num.h"

#include "ok_asn1.h"
#include "ok_pkcs.h"
#include "ok_tool.h"
#include "ok_rsa.h"
#include "ok_uconv.h"

/* asn1_set.c */
int bmp_len(char *str);

/*-----------------------------------------
  PKCS#12 find baggage
-----------------------------------------*/
P12_Baggage *P12_find_bag(PKCS12 *p12,int type,unsigned char keyID){
	P12_Baggage *bg;

	for(bg=p12->bag;bg!=NULL;bg=bg->next)
		if((type==bg->type)&&(keyID==bg->localKeyID[0]))
			break;

	return bg;
}

/*-----------------------------------------
  PKCS#12 get max depth
-----------------------------------------*/
int P12_max_depth(PKCS12 *p12,int type){
	P12_Baggage *bg;
	int ret=0;

	for(bg=p12->bag;bg!=NULL;bg=bg->next)
		if((type==bg->type)&&(bg->localKeyID[0]>ret))
			ret=bg->localKeyID[0];
	return ret;
}

/*-----------------------------------------
  PKCS#12 set baggage value
-----------------------------------------*/
int P12_set_Bag_f_l(P12_Baggage *bg,char *fname,unsigned char id){
	int len = bmp_len(fname);

	if(bg->friendlyName) FREE(bg->friendlyName);
	if((bg->friendlyName=(unsigned char*)MALLOC(len+2))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PKCS12,ERR_PT_P12TOOL,NULL);
		return -1;
	}
	memset(bg->friendlyName,0,len+2);
	memcpy(bg->friendlyName,fname,len);
	bg->localKeyID[0] = id;
	return 0;
}

int P12_set_KeyBag(P12_KeyBag *kb,Key *key,char *fname,unsigned char id){
	kb->key = key;
	return P12_set_Bag_f_l((P12_Baggage*)kb,fname,id);
}

int P12_set_CertBag(P12_CertBag *cb,Cert *cert,char *fname,unsigned char id){
	cb->cert = cert;
	return P12_set_Bag_f_l((P12_Baggage*)cb,fname,id);
}

int P12_set_CRLBag(P12_CRLBag *cb,CRL *crl,char *fname,unsigned char id){
	cb->crl = crl;
	return P12_set_Bag_f_l((P12_Baggage*)cb,fname,id);
}

/*-----------------------------------------
  PKCS#12 add cert & key by bag
-----------------------------------------*/
int P12_add_cert(PKCS12 *p12,Cert *ct,char *fname,unsigned char id){
	unsigned char buf[64];
	P12_CertBag *cb;

	if(fname==NULL){
		fname = buf;
		strcpy(buf,"Certificate");
		if(get_dn_for_friendlyname(&ct->subject_dn,buf)) goto error;
	}
	if((cb=P12_Cert_new())==NULL) goto error;
	if(P12_set_CertBag(cb,ct,fname,id)) goto error;

	P12_add_bag(p12,(P12_Baggage*)cb);
	return 0;
error:
	return -1;
}

int P12_add_key(PKCS12 *p12,Key *key,char *fname,unsigned char id){
	unsigned char buf[64];
	char *txt="Private Key";
	P12_KeyBag *kb;

	if(fname==NULL){
		memset(buf,0,64); 
		if(UC_conv(UC_LOCAL_JCODE,UC_CODE_UNICODE,txt,strlen(txt),buf,62)<0) goto error;
		fname = buf;
	}
	if((kb=P12_Key_new())==NULL) goto error;
	if(P12_set_KeyBag(kb,key,fname,id)) goto error;

	P12_add_bag(p12,(P12_Baggage*)kb);
	return 0;
error:
	return -1;
}

int P12_add_crl(PKCS12 *p12,CRL *crl,char *fname,unsigned char id){
	unsigned char buf[64];
	P12_CRLBag *cb;

	if(fname==NULL){
		fname = buf;
		strcpy(buf,"CRL"); 
		if(get_dn_for_friendlyname(&crl->issuer_dn,buf)) goto error;
	}
	if((cb=P12_CRL_new())==NULL) goto error;
	if(P12_set_CRLBag(cb,crl,fname,id)) goto error;

	P12_add_bag(p12,(P12_Baggage*)cb);
	return 0;
error:
	return -1;
}

/* return buffer should be more than 64 byte */
int get_dn_for_friendlyname(CertDN *dn, char *ret){
	int i,j,t[4]={OBJ_DIR_CN,OBJ_DIR_EMAIL,OBJ_DIR_OU,OBJ_DIR_O};
	char *tmp;

	for(i=0;i<4;i++){
		if(tmp = Cert_find_dn(dn,t[i],&j)){
			memset(ret,0,64);
			switch(dn->rdn[j].derform){
			default:
				if(UC_conv(UC_LOCAL_JCODE,UC_CODE_UNICODE,tmp,strlen(tmp),ret,62)<0)
					return -1;
				break;
			case ASN1_BMPSTRING:
				j = bmp_len(tmp);
				memcpy(ret,tmp,(j<64)?(j):(62));
				break;
			}
			break;
		}
	}
	return 0;
}

unsigned char *get_frname_from_dn(Cert *ct){
	unsigned char *ret=NULL,buf[128];
	int len;

	memset(buf,0,128);
	strcpy(buf,"Certificate");
	if(get_dn_for_friendlyname(&ct->subject_dn,buf)) goto error;
	len = bmp_len(buf);

	if((ret=(unsigned char*)MALLOC(len+2))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PKCS12,ERR_PT_P12TOOL+1,NULL);
		goto error;
	}
	memcpy(ret      ,buf,len);
	memset(&ret[len],  0,  2);
	return ret;
error:
	return NULL;
}

/*-----------------------------------------
  PKCS#12 move bags from mov to p12
-----------------------------------------*/
void P12_mov_p12bags(PKCS12 *p12,PKCS12 *mov){
	P12_Baggage *bg,*prev;

	prev=NULL;
	for(bg=p12->bag;bg!=NULL;bg=bg->next)
		prev=bg;

	if(prev) prev->next=mov->bag;
	else	p12->bag=mov->bag;
	mov->bag=NULL;
}

/*-----------------------------------------
  PKCS#12 copy bags
-----------------------------------------*/
unsigned char *bmpstr_dup(unsigned char *org){
	unsigned char *ret=NULL;
	int i;

	if(org==NULL) goto done;

	i = bmp_len(org);

	if((ret=(char*)MALLOC(i+2))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_PKCS12,ERR_PT_P12TOOL+2,NULL);
		goto done;
	}
	memcpy(ret,org,i);
	memset(&ret[i],0,2);
done:
	return ret;
}

int P12_copy_p12bags(PKCS12 *to,PKCS12 *from){
	P12_Baggage *bg,*tmp;
	Cert *cert;
	Key *key;
	CRL *crl;

	for(bg=from->bag;bg!=NULL;bg=bg->next){
		/* get enough size of structure */
		if((tmp=(P12_Baggage*)P12_Cert_new())==NULL) goto error;
		memcpy(tmp,bg,sizeof(P12_Baggage));

		if(bg->friendlyName){
			if((tmp->friendlyName=bmpstr_dup(bg->friendlyName))==NULL)
				goto error;
		}
		tmp->next=NULL;

		switch(bg->type){
		case OBJ_P12v1Bag_PKCS8:
			if((key=Key_dup(((P12_KeyBag*)bg)->key))==NULL) goto error;
			((P12_KeyBag*)tmp)->key=key;
			break;
		case OBJ_P12v1Bag_CERT:
			if((cert=Cert_dup(((P12_CertBag*)bg)->cert))==NULL) goto error;
			((P12_CertBag*)tmp)->cert=cert;
			break;
		case OBJ_P12v1Bag_CRL:
			if((crl=CRL_dup(((P12_CRLBag*)bg)->crl))==NULL) goto error;
			((P12_CRLBag*)tmp)->crl=crl;
			break;
		}
		P12_add_bag(to,tmp);
	}
	return 0;
error:
	P12Bag_free_all(to->bag);
	to->bag=NULL;
	return -1;
}

/*-----------------------------------------
  duplicate PKCS12 Struct
-----------------------------------------*/
PKCS12 *P12_dup(PKCS12 *org){
	PKCS12 *p12;
	int err=-1;

	if(org==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_PKCS12,ERR_PT_P12TOOL+3,NULL);
		return NULL;
	}
	if((p12=P12_new())==NULL) goto done;

	p12->version = org->version;
	if(P12_copy_p12bags(p12,org)) goto done;
	err=0;
done:
	if(err&&p12){P12_free(p12);p12=NULL;}
	return p12;
}


/*-----------------------------------------
  PKCS#12 get user certificate
  Return Cert pointer...
-----------------------------------------*/
Cert *P12_get_usercert(PKCS12 *p12){
	P12_CertBag *cb;
	int dp;

	dp=P12_max_depth(p12,OBJ_P12v1Bag_CERT);
	if(dp==0xff){
		P12_check_chain(p12,0);
		dp=P12_max_depth(p12,OBJ_P12v1Bag_CERT);
	}
	if(cb=(P12_CertBag*)P12_find_bag(p12,OBJ_P12v1Bag_CERT,(unsigned char)dp)){
		return cb->cert;
	}else{
		OK_set_error(ERR_ST_P12_BADDEPTH,ERR_LC_PKCS12,ERR_PT_P12TOOL+4,(int*)dp);
		return NULL;
	}
}

/*-----------------------------------------
  PKCS#12 get user certificate
  Return Key pointer...
-----------------------------------------*/
Key *P12_get_privatekey(PKCS12 *p12){
	P12_KeyBag *kb;
	int dp;

	dp=P12_max_depth(p12,OBJ_P12v1Bag_PKCS8);
	if(dp==0xff){
		P12_check_chain(p12,0);
		dp=P12_max_depth(p12,OBJ_P12v1Bag_PKCS8);
	}
	if(kb=(P12_KeyBag*)P12_find_bag(p12,OBJ_P12v1Bag_PKCS8,(unsigned char)dp)){
		return kb->key;
	}else{
		OK_set_error(ERR_ST_P12_BADDEPTH,ERR_LC_PKCS12,ERR_PT_P12TOOL+5,(int*)dp);
		return NULL;
	}
}

/*-----------------------------------------
  PKCS#12 check chain and
	write depth to localKeyID[0]
-----------------------------------------*/
int P12_check_chain(PKCS12 *p12,int print){
	P12_Baggage	*bg,*bg2,*prev;
	Cert *c1,*c2;
	Cert *chain[12];
	unsigned char tmp,depth,ct;
	int err=-1;

	if(!p12->bag){
		OK_set_error(ERR_ST_P12_NOBAG,ERR_LC_PKCS12,ERR_PT_P12TOOL+6,NULL);
		goto done;
	}
	for(bg=p12->bag;bg!=NULL;bg=bg->next){
		bg->localKeyID[0]=0xff; /* reset localKeyID */
		if(print) printf("++Check One PKCS#12Bag, type=%d\r\n",bg->type);
	    }

	/* find top certificate */
	ct=depth=0; chain[0]=NULL;
	bg=p12->bag;
	while( bg ){
		if(bg->type != OBJ_P12v1Bag_CERT){
			bg=bg->next; continue;}

		ct++;	/* certificate or request is found in p12 bags */

		if((c1=((P12_CertBag*)bg)->cert)==NULL){
			OK_set_error(ERR_ST_P12_NOCERT,ERR_LC_PKCS12,ERR_PT_P12TOOL+6,NULL);
			goto done;
		}
		if(c1->issuer==NULL){	/* it's request... */
			bg=bg->next; continue;}

		prev=bg;
		bg2=bg->next;
		for(; bg2 ;prev=bg2, bg2=bg2->next){

			if(bg2->type != OBJ_P12v1Bag_CERT)
				continue;

			if((c2=((P12_CertBag*)bg2)->cert)==NULL){
				OK_set_error(ERR_ST_P12_NOCERT,ERR_LC_PKCS12,ERR_PT_P12TOOL+6,NULL);
				goto done;
			}

			if(c2->issuer==NULL) /* it's request... */
				continue;

			if(!Cert_dncmp(&c1->issuer_dn,&c2->subject_dn)){
				/* find chain to the top */
				depth = 1;
				chain[0] = c2;
				bg2->localKeyID[0] = 0;
				prev->next= bg2->next;
				bg2->next = bg->next;
				bg->next  = bg2;

				if(bg2->friendlyName==NULL){
					/* if it returns NULL, just ignore... */
					bg2->friendlyName = get_frname_from_dn(c2);
				}
				break;
			}
		}
		bg=bg2;
	}

	if(ct&&(depth==0)){/* hmm, begining one might be top CA cert */
		depth=1;
		if((bg=P12_find_bag(p12,OBJ_P12v1Bag_CERT,0xff))==NULL) goto done;
		chain[0] =((P12_CertBag*)bg)->cert;

		bg->localKeyID[0] = 0;
		if(bg->friendlyName==NULL){
			/* if it returns NULL, just ignore... */
			bg->friendlyName = get_frname_from_dn(((P12_CertBag*)bg)->cert);
		}
	}

	if(chain[0]&&print){printf("TOP - %s --%d\r\n",chain[0]->subject,depth-1);}

	/* check certificate chain */
	while(tmp=depth){ /* not compare */
	for(bg=p12->bag;bg!=NULL;bg=bg->next){
		switch(bg->type){
		case OBJ_P12v1Bag_CERT:
			if((c1=((P12_CertBag*)bg)->cert)==NULL){
				OK_set_error(ERR_ST_P12_NOCERT,ERR_LC_PKCS12,ERR_PT_P12TOOL+6,NULL);
				goto done;
			}
			if(c1->issuer==NULL)/* it's request... */
				break;

			if(!Cert_dncmp(&chain[depth-1]->subject_dn,&c1->issuer_dn)){

				if(tmp!=depth) break;/* one cert was already found. */

				/* sometimes input certificates might be
				 * ca certificate... */
				if(!Cert_dncmp(&c1->subject_dn,&c1->issuer_dn)) break;

				/* cross certificate pattern */
				if(depth>1)
					if(!Cert_dncmp(&chain[depth-2]->subject_dn,&c1->subject_dn)) break;

				bg->localKeyID[0] = depth;
				chain[depth] = c1;
				tmp++;
				if(chain[depth]&&print)
				    printf("UCERT - %s --%d\r\n",chain[depth]->subject,depth);

				if(bg->friendlyName==NULL){
					/* if it returns NULL, just ignore... */
					bg->friendlyName = get_frname_from_dn(c1);
				}
				break;
			}
			break;
		case OBJ_P12v1Bag_CRL:
			if(((P12_CRLBag*)bg)->crl==NULL){
				OK_set_error(ERR_ST_P12_NOCRL,ERR_LC_PKCS12,ERR_PT_P12TOOL+6,NULL);
				goto done;
			}
			if(!Cert_dncmp(&chain[depth-1]->subject_dn,&((P12_CRLBag*)bg)->crl->issuer_dn)){
				bg->localKeyID[0] = depth;
				if(print) printf("CRL -- %d\r\n",depth);
			}
			break;
		}
	}
	if(tmp==depth) break;
	else depth++;
	}

	/* set depth */
	if(ct) depth--;

	if((ct==0)&&(depth==0)){
		/* if there is no certificate, keep CRL and key in the buffer */
		if(bg=P12_find_bag(p12,OBJ_P12v1Bag_CRL,0xff))
			bg->localKeyID[0]=0;
		if(bg=P12_find_bag(p12,OBJ_P12v1Bag_PKCS8,0xff))
			bg->localKeyID[0]=0;
	}

	/* set private key ID */
	if(bg=P12_find_bag(p12,OBJ_P12v1Bag_CERT,depth)){
		c1 = ((P12_CertBag*)bg)->cert; /* this certificate was checked already */

		for(bg=p12->bag;bg!=NULL;bg=bg->next){
			if(bg->type == OBJ_P12v1Bag_PKCS8){
				if(!Key_pair_cmp(((P12_KeyBag*)bg)->key,c1->pubkey)){
					bg->localKeyID[0]=depth;

					if(bg->friendlyName==NULL){
						/* if it returns NULL, just ignore... */
						bg->friendlyName = get_frname_from_dn(c1);
					}
					break;
				}
			}
		}
	}

	/* clean useless baggages */
	prev=(P12_Baggage*)p12;
	for(bg=p12->bag;bg!=NULL;bg=bg->next){
		if(bg->localKeyID[0] == 0xff){
			prev->next=bg->next;
			if(print) printf("--Clean One PKCS#12Bag, type=%d\r\n",bg->type);
			P12Bag_free(bg);
			bg=prev;
		}else{
			prev=bg;
		}
	}
	err=0;
done:
	return err;
}
