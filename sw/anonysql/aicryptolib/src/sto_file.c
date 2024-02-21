/* sto_file.c */
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ok_err.h"
#include "ok_sha1.h"
#include "ok_asn1.h"
#include "ok_tool.h"
#include "ok_store.h"

void get_store_fname(char *buf,char *path, char *name, int ctx_type);

/*-----------------------------------------------
   Init Store file
-----------------------------------------------*/
void cs_init_file_store(CStore *ret,int ctx_type,int mode){
	ret->dev_type   = CSTORE_ON_STORAGE;
	ret->ctx_type   = ctx_type;
	ret->mode       = mode;
	ret->dev_info_new  = (void *(*)(void*))CSDevStrage_new;
	ret->dev_info_free = (void (*)(void*))CSDevStrage_free;
	switch(ctx_type){
	case CSTORE_CTX_CERT:
		ret->bag2data   = (void *(*)(CSBag*))CS_bag2cert_on_strage;
		ret->data2bag   = (CSBag *(*)(CStore*,void*,char*,int))CS_cert2bag; break;
	case CSTORE_CTX_CRL:
		ret->bag2data   = (void *(*)(CSBag*))CS_bag2crl_on_strage;
		ret->data2bag   = (CSBag *(*)(CStore*,void*,char*,int))CS_crl2bag; break;
	case CSTORE_CTX_KEY:
		ret->bag2data   = (void *(*)(CSBag*))CS_bag2key_on_strage;
		ret->data2bag   = (CSBag *(*)(CStore*,void*,char*,int))CS_key2bag; break;
	case CSTORE_CTX_CSR:
		ret->bag2data   = (void *(*)(CSBag*))CS_bag2req_on_strage;
		ret->data2bag   = (CSBag *(*)(CStore*,void*,char*,int))CS_req2bag; break;
	case CSTORE_CTX_DER:
		ret->bag2data   = (void *(*)(CSBag*))CS_bag2der_on_strage;
		ret->data2bag   = (CSBag *(*)(CStore*,void*,char*,int))CS_der2bag; break;
	case CSTORE_CTX_ENCDER:
		ret->bag2data   = (void *(*)(CSBag*))CS_bag2encder_on_strage;
		ret->data2bag   = (CSBag *(*)(CStore*,void*,char*,int))CS_encder2bag; break;
	}
}

/*-----------------------------------------------
   Open & Close Certificate Store file
-----------------------------------------------*/
CStore *CStore_open_file(char *path, char *name, int ctx_type, int mode){
	CStore *ret=NULL;
	char buf[256];

	if((ret=CStore_new())==NULL) goto error;
	if((ret->dev_info=CSDevStrage_new(path))==NULL) goto error;

	cs_init_file_store(ret,ctx_type,mode);

	/* get store file name */
	get_store_fname(buf,path,name,ctx_type);

	if((((CSDevStrage*)ret->dev_info)->fp=fopen(buf,"rb"))==NULL){
		OK_set_error(ERR_ST_FILEOPEN,ERR_LC_STOREDEV,ERR_PT_STFILE,NULL);
		goto error;
	}
	fstat(fileno(((CSDevStrage*)ret->dev_info)->fp),&ret->csf_stat);

	if((STRDUP(ret->name,name))==NULL){
		OK_set_error(ERR_ST_STRDUP,ERR_LC_STOREDEV,ERR_PT_STFILE,NULL);
		goto error;
	}
	if(cstore_load_file(ret)) goto error;

	return ret;
error:
	if(ret){ CStore_close_file(ret); CStore_free(ret); }
	return NULL;
}

void CStore_close_file(CStore *cs){
	if(cs->dev_info){
		if(((CSDevStrage*)cs->dev_info)->fp){
			fclose(((CSDevStrage*)cs->dev_info)->fp);
			((CSDevStrage*)cs->dev_info)->fp=NULL;
		}
	}
}

void get_store_fname(char *buf,char *path, char *name, int ctx_type){
	unsigned char buf2[32],hs[20];

	strncpy(buf,name,64);
	switch(ctx_type){
	case CSTORE_CTX_CERT: strncat(buf,"--Cert--",16); break;
	case CSTORE_CTX_CSR:  strncat(buf,"--CSR--",16); break;
	case CSTORE_CTX_KEY:  strncat(buf,"--PrvKey--",16); break;
	case CSTORE_CTX_CRL:  strncat(buf,"--CRL--",16); break;
	case CSTORE_CTX_DER:  strncat(buf,"--DER--",16); break;
	case CSTORE_CTX_ENCDER:  strncat(buf,"--ENCDER--",16); break;
	default: strncat(buf,"--Default--",16); break;
	}
	OK_SHA1(strlen(buf),buf,hs);
	sprintf(buf2,"%.2x%.2x-%.2x%.2x%.2x.acs",hs[5],hs[2],hs[3],hs[4],hs[1]);
	strncpy(buf,path,200);
	strncat(buf,PATH_DELI,8);
	strncat(buf,buf2,16);
}

/*-----------------------------------------------
   new Certificate Store file
-----------------------------------------------*/
CStore *CStore_new_file(char *path, char *name, int ctx_type, int mode){
	CStore *ret=NULL;
	FILE *fp;
	char buf[256];

	if((ret=CStore_new())==NULL) goto error;
	if((ret->dev_info=CSDevStrage_new(path))==NULL) goto error;

	cs_init_file_store(ret,ctx_type,mode);

	/* get store file name */
	get_store_fname(buf,path,name,ctx_type);

	/* check file exists or not ... if it exists, return error */
	if(fp=fopen(buf,"rb")){
		OK_set_error(ERR_ST_FILEOPEN,ERR_LC_STOREDEV,ERR_PT_STFILE+2,NULL);
		fclose(fp); goto error;
	}
	if((((CSDevStrage*)ret->dev_info)->fp=fopen(buf,"ab"))==NULL){
		OK_set_error(ERR_ST_FILEOPEN,ERR_LC_STOREDEV,ERR_PT_STFILE+2,NULL);
		goto error;
	}
	fstat(fileno(((CSDevStrage*)ret->dev_info)->fp),&ret->csf_stat);

	if((STRDUP(ret->name,name))==NULL){
		OK_set_error(ERR_ST_STRDUP,ERR_LC_STOREDEV,ERR_PT_STFILE+2,NULL);
		goto error;
	}
	if(cstore_save_file(ret)) goto error;

	return ret;
error:
	if(ret){ CStore_close_file(ret); CStore_free(ret); }
	return NULL;
}


/*-----------------------------------------------
   Load Certificate Store file
-----------------------------------------------*/
/* this function should be call as soon as file is open */
int cstore_load_file(CStore *cs){
	CSBag *bg,*hd;
	fpos_t pos;
	int mode = cs->mode;
	unsigned char tmp[16],pass[32],*der=NULL;
	FILE *fp = ((CSDevStrage*)cs->dev_info)->fp;

	OK_get_localpass(pass);
	
	cs->bags=NULL;
	rewind(fp);

	do{
		if(fgetpos(fp,&pos)) goto error;

		if(fread(tmp,1,16,fp)<=1) break;

		if((der=get_der_from_fposition(fp, pos))==NULL) goto error;
		if((bg=asn1_bag_info(cs,der))==NULL) goto error;
		FREE(der); der=NULL;

		if(fgetpos(fp,&pos)) goto error;
		((CSDevStrage*)bg->dev_info)->fp = fp;
		((CSDevStrage*)bg->dev_info)->pos= pos;

		if((bg->der=get_der_from_fposition(fp, pos))==NULL) goto error;

		if(mode & CSMODE_CACHE){
			/* because PKCS#8 bag might be clean static passwd */
			OK_set_passwd(pass);
			if(cs->bag2data){
				if((bg->cache=cs->bag2data(bg))==NULL){
					CSBag_free(cs,bg);
					continue;
				}
			}
		}

		if(cs->bags==NULL){
			cs->bags=hd=bg;
		}else{
			hd->next=bg; bg->prev=hd; hd=bg;
		}
	}while(1);

	return 0;
error:
	if(der) FREE(der);
	return -1;
}

/*-----------------------------------------------
   Reload Certificate Store file
-----------------------------------------------*/
int cstore_reload_file(CStore *cs){
	struct stat sbuf;
	FILE *fp = ((CSDevStrage*)cs->dev_info)->fp;

	fstat(fileno(fp),&sbuf);

	if(sbuf.st_mtime != cs->csf_stat.st_mtime){
		CSBag_free_all(cs,cs->bags);
		cs->bags = NULL;

		if(cstore_load_file(cs)) goto error;
		memcpy(&cs->csf_stat,&sbuf,sizeof(struct stat));
	}
	return 0;
error:
	return -1;
}

CSBag *asn1_bag_info(CStore *cs, unsigned char *der){
	CSBag *ret;
	unsigned char *cp,*buf;
	int i;

	if((ret=CSBag_new())==NULL) goto error;
	if(cs->dev_info_new==NULL){
		OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_STOREDEV,ERR_PT_STFILE+4,NULL);
		goto error;
	}
	if((ret->dev_info=cs->dev_info_new(NULL))==NULL) goto error;

	cp = ASN1_next(der);

	/* context type */
	if((ret->ctx_type=ASN1_integer(cp,&i))<0) goto error;
	cp = ASN1_next(cp);

	/* unique_id */
	if((ret->unique_id=asn1_get_str(cp,&i))<0) goto error;
	cp = ASN1_next(cp);

	/* status */
	if((ret->status=ASN1_integer(cp,&i))<0) goto error;
	cp = ASN1_next(cp);

	/* use_flag */
	if((ret->use_flag=ASN1_integer(cp,&i))<0) goto error;
	cp = ASN1_next(cp);

	/* serialNumber */
	if((ret->serialNumber=ASN1_integer(cp,&i))<0) goto error;
	cp = ASN1_next(cp);

	/* issuer */
	if(*cp==0x83){
		*cp = ASN1_T61STRING;
		if((ret->issuer=asn1_get_str(cp,&i))<0) goto error;
		cp = ASN1_next(cp);
	}
	/* subject */
	if(*cp==0x84){
		*cp = ASN1_T61STRING;
		if((ret->subject=asn1_get_str(cp,&i))<0) goto error;
		cp = ASN1_next(cp);
	}
	/* key_hash */
	if(*cp==0x85){
		if(ASN1_octetstring_(cp,&i,&buf,&ret->hlen,1))
			goto error;
		memcpy(ret->key_hash,buf,ret->hlen);
		FREE(buf);
	}
	return ret;
error:
	CSBag_free(cs,ret);
	return NULL;
}


/*-----------------------------------------------
   Save Certificate Store file
-----------------------------------------------*/
int cstore_save_file(CStore *cs){
	char buf[256];
	FILE *fp;

	/* get file name */
	get_store_fname(buf,((CSDevStrage*)cs->dev_info)->path,
					cs->name,cs->ctx_type);

	/* close file once */
	if(((CSDevStrage*)cs->dev_info)->fp)
		fclose(((CSDevStrage*)cs->dev_info)->fp);

	/* rewrite file */
	if((fp=fopen(buf,"wb"))==NULL){
		OK_set_error(ERR_ST_FILEOPEN,ERR_LC_STOREDEV,ERR_PT_STFILE+5,NULL);
		goto error;
	}
	if(cs_save_bags(fp,cs)) goto error;
	fclose(fp);

	/* reload file */
	CSBag_free_all(cs,cs->bags); cs->bags=NULL;
	if((((CSDevStrage*)cs->dev_info)->fp=fopen(buf,"rb"))==NULL){
		OK_set_error(ERR_ST_FILEOPEN,ERR_LC_STOREDEV,ERR_PT_STFILE+5,NULL);
		goto error;
	}
	fstat(fileno(((CSDevStrage*)cs->dev_info)->fp),&cs->csf_stat);

	if(cstore_load_file(cs)) goto error;

	return 0;
error:
	return -1;
}

int cs_save_bags(FILE *fp,CStore *cs){
	CSBag *bg;
	unsigned char *buf;
	int i;

	for(bg=cs->bags; bg ; bg=bg->next){
		if((buf=cs_DER_bag(bg,&i))==NULL) goto error;
		if(fwrite(buf,1,i,fp)<(unsigned)i){
			OK_set_error(ERR_ST_FILEWRITE,ERR_LC_STOREDEV,ERR_PT_STFILE+6,NULL);
			goto error;
		}
		FREE(buf); buf=NULL;
		
		if(bg->der==NULL){
			OK_set_error(ERR_ST_NULLPOINTER,ERR_LC_STOREDEV,ERR_PT_STFILE+6,NULL);
			goto error;
		}
		if(ASN1_skip_(bg->der,&i)==NULL) goto error;
		if(fwrite(bg->der,1,i,fp)<(unsigned)i){
			OK_set_error(ERR_ST_FILEWRITE,ERR_LC_STOREDEV,ERR_PT_STFILE+6,NULL);
			goto error;
		}
	}
	if(fflush(fp)) goto error;

	return 0;
error:
	if(buf) FREE(buf);
	return -1;
}

unsigned char *cs_DER_bag(CSBag *bg, int *ret_len){
	unsigned char *ret,*cp;
	int i=32,j;

	/* estimate DER size */
	if(bg->unique_id) i+=strlen(bg->unique_id)+4;
	if(bg->issuer)    i+=strlen(bg->issuer)+4;
	if(bg->subject)   i+=strlen(bg->subject)+4;
	i+=bg->hlen + 4;

	if((ret=(unsigned char*)MALLOC(i))==NULL){
		OK_set_error(ERR_ST_FILEWRITE,ERR_LC_STOREDEV,ERR_PT_STFILE+7,NULL);
		return NULL;
	}

	/* get DER */
	ASN1_set_integer(bg->ctx_type,ret,&i); /* bag type :INT */
	cp = ret+i;
	ASN1_set_t61(bg->unique_id,cp,&j); /* bag unique id : STR */
	cp+=j; i+=j;
	ASN1_set_integer(bg->status,cp,&j); /* status : INT */
	cp+=j; i+=j;
	ASN1_set_integer(bg->use_flag,cp,&j); /* use flag : INT */
	cp+=j; i+=j;
	ASN1_set_integer(bg->serialNumber,cp,&j); /* S/N : INT */
	cp+=j; i+=j;
	if(bg->issuer){ /* [3] issuer DN   OPTIONAL */
		ASN1_set_t61(bg->issuer,cp,&j);
		*cp=0x83; cp+=j; i+=j;
	}
	if(bg->subject){ /* [4] subject DN   OPTIONAL */
		ASN1_set_t61(bg->subject,cp,&j);
		*cp=0x84; cp+=j; i+=j;
	}
	if(bg->key_hash){ /* [5] public key hash  OPTIONAL */
		ASN1_set_octetstring(bg->hlen,bg->key_hash,cp,&j);
		*cp=0x85; cp+=j; i+=j;
	}
	ASN1_set_sequence(i,ret,ret_len);
	return ret;
}

