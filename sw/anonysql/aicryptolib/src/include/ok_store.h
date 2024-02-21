/* ok_store.h */
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

#ifndef __OK_STORE_H__
#define __OK_STORE_H__

#include "aiconfig.h"

#include <sys/stat.h>
#include "ok_x509.h"

#ifdef  __cplusplus
extern "C" {
#endif

/*
 * Store Bags
 */
/* strage device info */
typedef struct st_dev_strage_info{
	int		mode;
	char	*path;
	FILE	*fp;
	fpos_t	pos;  
}CSDevStrage;

typedef struct store_bag CSBag;
struct store_bag{
	int ctx_type; /* bag context : cert, crl, key... */
	char *unique_id;   /* bag name (must be unique in a store) */

	CSBag *next;
	CSBag *prev;

	int status;
	int use_flag;

	int serialNumber;
	char *issuer;
	char *subject;

	int hlen;
	unsigned char key_hash[32];

	unsigned char *der;	/* cache of raw der */
	void *cache;	/* on memory cache : Cert*, CRL*, Key*... */
	void *dev_info;	/* device specific access information */
};

/*
 * Certifiacate Store 
 */
typedef struct cert_store CStore;
struct cert_store{
	int dev_type; /* store device : strage, IC card... */ 
	int ctx_type; /* store context : cert, crl, key... */
	char *name;   /* store name */

	CStore *next;
	CStore *prev;

	/* store context information */
	int mode;
	int option; /* reserve */

	struct stat csf_stat;

	CSBag *bags;

	/* methods */
	void* (*bag2data)(CSBag*);
	CSBag* (*data2bag)(CStore*,void*,char*,int);
	void* (*dev_info_new)(void*);
	void (*dev_info_free)(void*);

	/* device specific information */
	void *dev_info;
};


/* 
 * Store Manager
 */
typedef struct store_manager{
	int version;
	char *path;

	CStore *store;

	unsigned char *der;
}STManager;

#define CSTORE_CTX_CERT		10
#define CSTORE_CTX_CSR		11
#define CSTORE_CTX_KEY		12
#define CSTORE_CTX_CRL		13

#define CSTORE_CTX_DER		20		/* raw DER data */
#define CSTORE_CTX_ENCDER	21		/* encrypted DER data */

#define CSTORE_ON_STORAGE	100
#define CSTORE_ON_SMTCARD	101		/* reserve */
#define CSTORE_ON_HARDWARE	102		/* reserve */
#define CSTORE_ON_MEMORY	103		/* reserve */
#define CSTORE_ON_SYSTEM	104		/* reserve */
#define CSTORE_ON_WINDOWS	105		/* reserve */

#define CSMODE_NULL		0x0
#define CSMODE_CACHE	0x1


#define STORE_MY		"MY"	/* my user store */
#define STORE_ROOT		"ROOT"	/* root CA store */
#define STORE_MIDCA		"MIDCA"	/* intermediate CA store */
#define STORE_OTHER		"OTHER"	/* other's store */

#ifdef __WINDOWS__
#define PATH_DELI	"\\"
#else
#define PATH_DELI	"/"
#endif

/* manager.c */
STManager *STM_new();
void STM_free(STManager *stm);

STManager *STM_open(char *path);
void STM_close(STManager *stm);
int STM_update(STManager *stm);
int STM_reload(STManager *stm);
int stm_file_update(STManager *stm);

STManager *STM_system_new(char *path);


/* man_add.c */
int STM_regist_store(STManager *stm, CStore *reg);

int STM_cert_type(STManager *stm, Cert *cert);
int STM_crl_type(STManager *stm, CRL *crl);
int STM_import_cert(STManager *stm, Cert *cert, char *unique_id);
int STM_import_certkey(STManager *stm, Cert *cert, Key *key, char *unique_id);
int STM_import_reqkey(STManager *stm, Req *req, Key *key, char *unique_id);
int STM_import_crl(STManager *stm, CRL *crl, char *unique_id);

CSBag* STM_import_cert_byName(STManager *stm, Cert *cert, int dev, char *name, char *unique_id);
CSBag* STM_import_key_byName(STManager *stm, Key *key, int dev, char *name, char *unique_id);
CSBag* STM_import_crl_byName(STManager *stm, CRL *crl, int dev, char *name, char *unique_id);
CSBag* STM_import_req_byName(STManager *stm, Req *req, int dev, char *name, char *unique_id);

/* man_del.c */
void STM_delete_store(STManager *stm, CStore *del);

int STM_del_byID(STManager *stm, char *name, int dev, int ctx, char *unique_id);


/* man_asn1.c */
STManager *ASN1_read_stm(unsigned char *der, char *path);
int asn1_stm_names(unsigned char *in,STManager *stm);
unsigned char *STM_toDER(STManager *stm, unsigned char *buf, int *ret_len);
int STM_DER_names(STManager *stm, unsigned char *ret, int *ret_len);
int STM_estimate_der_size(STManager *stm);

/* man_search.c */
CStore *STM_find_store(STManager *stm, CStore *dst);
CStore *STM_find_byName(STManager *stm, char *name, int dev, int ctx);
CSBag *STM_find_byID(STManager *stm, char *name, int dev, int ctx, char *unique_id);
CSBag *STM_find_byCert(STManager *stm, Cert *ct);
CSBag *STM_find_byCRL(STManager *stm, CRL *crl);

/* man_tool.c */
int STM_verify_cert(STManager *stm, Cert *ct, int mode);
CertList *STM_get_pathcert(STManager *stm,Cert *ct);
CertList *STM_get_pathcert_crl(STManager *stm,CRL *crl);
CRLList *STM_get_pathcrl(STManager *stm,CertList *cl);

/* store.c */
CStore *CStore_new();
void CStore_free(CStore *cs);
void CStore_free_all(CStore *top);

CStore *CStore_open(int dev_type, char *name, int ctx_type, char *path);
void CStore_close(CStore *cs);
int CStore_update(CStore *cs);
int CStore_reload(CStore *cs);

CSBag* CSBag_new();
void CSBag_free(CStore *cs,CSBag *bg);
void CSBag_free_all(CStore *cs,CSBag *top);


/* sto_file.c */
CStore *CStore_new_file(char *path, char *name, int ctx_type, int mode);
CStore *CStore_open_file(char *path, char *name, int ctx_type, int mode);
void CStore_close_file(CStore *cs);

int cstore_load_file(CStore *cs);
int cstore_reload_file(CStore *cs);
CSBag *asn1_bag_info(CStore *cs, unsigned char *der);

int cstore_save_file(CStore *cs);
int cs_save_bags(FILE *fp,CStore *cs);
unsigned char *cs_DER_bag(CSBag *bg, int *ret_len);


/* sto_filemeth.c */
CSDevStrage* CSDevStrage_new(char *path);
void CSDevStrage_free(CSDevStrage *dev);

Cert *CS_bag2cert_on_strage(CSBag *bag);
CRL *CS_bag2crl_on_strage(CSBag *bag);
Req *CS_bag2req_on_strage(CSBag *bag);
Key *CS_bag2key_on_strage(CSBag *bag);
unsigned char *CS_bag2der_on_strage(CSBag *bag);
unsigned char *CS_bag2encder_on_strage(CSBag *bag);
unsigned char *get_der_from_fposition(FILE *fp, fpos_t pos);


/* sto_add.c */
int CStore_add_bag(CStore *cs, void *ct, char *unique_id, int stat, int ctx);
CSBag *CS_cert2bag(CStore *cs, Cert *ct, char *unique_id, int stat);
CSBag *CS_crl2bag(CStore *cs, CRL *crl, char *unique_id, int stat);
CSBag *CS_req2bag(CStore *cs, Req *req, char *unique_id, int stat);
CSBag *CS_key2bag(CStore *cs, Key *key, char *unique_id, int stat);
CSBag *CS_der2bag(CStore *cs, unsigned char *der, char *unique_id, int stat);
CSBag *CS_encder2bag(CStore *cs, unsigned char *der, char *unique_id, int stat);
int cs_get_keyhash(Key *key,unsigned char *ret,int *ret_len);

#define CStore_add_cert(cs,ct,unique_id,st)	CStore_add_bag((cs),(ct),(unique_id),(st),CSTORE_CTX_CERT)
#define CStore_add_crl(cs,ct,unique_id,st)	CStore_add_bag((cs),(ct),(unique_id),(st),CSTORE_CTX_CRL)
#define CStore_add_req(cs,ct,unique_id,st)	CStore_add_bag((cs),(ct),(unique_id),(st),CSTORE_CTX_CSR)
#define CStore_add_key(cs,ct,unique_id,st)	CStore_add_bag((cs),(ct),(unique_id),(st),CSTORE_CTX_KEY)
#define CStore_add_der(cs,ct,unique_id,st)	CStore_add_bag((cs),(ct),(unique_id),(st),CSTORE_CTX_DER)
#define CStore_add_encder(cs,ct,unique_id,st)	CStore_add_bag((cs),(ct),(unique_id),(st),CSTORE_CTX_ENCDER)


/* sto_del.c */
void CStore_remove_all(CStore *cs);
int CStore_del_bag(CStore *cs, CSBag *del);
int CStore_del_byID(CStore *cs, char *unique_id);
int CStore_del_byKeyHash(CStore *cs, unsigned char hash[20]);


/* sto_search.c */
CSBag *CStore_find_byID(CSBag *top, char *unique_id);
CSBag *CStore_find_bySNum(CSBag *top, int serialNum);
CSBag *CStore_find_bySubject(CSBag *top, char *sbj);
CSBag *CStore_find_byIssuer(CSBag *top, char *iss);
CSBag *CStore_find_byKeyHash(CSBag *top, unsigned char hash[20]);
CSBag *CStore_find_bySbjDN(CStore *cs,CSBag *top,CertDN *dn);

CSBag *CStore_find_byCert(CSBag *top, Cert *ct);
CSBag *CStore_find_byCRL(CSBag *top, CRL *crl);
CSBag *CStore_find_byReq(CSBag *top, Req *crl);

#define CStore_get_firstBag(cs)	((cs))->bags
#define CSBag_next(bg)			((bg))->next

/* sto_tool.c*/
void *cstore_get_data(void *(*cb)(CSBag*), CSBag *bg, int ctx);
Cert *CStore_get_cert(CStore *cs, CSBag *bg);
CRL *CStore_get_crl(CStore *cs, CSBag *bg);
Req *CStore_get_req(CStore *cs, CSBag *bg);
Key *CStore_get_key(CStore *cs, CSBag *bg);

int Store_count_bag(CStore *cs);

int get_dn_for_unique_id(CertDN *dn, char *ret);
char *CStore_get_unique_id(CStore *cs, CertDN *dn);
char *CStore_get_unique_idk(CStore *cs, Key *key);

CertList* CStore_2certlist(CStore *cs);
CRLList* CStore_2crllist(CStore *cs);


#ifdef  __cplusplus
}
#endif

#endif  /* __OK_STORE_H__ */
