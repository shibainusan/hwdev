/* ok_x509.h */
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

#ifndef __OK_X509_H__
#define __OK_X509_H__

#include <stdio.h>
#include <time.h>
#include "key_type.h"

#ifdef  __cplusplus
extern "C" {
#endif

/* public or private key struct 
 *    base structure 
 */
typedef struct crypt_key{
	int key_type; /* key identifier */
	int size;

	/* type field */
}Key;

/*
 * the X.509 digital certificate structures
 */
typedef struct validity{
	struct tm notBefore;
	struct tm notAfter;
}Validity;

typedef struct certificate_extension CertExt;
typedef struct certificate_extension AttrTAV; /* AttributeTypeAndValue */
struct certificate_extension{
	int extnID;
	int critical;	/* boolean default false */
	unsigned char *objid;	/* if extnID==0, this has byte string value */

	int dlen;
	unsigned char *der;

	CertExt *next;
};

#define RDN_MAX		16

typedef struct certificate_dir{
	int num;
	struct cert_rdn{
		int	 derform;
		int  tagoid;
		char *tag;
	} rdn[RDN_MAX];
}CertDN,CertDIR;

typedef struct x509_certificate{
	int version;
	int serialNumber;
	unsigned char *long_sn;	/* long serial number (usually NULL) */

	int	signature_algo;
	char	*issuer;
	CertDN	issuer_dn;

	Validity	time;

	char	*subject;
	CertDN	subject_dn;

	int	pubkey_algo;
	Key	*pubkey;

	long	issuerUniqueID;
	long	subjectUniqueID;

	CertExt	*ext;

	int	siglen;
	unsigned char	*signature;

	/* DER encode strings */
	unsigned char	*der;
}Cert,Req;

/*
 * the X.509 cross certificate pair
 */
typedef struct cross_cert_pair{
	Cert *issuedToThisCA;
	Cert *issuedByThisCA;

	/* DER encode strings */
	unsigned char	*der;
}CertPair;

/*
 * the X.509 certificate revocation list (CRL) structures
 */
typedef struct revoked_list Revoked;
struct revoked_list{
	int	serialNumber;
	unsigned char *long_sn;	/* long serial number (usually NULL) */

	struct tm revocationDate;

	/* CRL entry extension */
	CertExt	*entExt;

	Revoked	*next;
};

typedef struct x509_crl{
	long	version;

	int	signature_algo;
	char *issuer;
	CertDN issuer_dn;

	struct tm lastUpdate;
	struct tm nextUpdate;
 
	Revoked	*next;

	/* CRL extension (for version.2) */
	CertExt	*ext;

	int	siglen;
	unsigned char *signature;

	/* DER encode strings */
	unsigned char *der;
}CRL;

/*
 * certificate list
 */
typedef struct certificate_list CertList;
struct certificate_list{
	CertList *next;
	CertList *prev;

	int state;
	int	serialNumber;
	char  *subject;
	char  *issuer;

	Cert  *cert;
};

typedef struct certRevocationList_list CRLList;
struct certRevocationList_list{
	CRLList *next;
	CRLList *prev;

	int state;
	char  *issuer;

	CRL  *crl;
};

extern char *dir_t[];


/* define verify error */
#define X509_VFY_ERR			0x0100
#define X509_VFY_ERR_SIGNATURE		0x0200
#define X509_VFY_ERR_SIGNATURE_CRL	0x0300
#define X509_VFY_ERR_NOTBEFORE		0x0400
#define X509_VFY_ERR_NOTAFTER		0x0500
#define X509_VFY_ERR_LASTUPDATE		0x0600
#define X509_VFY_ERR_NEXTUPDATE 	0x0700
#define X509_VFY_ERR_REVOKED		0x0a00
#define X509_VFY_ERR_SELF_SIGN		0x0b00
#define X509_VFY_ERR_CA_CHAIN		0x0c00
#define X509_VFY_ERR_SYSTEMERR		0x0d00

#define X509_VFY_ERR_NOT_CACERT		0x1000
#define X509_VFY_ERR_ISSUER_CRL		0x1100
#define X509_VFY_ERR_NOT_IN_CERTLIST	0x1200
#define X509_VFY_ERR_UNKOWN_SIG_ALGO	0x1300

/* define verify check type */
#define DONT_VERIFY_CRL			0x0001	/* not verify CRL's signature and expiry date */
#define ALLOW_SELF_SIGN			0x0002	/* allow self sign certificate */
#define DONT_CHECK_REVOKED		0x0004	/* don't check revoked certificate with CRL */
#define IF_NO_CRL_DONT_CHECK_REVOKED	0x0008	/* there is not CRL, then don't check revoked */
#define ONLY_FIRST_DEPTH_CHECK_REVOKED	0x0010	/* revoked check is done at only first depth */
#define DONT_VERIFY			0x0080	/* don't verify anything, just return 0 */

/* certificate stete */
#define	AIST_OK			0x0000
#define	AIST_EXPIRED	0x0001
#define	AIST_REVOKED	0x0002
#define AIST_CA			0x0010
#define AIST_ROOT		0x0020
#define AIST_OTHER		0x0040
#define AIST_MY			0x0080	/* should have private key */
#define AIST_XCERTFWD	0x0100	/* cross cert - foward */
#define AIST_XCERTREV	0x0200	/* cross cert - reverse */
#define AIST_LINK		0x0400	/* root ca, but link certificate */
#define AIST_TRUST		0x1000	/* trust anchor flag (usually rootCA) */
#define AIST_UNTRUST	0x2000	/* untrust flag */
#define AIST_ONPATH		0x4000	/* path is OK (found trust anchor) */


/* cert.c */
Cert *Cert_new(void);
void Cert_free(Cert *ct);
Cert *Cert_dup(Cert *src);
void cert_dn_init(CertDN *dn);
void cert_dn_free(CertDN *dn);


/* cert_vfy.c */
int Cert_verify(CertList *crtl,CRLList *crll,Cert *cert,int max_depth,int type);
int Cert_signature_verify(Cert *ca,Cert *user);
int Cert_validity_verify(Cert *ct);
int Cert_revoked_check(Cert *ct,CRL *crl);
char *Cert_get_vfyerrstr(int err);

int hash_size(int hash_algo);
int obj_sig2hash(int sig_oid);

/* cert_print.c */
void Cert_print(Cert *ct);

/* cert_tool.c */
int Cert_dncopy(CertDN *from,CertDN *to);
int Cert_dncmp(CertDN *d1,CertDN *d2);
char *Cert_find_dn(CertDN *dn, int tkind, int *cr_num);
char *Cert_subject_str(CertDN *dn);

int igcase_strcmp(char *c1, char *c2);

int Cert_cmp(Cert *c1,Cert *c2);
int Cert_set_sigalgo(Cert *ct,Key *prv);
int x509_set_signature(unsigned char *data,Key *prv,unsigned char **signature,int *sig_len);

int Cert_is_CA(Cert *ct);
int Cert_is_root(Cert *ct);
int Cert_is_path(Cert *upper, Cert *lower);
int CRL_is_path(Cert *ca, CRL *crl);


/* cert_asn1.c */
unsigned char *Cert_toDER(Cert *ct,Key *prv,unsigned char *buf,int *ret_len);
int Cert_DER_data(Cert *ct,unsigned char *ret,int *ret_len);
int Cert_DER_time(struct tm *time,unsigned char *ret,int *ret_len);
int Cert_DER_subject(CertDN *dn,unsigned char *ret,int *ret_len);
int Cert_DER_certext(Cert *ct,unsigned char *ret,int *ret_len);
int x509_DER_pubkey(Key *key,unsigned char *ret,int *ret_len);
int x509_DER_algoid(int id,Key *key,unsigned char *ret,int *ret_len);
int x509_DER_exts(CertExt *top,unsigned char *ret,int *ret_len);
int Cert_estimate_der_size(Cert *ct);


/* crtp.c */
CertPair *CertPair_new(void);
void CertPair_free(CertPair *ctp);
CertPair *CertPair_dup(CertPair *org);

/* crtp_asn1.c */
unsigned char *CertPair_toDER(CertPair *ctp,unsigned char *buf,int *ret_len);

/* crtp_print.c */
void CertPair_print(CertPair *ctp);

/* crl.c */
CRL *CRL_new(void);
void CRL_free(CRL *crl);
Revoked *Revoked_new(void);
void Revoked_free(Revoked *rv);
void Revoked_free_all(Revoked *top);
CRL *CRL_dup(CRL *src);
Revoked *Revoked_dup(Revoked *src);

/* crl_vfy.c */
int CRL_verify(CertList *crtl,CRLList *crll,CRL *crl,int max_depth,int type);
int CRL_signature_verify(Cert *ca,CRL *crl);
int CRL_time_verify(CRL *crl);
int CRL_cmp(CRL *c1, CRL *c2);

/* crl_print.c */
void CRL_print(CRL *crl);

/* crl_asn1.c */
unsigned char *CRL_toDER(CRL *crl,Key *prv,unsigned char *buf,int *ret_len);
int CRL_DER_data(CRL *crl,unsigned char *ret,int *ret_len);
int CRL_DER_revoked(CRL *crl,unsigned char *ret,int *ret_len);
int CRL_set_sigalgo(CRL *crl,Key *prv);
int CRL_estimate_der_size(CRL *crl);


/* key.c */
Key *Key_new(int type);
void Key_free(Key *key);
int Key_set(Key *key,unsigned char *passwd, int len);
int Key_set_iv(Key *key,unsigned char *iv);
int Key_print(Key *key);
/* void key_print_dsaparam(DSAParam *pm); */
/* void key_print_ecparam(ECParam *pm); */

/* key_tool.c */
Key *Key_dup(Key *src);
int Key_cmp(Key *k1, Key *k2);
int Key_pair_cmp(Key *prv, Key *pub);


/* req_vfy.c */
int Req_cmp(Req *r1, Req *r2);
/* int Req_signature_verify(Req *req); */
#define Req_signature_verify(req)	Cert_signature_verify((req),(req))

/* req_asn1.c */
unsigned char *Req_toDER(Req *req,Key *prv,unsigned char *buf,int *ret_len);
int Req_DER_data(Req *req,unsigned char *ret,int *ret_len);
int Req_DER_attrs(CertExt *top,unsigned char *ret,int *ret_len);

#define Req_new()		(Req*)Cert_new()
#define Req_free(req)	Cert_free((Cert*)req)
#define Req_dup(req)	(Req*)Cert_dup((Cert*)req)
#define Req_print(req)	Cert_print((Cert*)req)
#define Req_estimate_der_size(req)	Cert_estimate_der_size((Cert*)req)


/* x509_file.c */
void *read_x509_file(char *fname,int type);
void *_read_x509_file(char *fname,void* (*der_cb)(unsigned char*),
					void* (*pem_cb)(char*));
int get_fformat(char *fname,unsigned char **rbuf);

#define Cert_read_file(fname)	(Cert*)read_x509_file((fname),1)
#define CRL_read_file(fname)	(CRL*)read_x509_file((fname),2)
#define Req_read_file(fname)	(Req*)read_x509_file((fname),3)
#define CertPair_read_file(fname)	(CertPair*)read_x509_file((fname),4)

/* x509_time.c */
time_t UTC2time_t(unsigned char *utc);
int UTC2stm(unsigned char *utc, struct tm *ctm);
unsigned char *stm2UTC(struct tm *stm,unsigned char *buf,unsigned char tag);
char *UTC2str(unsigned char *utc,int type);
char *stm2str(struct tm *stm,int type);
int stmcmp(struct tm *a, struct tm *b);
#ifndef HAVE_TIMEGM
time_t timegm(struct tm *stm);
#endif

/* clist.c */
CertList *Certlist_new(void);
void Certlist_free(CertList *cl);
void Certlist_free_all(CertList *top);
CertList *Certlist_dup(CertList *org);
CertList *Certlist_dup_all(CertList *top);

CRLList *CRLlist_new(void);
void CRLlist_free(CRLList *cl);
void CRLlist_free_all(CRLList *top);
CRLList *CRLlist_dup(CRLList *org);
CRLList *CRLlist_dup_all(CRLList *top);

/* clist_file.c */
/* CertList *Certlist_read_list(char *path,char *fname); */

/* clist_tool.c */
CertList *Cert_2Certlist(Cert *ct);
#define Certlist_get_cert(cl)	(cl)->cert
#define Certlist_next(cl)		(cl)->next
#define Certlist_prev(cl)		(cl)->prev

CertList *Certlist_find_bySbj(CertList *top, char *subject);
CertList *Certlist_find_byIss(CertList *top, char *issuer);
CertList *Certlist_find_bySNum(CertList *top, int serial);

int Certlist_insert(CertList *where, CertList *data);
CertList *Certlist_join(CertList *top, CertList *join);
int Certlist_delete(CertList *list);
int Certlist_count(CertList *top);

CRLList *CRLlist_find_byIss(CRLList *top, char *issuer);
#define CRLlist_get_crl(cl)	(cl)->crl
#define CRLlist_next(cl)	(cl)->next
#define CRLlist_prev(cl)	(cl)->prev

CRLList *CRL_2CRLlist(CRL *crl);

int CRLlist_insert(CRLList *where, CRLList *data);
CRLList *CRLlist_join(CRLList *top, CRLList *join);
int CRLlist_delete(CRLList *list);
int CRLlist_count(CRLList *top);


/***** gloval values *****/
/* !! sig-algo hash must be same as digest-algo
 * !! crl_digest and cert_digest is same algorithm...
 */
/* just use OBJ_SIG_*, because of object identifier */
extern int default_cert_sig_algo;
extern int default_crl_sig_algo;

/* just use OBJ_HASH_*, because of object identifier */
/* this one depends on default_cert_sig_algo or default_crl_sig_algo */
extern int sign_digest_algo;

/* crypto extention flag, it's really "extention" use */
extern unsigned char ai_ext_flag[16];

#ifdef  __cplusplus
}
#endif

#endif  /* __OK_X509_H__ */
