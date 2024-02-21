/* ok_x509ext.h */
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

#ifndef __OK_X509EXT_H__
#define __OK_X509EXT_H__

#include <time.h>
#include "key_type.h"

#ifdef  __cplusplus
extern "C" {
#endif


/*
 *  Policy Qualifier Info
 */
typedef struct ext_policy_qualifier_usernotice{
	char *organization;
	int noticeNumbers[4];

	char *explicitText;
}ExtPolUN;

typedef struct ext_policy_qualifier_info ExtPolInfo;
struct ext_policy_qualifier_info{
    ExtPolInfo *next;

	int qid;
    char *qualifierID;	/* OBJECT-Identifier string ex. "1.2.34." */

    int qual_len;
    unsigned char *qualifier;	/* this might be *ExtPolUN */
};

typedef struct ext_cert_policy_extension ExtCertPol;
struct ext_cert_policy_extension{
    char *policyID;	/* OBJECT-Identifier string ex. "1.2.34." */

    ExtPolInfo	*info;
	ExtCertPol	*next;
};

/*
 *  General Names
 */
typedef struct edi_partyname{
	int  na_sintax;		/* i.e. ASN1_IA5STRING, ASN1_PRINTABLE... */
	char *nameAssigner;
	int  pn_sintax;
	char *partyName;
}EDIName;

typedef struct other_name{
	int oid;
	char *oidc;

	int nlen;
	unsigned char *name;
}OtherName;

typedef struct ext_general_names ExtGenNames;
struct ext_general_names{
    ExtGenNames *next;

    int	type;

    /*
     * "char *name" depends on the type, such as
     * IA5String(char*), Name(CertDN*), OBJ-ID, OCT-String(unsigned char*) and
     * EDIPartyName(EDIName*). otherwise, ORAddress, and otherName are not supported..
     */
    int  name_len;
    char *name;		/* depend on the type -- might be something struct */
};


/*
 * Default Extensions
 */
#define COMMON_USE_IN_CERTEXT \
	int	extnID; \
	int	critical; /* boolean default false */ \
	unsigned char *objid; /* if extnID==0, this has byte string value */ \
	int	dlen; \
	unsigned char	*der; \
	CertExt	*next;

/* AuthorityKeyIdentifier */
typedef struct certext_authkey_id{
	COMMON_USE_IN_CERTEXT

	int klen;
	unsigned char *keyid;

	ExtGenNames *authorityCertIssuer;

	int slen;
	int serialNum;
	unsigned char *long_sn;
}CE_AuthKID;

/* SubjectKeyIdentifier */
typedef struct certext_sbj_id{
	COMMON_USE_IN_CERTEXT

	int klen;
	unsigned char *keyid;
}CE_SbjKID;

/* KeyUsage */
typedef struct certext_keyusage{
	COMMON_USE_IN_CERTEXT

	int flag;
}CE_KUsage;

/* caution !! these definition will not be used.
 * AiCrypto just support 1 byte flag
 * (from digitalSignature to cRLSign);
 */
#define EXT_KU_digitalSignature		0x8000
#define EXT_KU_nonRepudiation		0x4000
#define EXT_KU_keyEncipherment		0x2000
#define EXT_KU_dataEncipherment		0x1000
#define EXT_KU_keyAgreement			0x0800
#define EXT_KU_keyCertSign			0x0400
#define EXT_KU_cRLSign				0x0200
#define EXT_KU_encipherOnly			0x0100
#define EXT_KU_decipherOnly			0x0080

/* extKeyUsage */
typedef struct certext_extkeyusage{
	COMMON_USE_IN_CERTEXT

	unsigned char *keyPurposeId[16];
}CE_ExtKUsage;

/* privateKeyUsagePeriod */
typedef struct certext_prvkusage_period{
	COMMON_USE_IN_CERTEXT

	struct tm notBefore;
	struct tm notAfter;
}CE_PKUsagePrd;

/* CertificatePolicies */
typedef struct certext_certpolicy{
	COMMON_USE_IN_CERTEXT

	ExtCertPol *ecp;
}CE_CertPol,CE_JCertPol;

/* policyMappings */
typedef struct certext_policymapping{
	COMMON_USE_IN_CERTEXT

	int pnum;
	char *issuerDomainPolicy[16]; /* OID text type, ex. "1.2.33.444" */
	char *subjectDomainPolicy[16]; /* OID text type, ex. "1.2.33.444" */
}CE_PolMap;

/* subjectAltName, issuerAltName */
typedef struct certext_subjectaltname{
	COMMON_USE_IN_CERTEXT

	ExtGenNames *egn;
}CE_SbjAltName, CE_IssAltName;

/* basicConstraints */
typedef struct certext_basiccons{
	COMMON_USE_IN_CERTEXT

	int	ca;
	int pathLen;
}CE_BasicCons;

/* nameConstraints */
typedef struct ext_subtrees ExtSubTrees;
struct ext_subtrees{
	ExtGenNames *base;
	int minimum;
	int maximum;

	ExtSubTrees *next;
};

typedef struct certext_namecons{
	COMMON_USE_IN_CERTEXT

	ExtSubTrees *permittedSubtrees;
	ExtSubTrees *excludedSubtrees;

}CE_NameCons;

/* policyConstraints */
typedef struct certext_policycons{
	COMMON_USE_IN_CERTEXT

	int requireExplicitPolicy;
	int inhibitPolicyMapping;
}CE_PolCons;

/* cRLDistributionPoints */
typedef struct ext_distpoint_name{
	int FullorRDN;
	ExtGenNames *fullName;
	char *nameRelativeToCRLIssuer;
}DistPointName;

typedef struct certext_cridistpoint{
	COMMON_USE_IN_CERTEXT

	int pnum;
	struct distpoint{
		DistPointName distp;
		unsigned char flag[2];
		ExtGenNames *cRLIssuer;

	}	distp[8];

}CE_CRLDistPt;


/* pkix AuthInfoAccess */
typedef struct certext_authinfoaccess{
	COMMON_USE_IN_CERTEXT

	int pnum;
	struct AccessDescription{
		int oid;
		unsigned char *oidc;
		ExtGenNames *accessLocation;
	}	adesc[4];
}CE_AIA;

/* PKCS#9 extension request (for PKCS#10 attribute) */
typedef struct certext_extreq{
	COMMON_USE_IN_CERTEXT

	CertExt *ext;
}CE_ExtReq;


/* comment extension (Netscape, MOJ, ChallengePasswd...) */
/* Netscape CRL URL */
typedef struct certext_comment{
	COMMON_USE_IN_CERTEXT

	unsigned char *comment;
}CE_Com;

/* Netscape type */
typedef struct certext_nstype{
	COMMON_USE_IN_CERTEXT

	int type;
}CE_NSType;

/* reasonCode */
typedef struct certext_reasoncode{
	COMMON_USE_IN_CERTEXT

	int code;
}CE_Reason;

/* cRLNumber */
typedef struct certext_crlnumber{
	COMMON_USE_IN_CERTEXT

	int num;
}CE_CRLNum;

/* issuingDistributionPoint */
typedef struct certext_issdistpt{
	COMMON_USE_IN_CERTEXT

	DistPointName distp;
	int onlyContainsUserCerts;
    int onlyContainsCACerts;
	unsigned char rflag[2];
    int indirectCRL;

}CE_IssDistPt;

#define EXT_IDP_UCert		0x80
#define EXT_IDP_CACert		0x40
#define EXT_IDP_indCRL		0x08

/* MOJ corporate information */
typedef struct certext_moj_corpinfo{
	COMMON_USE_IN_CERTEXT

	char *corpInfo[8];
}CE_MOJCoInfo;

/* MOJ suspention secret code */
typedef struct certext_moj_suspendCode{
	COMMON_USE_IN_CERTEXT

	int hash_algo;
	int hlen;
	unsigned char hash[32];
}CE_MOJSuspCode;

/* MOJ GenmInfoReqContent */
typedef struct negotiation_key{
	int symm_algo;
	int pub_algo;
	int hash_algo;
}NegoKey;

typedef struct certext_moj_genmreq{
	COMMON_USE_IN_CERTEXT

	int nego_num;
	NegoKey	nego[4];
}CE_MOJGenmReq;

/* MOJ GenpInfoResContent */
typedef struct certext_moj_genpres{
	COMMON_USE_IN_CERTEXT

	int pki_status;
	int nego_num;
	NegoKey	nego[4];
}CE_MOJGenpRes;

/* MOJ GenmSuspReqContent */
typedef struct certext_moj_genmspreq{
	COMMON_USE_IN_CERTEXT

	/* cert template (CMP) */
	unsigned char *snum_der; /* serial number : DER integer */
	CertDN issuer_dn;

	/* Reasons */
	unsigned char revReason[4];
	int suspReason;

	/* EncryptedValue */
	int keyAlg;

	int enc_len;
	unsigned char *encValue;
}CE_MOJGenSpReq;

/* MOJ GenpSuspResContent */
typedef struct certext_moj_genpspres{
	COMMON_USE_IN_CERTEXT

	/* pki status */
	int status;

	/* certID */
	unsigned char *snum_der;		/* serialNumber : DER Integer */
	CertDN issuer_dn;

}CE_MOJGenSpRes;

/* cert_ext.c */
CertExt *CertExt_new(int obj_id);
void CertExt_free(CertExt *ext);
void CertExt_free_all(CertExt *top);
CertExt *CertExt_dup(CertExt *src);
CertExt *CertExt_dup_all(CertExt *top);
CertExt *CertExt_find(CertExt* head,int id);

/* ext_cert.c */
CertExt *Extnew_authkey_id(Cert *auth,int option);
CertExt *Extnew_sbjkey_id(Cert *ct);
CertExt *Extnew_basic_cons(int ca,int path);
CertExt *Extnew_name_cons(ExtSubTrees *permit,ExtSubTrees *exclude);
CertExt *Extnew_policy_cons(int req, int inhibit);
CertExt *Extnew_keyusage(unsigned char flag);
CertExt *Extnew_extkeyusage(char **obj_ids);
CertExt *Extnew_altname(int id, ExtGenNames *top);
CertExt *Extnew_crl_distpoint(ExtGenNames *distp,unsigned char *flg,ExtGenNames *issuer);
CertExt *Extnew_cert_policy(int type,ExtCertPol *ecp);
CertExt *Extnew_policy_map(char *issdp,char *sbjdp);
CertExt *Extnew_comment(int type,char *comment);

CertExt *Extnew_pkix_aia(char *oid,ExtGenNames *aloc);
CertExt *Extnew_ocsp_nocheck();

CertExt *Extnew_extreq(CertExt *ext);

CertExt *Extnew_ns_flag(unsigned char flag);
CertExt *Extnew_moj_corpinfo(char *corpName, char *regNum, char *corpAddress,
		char *directorName, char *directorTitle, char *resv, char *regOffice, int sjis);
AttrTAV *Extnew_moj_timelimit(int limit);
AttrTAV *Extnew_moj_suspcode(int hash_algo, unsigned char *data, int len);
AttrTAV *Extnew_moj_genmreq(int symm, int pubkey, int hash);
AttrTAV *Extnew_moj_genpres(int pkistat, int symm, int pubkey, int hash);
AttrTAV *Extnew_moj_genspreq(unsigned char *snum_der, CertDN *dn, unsigned char revReason, int suspReason,
							 Key *pub, unsigned char *data, int dlen);
AttrTAV *Extnew_moj_genspres(int pkistat, CertDN *dn, unsigned char *snum_der);

#define Extnew_ns_crlurl(comm)		Extnew_comment(OBJ_NS_CERT_CRLURL,(comm))
#define Extnew_ns_comment(comm) 	Extnew_comment(OBJ_NS_CERT_COMMENT,(comm))
#define Extnew_moj_registrar(comm)	Extnew_comment(OBJ_MOJ_Registrar,(comm))
#define Extnew_unst_name(comm)		Extnew_comment(OBJ_P9_UNST_NAME,(comm))
#define Extnew_cha_passwd(comm)		Extnew_comment(OBJ_P9_CHALL_PWD,(comm))

/* ext_crtstr.c */
int Ext_authkey_str(CE_AuthKID *ce, char *buf, int max);
int Ext_sbjkey_str(CE_SbjKID *ce, char *buf, int max);
int Ext_keyusage_str(CE_KUsage *ce, char *buf, int max);
int Ext_extkeyusage_str(CE_ExtKUsage *ce, char *buf, int max);
int Ext_prvkey_period_str(CE_PKUsagePrd *ce, char *buf, int max);
int get_polunotice_str(ExtPolUN *epu, char *buf);
int get_polqualinfo_str(ExtPolInfo *epi, char *buf, int max);
int Ext_certpol_str(CE_CertPol *ce, char *buf, int max);
int Ext_certpolmap_str(CE_PolMap *ce, char *buf, int max);
int Ext_altname_str(CE_SbjAltName *ce, char *buf, int max);
int Ext_basiccons_str(CE_BasicCons *ce,char *buf, int max);
int get_gensubtrees_str(ExtSubTrees *est, char *buf, int max);
int Ext_namecons_str(CE_NameCons *ce,char *buf,int max);
int Ext_polcons_str(CE_PolCons *ce, char *buf, int max);
int Ext_crlpoint_str(CE_CRLDistPt *ce, char *buf, int max);

int Ext_pkixaia_str(CE_AIA *aia, char *buf, int max);
int Ext_ocspnochk_str(CertExt *onk, char *buf, int max);

int Ext_comment_str(CE_Com *ce, char *buf, int max);
int Ext_nscerttype_str(CE_NSType *ce, char *buf, int max);

int Ext_mojcorpinfo_str(CE_MOJCoInfo *ce, char *buf, int max);

/* ext_crl.c */
CertExt *Extnew_reason_code(int code);
CertExt *Extnew_crl_number(int num);
CertExt *Extnew_crl_issdistpt(ExtGenNames *distp,unsigned char *rflg,int bflg);


/* ext_crlstr.c */
int Ext_reasoncode_str(CE_Reason *ce,char *buf,int max);
int Ext_holdinstcode_str(CertExt *ce, char *buf,int max);
int Ext_invdate_str(CertExt *ce, char *buf,int max);

int Ext_crlnum_str(CE_CRLNum *ce,char *buf,int max);
int Ext_issdistpt_str(CE_IssDistPt *ce, char *buf,int max);

int get_genname_str(ExtGenNames *egn, char *buf,int bufmax);
int get_gennames_str(ExtGenNames *egn, char *buf,int bufmax);

int get_reason_str(unsigned char *cp, char *buf, int max);
int get_distpoint_str(DistPointName *dpn, char *buf, int max);

/* ext_gn.c */
ExtGenNames *ExtGN_new();
void ExtGN_free(ExtGenNames *top);
ExtGenNames *ExtGN_dup(ExtGenNames *src);
ExtGenNames *ExtGN_dup_all(ExtGenNames *top);
ExtGenNames *ExtGN_set_str(char *str,int type);
ExtGenNames *ExtGN_set_dn(CertDN *dn);
ExtGenNames *ExtGN_set_bin(unsigned char *buf, int len, int type);
ExtGenNames *ExtGN_set_oth(OtherName *son, int len);

int ExtGN_DER_gname(ExtGenNames *now,unsigned char *ret,int *ret_len);
int ExtGN_DER_othname(OtherName *on,unsigned char *ret,int *ret_len);
unsigned char *ExtGN_toDER(ExtGenNames *top,unsigned char *buf,int *ret_len);
int ExtGN_estimate_der_size(ExtGenNames *top);

#define ExtGN_set_url(str)		ExtGN_set_str((str),6)
#define ExtGN_set_email(str)	ExtGN_set_str((str),1)
#define ExtGN_set_dns(str)		ExtGN_set_str((str),2)
#define ExtGN_set_ip(ip,len)	ExtGN_set_bin((ip),(len),7)

OtherName *ExtGN_on_new();
void ExtGN_on_free(OtherName *on);
OtherName *ExtGN_on_dup(OtherName *src);

ExtSubTrees *ExtSubT_new();
void ExtSubT_free(ExtSubTrees *ext);
void ExtSubT_free_all(ExtSubTrees *top);
ExtSubTrees *ExtSubT_dup(ExtSubTrees *src);
ExtSubTrees *ExtSubT_dup_all(ExtSubTrees *top);

unsigned char *ExtSubT_toDER(ExtSubTrees *top,unsigned char *buf,int *ret_len);
int ExtSubT_estimate_der_size(ExtSubTrees *top);

ExtSubTrees *ExtSubT_get_tree(ExtGenNames *base, int min, int max);


/* ext_pol.c */
ExtCertPol *ExtCP_new();
ExtPolUN *ExtPUN_new();
ExtPolInfo *ExtPI_new();
void ExtCP_free(ExtCertPol *ecp);
void ExtCP_free_all(ExtCertPol *top);
void ExtPUN_free(ExtPolUN *epu);
void ExtPI_free(ExtPolInfo *epi);
void ExtPI_free_all(ExtPolInfo *top);
ExtCertPol *ExtCP_dup(ExtCertPol *ecp);
ExtCertPol *ExtCP_dup_all(ExtCertPol *top);
ExtPolUN *ExtPUN_dup(ExtPolUN *src);
ExtPolInfo *ExtPI_dup(ExtPolInfo *src);
ExtPolInfo *ExtPI_dup_all(ExtPolInfo *top);

ExtPolInfo *ExtPI_get_unotice(char *id, char *org, int num, char *expText);
ExtPolInfo *ExtPI_get_cps(char *id, char *qual);

int ExtPUN_DER_un(ExtPolUN *epu,unsigned char *ret,int *ret_len);
unsigned char *ExtCP_toDER(ExtCertPol *pol,unsigned char *buf,int *ret_len);
unsigned char *ExtPI_toDER(ExtPolInfo *epi,unsigned char *buf,int *ret_len);
int ExtCP_estimate_der_size(ExtCertPol *ecp);

/* ext_moj.c (for attrTypeAndValue) */
int x509_DER_attrs(AttrTAV *top,unsigned char *ret,int *ret_len);

#ifdef  __cplusplus
}
#endif

#endif  /* __OK_X509EXT_H__ */
