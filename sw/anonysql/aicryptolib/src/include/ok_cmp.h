/* ok_cmp.h */
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

#ifndef __OK_CMP_H__
#define __OK_CMP_H__

#include "aiconfig.h"
#include "ok_err.h"

#include "ok_x509.h"
#include "ok_x509ext.h"

#ifdef  __cplusplus
extern "C" {
#endif

/*
 * PKI Certifiate Management Protocols [RFC2510]
 * PKI structures.
 */
typedef struct pki_header PKIHeader;
typedef struct pki_body PKIBody;
typedef struct pki_protection PKIProtection;

/*
 * PKIMessage -- top structure
 */
typedef struct pki_message{
	PKIHeader		*header;
	PKIBody			*body;
	int				plen;
	unsigned char	*protection; /* PKIProtection (BITSTRING) OPTIONAL */
	CertList		*extraCerts; /* OPTIONAL */
}PKIMessage;

/*
 * PKIHeader -- Header Information.
 */
typedef struct info_type_and_value InfoTAV; /* same as CertExt */
struct info_type_and_value{
	COMMON_USE_IN_CERTEXT

	void *infoValue;
};

struct pki_header{
	int	pvno;

	/* actually, sender and recipient are GeneralName but not
	 * Name. Just ignore it :-)
	 */
	CertDN	sender;
	CertDN	recipient;

	struct tm messageTime; /* OPTIONAL */
	int		protectionAlg; /* OPTIONAL */

	unsigned char *senderKID; /* OPTIONAL */
	unsigned char *recipKID;  /* OPTIONAL */
	int		skid_len;
	int		rkid_len;

	unsigned char *transactionID; /* OPTIONAL */
	int		trid_len;

	unsigned char *senderNonce; /* OPTIONAL */
	unsigned char *recipNonce;  /* OPTIONAL */
	int		snon_len;
	int		rnon_len;

	char	*freeText[8];

	InfoTAV *generalInfo;
};

/* 
 * PKIStatusInfo
 */
typedef struct pki_stat_info PKIStatusInfo;
struct pki_stat_info{
	PKIStatusInfo *next;

	int		status;
	char	*freeText[8];	/* OPTIONAL */
	unsigned char	failInfo[2]; /* OPTIONAL */
};

/*
 * ProofOfPossession
 */
typedef struct pk_mac_value{
	int	algId;
	int vlen;
	unsigned char *value;
}PKMACValue;

typedef struct popo_signing_key{
	struct POPOSigningKeyInput{
		/* authInfo CHOICE { */
		CertDN		sender;
		PKMACValue	*publicKeyMac;		
		/* } */

		Key *publicKey;
		int option;
	}	poposkInput;	/* OPTIONAL */

	int	algo_id;

	int	sig_len;
	unsigned char *signature;
}POPOSigningKey;

typedef struct popo_priv_key{ /* CHOICE */
	int choice;

	int tm_len;
	unsigned char *thisMessage; /* [0] BIT STRING */

	int subsequentMessage; /* [1] */

	int dh_len;
	unsigned char *dhMAC; /* [2] BIT STRING */
}POPOPrivKey;

#define PKI_SUBSQMSG_ENCRCERT	0
#define PKI_SUBSQMSG_CHALLENGE	1

typedef struct proof_of_posession{ /* CHOICE */
	int	choice;
	/* [0] NULL */
	POPOSigningKey	*signature;	/* [1] */
	POPOPrivKey		*keyEncipherment; /* [2] */
	POPOPrivKey		*keyAgreement; /* [3] */
}POfP;


/*
 * PKIBody -- Body of PKIMessage
 */
/*--- template structure of PKIMessage ---*/
struct pki_body{
	int msg_type;
};

/*--- CertReqMessages ---*/
typedef struct cert_template{
	int	version;		/* [0] OPTIONAL */
	int	serialNumber;	/* [1] OPTIONAL */
	unsigned char *snum_der; /* serialNumber for long Integer */
	int	signingAlg;		/* [2] AlgID optional */

	CertDN	issuer;		/* [3] OPTIONAL */

	Validity	validity; /* [4] OPTIONAL */

	CertDN	subject;	/* [5] OPTIONAL */

	Key	*publicKey;		/* [6] OPTIONAL */
	/* issuerUID  [7] not used */
	/* subjectUID [8] not used */

	CertExt	*ext;		/* [9] OPTIONAL */
}CertTemplate;

typedef struct pkibd_certreqmsg PKIBD_CertReqMsg;
struct pkibd_certreqmsg{
	int msg_type;

	PKIBD_CertReqMsg *next;

	struct CertRequest{
		int	certReqId;

		CertTemplate *certTemplate;
		CertExt *controls;	/* Attribute OPTIONAL */
	}	certReq;

	POfP	*pop;		/* OPTIONAL */

	CertExt *regInfo;	/* Attribute OPTIONAL */
};

typedef struct cert_id CertId;
struct cert_id{
	CertId	*next;

	CertDN	issuer;
	int		serialNumber;				
};


/*--- CertRepMessage ---*/
typedef struct encrypted_value{
	int intendedAlg;	/* AlgID OPTIONAL */

	int symmAlg;
	Key *symmKey;	/* OPTIONAL */
	int esymm_len;
	unsigned char *enc_symmkey;

	int	keyAlg;			/* AlgID OPTIONAL */

	int hint_len;
	unsigned char *valueHint;	/* OPTIONAL */

	int enc_len;
	unsigned char *encValue;
}EncryptedValue;

typedef struct pki_publication_info{
	int		action;

	struct SignlePubInfo{
		int		pubMethod;
		ExtGenNames *pubLocation; /* OPTIONAL */
	}	pubInfo[4];	/* OPTIONAL */

}PKIPubInfo;

typedef struct cert_key_pair CertifiedKeyPair;
struct cert_key_pair{
	CertifiedKeyPair *next;

	struct CertOrEncCert{ /* CHOICE */
		Cert	*cert;
		EncryptedValue	*encCert;
	}	certOrEncCert;

	EncryptedValue	*privateKey;		/* OPTIONAL */
	PKIPubInfo		*publicationInfo;	/* OPTIONAL */
};

typedef struct cert_response CertResponse;
struct cert_response{
	CertResponse	*next;

	int		certReqID;
	PKIStatusInfo		*status;
	CertifiedKeyPair	*certifiedKeyPair; /* OPTIONAL */

	int		rsp_len;
	unsigned char	*rspInfo;
};

typedef struct pkibd_certrepmsg{
	int msg_type;

	CertList		*caPubs; /* OPTIONAL */
	CertResponse	*response;

}PKIBD_CertRepMsg;

/*--- POPODecKeyChallContent ---*/
typedef struct popo_challenge{
	int owf;	/* AlgID OPTIONAL */
	
	int wit_len;
	unsigned char *witness;
	
	int ch_len;
	unsigned char *challenge;
}Challenge;

typedef struct pkibd_popo_challenge{
	int msg_type;

	int num;
	Challenge	chall[8];
}PKIBD_PopoCH;

/*--- POPODecKeyRespContent ---*/
typedef struct pkibd_popo_resp{
	int msg_type;

	int num;
	int content[8];
}PKIBD_PopoRS;

/*--- KeyRecRepContent ---*/
typedef struct pkibd_recrep_cont{
	int msg_type;

	PKIStatusInfo	*status;
	Cert			*newSigCert;	/* OPTIONAL */
	CertList		*caCerts;		/* OPTIONAL */

	CertifiedKeyPair	*keyPairHist; /* OPTIONAL */

}PKIBD_RecRep;

/*--- RevReqContent ---*/
typedef struct pkibd_revreq_cont PKIBD_RevReq;
struct pkibd_revreq_cont{
	int msg_type;

	PKIBD_RevReq	*next;

	CertTemplate	*certDetails;
	unsigned char	revocationReason[2];	/* ReasonFlags OPTIONAL */
	struct tm	badSinceDate;	/* GenTime OPTIONAL */
	CertExt	*crlEntryDetails;	/* OPTIONAL */
	
};

/*--- RevRepContent ---*/
typedef struct pkibd_revrep_cont{
	int msg_type;

	PKIStatusInfo	*status;
	CertId	*revCerts;	/* OPTIONAL */
	CRL		*crl;		/* OPTIONAL -- Only one CRL will be returned */

}PKIBD_RevRep;

/*--- CAKeyUpdAnnContent ---*/
typedef struct pkibd_keyupd_ann{
	int msg_type;

	Cert	*oldWithNew;
	Cert	*newWithOld;
	Cert	*newWithNew;
}PKIBD_KeyUpDAnn;

/*--- CertAnnContent ---*/
typedef struct pkibd_cert_ann{
	int msg_type;

	Cert	*cert;
}PKIBD_CertAnn,PKIBD_PKCS10;

/*--- RevAnnContent ---*/
typedef struct pkibd_rev_ann{
	int msg_type;

	int		status;
	CertId		certId;
	struct tm	willBeRevokedAt;
	struct tm	badSinceData;
	CertExt		*crlDetails;
}PKIBD_RevAnn;

/*--- CRLAnnContent ---*/
typedef struct pkibd_crl_ann{
	int msg_type;

	CRL	*crl;
}PKIBD_CRLAnn;

/*--- PKIConfirmContent ---*/
/* = NULL */
/* In this case, PKIBody is used */

/*--- NestedMessageContent ---*/
typedef struct pkibd_nested{
	int msg_type;

	PKIMessage *msg;
}PKIBD_Nested;

/*--- GenMsgContent ---*/
typedef struct pkibd_genmsg{
	int msg_type;

	InfoTAV *content;
}PKIBD_GenMsg,PKIBD_GenRsp;

/*--- ErrorMsgContent ---*/
typedef struct pkibd_errmsg{
	int msg_type;

	PKIStatusInfo	*status;
	int		errorCode;
	char	*errorDetails[8];
}PKIBD_ErrMsg;


#define PKIBD_INIT_REQ		0
#define PKIBD_INIT_RSP		1
#define PKIBD_CERT_REQ		2
#define PKIBD_CERT_RSP		3
#define PKIBD_PKCS10		4
#define PKIBD_POP_CHALL		5
#define PKIBD_POP_RSP		6
#define PKIBD_KEYUPD_REQ	7
#define PKIBD_KEYUPD_RSP	8
#define PKIBD_KEYRCV_REQ	9
#define PKIBD_KEYRCV_RSP	10
#define PKIBD_RVOC_REQ		11
#define PKIBD_RVOC_RSP		12
#define PKIBD_CCERT_REQ		13
#define PKIBD_CCERT_RSP		14
#define PKIBD_CAKEYUPD_ANN	15
#define PKIBD_CERT_ANN		16
#define PKIBD_RVOC_ANN		17
#define PKIBD_CRL_ANN		18
#define PKIBD_CONFIRM		19
#define PKIBD_NESTED_MSG	20
#define PKIBD_GEN_MSG		21
#define PKIBD_GEN_RSP		22
#define PKIBD_ERR_MSG		23

#define PKISTAT_GRANTED			0
#define PKISTAT_GRNT_WT_MODS	1
#define PKISTAT_REJECTION		2
#define PKISTAT_WAITING			3
#define PKISTAT_RVOC_WARNING	4
#define PKISTAT_RVOC_NOTIFY		5
#define PKISTAT_KEYUPD_WARNING	6

#define PKIFL_BADALG		0x8000
#define PKIFL_BADMSGCHK		0x4000
#define PKIFL_BADBADREQ		0x2000
#define PKIFL_BADBADTIME	0x1000
#define PKIFL_BADCERTID		0x0800
#define PKIFL_BADFORMAT		0x0400
#define PKIFL_WRONGAUTH		0x0200
#define PKIFL_INCRCTDATA	0x0100
#define PKIFL_MISSTMSTP		0x0080
#define PKIFL_BADPOP		0x0040


/* pki_msg.c */
PKIMessage *PKImsg_new();
void PKImsg_free(PKIMessage *msg);

/* pki_head.c */
PKIHeader *PKIhead_new();
void PKIhead_free(PKIHeader *hd);

InfoTAV *CMP_infotype_new(unsigned char *oid, void *value);
void CMP_infotype_free(InfoTAV *info);
void CMP_infotype_free_all(InfoTAV *top);

/* pki_body.c */
PKIBody *PKIbody_new(int type);
void PKIbody_free(PKIBody *bd);

PKIStatusInfo *PKI_statinfo_new(int status);
void PKI_statinfo_free(PKIStatusInfo *si);
void PKI_statinfo_free_all(PKIStatusInfo *top);

void PKIbd_creqmsg_free_all(PKIBD_CertReqMsg *bd);
void PKIbd_crspmsg_free(PKIBD_CertRepMsg *bd);
void PKIbd_popch_free(PKIBD_PopoCH *bd);
void PKIbd_poprs_free(PKIBD_PopoRS *bd);
void PKIbd_recrsp_free(PKIBD_RecRep *bd);
void PKIbd_revreq_free(PKIBD_RevReq *bd);
void PKIbd_revreq_free_all(PKIBD_RevReq *bd);
void PKIbd_revrsp_free(PKIBD_RevRep *bd);
void PKIbd_keyupd_free(PKIBD_KeyUpDAnn *bd);
void PKIbd_ctann_free(PKIBD_CertAnn *bd);
void PKIbd_revann_free(PKIBD_RevAnn *bd);
void PKIbd_crlann_free(PKIBD_CRLAnn *bd);
void PKIbd_genmsg_free(PKIBD_GenMsg *bd);
void PKIbd_errmsg_free(PKIBD_ErrMsg *bd);

/* cmp.c */
CertTemplate *CMP_certtmpl_new();
void CMP_certtmpl_free(CertTemplate *ctt);

POfP *CMP_pofp_new();
POPOSigningKey *CMP_poposign_new();
POPOPrivKey *CMP_popopriv_new();
PKMACValue *CMP_pkmacv_new();
void CMP_pofp_free(POfP *pp);
void CMP_poposign_free(POPOSigningKey *pps);
void CMP_popopriv_free(POPOPrivKey *ppp);
void CMP_pkmacv_free(PKMACValue *mac);

EncryptedValue *CMP_encval_new();
PKIPubInfo *CMP_pubinfo_new();
CertifiedKeyPair *CMP_ctkeypair_new();
void CMP_encval_free(EncryptedValue *ev);
void CMP_pubinfo_free(PKIPubInfo *ppi);
void CMP_ctkeypair_free(CertifiedKeyPair *ckp);
void CMP_ctkeypair_free_all(CertifiedKeyPair *top);

CertId *CMP_certid_new();
void CMP_certid_free(CertId *cid);
void CMP_certid_free_all(CertId *top);

CertResponse *CMP_certrsp_new();
void CMP_certrsp_free(CertResponse *cr);
void CMP_certrsp_free_all(CertResponse *top);


/* asn1_pkibd.c */
PKIBody *ASN1_read_pkibody(unsigned char *der);
PKIBD_CertReqMsg *ASN1_pkibd_creqmsg(unsigned char *in,int type);
PKIBD_CertRepMsg *ASN1_pkibd_crspmsg(unsigned char *in,int type);
PKIBD_CertAnn *ASN1_pkibd_p10(unsigned char *in);
PKIBD_CertAnn *ASN1_pkibd_ctann(unsigned char *in);
PKIBD_PopoCH *ASN1_pkibd_popch(unsigned char *in);
PKIBD_PopoRS *ASN1_pkibd_poprs(unsigned char *in);
PKIBD_RecRep *ASN1_pkibd_recrsp(unsigned char *in);
PKIBD_RevReq *ASN1_pkibd_revreq(unsigned char *in);
PKIBD_RevRep *ASN1_pkibd_revrsp(unsigned char *in);
PKIBD_KeyUpDAnn *ASN1_pkibd_keyupd(unsigned char *in);
PKIBD_RevAnn *ASN1_pkibd_revann(unsigned char *in);
PKIBD_CRLAnn *ASN1_pkibd_crlann(unsigned char *in);
PKIBD_Nested *ASN1_pkibd_nested(unsigned char *in);
PKIBD_GenMsg *ASN1_pkibd_genmsg(unsigned char *in,int type);
PKIBD_ErrMsg *ASN1_pkibd_errmsg(unsigned char *in);

PKIStatusInfo *ASN1_read_statinfo(unsigned char *in,int *mv);
int asn1_pki_freetext(unsigned char *in,char *ftxt[]);
int asn1_pki_certreq(unsigned char *in, struct CertRequest *req);


/* asn1_pkihd.c */
PKIHeader *ASN1_read_pkihead(unsigned char *der);
InfoTAV *ASN1_cmp_infotype(unsigned char *in,int *mv);


/* asn1_cmp.c */
CertTemplate *ASN1_cmp_certtmpl(unsigned char *in,int *mv);

POfP *ASN1_cmp_pofp(unsigned char *in);
POPOSigningKey *ASN1_cmp_poposign(unsigned char *in);
POPOPrivKey *ASN1_cmp_popopriv(unsigned char *in);
PKMACValue *ASN1_cmp_pkmacv(unsigned char *in);

EncryptedValue *ASN1_cmp_encval(unsigned char *in);
PKIPubInfo *ASN1_cmp_pubinfo(unsigned char *in);
CertifiedKeyPair *ASN1_cmp_ctkeypair(unsigned char *in,int *mv);

CertResponse *ASN1_cmp_certrsp(unsigned char *in,int *mv);


/* pkimg_asn1.c */
PKIMessage *ASN1_read_pkimsg(unsigned char *der);
CertList *asn1_seq_certlist(unsigned char *in);

unsigned char *PKImsg_toDER(PKIMessage *pki,unsigned char *buf,int *ret_len);
int Certlist_DER_data(CertList *cl,unsigned char *ret,int *ret_len);
int PKImsg_estimate_der_size(PKIMessage *pki);


/* pkibd_asn1.c */
unsigned char *PKIbody_toDER(PKIBody *pki,unsigned char *buf,int *ret_len);

int PKIbd_DER_creqmsg(PKIBD_CertReqMsg *bd,unsigned char *ret,int *ret_len);
int PKIbd_DER_crspmsg(PKIBD_CertRepMsg *bd,unsigned char *ret,int *ret_len);
int PKIbd_DER_popch(PKIBD_PopoCH *bd,unsigned char *ret,int *ret_len);
int PKIbd_DER_poprs(PKIBD_PopoRS *bd,unsigned char *ret,int *ret_len);
int PKIbd_DER_recrsp(PKIBD_RecRep *bd,unsigned char *ret,int *ret_len);
int PKIbd_DER_revreq(PKIBD_RevReq *bd,unsigned char *ret,int *ret_len);
int PKIbd_DER_revrsp(PKIBD_RevRep *bd,unsigned char *ret,int *ret_len);
int PKIbd_DER_keyupd(PKIBD_KeyUpDAnn *bd,unsigned char *ret,int *ret_len);
int PKIbd_DER_ctann(PKIBD_CertAnn *bd,unsigned char *ret,int *ret_len);
int PKIbd_DER_revann(PKIBD_RevAnn *bd,unsigned char *ret,int *ret_len);
int PKIbd_DER_crlann(PKIBD_CRLAnn *bd,unsigned char *ret,int *ret_len);
int PKIbd_DER_nested(PKIBD_Nested *bd,unsigned char *ret,int *ret_len);
int PKIbd_DER_genmsg(PKIBD_GenMsg *bd,unsigned char *ret,int *ret_len);
int PKIbd_DER_errmsg(PKIBD_ErrMsg *bd,unsigned char *ret,int *ret_len);

int PKI_DER_statinfo(PKIStatusInfo *stat,unsigned char *ret,int *ret_len);
int PKI_DER_freetext(char *ftxt[],unsigned char *ret,int *ret_len);

/* pkibd_asn1sz.c */
int PKIbody_estimate_der_size(PKIBody *pki);

int der_size_creqmsg(PKIBD_CertReqMsg *bd);
int der_size_crspmsg(PKIBD_CertRepMsg *bd);
int der_size_popch(PKIBD_PopoCH *bd);
int der_size_poprs(PKIBD_PopoRS *bd);
int der_size_recrsp(PKIBD_RecRep *bd);
int der_size_revreq(PKIBD_RevReq *bd);
int der_size_revrsp(PKIBD_RevRep *bd);
int der_size_keyupd(PKIBD_KeyUpDAnn *bd);
int der_size_ctann(PKIBD_CertAnn *bd);
int der_size_revann(PKIBD_RevAnn *bd);
int der_size_crlann(PKIBD_CRLAnn *bd);
int der_size_errmsg(PKIBD_ErrMsg *msg);

int der_size_statinfo(PKIStatusInfo *stat);
int der_size_freetext(char *ftxt[]);
int der_size_exts(CertExt *top);
int der_size_seqofcert(CertList *cl);

/* pkihd_asn1.c */
unsigned char *PKIhead_toDER(PKIHeader *pki,unsigned char *buf,int *ret_len);
int CMP_DER_infotype(InfoTAV *itv,unsigned char *ret,int *ret_len);
int PKIhead_estimate_der_size(PKIHeader *pki);
int der_size_infotype(InfoTAV *itv);

/* cmp_asn1.c */
int CMP_DER_certtmpl(CertTemplate *ctp,unsigned char *ret,int *ret_len);
int CMP_DER_certid(CertId *cid,unsigned char *ret,int *ret_len);

int CMP_DER_pofp(POfP *pop,unsigned char *ret,int *ret_len);
int CMP_DER_poposign(POPOSigningKey *pps,unsigned char *ret,int *ret_len);
int CMP_DER_popopriv(POPOPrivKey *pp,unsigned char *ret,int *ret_len);
int CMP_DER_pkmacv(PKMACValue *pkm,unsigned char *ret,int *ret_len);

int CMP_DER_encval(EncryptedValue *ev,unsigned char *ret,int *ret_len);
int CMP_DER_pubinfo(PKIPubInfo *pi,unsigned char *ret,int *ret_len);
int CMP_DER_ctkeypair(CertifiedKeyPair *ckp,unsigned char *ret,int *ret_len);

int CMP_DER_certrsp(CertResponse *cr,unsigned char *ret,int *ret_len);


/* cmp_asn1.c */
int der_size_certtmpl(CertTemplate *ctp);
int der_size_pubkeyinfo(Key *pub);

int der_size_pofp(POfP *pop);
int der_size_poposign(POPOSigningKey *pps);
int der_size_popopriv(POPOPrivKey *pp);
int der_size_pkmacv(PKMACValue *pkm);

int der_size_encval(EncryptedValue *ev);
int der_size_pubinfo(PKIPubInfo *pi);
int der_size_ctkeypair(CertifiedKeyPair *ckp);

int der_size_name(CertDN *dir);
int der_size_certid(CertId *id);
int der_size_certrsp(CertResponse *cr);

#ifdef  __cplusplus
}
#endif

#endif /* __OK_CMP_H__ */
