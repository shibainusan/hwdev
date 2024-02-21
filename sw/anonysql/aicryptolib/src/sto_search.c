/* sto_search.c */
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
#include "ok_store.h"

/*-----------------------------------------
  simple search
-----------------------------------------*/
CSBag *CStore_find_byID(CSBag *top, char *unique_id){
	while(top){
		if(!strcmp(unique_id,top->unique_id))
			return top;
		top=top->next;
	}
	return NULL;
}

CSBag *CStore_find_byCert(CSBag *top, Cert *ct){
	Cert *tmp;
	while(top){
		if((top->ctx_type==CSTORE_CTX_CERT)&&(top->cache)){
			tmp = (Cert*)top->cache;
			if(!strcmp(ct->subject,tmp->subject))
				if(!Cert_cmp(ct,tmp)) return top;
		}
		top=top->next;
	}
	return NULL;
}

CSBag *CStore_find_byCRL(CSBag *top, CRL *crl){
	CRL *tmp;
	while(top){
		if((top->ctx_type==CSTORE_CTX_CRL)&&(top->cache)){
			tmp = (CRL*)top->cache;
			if(!strcmp(crl->issuer,tmp->issuer))
				if(!CRL_cmp(crl,tmp)) return top;
		}
		top=top->next;
	}
	return NULL;
}

CSBag *CStore_find_byReq(CSBag *top, Req *crl){
	Req *tmp;
	while(top){
		if((top->ctx_type==CSTORE_CTX_CSR)&&(top->cache)){
			tmp = (Req*)top->cache;
			if(!strcmp(crl->subject,tmp->subject))
				if(!Req_cmp(crl,tmp)) return top;
		}
		top=top->next;
	}
	return NULL;
}

CSBag *CStore_find_bySNum(CSBag *top, int serialNum){
	while(top){
		if(serialNum==top->serialNumber)
			return top;
		top=top->next;
	}
	return NULL;
}

CSBag *CStore_find_bySbjDN(CStore *cs,CSBag *top,CertDN *dn){
	Cert *ct;
	while(top){
		if((top->ctx_type==CSTORE_CTX_CERT)&&(top->cache)){
			ct = (Cert*)top->cache;
			if(!Cert_dncmp(&ct->subject_dn,dn)){
				return top;
			}
#if 0
		if(top->ctx_type==CSTORE_CTX_CERT){
			if(ct=CStore_get_cert(cs,top)){
				if(!Cert_dncmp(&ct->subject_dn,dn)){
					/* if cs is not cache mode, memory will leak... */
					if((cs->mode&CSMODE_CACHE)==0) Cert_free(ct);
					return top;
				}
				if((cs->mode&CSMODE_CACHE)==0) Cert_free(ct);
			}
#endif
		}
		top=top->next;
	}
	return NULL;
}

CSBag *CStore_find_bySubject(CSBag *top, char *sbj){
	while(top){
		if(top->subject)
			if(!strcmp(sbj,top->subject))
				return top;
		top=top->next;
	}
	return NULL;
}

CSBag *CStore_find_byIssuer(CSBag *top, char *iss){
	while(top){
		if(top->issuer)
			if(!strcmp(iss,top->issuer))
				return top;
		top=top->next;
	}
	return NULL;
}

/* 
 * hash must has more than 20 byte buffer.
 */
CSBag *CStore_find_byKeyHash(CSBag *top, unsigned char hash[20]){
	while(top){
		if(top->hlen)
			if(!memcmp(hash,top->key_hash,top->hlen))
				return top;
		top=top->next;
	}
	return NULL;
}
