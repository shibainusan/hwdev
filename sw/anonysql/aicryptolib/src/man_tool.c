/* man_tool.c */
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
#include "ok_asn1.h"
#include "ok_store.h"

/*-----------------------------------------------
   Verify certificate
-----------------------------------------------*/
int STM_verify_cert(STManager *stm, Cert *ct, int mode){
	CertList *ctl=NULL;
	CRLList *cll=NULL;
	int ret=-1;

	if((ctl=STM_get_pathcert(stm,ct))==NULL) goto done;
	cll = STM_get_pathcrl(stm,ctl); /* might be null */
	ret = Cert_verify(ctl,cll,ct,16,mode);

done:
	Certlist_free_all(ctl);
	CRLlist_free_all(cll);
	return ret;
}

/*-----------------------------------------------
   Get path certificates
-----------------------------------------------*/
CertList *STM_get_pathcert(STManager *stm,Cert *ct){
	CertList *pt,*ret=NULL;
	Cert *ca;
	CStore *cs;
	CSBag *bg;

	if(Cert_is_root(ct)){
		ret = Cert_2Certlist(ct);
		goto done;
	}

	for(cs=stm->store; cs ; cs=cs->next){
		if(cs->ctx_type == CSTORE_CTX_CERT){
			bg = CStore_get_firstBag(cs);
			while(bg=CStore_find_bySbjDN(cs,bg,&ct->issuer_dn)){
				if((ca=(Cert*)bg->cache)==NULL) goto done;

				if(Cert_is_path(ca,ct)){
					if((pt=STM_get_pathcert(stm,ca))==NULL) goto done;
					if((ret=Cert_2Certlist(ct))==NULL) goto done;
					ret->next = pt;
					pt->prev = ret;
					goto done;
				}
				bg = CSBag_next(bg);
			}
		}
	}
	if(cs==NULL){ /* only one cert (not root CA) */
		ret = Cert_2Certlist(ct);
	}
done:
	return ret;
}

/*-----------------------------------------------
   Get path certificates
-----------------------------------------------*/
CertList *STM_get_pathcert_crl(STManager *stm,CRL *crl){
	CertList *ret=NULL;
	Cert *ca;
	CStore *cs;
	CSBag *bg;

	for(cs=stm->store; cs ; cs=cs->next){
		if(cs->ctx_type == CSTORE_CTX_CERT){
			bg = CStore_get_firstBag(cs);
			while(bg=CStore_find_bySbjDN(cs,bg,&crl->issuer_dn)){
				if((ca=(Cert*)bg->cache)==NULL) goto done;

				if(CRL_is_path(ca,crl)){
					ret = STM_get_pathcert(stm,ca);
					goto done;
				}
				bg = CSBag_next(bg);
			}
		}
	}
done:
	return ret;
}

/*-----------------------------------------------
   Get path CRLs
-----------------------------------------------*/
/* certlist should created by STM_get_pathcert,
 * then list has certificates with up path order.
 * ex. (top of the list) ee -> sub-ca -> root-ca
 */
CRLList *STM_get_pathcrl(STManager *stm,CertList *clt){
	CRLList *pt,*hd,*ret=NULL;
	CertList *cl=NULL;
	CRL *crl;
	CStore *cs;
	CSBag *bg;

	if(Cert_is_root(clt->cert)) goto done;

	for(cs=stm->store; cs ; cs=cs->next){
	  if(cs->ctx_type != CSTORE_CTX_CRL) continue;

	  for(cl=clt; cl->next ; cl=cl->next){
	    bg = CStore_get_firstBag(cs);

	    while(bg=CStore_find_byIssuer(bg,cl->issuer)){
	      if(crl=(CRL*)bg->cache){
		if(CRL_is_path(cl->next->cert,crl)){
		  if((pt=CRL_2CRLlist(crl))==NULL) goto done;

		  if(ret){
		    hd->next=pt;
		    hd=pt;
		  }else{
		    ret=hd=pt;
		  }
		  break; /* just find one CRL for verification */
		}
	      }
	      bg = CSBag_next(bg);
	    }
	  }
	}

done:
	return ret;
}



