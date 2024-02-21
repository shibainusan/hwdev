/* mimebd_smime.c */
/*
 * Copyright (C) 1998-2002
 *  Akira Iwata Laboratory. 
 *  Nagoya Institute of Technology in Japan.
 *
 * All rights reserved.
 *
 * This software is written by Takuto Okuno(usagi@mars.elcom.nitech.ac.jp)
 * And if you want to contact us, e-mail to Kimitake Wakayama
 * (wakayama@elcom.nitech.ac.jp)
 *
 * This library is FREE for commercial and non-commercial use as long as
 * the following conditions are aheared to.
 * If you want to use aicrypto library and CA applications code in product,
 * should be e-mail to Akira Iwata Laboratory (wakayama@elcom...).
 * 
 * Please note that MD2 and MD5 includes RSA Data Security, Inc. LICENSE.
 * Those are besed on RFC1319 and RFC1321 document. And copyright distribution
 * is following in ok_md2.h ok_md5.h .
 *
 */

#include "aiconfig.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ok_asn1.h"
#include "ok_mime.h"
#include "ok_pkcs.h"

PKCS7 *ASN1_read_p7s(unsigned char *der);
PKCS7 *ASN1_read_p7env(unsigned char *der);

/*-----------------------------------------
  Get mail body
-----------------------------------------*/
void MBody_smime_get_body(Mail *ml,MBody **ret, char *top){
	PKCS7 *p7;
	unsigned char *dec,*msg;
	char *cp,*body;
	long type,encode;
	int	 dec_len;

	cp = strstr(top,"ncoding:");
	encode = type= get_encoding_type(cp);

	if(type!=MAIL_ENC_BS64)
		return;

	/* This doesn't work sometimes ...(ex. IE5,)
	if(!strcmp(fname,"smime.p7m")){ */

	if(body = strstr(cp,"\n\n")){
		body+=2;
	}else{
		body = strstr(cp,"\r\n\r\n");
		body+=4;}

	dec=Base64_decode(body,&dec_len);

/*	{FILE *fp;fp=fopen("p7dec.der","wb");fwrite(dec,1,dec_len,fp);fclose(fp);}*/

	/* decode smime, PKCS7 MIME ENCODE */
	if(p7=ASN1_read_p7env(dec)){
		/* data is PKCS7 Enveloped Data */
		if((msg=P7m_decrypt_enveloped(p7,ml->cert,ml->key))==NULL){
			FREE(dec); P7_free(p7); return;}

		/* get real (decrypted) context */
		Mail_get_body(msg,ml);

		*ret = ml->body;

		FREE(msg); /* <- BUG!? there is memory error somewhere... */
	}else if(p7=ASN1_read_p7s(dec)){
		/* data is PKCS7 Signed Data */
		/* just we want to get body content... */
		if(cp=((P7_Signed*)p7->cont)->content){
			dec_len = ((P7_Signed*)p7->cont)->cnt_size;
			msg=(unsigned char*)MALLOC(dec_len+1);
			memcpy(msg,cp,dec_len);
			msg[dec_len]=0;

			Mail_get_body(msg,ml);

			*ret = ml->body;
			FREE(msg);
		}
	}

	if(p7) P7_free(p7);
	FREE(dec);	/* p7->der != dec, so FREE dec now */
}
