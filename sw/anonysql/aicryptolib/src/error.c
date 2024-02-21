/* error.c */
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

#include "ok_io.h"
#include "ok_err.h"

static ULONG aicrypto_error=0;
static int	*error_info=NULL;

/* set error */
void OK_set_error(int error,int location,int point,int *info){
	aicrypto_error = (ULONG)(error|(location<<16)|(point<<24));
	error_info = info;
	OK_print_error();
}

void OK_set_errorlocation(int location,int point){
	aicrypto_error = (ULONG)((aicrypto_error&0xffff)|(location<<16)|(point<<24));
}

/* clear error */
void OK_clear_error(){
	aicrypto_error = 0;
	error_info = NULL;
}

/* get error */
ULONG OK_get_error(){
	return aicrypto_error;
}

int *OK_get_errorinfo(){
	return error_info;
}

/*---------------------------------------
  AiCrypto error string
---------------------------------------*/
char *get_err_location(int err){
	static char buf[64],tmp[16];
	int point = err>>8;

	err &= 0xff;
	*buf = 0;

	switch(err){
	case ERR_LC_NON:
		strcat(buf,"NO ERROR");
		break;
	case ERR_LC_LNM:
		strcat(buf,"LNM:");
		switch(point&0xf0){
		case ERR_PT_LNMADD: strcat(buf,"LNMADD"); break;
		case ERR_PT_LNMSUB: strcat(buf,"LNMSUB"); break;
		case ERR_PT_LNMMUL: strcat(buf,"LNMMULTI"); break;
		case ERR_PT_LNMDIV: strcat(buf,"LNMDIV"); break;
		case ERR_PT_LNMSQR: strcat(buf,"LNMSQR"); break;
		case ERR_PT_LNMSHF: strcat(buf,"LNMSHIFT"); break;
		case ERR_PT_LNMSET: strcat(buf,"LNMSET"); break;
		case ERR_PT_LNMLONG: strcat(buf,"LNMLONG"); break;
		case ERR_PT_LNMSYS: strcat(buf,"LNMSYS"); break;
		case ERR_PT_LNMRAND: strcat(buf,"LNMRAND"); break;
		case ERR_PT_LNMPRIME: strcat(buf,"LNMPRIME"); break;
		case ERR_PT_LNMSQRT: strcat(buf,"LNMSQRT"); break;
		}
		break;
	case ERR_LC_ECC:
		strcat(buf,"ECC:");
		switch(point&0xf0){
		case ERR_PT_ECC: strcat(buf,"ECC"); break;
		case ERR_PT_ECCADD: strcat(buf,"ECCADD"); break;
		case ERR_PT_ECCMUL: strcat(buf,"ECCMUL"); break;
		case ERR_PT_ECCPADD: strcat(buf,"ECCPADD"); break;
		case ERR_PT_ECCPMUL: strcat(buf,"ECCPMUL"); break;
		case ERR_PT_ECCTOOL: strcat(buf,"ECCTOOL"); break;
		case ERR_PT_ECCCONV: strcat(buf,"ECCCONV"); break;
		case ERR_PT_ECCSTD: strcat(buf,"ECCSTD"); break;
		case ERR_PT_ECCGEN: strcat(buf,"ECCGEN"); break;
		case ERR_PT_ECCVFY: strcat(buf,"ECCVFY"); break;
		case ERR_PT_ECCASN1: strcat(buf,"ECCASN1"); break;
		}
		break;
	case ERR_LC_RAND:
		strcat(buf,"RAND:");
		switch(point&0xf0){
		case ERR_PT_RAND: strcat(buf,"RAND"); break;
		case ERR_PT_LUTZRAND: strcat(buf,"LUTZRAND"); break;
		case ERR_PT_LUTZSEED: strcat(buf,"LUTZSEED"); break;
		}
		break;
	case ERR_LC_DES:
		strcat(buf,"DES:");
		switch(point&0xf0){
		case ERR_PT_DES: strcat(buf,"DES"); break;
		case ERR_PT_3DES: strcat(buf,"3DES"); break;
		case ERR_PT_DESKEY: strcat(buf,"DESKEY"); break;
		case ERR_PT_DESMODE: strcat(buf,"DESMODE"); break;
		}
		break;
	case ERR_LC_RC2:
		strcat(buf,"RC2:");
		switch(point&0xf0){
		case ERR_PT_RC2: strcat(buf,"RC2"); break;
		case ERR_PT_RC2KEY: strcat(buf,"RC2KEY"); break;
		case ERR_PT_RC2MODE: strcat(buf,"RC2MODE"); break;
		}
		break;
	case ERR_LC_RC4:
		strcat(buf,"RC4:");
		switch(point&0xf0){
		case ERR_PT_RC4: strcat(buf,"RC4"); break;
		case ERR_PT_RC4KEY: strcat(buf,"RC4KEY"); break;
		}
		break;
/*
	case ERR_LC_MD2:
		strcat(buf,"MD2:");
		break;
	case ERR_LC_MD5:
		strcat(buf,"MD5:");
		break;
	case ERR_LC_SHA1:
		strcat(buf,"SHA1:");
		break;
	case ERR_LC_HMAC:
		strcat(buf,"HMAC:");
		break;
*/
	case ERR_LC_RSA:
		strcat(buf,"RSA:");
		switch(point&0xf0){
		case ERR_PT_RSA: strcat(buf,"RSA"); break;
		case ERR_PT_RSAKEY: strcat(buf,"RSAKEY"); break;
		case ERR_PT_RSAASN: strcat(buf,"RSAASN"); break;
		}
		break;
	case ERR_LC_DSA:
		strcat(buf,"DSA:");
		switch(point&0xf0){
		case ERR_PT_DSA: strcat(buf,"DSA"); break;
		case ERR_PT_DSAKEY: strcat(buf,"DSAKEY"); break;
		case ERR_PT_DSAGEN: strcat(buf,"DSAGEN"); break;
		case ERR_PT_DSAASN: strcat(buf,"DSAASN"); break;
		case ERR_PT_DSASIG: strcat(buf,"DSASIG"); break;
		}
	case ERR_LC_ECDSA:
		strcat(buf,"ECDSA:");
		switch(point&0xf0){
		case ERR_PT_ECDSA: strcat(buf,"ECDSA"); break;
		case ERR_PT_ECDSAKEY: strcat(buf,"ECDSAKEY"); break;
		case ERR_PT_ECDSAASN: strcat(buf,"ECDSAASN"); break;
		}
		break;
	case ERR_LC_DH:
		strcat(buf,"DH:");
		switch(point&0xf0){
		case ERR_PT_DH: strcat(buf,"DH"); break;
		case ERR_PT_DHKEY: strcat(buf,"DHKEY"); break;
		case ERR_PT_DHASN: strcat(buf,"DHASN"); break;
		}
		break;
	case ERR_LC_ASN1:	/* asn1 .. 1 */
		strcat(buf,"ASN1:");
		switch(point&0xf0){
		case ERR_PT_ASN1: strcat(buf,"ASN1"); break;
		case ERR_PT_ASN1CERT: strcat(buf,"ASN1CERT"); break;
		case ERR_PT_ASN1CRL: strcat(buf,"ASN1CRL"); break;
		case ERR_PT_ASN1FILE: strcat(buf,"ASN1FILE"); break;
		case ERR_PT_ASN1OBJ: strcat(buf,"ASN1OBJ"); break;
		case ERR_PT_ASN1P7E: strcat(buf,"ASN1P7E"); break;
		case ERR_PT_ASN1P7S: strcat(buf,"ASN1P7S"); break;
		case ERR_PT_ASN1REQ: strcat(buf,"ASN1REQ"); break;
		case ERR_PT_ASN1RSA: strcat(buf,"ASN1RSA"); break;
		case ERR_PT_ASN1SET: strcat(buf,"ASN1SET"); break;
		case ERR_PT_ASN1PRT: strcat(buf,"ASN1PRT"); break;
		case ERR_PT_ASN1P12: strcat(buf,"ASN1P12"); break;
		case ERR_PT_ASN1EXT: strcat(buf,"ASN1EXT"); break;
		case ERR_PT_ASN1ECC: strcat(buf,"ASN1ECC"); break;
		case ERR_PT_ASN1DSA: strcat(buf,"ASN1DSA"); break;
		}
		break;
	case ERR_LC_ASN1_:	/* asn1 .. 2 */
		strcat(buf,"ASN1:");
		switch(point&0xf0){
		case ERR_PT_ASN1DH: strcat(buf,"ASN1DH"); break;
		case ERR_PT_ASN1EXTDEF: strcat(buf,"ASN1EXTDEF"); break;
		case ERR_PT_ASN1EXTMOJ: strcat(buf,"ASN1EXTMOJ"); break;
		case ERR_PT_ASN1CRTP: strcat(buf,"ASN1CRTP"); break;
		case ERR_PT_ASN1ECDSA: strcat(buf,"ASN1ECDSA"); break;
		}
		break;
	case ERR_LC_X509:
		strcat(buf,"X509:");
		switch(point&0xf0){
		case ERR_PT_X509FILE: strcat(buf,"X509FILE"); break;
		case ERR_PT_X509TIME: strcat(buf,"X509TIME"); break;
		}
		break;
	case ERR_LC_X509CERT:
		strcat(buf,"X509CERT:");
		switch(point&0xf0){
		case ERR_PT_CERT: strcat(buf,"CERT"); break;
		case ERR_PT_CERTASN1: strcat(buf,"CERTASN1"); break;
		case ERR_PT_CERTEXT: strcat(buf,"CERTEXT"); break;
		case ERR_PT_CERTEXTNS: strcat(buf,"CERTEXTNS"); break;
		case ERR_PT_CERTEXTSTR: strcat(buf,"CERTEXTSTR"); break;
		case ERR_PT_CERTPRINT: strcat(buf,"CERTPRINT"); break;
		case ERR_PT_CERTTOOL: strcat(buf,"CERTTOOL"); break;
		case ERR_PT_CERTVFY: strcat(buf,"CERTVFY"); break;
		case ERR_PT_CLIST: strcat(buf,"CERTLIST"); break;
		case ERR_PT_CLFILE: strcat(buf,"CERTLISTFILE"); break;
		case ERR_PT_CLTOOL: strcat(buf,"CERTLISTTOOL"); break;
		case ERR_PT_CRTP: strcat(buf,"CERTPAIR"); break;
		case ERR_PT_CRTPASN1: strcat(buf,"CERTPAIR_ASN1"); break;
		}
		break;
	case ERR_LC_X509CRL:
		strcat(buf,"X509CRL:");
		switch(point&0xf0){
		case ERR_PT_CRL: strcat(buf,"CRL"); break;
		case ERR_PT_CRLASN1: strcat(buf,"CRLASN1"); break;
		case ERR_PT_CRLEXT: strcat(buf,"CRLEXT"); break;
		case ERR_PT_CRLEXTSTR: strcat(buf,"CRLEXTSTR"); break;
		case ERR_PT_CRLPRINT: strcat(buf,"CRLPRINT"); break;
		case ERR_PT_CRLVFY: strcat(buf,"CRLVFY"); break;
		}
		break;
	case ERR_LC_X509KEY:
		strcat(buf,"X509KEY:");
		switch(point&0xf0){
		case ERR_PT_KEY: strcat(buf,"KEY"); break;
		case ERR_PT_KEYTOOL: strcat(buf,"KEYTOOL"); break;
		}
		break;
	case ERR_LC_X509EXT:
		strcat(buf,"X509EXT:");
		switch(point&0xf0){
		case ERR_PT_EXTGN: strcat(buf,"EXTGN"); break;
		case ERR_PT_EXTPOL: strcat(buf,"EXTPOL"); break;
		case ERR_PT_EXTCERT: strcat(buf,"EXTCERT"); break;
		case ERR_PT_EXTCRL: strcat(buf,"EXTCRL"); break;
		case ERR_PT_EXTMS: strcat(buf,"EXTMS"); break;
		case ERR_PT_EXTMOJ: strcat(buf,"EXTMOJ"); break;
		}
		break;
	case ERR_LC_X509REQ:
		strcat(buf,"X509REQ:");
		switch(point&0xf0){
		case ERR_PT_REQASN1: strcat(buf,"REQASN1"); break;
		case ERR_PT_REQVFY: strcat(buf,"REQVFY"); break;
		}
		break;
	case ERR_LC_PKCS:
		strcat(buf,"PKCS:");
		switch(point&0xf0){
		case ERR_PT_PKCS8: strcat(buf,"PKCS8"); break;
		case ERR_PT_P8FILE: strcat(buf,"P8FILE"); break;
		case ERR_PT_PBE: strcat(buf,"PBE"); break;
		case ERR_PT_PBECRY: strcat(buf,"PBECRY"); break;
		case ERR_PT_PBEKEY: strcat(buf,"PBEKEY"); break;
		case ERR_PT_DECINFO: strcat(buf,"DECINFO"); break;
		}
		break;
	case ERR_LC_PKCS7:
		strcat(buf,"PKCS7:");
		switch(point&0xf0){
		case ERR_PT_PKCS7: strcat(buf,"PKCS8"); break;
		case ERR_PT_P7DATA: strcat(buf,"P7DATA"); break;
		case ERR_PT_P7ENC: strcat(buf,"P7ENC"); break;
		case ERR_PT_P7ENV: strcat(buf,"P7ENV"); break;
		case ERR_PT_P7FILE: strcat(buf,"P7FILE"); break;
		case ERR_PT_P7SIGN: strcat(buf,"P7SIGN"); break;
		case ERR_PT_P7MASN1: strcat(buf,"P7MASN1"); break;
		case ERR_PT_P7SASN1: strcat(buf,"P7SASN1"); break;
		case ERR_PT_P7SATTR: strcat(buf,"P7SATTR"); break;
		}
		break;
	case ERR_LC_PKCS12:
		strcat(buf,"PKCS12:");
		switch(point&0xf0){
		case ERR_PT_PKCS12: strcat(buf,"PKCS12"); break;
		case ERR_PT_P12ASN1: strcat(buf,"P12ASN1"); break;
		case ERR_PT_P12FILE: strcat(buf,"P12FILE"); break;
		case ERR_PT_P12KEY: strcat(buf,"P12KEY"); break;
		case ERR_PT_P12MAC: strcat(buf,"P12MAC"); break;
		case ERR_PT_P12TOOL: strcat(buf,"P12TOOL"); break;
		}
		break;
	case ERR_LC_PEM:
		strcat(buf,"PEM:");
		switch(point&0xf0){
		case ERR_PT_BASE64: strcat(buf,"BASE64"); break;
		case ERR_PT_PEM: strcat(buf,"PEM"); break;
		case ERR_PT_PEMCRY: strcat(buf,"PEMCRY"); break;
		case ERR_PT_PEMMSG: strcat(buf,"PEMMSG"); break;
		case ERR_PT_PEMWRITE: strcat(buf,"PEMWRITE"); break;
		case ERR_PT_PEMPKCS: strcat(buf,"PEMPKCS"); break;
		}
		break;
	case ERR_LC_SMIME:
		strcat(buf,"SMIME:");
		switch(point&0xf0){
		case ERR_PT_SMIME_DEC: strcat(buf,"SMIMEDEC"); break;
		case ERR_PT_SMIME_ENC: strcat(buf,"SMIMEENC"); break;
		case ERR_PT_MIME_HEAD: strcat(buf,"MIMEHEAD"); break;
		}
		break;
	case ERR_LC_SSL:
		strcat(buf,"SSL:");
		switch(point&0xf0){
		case ERR_PT_SSL: strcat(buf,"SSL"); break;
		case ERR_PT_SSL_BIND: strcat(buf,"BIND"); break;
		case ERR_PT_SSL_CB: strcat(buf,"CALL BACK"); break;
		case ERR_PT_SSL_CS: strcat(buf,"CIPHER SPEC"); break;
		case ERR_PT_SSL_HELLO: strcat(buf,"HELLO"); break;
		case ERR_PT_SSL_LIST: strcat(buf,"LIST"); break;
		case ERR_PT_SSL_NAME: strcat(buf,"NAME"); break;
		case ERR_PT_SSL_RAND: strcat(buf,"RAND"); break;
		case ERR_PT_SSL_READ: strcat(buf,"READ"); break;
		case ERR_PT_SSL_SOCK: strcat(buf,"SOCK"); break;
		case ERR_PT_SSL_TOOL: strcat(buf,"TOOL"); break;
		case ERR_PT_SSL_VFY: strcat(buf,"VERIFY"); break;
		case ERR_PT_SSL_WRITE: strcat(buf,"WRITE"); break;
		}
		break;
	case ERR_LC_SSLHS:
		strcat(buf,"SSLHS:");
		switch(point&0xf0){
		case ERR_PT_SSLHS: strcat(buf,"HAND SHAKE"); break;
		case ERR_PT_SSLHS_CLNT: strcat(buf,"HAND SHAKE CLIENT"); break;
		case ERR_PT_SSLHS_KEY: strcat(buf,"HAND SHAKE KEY"); break;
		case ERR_PT_SSLHS_SERV: strcat(buf,"HAND SHAKE SERV"); break;
		}
		break;
	case ERR_LC_SSLREC:
		strcat(buf,"SSLREC:");
		switch(point&0xf0){
		case ERR_PT_SSLREC: strcat(buf,"RECORD"); break;
		case ERR_PT_SSLREC_PROC: strcat(buf,"RECORD PROC"); break;
		}
		break;
	case ERR_LC_SSLALERT:
		strcat(buf,"SSLALERT:");
		switch(point&0xf0){
		case ERR_PT_SSLALERT: strcat(buf,"ALERT"); break;
		}
		break;
	case ERR_LC_TOOL:
		strcat(buf,"TOOL:");
		switch(point&0xf0){
		case ERR_PT_DIGEST: strcat(buf,"DIGEST"); break;
		case ERR_PT_SIG: strcat(buf,"SIGNATURE"); break;
		case ERR_PT_PASS: strcat(buf,"PASSWORD"); break;
		}
		break;
	case ERR_LC_STORE:
		strcat(buf,"STORE:");
		switch(point&0xf0){
		case ERR_PT_STORE: strcat(buf,"STORE"); break;
		case ERR_PT_STADD: strcat(buf,"STORE ADD"); break;
		case ERR_PT_STDEL: strcat(buf,"STORE DEL"); break;
		case ERR_PT_STSEARCH: strcat(buf,"STORE SEARCH"); break;
		case ERR_PT_STTOOL: strcat(buf,"STORE TOOL"); break;
		case ERR_PT_MANAGER: strcat(buf,"MANAGER"); break;
		case ERR_PT_MANADD: strcat(buf,"MANAGER ADD"); break;
		case ERR_PT_MANDEL: strcat(buf,"MANAGER DEL"); break;
		case ERR_PT_MANSEARCH: strcat(buf,"MANAGER SEARCE"); break;
		case ERR_PT_MANASN1: strcat(buf,"MANAGER ASN1"); break;
		case ERR_PT_MANTOOL: strcat(buf,"MANAGER TOOL"); break;
		}
		break;
	case ERR_LC_STOREDEV:
		strcat(buf,"STORE DEV:");
		switch(point&0xf0){
		case ERR_PT_STFILE: strcat(buf,"STFILE"); break;
		case ERR_PT_STFILEMETH: strcat(buf,"STFILEMETH"); break;
		}
		break;
	case ERR_LC_WINCRY:
		strcat(buf,"WINCRY:");
		switch(point&0xf0){
		case ERR_PT_WINCRY_CERT: strcat(buf,"CERT"); break;
		case ERR_PT_WINCRY_CLIST: strcat(buf,"CLIST"); break;
		case ERR_PT_WINCRY_CRL: strcat(buf,"CRL"); break;
		case ERR_PT_WINCRY_KEY: strcat(buf,"KEY"); break;
		}
		break;
	case ERR_LC_UCONV:
		strcat(buf,"UCONV:");
		switch(point&0xf0){
		case ERR_PT_UCONV: strcat(buf,"UCONV"); break;
		case ERR_PT_UC_JIS: strcat(buf,"UC_JIS"); break;
		case ERR_PT_UC_SJIS: strcat(buf,"UC_SJIS"); break;
		case ERR_PT_UC_EUC: strcat(buf,"UC_EUC"); break;
		case ERR_PT_UC_UNI: strcat(buf,"UC_UNI"); break;
		case ERR_PT_UC_UTF8: strcat(buf,"UC_UTF8"); break;
		}
		break;
	default:
		strcat(buf,"UNKNOWN");
		break;
	}
	sprintf(tmp,"(%d)",point&0xf);
	strcat(buf,tmp);
	return buf;
}

char *get_err_type(int err){
	static char tmp[32];
	char *ret;
	switch(err){
	case ERR_ST_NON: ret="no error"; break;
	case ERR_ST_MEMALLOC: ret="memory alloc"; break;
	case ERR_ST_NULLPOINTER: ret="null pointer"; break;
	case ERR_ST_BADPARAM: ret="bad parameter"; break;
	case ERR_ST_BADFORMAT: ret="bad format"; break;
	case ERR_ST_BADVER: ret="bad version"; break;
	case ERR_ST_BADPADDING: ret="bad padding"; break;
	case ERR_ST_UNMATCHEDPARAM: ret="parameter unmatched"; break;
	case ERR_ST_STRDUP: ret="strdup error"; break;
	case ERR_ST_BADSTATE: ret="bad state"; break;
	case ERR_ST_UNSUPPORTED_ALGO: ret="unsupported algorithm"; break;
	case ERR_ST_UNSUPPORTED_VER: ret="unsupported version"; break;
	case ERR_ST_UNSUPPORTED_PARAM: ret="unsupported parameter"; break;
	case ERR_ST_UNSUPPORTED_CODE: ret="unsupported code"; break;
	case ERR_ST_BADNAME: ret="bad name"; break;
	case ERR_ST_NULLKEY: ret="null key"; break;
	case ERR_ST_BADKEY: ret="bad key"; break;
	case ERR_ST_FILEOPEN: ret="cannot open file"; break;
	case ERR_ST_FILEREAD: ret="cannot read file"; break;
	case ERR_ST_FILEWRITE: ret="cannot write file"; break;

	case ERR_ST_LNM_BUFOVERFLOW: ret="buffer over flow"; break;
	case ERR_ST_LNM_DIVBYZERO: ret="divide by zero"; break;
	case ERR_ST_LNM_NOSQRT: ret="squre root doesn't exist"; break;

	case ERR_ST_ASN_NOTINTEGER: ret="asn1 not integer"; break;
	case ERR_ST_ASN_NOTENUMERATED: ret="asn1 not enumrated"; break;
	case ERR_ST_ASN_NOTBITSTR: ret="asn1 not bit-string"; break;
	case ERR_ST_ASN_NOTOCTETSTR: ret="asn1 not octet string"; break;
	case ERR_ST_ASN_NOTOID: ret="asn1 not object-id"; break;
	case ERR_ST_ASN_NOTPRINTABLESTR: ret="asn1 not printable-string"; break;
	case ERR_ST_ASN_NOTUTF8STR: ret="asn1 not utf8-string"; break;
	case ERR_ST_ASN_NOTT61STR: ret="asn1 not t61-string"; break;
	case ERR_ST_ASN_NOTIA5STR: ret="asn1 not ia5-string"; break;
	case ERR_ST_ASN_NOTBMPSTR: ret="asn1 not bmp-string"; break;
	case ERR_ST_ASN_NOTISO64STR: ret="asn1 not iso64-string"; break;
	case ERR_ST_ASN_NOTUTCTIME: ret="asn1 not utc-time"; break;
	case ERR_ST_ASN_NOTGENTIME: ret="asn1 not generalized-time"; break;
	case ERR_ST_ASN_UNKNOWNOID: ret="asn1 unknown object-id"; break;
	case ERR_ST_ASN_BADOID: ret="asn1 bad object-id"; break;
	case ERR_ST_ASN_NOTASN1: ret="not asn1 format"; break;
	case ERR_ST_ASN_NOTBOOLEAN: ret="asn1 not boolean"; break;

	case ERR_ST_P12_BADDEPTH: ret="pkcs12 bad depth"; break;
	case ERR_ST_P12_NOBAG: ret="pkcs12 no bag"; break;
	case ERR_ST_P12_NOCERT: ret="pkcs12 no cert"; break;
	case ERR_ST_P12_NOCRL: ret="pkcs12 no crl"; break;
	case ERR_ST_P12_NOKEY: ret="pkcs12 no key"; break;
	case ERR_ST_P12_BADMAC: ret="pkcs12 bad mac"; break;

	case ERR_ST_PEM_BADHEADER: ret="pem bad header"; break;
	case ERR_ST_PEM_BADFOOTER: ret="pem bad footer"; break;
	case ERR_ST_PEM_BADPASSWD: ret="pem bad password"; break;
	case ERR_ST_P1_BADPADDING: ret="pkcs1 bad padding"; break;

	case ERR_ST_STO_MANAGNOTFOUND: ret="store manager not found"; break;
	case ERR_ST_STO_STORENOTFOUND: ret="store not found"; break;
	case ERR_ST_STO_BAGNOTFOUND: ret="bag not found"; break;
	case ERR_ST_STO_BADMANAG: ret="invalid store manager"; break;
	case ERR_ST_STO_BADSTORE: ret="invalid store"; break;
	case ERR_ST_STO_BADBAG: ret="invalid store bag"; break;
	case ERR_ST_STO_BADID: ret="invalid unique id"; break;

	case ERR_ST_WINAPI: ret="windows CryptAPI"; break;

	case ERR_ST_UC_BADJISCODE: ret="bad JIS code"; break;
	case ERR_ST_UC_BADUTF8CODE: ret="bad UTF8 code"; break;
	case ERR_ST_UC_UNKNOWNCODE: ret="unknown code"; break;

	case ERR_ST_MIME_BADHEADER: ret="mime bad header"; break;
	case ERR_ST_MIME_BADFOOTER: ret="mime bad footer"; break;

	case ERR_ST_RAND_NOPOOL: ret="random pool is empty"; break;
	case ERR_ST_RAND_NOTSEEDED: ret="random pool is not seeded"; break;

	case ERR_ST_SSL_CLOSE_NOTIFY: ret="ssl close notify"; break;
	case ERR_ST_SSL_UNEXPECTED_MESSAGE: ret="ssl unexpected message"; break;
	case ERR_ST_SSL_BAD_RECORD_MAC: ret="ssl bad record mac"; break;
	case ERR_ST_SSL_DECOMPRESSION_FAILURE: ret="ssl decompression failure"; break;
	case ERR_ST_SSL_HAND_SHAKE_FAILURE: ret="ssl hand shake failure"; break;
	case ERR_ST_SSL_NO_CERT: ret="ssl no cert"; break;
	case ERR_ST_SSL_BAD_CERT: ret="ssl bad cert"; break;
	case ERR_ST_SSL_UNSUPPORTED_CERT: ret="ssl unsupported cert"; break;
	case ERR_ST_SSL_CERT_REVOKED: ret="ssl cert revoked"; break;
	case ERR_ST_SSL_CERT_EXPIRED: ret="ssl cert expired"; break;
	case ERR_ST_SSL_CERT_UNKNOWN: ret="ssl cert unknown"; break;
	case ERR_ST_SSL_ILLEGAL_PARAMETER: ret="ssl illegal parameter"; break;
	case ERR_ST_SSL_WRITE: ret="ssl write"; break;
	case ERR_ST_SSL_READ: ret="ssl read"; break;
	case ERR_ST_SSL_BADHEADER: ret="ssl bad header"; break;
	case ERR_ST_SSL_BADSIGNATURE: ret="ssl bad signature"; break;
	case ERR_ST_SSL_BADFINISHED: ret="ssl bad finished"; break;

	case ERR_ST_ACCEPT: ret="sock accept"; break;
	case ERR_ST_CONNECT: ret="sock connect"; break;
	case ERR_ST_SOCKOPEN: ret="sock open"; break;
	case ERR_ST_SOCKWRITE: ret="sock write"; break;
	case ERR_ST_SOCKREAD: ret="sock read"; break;
	case ERR_ST_SOCKBIND: ret="sock bind"; break;
	case ERR_ST_SOCKLISTEN: ret="sock listen"; break;

	default: ret=tmp; sprintf(tmp,"%d",err); break;
	}
	return ret;
}

char *OK_get_errstr(){
	static char buf[128];

	SNPRINTF (buf,126,"[aicrypto] error:0x%x:%s:%s",
		aicrypto_error,
		get_err_location(aicrypto_error>>16),
		get_err_type(aicrypto_error&0xffff));
	return buf;
}

/*---------------------------------------
  print error string
---------------------------------------*/
void OK_print_error(){
	if(okerr) fprintf(okerr,"%s\n",OK_get_errstr());
}
