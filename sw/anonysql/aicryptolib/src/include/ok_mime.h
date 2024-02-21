/* ok_mime.h */
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

#ifndef __OK_MIME_H__
#define __OK_MIME_H__

#include "ok_err.h"

#include "ok_base64.h"
#include "ok_x509.h"
#include "ok_pkcs.h"

#ifdef  __cplusplus
extern "C" {
#endif

/*** Common mail body structures ***/
/* text/plain or NO "Content-Type" */
typedef struct{
	long	body_type;

	/* type field */
	long	charset;
	long	encode;	/* 7bit, 8bit, base64 or... */

	char	*message;
}MBody;

/* define multipart/mixed max number */
#define	MMULTI_MAX	16

/* multipart/* type */
typedef struct{
	long	body_type;

	/* type field */
	char	*boundary;
	long	bodynum;

	MBody	**body;
}MBody_Multi;

/* message/* type */
typedef struct{
	long	body_type;

	/* type field */
	char	*id;
	short	number;
	short	total;
	long	size;

	char	*message;
}MBody_Msg;

/* etc (binary) type */
typedef struct{
	long	body_type;

	/* type field */
	char	*fname;
	long	encode;	/* 7bit, 8bit, base64 or... */
	long	size;

	char	*message;
}MBody_Bin;

/*** main mail structure ***/
typedef struct{
	/* should be 4 byte... */
	char	*from;
	char	*to;
	char	*subject;
	char	*date;
	char	*sender;

	char	*header;
	
	MBody	*body; /* mail type e.g. plain/text ... */

	Cert	*cert;
	Key		*key;
}Mail;


/* define char set type (text/plain) */
#define	MAIL_CHSET_USASCII		0		/* us-ascii */
#define MAIL_CHSET_ISO2022JP	100		/* iso-2022-jp */

/* define content-transfer-encoding type */
#define	MAIL_ENC_7BIT		0	/* 7bit */
#define	MAIL_ENC_QUOTE		1	/* quoted-printable */
#define	MAIL_ENC_BS64		2	/* base64 */
#define	MAIL_ENC_8BIT		3	/* 8bit */
#define	MAIL_ENC_BIN		4	/* binary */
#define	MAIL_ENC_XTOKEN		0x10/* x-token */

/* define body_type */
#define MAIL_BDT_TXT		0x00010000	/* text */
#define MAIL_BDT_TXT_PL		0x00010001	/* text/plain */
#define MAIL_BDT_TXT_RITCH	0x00010002	/* text/richtext */
#define MAIL_BDT_TXT_HTML	0x00010003	/* text/html */
#define MAIL_BDT_TXT_XW		0x00011000	/* text/x-whatever */

#define MAIL_BDT_MP			0x00020000	/* multipart */
#define	MAIL_BDT_MP_MIXED	0x00020001	/* multipart/mixed */
#define MAIL_BDT_MP_ALT		0x00020002	/* multipart/alternative */
#define MAIL_BDT_MP_DIGST	0x00020003	/* multipart/digest */
#define MAIL_BDT_MP_PARALL	0x00020004	/* multipart/parallel */
#define MAIL_BDT_MP_SIGNED	0x00020010	/* multipart/signed */

#define MAIL_BDT_MSG		0x00040000	/* message */
#define MAIL_BDT_MSG_RFC822	0x00040001	/* message/rfc822 */
#define MAIL_BDT_MSG_PRTI	0x00040002	/* message/partial */
#define MAIL_BDT_MSG_EXTB	0x00040003	/* message/external-body */
#define MAIL_BDT_MSG_EXTKN	0x00041000	/* message/extention-token */

#define MAIL_BDT_IMG		0x00080000	/* image */
#define MAIL_BDT_IMG_GIF	0x00080001	/* image/gif */
#define MAIL_BDT_IMG_JPEG	0x00080002	/* image/jpeg */
#define MAIL_BDT_IMG_EXTKN	0x00081000	/* image/extension-token */

#define MAIL_BDT_AUD		0x00100000	/* audio */
#define MAIL_BDT_AUD_BC		0x00100001	/* audio/basic */
#define MAIL_BDT_AUD_EXTKN	0x00101000	/* audio/extension-token */

#define MAIL_BDT_VID		0x00200000	/* video */
#define MAIL_BDT_VID_MPEG	0x00200001	/* video/mpeg */
#define MAIL_BDT_VID_EXTKN	0x00201000	/* video/extension-token */

#define MAIL_BDT_APP		0x00400000	/* application */
#define MAIL_BDT_APP_OCT	0x00400001	/* application/octet-stream */
#define MAIL_BDT_APP_SMIME	0x00401000
#define MAIL_BDT_APP_P7SIG	0x00401001	/* application/pkcs7-signature */
#define MAIL_BDT_APP_P7MM	0x00401002	/* application/pkcs7-mime */
#define MAIL_BDT_APP_P10	0x00401003	/* application/pkcs10 */
#define MAIL_BDT_APP_P12	0x00401004	/* application/pkcs12 */

#define MAIL_BDT_EXT_EXTKN	0x01000000	/* extension-token */

/* mime.c */
Mail *Mail_new(void);
void Mail_free(Mail *ml);
MBody *MBody_new(long type);
void MBody_free(MBody *mb);

Mail *Mail_read_str(char *buf,Cert *cert,Key *key);
char *Mail_get_str(Mail *ml);

/* mime_head.c */
int Mail_get_stdheader(char *buf, Mail *ret);
int get_content_type(char *cp);
int get_encoding_type(char *cp);
char *get_attach_fname(char *cp);
int get_charset_type(char *cp);

/* mime_body.c */
void Mail_get_body(char *tp, Mail *ml);
void MBody_get_body_str(MBody *bd, char *buf);
void MBody_decode_file(MBody *bd);

/* mime_tool.c */
void Mail_print(Mail *ml);

/* mimebd_txt.c */
MBody *MBody_txt_new(long type);
void MBody_txt_free(MBody *mb);
void MBody_txt_get_body(MBody *ret, char *top);

/* mimebd_bin.c */
MBody_Bin *MBody_bin_new(long type);
void MBody_bin_free(MBody_Bin *mb);
void MBody_bin_get_body(MBody_Bin *ret, char *top);

/* mimebd_msg.c */
MBody_Msg *MBody_msg_new(long type);
void MBody_msg_free(MBody_Msg *mb);
void MBody_msg_get_body(MBody_Msg *ret, char *top);

/* mimebd_multi.c */
MBody_Multi *MBody_multi_new(long type);
void MBody_multi_free(MBody_Multi *mb);
void MBody_multi_get_body(MBody_Multi *ret, char *top);

/* mimebd_smime.c */
void MBody_smime_get_body(Mail *ml,MBody **ret, char *top);

/* smime_dec.c */
PKCS7 *SMIME_p7s_get_certs(char *msg);
PKCS7 *SMIME_p7s_get_msg(char *msg, char **ret);
unsigned char *SMIME_p7m_decrypt(char *msg, PKCS12 *p12);
int SMIME_p7s_verify(PKCS7 *p7, unsigned char *data, int len);

/* smime_enc.c */
char *SMIME_p7s_set_signature(char *msg, PKCS12 *p12, int clear_sig);
char *SMIME_p7s_set_msg_sign(char *msg, PKCS12 *p12, int clear_sig);
char *SMIME_p7m_encrypt(char *msg, PKCS7 *p7b);

#ifdef  __cplusplus
}
#endif

#endif /* __OK_MIME_H__ */
