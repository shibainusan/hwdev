/* ok_ssl.h */
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
 *	this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *	this list of conditions and the following disclaimer in the documentation
 *	and/or other materials provided with the distribution.
 *
 * 3. All advertising materials mentioning features or use of this software must
 *	display the following acknowledgment:
 *	"This product includes software developed by Akira Iwata Laboratory,
 *	Nagoya Institute of Technology in Japan (http://mars.elcom.nitech.ac.jp/)."
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *	acknowledgment:
 *	"This product includes software developed by Akira Iwata Laboratory,
 *	 Nagoya Institute of Technology in Japan (http://mars.elcom.nitech.ac.jp/)."
 *
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

#ifndef __OK_SSL_H__
#define __OK_SSL_H__

#include "aiconfig.h"

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#include <sys/types.h>
#ifdef __WINDOWS__
#undef ULONG
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#endif

#include "ok_md5.h"
#include "ok_sha1.h"
#include "ok_x509.h"
#include "ok_pkcs.h"
#include "ok_store.h"

#ifdef  __cplusplus
extern "C" {
#endif

/*
 * SSL Record Layer
 */
typedef struct protocol_version{
	unsigned char major,minor;
}ProtocolVersion;

/*** Plain Text Struct ***/
typedef struct ssl_plain_text{
	unsigned int	type;	/* ContentType */
	unsigned int	length;	/* < 2^14 */

	/* this fragment doesn't have allocated memory.
	 * usually it points current buffer of procedure's buffer value.
	 * (i.e. the case of SSL_write(SSL*,void*,size_t), void* is taken)
	 */
	unsigned char	*fragment;	/* opaque [SSLPlaintext.length] */

}SSLPlaintext;

/*** Compressed Data Struct ***/
typedef SSLPlaintext	SSLCompressed;	/* same format */


/*** Cipher Text Struct ***/
typedef struct ssl_ciphertext{
	unsigned int	type;	/* ContentType */
	unsigned int	length;
	
	unsigned char	*fragment;

	/* these are cipher-fragment content */
	unsigned char	*content;		/* opaque [SSLCompressed.length] */
	unsigned char	MAC[32];		/* opaque [CipherSpec.hash_size] */
	unsigned char	padding[32];	/* [GenericBlockCipher.padding_length] */
	unsigned char	padding_length;
}SSLCiphertext;


/*
 * Cipher Spec
 */
typedef struct ssl_cipher_spec{
	int		bulk_cipher_algorithm;	/* current cipher (use OBJ_CRYALGO_* in ok_asn1.h) */
	int		mac_algorithm;		/* current mac(hash) (use OBJ_HASH_* in ok_asn1.h) */
	int		cipher_type;		/* stream (=0), block (=1) */
	int		is_exportable;		/* if exportable, (=1) */
	int		comp_meth;		/* compression method (usually 0) (ok_ssl original) */
	unsigned char	hash_size;
	unsigned char	key_material;
	unsigned char	IV_size;
}SSLCipherSpec;


/*
 * Handshake Protocol 
 */

/* Client Hello */
typedef struct hs_client_hello{
	ProtocolVersion	version;
	unsigned char	random[32];	/* gmt_unix_time & random_byte */
	/* unsigned char	session_id[32];	same number as server hello */

	/* CipherSuite (3 bytes) cipher_suites<2..2^16-1> */
	unsigned char	cipher_suites[64];

	/* enum { null=0, 255} CompressionMethod; */
	unsigned char	compression_methods[32];
}SSLClientHello;

/* Server Hello */
typedef struct hs_server_hello{
	ProtocolVersion	version;
	unsigned char	random[32];	/* gmt_unix_time & random_byte */

	unsigned char	session_id[32];	/* SessionID<0..32> */
	unsigned char	cipher_suites[64];
	unsigned char	compression_methods[32];
}SSLServerHello;


/*
 * SSL Structure
 */
typedef struct ssl SSL;
typedef struct ssl_context SSLCTX;

typedef struct ssl_callback_func{    
	int	(*read_cb)(int sock,char* buf,int len);
	int	(*write_cb)(int sock,char* buf,int len);
	int	(*read_debug)(SSL *ssl,int data);
	int	(*write_debug)(SSL *ssl,int data);
	int	(*vfy_cb)(SSL *ssl,Cert *cert);
}SSLCB;

struct ssl_context{
	ProtocolVersion	version;

	/***** currnt state *****/
	int		state;	/* current handshake state */
	int		errnum;	/* if error occured, error number is set */
	int		serv;	/* server flag */
	int		recv_cspec;	/* change chipher spec flag */

	unsigned char wseq[8];	/* message write sequence number */
	unsigned char rseq[8];	/* message read sequence number */

	MD5_CTX		*hsmsg_md5;		/* handshake-messages */
	SHA1_CTX	*hsmsg_sha1;	/* handshake-messages */

	/***** SSL infos *****/
	SSLCipherSpec	*cspec;
	SSLClientHello	*chello;
	SSLServerHello	*shello;

	/* client certificates (and private key) */
	PKCS12		*cp12;
	/* server certificates (and private key)
	 * in the case of server, this one is just pointer except the master SSL
	 */
	PKCS12		*sp12;
	/* server key exchange (if the server doesn't have its certificate) */
	Key			*exkey;

	/***** SSL Buffers *****/
	SSLPlaintext	*ptxt;	/* fragment doesn't have allocated memory */
	SSLCompressed	*comp;	/* usually this pointer is NULL */
	SSLCiphertext	*ctxt;

	unsigned char	*rbuf;	/* read buffer [SSLMAXBUF+3072] */
	unsigned char	*wbuf;	/* write buffer [SSLMAXBUF+3072] */
	int			wbuflen;
	int			rbuflen;	/* vailed read buffer length */
	/* sometimes, receive data includes several handshake packets.
	 * so, this data indicates current packet's length.
	 */
	int			rpklen;

	/* int			rbuftop; -- not use this */

	/***** SSL keys *****/
	unsigned char	premaster[48];	/* version[2] & random[46] */
	unsigned char	master_secret[48];

	/* SSL Final keys */
	unsigned char	client_write_MAC_secret[32];
	unsigned char	server_write_MAC_secret[32];

	Key		*skey;	/* server write key & IV */
	Key		*ckey;	/* client write key & IV */

	/***** system parameters *****/
	/* the master SSL should has SSLCTX list for reconnection.
	 * the master SSL has NULL pointer with top (maybe listening socket)
	 * and all clients have it, either.
	 */
	time_t	contime;	/* latest connection time */
	int		list_max;	/* max number of list */
	int		list_num;
	SSLCTX	*top;		/* pointer to top (master) SSLCTX */
	SSLCTX	*next;		/* pointer to next SSLCTX */
	SSLCTX	*prev;		/* pointer to previous SSLCTX */

	SSL		*ssl;		/* its owner SSL pointer */

	/* user certificate will be verified with this */
	STManager	*stm;		/* just pointer except the master SSL */
	int		vfy_type;	/* verification type */
	int		vfy_depth;	/* cert chain depth for verification (from bottom) */

	/* ssl call back functions */
	SSLCB	*cb;
};

struct ssl{
	/* socket & FILE */
	int		sock;
	FILE	*fp;
	
	/* SSL mode */
	int		mode;	/* current RecodeLayer ContentType (=0..no ssl) */
	int		opt;	/* ssl mode flag */

	/* SSL context */
	SSLCTX	*ctx;
};

/* SSL CipherSuite */
/* CipherSuite is usually 2 bytes, but listed definitions have
 * { 0x00,0x?? }, then first byte is just omitted.
 */
#define SSL_NULL_WITH_NULL_NULL					0x00
#define SSL_RSA_WITH_NULL_MD5					0x01
#define SSL_RSA_WITH_NULL_SHA					0x02
#define SSL_RSA_EXPORT_WITH_RC4_40_MD5			0x03
#define SSL_RSA_WITH_RC4_128_MD5				0x04
#define SSL_RSA_WITH_RC4_128_SHA				0x05
#define SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5		0x06
#define SSL_RSA_WITH_IDEA_CBC_SHA				0x07
#define SSL_RSA_EXPORT_WITH_DES40_CBC_SHA		0x08
#define SSL_RSA_WITH_DES_CBC_SHA				0x09
#define SSL_RSA_WITH_3DES_EDE_CBC_SHA			0x0A
#define SSL_DH_DSS_EXPORT_WITH_DES40_CBC_SHA	0x0B
#define SSL_DH_DSS_WITH_DES_CBC_SHA				0x0C
#define SSL_DH_DSS_WITH_3DES_EDE_CBC_SHA		0x0D
#define SSL_DH_RSA_EXPORT_WITH_DES40_CBC_SHA	0x0E
#define SSL_DH_RSA_WITH_DES_CBC_SHA				0x0F
#define SSL_DH_RSA_WITH_3DES_EDE_CBC_SHA		0x10
#define SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA	0x11
#define SSL_DHE_DSS_WITH_DES_CBC_SHA			0x12
#define SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA		0x13
#define SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA	0x14
#define SSL_DHE_RSA_WITH_DES_CBC_SHA			0x15
#define SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA		0x16
#define SSL_DH_anon_EXPORT_WITH_RC4_40_MD5		0x17
#define SSL_DH_anon_WITH_RC4_128_MD5			0x18
#define SSL_DH_anon_EXPORT_WITH_DES40_CBC_SHA	0x19
#define SSL_DH_anon_WITH_DES_CBC_SHA			0x1A
#define SSL_DH_anon_WITH_3DES_EDE_CBC_SHA		0x1B
#define SSL_FORTEZZA_KEA_WITH_NULL_SHA			0x1C
#define SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA	0x1D
#define SSL_FORTEZZA_KEA_WITH_RC4_128_SHA		0x1E

	
/* SSL Record Layer, ContentType */
#define SSL_HANDSHAKEv2			10
#define SSL_CHANGE_CIPHER_SPEC	20
#define SSL_ALERT				21
#define SSL_HANDSHAKE			22
#define SSL_APPLICATION_DATA	23
#define SSL_CONTENT_TYPE_NULL	255


/* SSL Alert Protocol, AlertLevel */
#define SSL_AL_WARNING	1
#define	SSL_AL_FATAL	2


/* SSL Alert Protocol, AlertDescription */
#define SSL_AD_CLOSE_NOTIFY			0
#define SSL_AD_UNEXPECTED_MESSAGE	10
#define SSL_AD_BAD_RECORD_MAC		20
#define SSL_AD_DECOMPRESSION_FAILURE	30
#define SSL_AD_HAND_SHAKE_FAILURE	40
#define SSL_AD_NO_CERTIFICATE		41
#define SSL_AD_BAD_CERTIFICATE		42
#define SSL_AD_UNSUPPORTED_CERTIFICATE	43
#define SSL_AD_CERTIFICATE_REVOKED	44
#define SSL_AD_CERTIFICATE_EXPIRED	45
#define SSL_AD_CERTIFICATE_UNKNOWN	46
#define SSL_AD_ILLEGAL_PARAMETER	47
#define SSL_AD_NULL					255


/* SSL Handshake Protocol, HandshakeType */
#define SSL_HT_HELLO_REQUEST		0
#define SSL_HT_CLIENT_HELLO			1
#define SSL_HT_SERVER_HELLO			2
#define SSL_HT_CERTIFICATE			11
#define SSL_HT_SERVER_KEY_EXCHANGE	12
#define SSL_HT_CERTIFICATE_REQUEST	13
#define SSL_HT_SERVER_HELLO_DONE	14
#define SSL_HT_CERTIFICATE_VERIFY	15
#define SSL_HT_CLIENT_KEY_EXCHANGE	16
#define	SSL_HT_FINISHED				20
#define SSL_HT_NULL					255
/* these are my original for processing */
#define SSL_HT_WAIT_CLIENT_HELLO	129
#define SSL_HT_WAIT_CLIENT_ANSWER	130
#define SSL_HT_WAIT_CLIENT_FINISH	131
#define SSL_HT_WAIT_SERVER_HELLO	135
#define SSL_HT_WAIT_SERVER_ANSWER	136
#define SSL_HT_WAIT_SERVER_FINISH	137

/* SSL Handshake Protocol, ClientCertificateType */
#define SSL_HT_RSA_SIGN			1
#define SSL_HT_DSS_SIGN			2
#define SSL_HT_RSA_FIXED_DH		3
#define SSL_HT_DSS_FIXED_DH		4
#define SSL_HT_RSA_EPHEMERAL_DH	5
#define SSL_HT_DSS_EPHEMERAL_DH	6
#define SSL_HT_FORTEZZA_KEA		20

/* SSL Verification mode -- see ok_x509.h more details */
#define SSL_DONT_VERIFY			DONT_VERIFY
#define SSL_DONT_VERIFY_CRL		DONT_VERIFY_CRL
#define SSL_ALLOW_SELF_SIGN		ALLOW_SELF_SIGN
#define SSL_DONT_CHECK_REVOKED		DONT_CHECK_REVOKED
#define SSL_IF_NO_CRL_DONT_CHECK_REVOKED	IF_NO_CRL_DONT_CHECK_REVOKED
#define SSL_ONLY_FIRST_DEPTH_CHECK_REVOKED	ONLY_FIRST_DEPTH_CHECK_REVOKED



/* number of available signature algorithms
 * (currently, it's RSA sign only.)
 */
#define SSL_CERT_ALGOMAX		1

/* maximum buffer in SSL PlainText (2^14)*/
#define SSLMAXBUF				16384

/* maximum list number of SSLCTX (for reconnection) */
#define SSL_CONNECT_LIST_MAX	100


/* ssl options & mode flag */
#define SSL_OPT_IMMEDIATE		0x0001	/* handshake after accept() immediately */
#define SSL_OPT_HS_SEPARATE		0x0002	/* send several handshake messages separately */
#define SSL_OPT_CERTREQ			0x0010	/* server send certificate request */
#define SSL_OPT_KEEPWBUF		0x0080	/* keep write buffer (data won't be flushed) */
/* system flags */
#define SSL_SYS_RESERVED0		0x0100	/* reserved */
#define SSL_SYS_RESERVED1		0x0200	/* reserved */
#define SSL_SYS_RESERVED2		0x0400	/* reserved */
#define SSL_SYS_CTXLISTED		0x0800	/* SSLCTX is in the list of SSL connection (might be reused) */
#define SSL_SYS_GOT_CERTREQ		0x1000	/* client got certificate request */
#define SSL_SYS_SOCK_PARENT		0x2000	/* parent socket */
#define	SSL_SYS_RECONNECTION	0x4000	/* re-connection flag */
#define SSL_SYS_SERVER			0x8000	/* SSL server flag */

/* ssl.c */
SSL *SSL_new(void);
SSL *SSL_dup(SSL *org);
void SSL_free(SSL *ssl);
SSLCTX *SSLCTX_new(void);
SSLCTX *SSLCTX_dup(SSLCTX *org);
void SSLCTX_free(SSLCTX *sl);
SSLCB *SSLCB_new(void);
void SSLCB_free(SSLCB *scb);
SSLCB *SSLCB_dup(SSLCB *scb);
SSLCipherSpec *SSL_CipherSpec_new(void);
SSLCipherSpec *SSL_CipherSpec_dup(SSLCipherSpec *org);
void SSL_CipherSpec_free(SSLCipherSpec *cs);


/* ssl_hello.c */
SSLClientHello *SSL_ClientHello_new(void);
SSLServerHello *SSL_ServerHello_new(void);
SSLClientHello *SSL_ClientHello_dup(SSLClientHello *org);
SSLServerHello *SSL_ServerHello_dup(SSLServerHello *org);
void SSL_ClientHello_free(SSLClientHello *ch);
void SSL_ServerHello_free(SSLServerHello *sh);


/* ssl_rec.c */
SSLPlaintext *SSL_Plaintext_new(void);
SSLPlaintext *SSL_Plaintext_dup(SSLPlaintext *org);
void SSL_Plaintext_free(SSLPlaintext *pl);
SSLCompressed *SSL_Compressed_new(void);
SSLCompressed *SSL_Compressed_dup(SSLCompressed *org);
void SSL_Compressed_free(SSLCompressed *cm);
SSLCiphertext *SSL_Ciphertext_new(void);
SSLCiphertext *SSL_Ciphertext_dup(SSLCiphertext *org);
void SSL_Ciphertext_free(SSLCiphertext *ci);

/* ssl_recproc.c */
/* encode message */
int SSL_enc_ptxt2comp(SSLCTX *ctx);
int SSL_enc_comp2ctxt(SSLCTX *ctx);
int SSL_set_ctxt2buf(SSLCTX *ctx,int mode);
/* decode message (if no error, return 0) */
int SSL_dec_comp2ptxt(SSLCTX *ctx);
int SSL_dec_ctxt2comp(SSLCTX *ctx);
int SSL_set_buf2ctxt(SSLCTX *ctx);


/* ssl_hs.c */
int SSL_handshake(SSL *ssl);
int SSL_sv_handshake(SSL *ssl);
int SSL_cl_handshake(SSL *ssl);


/* ssl_hsserv.c */
int SSL_send_helloreq(SSL *ssl);
int SSL_recv_client_hello(SSL *ssl);
int SSL_set_clienthello(SSLCTX *ctx, unsigned char *buf, int len);

int SSL_send_serv_hello(SSL *ssl);
int SSL_send_serv_cert(SSL *ssl);
int SSL_send_serv_keyexchange(SSL *ssl);
int SSL_send_certreq(SSL *ssl);
int SSL_send_serv_hellodone(SSL *ssl);
int SSL_get_serverhello(SSLCTX *ctx, unsigned char *buf);
int SSL_get_certificate(SSLCTX *ctx, unsigned char *buf);
int SSL_get_keyexchange(SSLCTX *ctx, unsigned char *buf);
int SSL_get_certreq(SSLCTX *ctx, unsigned char *buf);
int SSL_get_serverhellodone(SSLCTX *ctx, unsigned char *buf);

int SSL_recv_client_cert(SSL *ssl);
int SSL_recv_clikeyexchange(SSL *ssl);
int SSL_recv_client_certvfy(SSL *ssl);
int SSL_set_clikeyexchange(SSLCTX *ctx, unsigned char *buf, int len);
int SSL_set_certvfy(SSLCTX *ctx, unsigned char *buf, int len);

int SSL_recv_finished(SSL *ssl);
int SSL_send_finished(SSL *ssl);

/* ssl_hsclnt.c */
int SSL_send_client_hello(SSL *ssl);
int SSL_get_clienthello(SSLCTX *ctx, unsigned char *buf);

int SSL_recv_serv_hello(SSL *ssl);
int SSL_recv_serv_certificate(SSL *ssl);
int SSL_recv_serv_keyexchange(SSL *ssl);
int SSL_recv_serv_certreq(SSL *ssl);
int SSL_recv_serv_hellodone(SSL *ssl);
int SSL_set_serverhello(SSLCTX *ctx, unsigned char *buf, int len);
int SSL_set_certificate(SSLCTX *ctx, unsigned char *buf, int len);
int SSL_set_skeyexchange(SSLCTX *ctx, unsigned char *buf, int len);
int SSL_set_certreq(SSLCTX *ctx, unsigned char *buf, int len);

int SSL_send_client_cert(SSL *ssl);
int SSL_send_client_keyexchange(SSL *ssl);
int SSL_send_client_certvfy(SSL *ssl);
int SSL_get_clikeyexchange(SSLCTX *ctx,unsigned char *buf);
int SSL_get_client_certvfy(SSLCTX *ctx,unsigned char *buf);
void init_before_hello(SSL *ssl);

/* ssl_hskey.c */
void SSL_gen_mastersecret(SSLCTX *ctx);
int  SSL_gen_writekey(SSLCTX *ctx);
void SSL_hs_hashinit(SSLCTX *ctx);
void SSL_hs_hashupdate(SSLCTX *ctx,unsigned char *in,int len);
void SSL_hs_hashfinal(SSLCTX *ctx,unsigned char *md5,unsigned char *sha1);


/* ssl_sock.c */
SSL *SSL_socket(int af,int type,int protocol);
int SSL_shutdown(SSL *ssl, int how);
int SSL_close(SSL *ssl);
int SSL_setsockopt(SSL *ssl, int level, int optname, const void * optval, int optlen);
int SSL_getsockopt(SSL *ssl, int level, int optname, void  *optval, int *optlen);


/* ssl_bind.c */
int SSL_bind(SSL *ssl, const struct sockaddr *name, int namelen);
int SSL_listen(SSL *ssl, int backlog);
SSL *SSL_accept(SSL *ssl, struct sockaddr *addr, int *addrlen);
int SSL_connect(SSL *ssl, const struct sockaddr *name, int namelen);
int SSL_alloc_contexts(SSL *ssl);
void SSL_setopt(SSL *ssl, int flag);
int SSL_getopt(SSL *ssl);


/* ssl_name.c */
int SSL_getpeername(SSL *ssl, struct sockaddr *name, int *namelen);
int SSL_getsockname(SSL *ssl, struct sockaddr *name, int *namelen);


/* ssl_write.c */
int SSL_write(SSL *ssl, void *buf, size_t nbyte);
int SSL_encode_packet(SSL *ssl, void *msg, size_t len);
int SSL_wflush(SSL *ssl);
void SSL_clear_rwbuf(SSLCTX *ctx);
/*int SSL_send(SSL *ssl, void *msg, size_t len, int flags);*/


/* ssl_read.c */
int SSL_read(SSL *ssl, void *buf, size_t nbyte);
int SSL_packet_read(SSLCTX *ctx, void *buf, size_t nbyte);
int SSL_analize_header(SSLCTX *ctx,unsigned char *rbuf,int *hd_len);
int SSL_decode_packet(SSLCTX *ctx);
int SSL_calc_mac(SSLCTX *ctx, unsigned char *cmac,int len,int sv,int wt);
/*int SSL_recv(SSL *ssl, void *msg, size_t len, int flags);*/


/* ssl_alert.c */
int SSL_recv_alert(SSLCTX *ctx,unsigned char *buf,int *len);
int SSL_send_alert(SSL *ssl,int level,int description);
void SSL_alert_str(int level,int description,char *buf);


/* ssl_cs.c -- change cipher spec */
int SSL_send_change_cipherspec(SSLCTX *ctx,int ch);
int SSL_recv_change_cipherspec(SSLCTX *ctx,unsigned char *rbuf);
void SSL_cspec_str(SSLCTX *ctx,char *buf);
int set_cipher_spec(SSLCTX *ctx,int set);


/* ssl_tool.c */
int SSL_set_server_p12(SSL *ssl,char *fname,char *passwd);
int SSL_set_client_p12(SSL *ssl,char *fname,char *passwd);
Cert *SSL_get_scert(SSLCTX *ctx);
Cert *SSL_get_ccert(SSLCTX *ctx);
Cert *SSL_get_peer_cert(SSLCTX *ctx);
int ssl_check_sslctx(SSL *ssl);

/* ssl_rand.c */
int SSL_set_rand(unsigned char *cp,int byte);


/* ssl_list.c */
int SSL_add_connect_list(SSL *listen_ssl,SSL *ssl);
SSLCTX *find_old_ctx(SSLCTX *ctx, unsigned char *id, int len);
int copy_part_of_ctx(SSLCTX *to,SSLCTX *from);
int delete_one_ctx(SSLCTX *top);
void add_to_top(SSLCTX *top,SSLCTX *add);
void move_to_top(SSLCTX *top,SSLCTX *mv);
void SSL_set_list_max(SSL *ssl,int num);

/* ssl_vfy.c */
int SSL_cert_verify(SSL *ssl,Cert *ct);
int SSL_set_vfytype(SSL *ssl, int type);
int SSL_set_vfydepth(SSL *ssl, int depth);
int SSL_set_store(SSL *ssl,char *path);

/* ssl_cb.c */
int SSL_set_read_cb(SSL *ssl, int (*cb)(int,char*,int));
int SSL_set_write_cb(SSL *ssl, int (*cb)(int,char*,int));
int SSL_set_vfy_cb(SSL *ssl, int (*cb)(SSL*,Cert*));
int SSL_set_readdebug_cb(SSL *ssl, int (*cb)(SSL*,int));
int SSL_set_writedebug_cb(SSL *ssl, int (*cb)(SSL*,int));


/* etc */
#define SSL_get_client_cert(ssl)	SSL_get_ccert((ssl)->ctx)
#define SSL_get_server_cert(ssl)	SSL_get_scert((ssl)->ctx)

/* OpenSSL compatible macros */
#define SSL_set_fd(ssl,sk)		(ssl)->sock=(sk)
#define SSL_get_peer_certificate(ssl)	SSL_get_peer_cert((ssl)->ctx)


#ifdef  __cplusplus
}
#endif

#endif  /* __OK_SSL_H__ */



