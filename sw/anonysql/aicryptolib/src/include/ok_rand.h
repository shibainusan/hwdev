/* ok_rand.h */
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

#ifndef __OK_RAND_H__
#define __OK_RAND_H__

#include "aiconfig.h"
#include "ok_err.h"

#include "time.h"

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#ifdef HAVE_SYS_TIMES_H
#include <sys/times.h>
#endif

#ifdef HAVE_SYS_RESOURCE_H
# include <sys/resource.h>
#endif

#ifdef __WINDOWS__
#undef ULONG
#include<winsock2.h>
#include<process.h>
#endif

#ifdef  __cplusplus
extern "C" {
#endif

typedef struct {
	double rate;
	unsigned int badness;
	unsigned int sticky_badness;
	char *path;
	char *args[5];
	char *cmdstring;
} entropy_source_t;

typedef struct {
#ifdef __WINDOWS__
	SYSTEMTIME tp;
#else
	struct timeval tp;
#endif
	clock_t clock;
	int pid;
#ifdef HAVE_SYS_TIMES_H
	struct tms tmsbuf;
#endif
#ifdef HAVE_GETRUSAGE
	struct rusage usage;
#endif
} seed_t;

/* The SHA block size and message digest sizes, in bytes */
#define SHA_DIGEST_LENGTH 20

#define SHA_DATASIZE    64
#define SHA_DATALEN     16
#define SHA_DIGESTSIZE  20
#define SHA_DIGESTLEN    5

/* PRND common */
#define BITS_PER_BYTE	8

/*
 * The pool size of the PRNG
 * original PRNG has 1024*4 rand pool size...
 * but here, just 2KB buffer is allocated.
 */
#define PRNGD_STATE_SIZE	(1024 * 2)

#ifndef SEED_STAT_INTERVAL
#define SEED_STAT_INTERVAL	17
#endif
#ifndef SEED_EXT_INTERVAL
#define SEED_EXT_INTERVAL	49
#endif

#define MAX_GATHERER_BYTES	100000

/*
 * Define the minimum ENTROPY_NEEDED to be 256, as one can retrieve 255 bytes
 * with on egd-query.
 */
#ifndef ENTROPY_NEEDED
#define ENTROPY_NEEDED		256
#endif

/*
 * Define the minimum of entropy we want to have in the pool on a regular
 * basis. If we come below this threshold, the gatherer processes are fired
 * up continously until we come back over the threshold.
 */
#ifndef THRESHOLD
#define THRESHOLD		4
#endif
#define ENTROPY_THRESHOLD	(ENTROPY_NEEDED * BITS_PER_BYTE * THRESHOLD)


#ifdef __WINDOWS__
#define PATH_TMP        ""
#define PATH_VAR_TMP	"Temporary Internet Files"
#define PATH_PASSWD     "Cookies"

/* yes SWAP :-) but, only windows95/98/Me has this file */
#define PATH_WTMP       "Win386.swp"
#define PATH_UTMP       "system.ini"
#define PATH_SYSLOG     "win.ini"
#endif


/*
 * functions
 */
/* rand.c */
int RAND_init();
int RAND_bytes(unsigned char *buf,int num);
int RAND_add(const void *buf,int num,double entropy);
int RAND_seed(const void *buf,int num);
void RAND_cleanup(void);

/* lutzrand.c */
int lutz_rand_add(const void *buf, int num, double add);
int lutz_rand_bytes(unsigned char *buf, int num);
int lutz_rand_init(int set_pool_size, int set_entropy_needed);
void lutz_rand_clean();

int lutz_is_initialized();
int lutz_is_seeded();

/* lutzseed.c */
int seed_internal(seed_t *seed_p);
int seed_stat(void);
int seed_env();

#ifdef  __cplusplus
}
#endif

#endif /* __OK_RAND_H__ */
