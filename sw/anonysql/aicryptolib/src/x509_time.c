/* x509_time.c */
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

#include "aiconfig.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ok_x509.h"
#include "ok_rsa.h"
#include "ok_asn1.h"
#include "ok_tool.h"



/*-----------------------------------------
  ASN.1 UTC or GTIME to struct tm
-----------------------------------------*/
int UTC2stm(unsigned char *utc, struct tm *ctm){
	unsigned char buf[16];
	int i;

	memset(ctm,0,sizeof(struct tm));
	memset(buf,0,16);
	if(*utc==ASN1_GENERALIZEDTIME){
		buf[0]=utc[2];buf[1]=utc[3];
		buf[2]=utc[4];buf[3]=utc[5]; i=6;
		ctm->tm_year = atoi(buf) - 1900;
	}else if(*utc==ASN1_UTCTIME){
		buf[0]=utc[2];buf[1]=utc[3]; i=4;
		ctm->tm_year = atoi(buf);
		if(ctm->tm_year<50) ctm->tm_year+=100;	/* 2000 year problem */
	}else{
		OK_set_error(ERR_ST_BADFORMAT,ERR_LC_X509,ERR_PT_X509TIME,NULL);
		return -1;
	}

	buf[2]=0;
	memcpy(buf,&utc[i],2);
	ctm->tm_mon = (atoi(buf)-1) % 12;

	memcpy(buf,&utc[i+2],2);
	ctm->tm_mday = atoi(buf) % 32;

	memcpy(buf,&utc[i+4],2);
	ctm->tm_hour = atoi(buf) % 24;

	memcpy(buf,&utc[i+6],2);
	ctm->tm_min = atoi(buf) % 60;
  
	if((utc[i+8]=='Z')||(utc[i+9]=='+')||(utc[i+10]=='-')){
		ctm->tm_sec = 0;
	}else{
		memcpy(buf,&utc[i+8],2);
		ctm->tm_sec = atoi(buf) % 60;
	}
	return 0;
}

/*-----------------------------------------
  ASN.1 UTC or GTIME to time_t
-----------------------------------------*/
time_t UTC2time_t(unsigned char *utc){
	struct tm ctm;
	time_t ret;

	if(UTC2stm(utc,&ctm)) return -1;
	ret = timegm(&ctm);

	return ret;
} 

/*-----------------------------------------
  ASN.1 struct tm to UTC
-----------------------------------------*/
unsigned char *stm2UTC(struct tm *stm,unsigned char *buf,unsigned char tag){
	unsigned char *ret;

	if(buf==NULL){
		if((ret=(unsigned char*)MALLOC(20))==NULL){
			OK_set_error(ERR_ST_MEMALLOC,ERR_LC_X509,ERR_PT_X509TIME+1,NULL);
			return NULL;
		}
	}else{
		ret=buf;
	}

	if((stm->tm_year<150)&&(tag==ASN1_UTCTIME)){
		ret[0] = ASN1_UTCTIME;
		sprintf(&ret[2],"%.2d%.2d%.2d%.2d%.2d%.2dZ",
			stm->tm_year%100,stm->tm_mon+1,stm->tm_mday,
			stm->tm_hour,stm->tm_min,stm->tm_sec);
	}else{
		ret[0] = ASN1_GENERALIZEDTIME;
		sprintf(&ret[2],"%.4d%.2d%.2d%.2d%.2d%.2dZ",
			stm->tm_year+1900,stm->tm_mon+1,stm->tm_mday,
			stm->tm_hour,stm->tm_min,stm->tm_sec);
	}
	ret[1] = strlen(&ret[2]);

	return ret;
}

/*-----------------------------------------
  struct tm to string
-----------------------------------------*/
char *stm2str(struct tm *stm,int type){
	struct tm *ltm;
	time_t t;
	static char buf[64];
	char mon[12][8]={
		"Jan","Feb","Mar","Apr","May","Jun",
		"Jul","Aug","Sep","Oct","Nov","Dec"};

	/* get local time */
	if((t = timegm(stm))<0)
		ltm = stm;
	else
		ltm = localtime(&t); /* get localtime struct tm */

	/* get string */
	if(type==0){ /* default type */
		sprintf(buf,"%s %.2d %.2d:%.2d:%.2d %.4d %s",
			mon[ltm->tm_mon],ltm->tm_mday,ltm->tm_hour,
			ltm->tm_min,ltm->tm_sec,ltm->tm_year+1900,(t<0)?("UTC"):(""));
	}else{
		sprintf(buf,"%.2d/%.2d/%.2d %.2d:%.2d %s",
			ltm->tm_year%100,ltm->tm_mon+1,ltm->tm_mday,
			ltm->tm_hour,ltm->tm_min,(t<0)?("UTC"):(""));
	}
	return buf;
}

char *UTC2str(unsigned char *utc,int type){
	struct tm stm;
	char *ret;

	if(UTC2stm(utc,&stm)<0) return NULL;

	ret = stm2str(&stm,type);
	return ret;
}

/*-----------------------------------------
  compare struct tm
  output : b is newer than a ... positive
         : same ... 0
		 : b is older than a ... negative
-----------------------------------------*/
int stmcmp(struct tm *a, struct tm *b){
	int i;

	if(i=b->tm_year-a->tm_year) goto done;
	if(i=b->tm_mon -a->tm_mon)  goto done;
	if(i=b->tm_mday-a->tm_mday) goto done;
	if(i=b->tm_hour-a->tm_hour) goto done;
	if(i=b->tm_min -a->tm_min)  goto done;
	if(i=b->tm_sec -a->tm_sec)  goto done;

	i=0;
done:
	return i;
}

#ifndef HAVE_TIMEGM
/*-----------------------------------------
  return time_t from struct tm (UTC)
-----------------------------------------*/
time_t timegm(struct tm *stm){
	time_t ret;

	if((ret = mktime(stm))<0) goto done;
#if defined( __WINDOWS__ ) || defined( __CYGWIN__ )
	ret -= _timezone;
#else
	ret -= timezone;
#endif
done:
	return ret;
}
#endif
