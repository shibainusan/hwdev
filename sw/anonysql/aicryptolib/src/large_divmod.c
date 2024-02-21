/* large_divmod.c */
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

#include "large_num.h"

/*-----------------------------------------------
  large number div & mod (=a/b)
  (I think LN_div_mod() is better)
-----------------------------------------------*/
int LN_div(LNm *a,LNm *b,LNm *div){
	LNm *mod;
	if((mod=LN_alloc(LN_MAX))==NULL) return -1;
	if(LN_div_mod(a,b,div,mod)) return -1;
	LN_free(mod);
	return 0;
}

int LN_mod(LNm *a,LNm *b,LNm *mod){
	LNm *div;
	if((div=LN_alloc(LN_MAX))==NULL) return -1;
	if(LN_div_mod(a,b,div,mod)) return -1;
	LN_free(div);
	return 0;
}

/*-----------------------------------------------
  large number div_mod (*div=a/b,*mod=a%b)
-----------------------------------------------*/
int LN_div_mod(LNm *a,LNm *b,LNm *div,LNm *mod){
	ULONG *bn,*dn,*mn;
	ULONG g[LN_MAX];
	int i,k,BL,MAX,a_len,b_len;

	/** must be a->size = b->size = div->size = mod->size**/
	dn = div->num;
	memset(dn,0,sizeof(ULONG)*LN_MAX);
	mn = mod->num;

	if((a->top>LN_MAX)||(b->top>LN_MAX)){ /* BOF */
		OK_set_error(ERR_ST_LNM_BUFOVERFLOW,ERR_LC_LNM,ERR_PT_LNMDIV,NULL);
		return -1;
	}
	if(b->top==0){ /* woo, it's floating exception!! */
		OK_set_error(ERR_ST_LNM_DIVBYZERO,ERR_LC_LNM,ERR_PT_LNMDIV,NULL);
		return -1;		/* return div=0, mod=0 */
	}

	if((k=LN_zcmp(a,b))<0){
		div->top = 0;
		div->neg = 0;
		memcpy(mn,a->num,sizeof(ULONG)*LN_MAX);
		mod->neg = a->neg;
		mod->top = a->top;
		return 0;		/* return div=0, mod=a */
	}

	if(k==0){
		dn[LN_MAX-1] = 0x01;
		div->top = 1;
		div->neg = 0;
		memset(mn,0,sizeof(ULONG)*LN_MAX);
		mod->neg = 0;
		mod->top = 0;
		return 0;		/* return div=1, mod=0 */
	}

	a_len = a->top;
	b_len = b->top;
	bn  = b->num;

	BL  = LN_MAX-b_len;
	MAX = a_len-b_len;

	memcpy(mn,a->num,sizeof(ULONG)*LN_MAX);
	memcpy(g,mn,sizeof(ULONG)*LN_MAX);

	i = LN_MAX-1-a_len;
	k = MAX;
	mn[i]=0;
	do{
		ULLONG o;
		ULONG d1,l,m;
		int j;

		o = mn[i]; o<<=32; o|=mn[i+1];
		m = bn[BL];

		j=0;
		if(0xffff0000&m){
			if(!(0xff000000&m))
				j=8;
		}else{
			if(0x0000ff00&m)
				j=16;
			else
				j=24;
		}

		if(j){
		    ULLONG p=o;
		    p<<=j;
		    m<<=j;
			/* when b_len==1, mn[i+2] and bn[BL+1] don't have valid number */
			/* so I fixed it, but I should use LN_long_mod(), when a modular
			   number is just one block (32 bit). */
			if(b_len!=1){
				p|=(mn[i+2]>>(32-j));
				m|=(bn[BL+1]>>(32-j));
			}
		    d1 = (ULONG)(p/m);
		}else
		    d1 = (ULONG)(o/m);

DIV_LOOP:
		j=0;
		l=i;
		m=0;	/* kind of flag */
		do{
			ULLONG t;
			ULONG p;

			o|=mn[l+1];
			p = bn[j+BL];
			if(o<(t=(ULLONG)p*d1)){
				if(m){ /* do minus upper f[] */	
					m=l-1;
					while(!mn[m]){
						mn[m]=0xffffffff; m--;
					};
					mn[m]--;

#ifdef __WINDOWS__
					o+= (ULLONG)((ULLONG)0xffffffffffffffff -t)+1;
#else
					o+= (ULLONG)((ULLONG)0xffffffffffffffffLL -t)+1;
#endif
				}else{
					memcpy(&mn[i],&g[i],sizeof(ULONG)*(j));
					d1--;
					o = mn[i]; o<<=32;
					goto DIV_LOOP;
				}
			}else{
				o-=t;
			}
#ifdef __WINDOWS__
			if(o & 0xffffffff00000000) m=l;
#else
			if(o & 0xffffffff00000000LL) m=l;
#endif
			mn[l]=(ULONG)(o >> 32);
			o<<=32; 

			j++;
			l++;
		}while(j<b_len);
		
		o>>=32;
		mn[l]=(ULONG)o;
		dn[LN_MAX-1-k] = (ULONG)d1;
		memcpy(&g[i],&mn[i],sizeof(ULONG)*b_len);

		i++;
		k--;
	}while(k>=0);

	div->neg = a->neg ^ b->neg;
	mod->neg = a->neg;

	if(dn[LN_MAX-1-MAX])
		div->top = MAX+1;
	else
		div->top = MAX;

	mod->top = LN_now_top(BL,mod);
	memset(mn,0,sizeof(ULONG)*(LN_MAX-mod->top));
	return 0;
}
