/* defalgo.c */
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

#include "ok_x509.h"
#include "ok_pkcs.h"
#include "ok_pem.h"

/* crypto extention flag, it's really "extention" use */
unsigned char ai_ext_flag[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

/* set default algorithm */
void OK_set_p12_cb_cry_algo(int algo){
	default_p12_cb_cry_algo	= algo;
}

void OK_set_p12_kb_cry_algo(int algo){
	default_p12_kb_cry_algo = algo;
}

void OK_set_p7s_digest_algo(int algo){
	default_p7s_digest_algo= obj_sig2hash(algo);
}

void OK_set_p7env_cry_algo(int algo){
	default_p7env_cry_algo = algo;
}

void OK_set_p7env_passwd_len(int bit_len){
	default_p7env_passwd_len = bit_len;
}

void OK_set_p5_cry_algo(int algo){
	default_p5_cry_algo = algo;
}

void OK_set_pem_cry_algo(int algo){
	default_pem_cry_algo = algo;
}

void OK_set_sign_digest_algo(int algo){
	sign_digest_algo = obj_sig2hash(algo);
}

void OK_set_cert_sig_algo(int algo){
	default_cert_sig_algo = algo;
}

void OK_set_crl_sig_algo(int algo){
	default_crl_sig_algo = algo;
}

void OK_set_ext_flag(int locate, unsigned char flag){
	ai_ext_flag[locate] = flag;
}

void OK_add_ext_flag(int locate, unsigned char flag){
	ai_ext_flag[locate] |= flag;
}

void OK_del_ext_flag(int locate, unsigned char flag){
	ai_ext_flag[locate] &= ~flag;
}

/*
 * get current default algorithm
 */

int OK_get_p12_cb_cry_algo(){
	return default_p12_cb_cry_algo;
}

int OK_get_p12_kb_cry_algo(){
	return default_p12_kb_cry_algo;
}

int OK_get_p7s_digest_algo(){
	return default_p7s_digest_algo;
}

int OK_get_p7env_cry_algo(){
	return default_p7env_cry_algo;
}

int OK_get_p7env_passwd_len(){
	return default_p7env_passwd_len;
}

int OK_get_p5_cry_algo(){
	return default_p5_cry_algo;
}

int OK_get_pem_cry_algo(){
	return default_pem_cry_algo;
}

int OK_get_sign_digest_algo(){
	return sign_digest_algo;
}

int OK_get_cert_sig_algo(){
	return default_cert_sig_algo;
}

int OK_get_crl_sig_algo(){
	return default_crl_sig_algo;
}

unsigned char OK_get_ext_flag(int locate){
	return ai_ext_flag[locate];
}

