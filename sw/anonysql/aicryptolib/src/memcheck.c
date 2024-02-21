/* memckeck.c */
/*
 * this is memory test functions for AiCrypto.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <malloc.h>
#include <crtdbg.h>

#include "ok_rand.h"
#include "large_num.h"
#include "ok_ecc.h"
#include "ok_tool.h"

#ifdef   _DEBUG
#define  SET_CRT_DEBUG_FIELD(a) \
            _CrtSetDbgFlag((a) | _CrtSetDbgFlag(_CRTDBG_REPORT_FLAG))
#define  CLEAR_CRT_DEBUG_FIELD(a) \
            _CrtSetDbgFlag(~(a) & _CrtSetDbgFlag(_CRTDBG_REPORT_FLAG))
#else
#define  SET_CRT_DEBUG_FIELD(a)   ((void) 0)
#define  CLEAR_CRT_DEBUG_FIELD(a) ((void) 0)
#endif



/*--------------------------------------*/
int test_rand_memory(){
	_CrtMemState s1, s2, s3;

	_CrtMemCheckpoint(&s1);
	test_rand();
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 1;}

	return 0;
}

/*--------------------------------------*/
int test_large_num_memory(){
	_CrtMemState s1, s2, s3;
#if 1
	/* check plus minus */
	_CrtMemCheckpoint(&s1);
	test_plus_minus();
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 1;}

	_CrtMemCheckpoint(&s1);
	test_mul_div_mod();
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 2;}

	_CrtMemCheckpoint(&s1);
	test_karatsuba();
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 3;}

	_CrtMemCheckpoint(&s1);
	test_shift();
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 4;}

	_CrtMemCheckpoint(&s1);
	test_long();
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 5;}

	_CrtMemCheckpoint(&s1);
    test_ext_euclid();
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 6;}

	_CrtMemCheckpoint(&s1);
	test_exp_mod();
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 7;}
#endif

	_CrtMemCheckpoint(&s1);
	test_rsa();
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 8;}

	_CrtMemCheckpoint(&s1);
    test_prime();
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 9;}

	_CrtMemCheckpoint(&s1);
	test_sqrt();
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 10;}

	return 0;
}

/*--------------------------------------*/
int test_des_memory(){
	_CrtMemState s1, s2, s3;

	_CrtMemCheckpoint(&s1);
	test_des();
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 1;}

	return 0;
}

/*--------------------------------------*/
int test_rc2_memory(){
	_CrtMemState s1, s2, s3;

	_CrtMemCheckpoint(&s1);
	test_rc2();
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 1;}

	return 0;
}
	
/*--------------------------------------*/
int test_rc4_memory(){
	_CrtMemState s1, s2, s3;

	_CrtMemCheckpoint(&s1);
	test_rc4();
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 1;}

	return 0;
}
	
/*--------------------------------------*/
int test_md2_memory(){
	_CrtMemState s1, s2, s3;

	_CrtMemCheckpoint(&s1);
	test_md2();
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 1;}

	return 0;
}

/*--------------------------------------*/
int test_md5_memory(){
	_CrtMemState s1, s2, s3;

	_CrtMemCheckpoint(&s1);
	test_md5();
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 1;}

	return 0;
}

/*--------------------------------------*/
int test_sha1_memory(){
	_CrtMemState s1, s2, s3;

	_CrtMemCheckpoint(&s1);
	test_sha1();
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 1;}

	return 0;
}

/*--------------------------------------*/
int test_rsa_memory(){
	_CrtMemState s1, s2, s3;

	_CrtMemCheckpoint(&s1);
	test_rsa_pubprv();
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 1;}

	_CrtMemCheckpoint(&s1);
	test_rsa_keygen();
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 2;}

	_CrtMemCheckpoint(&s1);
	test_rsa_der_asn1();
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 3;}

	return 0;
}

/*--------------------------------------*/
int test_dsa_memory(){
	_CrtMemState s1, s2, s3;

	_CrtMemCheckpoint(&s1);
	test_dsapm_der();
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 1;}

	_CrtMemCheckpoint(&s1);
	test_dsakey_der();
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 2;}

	_CrtMemCheckpoint(&s1);
	test_dsa_sig();
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 3;}

	_CrtMemCheckpoint(&s1);
	test_dsa_gen();
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 4;}

	return 0;
}

/*--------------------------------------*/
int test_ecc_memory(){
	_CrtMemState s1, s2, s3, s4;
	ECParam *E;
	int j;

	_CrtMemCheckpoint(&s4);

	E=ECPm_get_std_parameter(ECP_X962_prime192v1);

	/* ecc add sub */
	_CrtMemCheckpoint(&s1);
	test_point_addsub(E);
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 1;}

	/* ecc multi */
	_CrtMemCheckpoint(&s1);
	test_point_multi(E);
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 2;}

	/* ecc projective calc */
	_CrtMemCheckpoint(&s1);
	test_point_projective(E);
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 3;}
	
	/* ecc projective calc (pow2) */
	_CrtMemCheckpoint(&s1);
	test_point_ppow2(E);
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 4;}

	ECPm_free(E);
	_CrtMemCheckpoint(&s1);
	if ( _CrtMemDifference(&s3,&s1,&s4)){
		_CrtMemDumpStatistics( &s3 ); return 5;}

	/* ecc generation test */
	_CrtMemCheckpoint(&s1);
	E = ECPm_gen_parameter(160);
	if(j=ECPm_verify_parameter(E))
		printf("verification error occured!! code=%d\n",j);
	else
		printf("elliptic curve verification ok!!\n");
	ECPm_free(E);
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 6;}

	/* ecc der test */
	_CrtMemCheckpoint(&s1);
	test_ecc_der();
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 7;}

	return 0;
}

/*--------------------------------------*/
int test_ecdsa_memory(){
	_CrtMemState s1, s2, s3;

	_CrtMemCheckpoint(&s1);
	test_ecdsa_signature();
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 1;}

	_CrtMemCheckpoint(&s1);
	test_ecdsakey_der();
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 2;}

	return 0;
}
/*--------------------------------------*/
int test_asn1_memory(){
	_CrtMemState s1, s2, s3;

	/* base 64 check */
	_CrtMemCheckpoint(&s1);
	test_asn1_oid();
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 1;}

	return 0;
}
/*--------------------------------------*/
int test_uconv_memory(){
	_CrtMemState s1, s2, s3;

	_CrtMemCheckpoint(&s1);
	test_jis();
	free_u2j_table();
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 1;}

	_CrtMemCheckpoint(&s1);
	test_sjis();
	free_u2j_table();
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 2;}

	_CrtMemCheckpoint(&s1);
	test_euc();
	free_u2j_table();
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 3;}

	return 0;
}

/*--------------------------------------*/
int test_x509_memory(){
	_CrtMemState s1, s2, s3;
#if 1
	/* x509 file check */
	_CrtMemCheckpoint(&s1);
	test_x509_cert();
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 1;}

	_CrtMemCheckpoint(&s1);
	test_x509_certpair();
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 2;}

	_CrtMemCheckpoint(&s1);
	test_x509_crl();
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 3;}

	_CrtMemCheckpoint(&s1);
	test_x509_req();
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 4;}

	_CrtMemCheckpoint(&s1);
	test_x509_certlist();
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 5;}
#endif
	_CrtMemCheckpoint(&s1);
	test_x509_certext();
	free_u2j_table();
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 6;}

	_CrtMemCheckpoint(&s1);
	test_tool_sign();
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 7;}

	return 0;
}

/*--------------------------------------*/
int test_pem_memory(){
	_CrtMemState s1, s2, s3;

	/* base 64 check */
	_CrtMemCheckpoint(&s1);
	test_base64();
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 1;}

	/* PEM encrypt & decrypt check */
	_CrtMemCheckpoint(&s1);
	test_pem_cry();
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 2;}

	/* PEM message file check */
	_CrtMemCheckpoint(&s1);
	test_pem_msg();
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 3;}

	/* PEM PKI file check */
	_CrtMemCheckpoint(&s1);
	test_pem_pki();
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 4;}

	/* PEM PKCS file check */
	_CrtMemCheckpoint(&s1);
	test_pem_pkcs();
	free_u2j_table();
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 5;}

	return 0;
}

/*--------------------------------------*/
int test_pkcs_memory(){
	_CrtMemState s1, s2, s3;

	/* pkcs file check */
	_CrtMemCheckpoint(&s1);
	test_pkcs_rwfile();
	free_u2j_table();
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 1;}

	/* pkcs 7 Signed & Envelope check */
	_CrtMemCheckpoint(&s1);
	test_pkcs_p7();
	free_u2j_table();
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 2;}

	/* pkcs 8 file check */
	_CrtMemCheckpoint(&s1);
	test_pkcs_p8();
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 3;}

	return 0;
}
/*--------------------------------------*/
int test_store_memory(){
	_CrtMemState s1, s2, s3;
#if 1
	/* store new & add check */
	_CrtMemCheckpoint(&s1);
	test_store_new();
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 1;}
#endif
	/* store open & seach check */
	_CrtMemCheckpoint(&s1);
	test_store_search();
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 2;}

	/* store open & seach check */
	_CrtMemCheckpoint(&s1);
	test_manager_new();
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 3;}

	return 0;
}

/*--------------------------------------*/
int test_smime_memory(){
	_CrtMemState s1, s2, s3;

	/* smime check */
	_CrtMemCheckpoint(&s1);
	test_smime();
	free_u2j_table();
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 1;}

	return 0;
}

/*--------------------------------------*/
int test_ssl_memory(){
	_CrtMemState s1, s2, s3;

	/* ssl check */
	_CrtMemCheckpoint(&s1);
	test_ssl_mem();
	free_u2j_table();
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 1;}

	return 0;
}

/*--------------------------------------*/
int test_wincry_memory(){
	_CrtMemState s1, s2, s3;

	/* wincry cert check */
	_CrtMemCheckpoint(&s1);
	test_wincry_cert();
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 1;}

	/* wincry key check */
	_CrtMemCheckpoint(&s1);
	test_wincry_key();
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 2;}

	/* wincry crl check */
	_CrtMemCheckpoint(&s1);
	test_wincry_crl();
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 3;}

	/* wincry clist check */
	_CrtMemCheckpoint(&s1);
	test_wincry_clist();
	free_u2j_table();
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 4;}

	return 0;
}

/*--------------------------------------*/
int test_cmp_memory(){
	_CrtMemState s1, s2, s3;

	/* CMP header check */
	_CrtMemCheckpoint(&s1);
	if(test_cmp_header()) return -1;
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 1;}
#if 1
	/* CMP body check */
	_CrtMemCheckpoint(&s1);
	if(test_cmp_body()) return -1;
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 2;}
#endif
	/* CMP message check */
	_CrtMemCheckpoint(&s1);
	if(test_cmp_message()) return -1;
	_CrtMemCheckpoint(&s2);

	if ( _CrtMemDifference(&s3,&s1,&s2)){
		_CrtMemDumpStatistics( &s3 ); return 3;}

	return 0;
}

/*-------------------------------------------
	test main
---------------------------------------------*/
int main(int argc, char **argv){
	_CrtMemState s1, s2, s3;
	int i;

	_CrtSetReportMode( _CRT_WARN, _CRTDBG_MODE_FILE );
	_CrtSetReportFile( _CRT_WARN, _CRTDBG_FILE_STDOUT );
	_CrtSetReportMode( _CRT_ERROR, _CRTDBG_MODE_FILE );
	_CrtSetReportFile( _CRT_ERROR, _CRTDBG_FILE_STDOUT );
	_CrtSetReportMode( _CRT_ASSERT, _CRTDBG_MODE_FILE );
	_CrtSetReportFile( _CRT_ASSERT, _CRTDBG_FILE_STDOUT );

	//SET_CRT_DEBUG_FIELD( _CRTDBG_DELAY_FREE_MEM_DF);
	SET_CRT_DEBUG_FIELD( _CRTDBG_LEAK_CHECK_DF );
	SET_CRT_DEBUG_FIELD( _CRTDBG_CHECK_ALWAYS_DF );
	_CrtMemDumpAllObjectsSince(&s1);
	_CrtMemCheckpoint( &s1 );

	OK_set_errout(stderr);

	/* test 0 -- rand */
	if(i=test_rand_memory()){
		printf("memory check error -- test_rand_memory : %d\n",i);
		exit(1);
	}

	/* every random fuction, such as RAND_add, RAND_byte,...
	 * needs allocated static memory. So, this timing is better
	 * to alloc random pool memory because of memory leak and
	 * status issue.
	 */
	RAND_init();

#if 0
	/* test 1-1 -- large number */
	if(i=test_large_num_memory()){
		printf("memory check error -- test_large_num_memory : %d\n",i);
		exit(1);
	}
#endif

	/* test 2-1 -- DES */
	if(i=test_des_memory()){
		printf("memory check error -- test_des_memory : %d\n",i);
		exit(1);
	}
	/* test 2-2 -- RC2 */
	if(i=test_rc2_memory()){
		printf("memory check error -- test_rc2_memory : %d\n",i);
		exit(1);
	}
	/* test 2-3 -- RC4 */
	if(i=test_rc4_memory()){
		printf("memory check error -- test_rc2_memory : %d\n",i);
		exit(1);
	}

	/* test 3-1 -- MD2 */
	if(i=test_md2_memory()){
		printf("memory check error -- test_md2_memory : %d\n",i);
		exit(1);
	}
	/* test 3-2 -- MD5 */
	if(i=test_md5_memory()){
		printf("memory check error -- test_md5_memory : %d\n",i);
		exit(1);
	}
	/* test 3-3 -- SHA1 */
	if(i=test_sha1_memory()){
		printf("memory check error -- test_sha1_memory : %d\n",i);
		exit(1);
	}

#if 0
	/* test 4-1 -- RSA */
	if(i=test_rsa_memory()){
		printf("memory check error -- test_rsa_memory : %d\n",i);
		exit(1);
	}
	/* test 4-2 -- DSA */
	if(i=test_dsa_memory()){
		printf("memory check error -- test_dsa_memory : %d\n",i);
		exit(1);
	}
#endif
#if 0
	/* test 4-3 -- Elliptic Curve */
	if(i=test_ecc_memory()){
		printf("memory check error -- test_ecc_memory : %d\n",i);
		exit(1);
	}
	/* test 4-4 -- ECDSA */
	if(i=test_ecdsa_memory()){
		printf("memory check error -- test_ecdsa_memory : %d\n",i);
		exit(1);
	}
#endif
#if 1
	/* test 5 -- ASN.1 */
	if(i=test_asn1_memory()){
		printf("memory check error -- test_asn1_memory : %d\n",i);
		exit(1);
	}
	/* test -- UCONV */
	if(i=test_uconv_memory()){
		printf("memory check error -- test_uconv_memory : %d\n",i);
		exit(1);
	}
	/* test 6 -- X.509 */
	if(i=test_x509_memory()){
		printf("memory check error -- test_x509_memory : %d\n",i);
		exit(1);
	}
#endif
#if 1
	/* test 7 -- PEM */
	if(i=test_pem_memory()){
		printf("memory check error -- test_pem_memory : %d\n",i);
		exit(1);
	}
	/* test 8 -- PKCS */
	if(i=test_pkcs_memory()){
		printf("memory check error -- test_pkcs_memory : %d\n",i);
		exit(1);
	}
#endif
#if 1
	/* test 9 -- STORE */
	if(i=test_store_memory()){
		printf("memory check error -- test_store_memory : %d\n",i);
		exit(1);
	}

	/* test 9 -- S/MIME */
	if(i=test_smime_memory()){
		printf("memory check error -- test_smime_memory : %d\n",i);
		exit(1);
	}

	/* test 10 -- SSL */
	if(i=test_ssl_memory()){
		printf("memory check error -- test_ssl_memory : %d\n",i);
		exit(1);
	}

	/* test 11 -- wincry */
	if(i=test_wincry_memory()){
		printf("memory check error -- test_wincry_memory : %d\n",i);
		exit(1);
	}
#endif
	/* test 12 -- cmp memory */
	if(i=test_cmp_memory()){
		printf("memory check error -- test_cmp_memory : %d\n",i);
		exit(1);
	}
	RAND_cleanup();

	_CrtMemCheckpoint( &s2 );
	if ( _CrtMemDifference( &s3, &s2, &s1 ) )
		_CrtMemDumpStatistics( &s3 );

	return 0;
}
