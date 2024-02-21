#include <stdio.h>
#include "ok_rsa.h"
#include "ok_asn1.h"
#include "ok_md5.h"
#include "ok_rand.h"
#include "large_num.h"
#include "minissl.h"
#include "anonysqllib.h"
#include "..\authent\anonysql.h"

static void gcd(const LNm *_a ,const LNm *_b , LNm *ret);
static void GenerateBlindFactor(LNm *bf, LNm *n);
static int DoSign(MiniSSL_INFO *si , unsigned char *hash, int hashSize, unsigned char *signedHash, int *signedHashSize);

Prvkey_RSA *LoadAuthorityPrvKey(int authority)
{
	unsigned char *buf;
	char filename[256];
	Prvkey_RSA *ret;

	//秘密キー読み込み
	sprintf(filename, ".\\authority\\%d.key",authority);
	buf = ASN1_read_der(filename);
	if( buf == NULL ){
		printf("failed to load %s\n",filename);
		return NULL;
	}
	ret = ASN1_read_rsaprv(buf);
//	free(buf);
	return ret;
}

int DoSign(MiniSSL_INFO *si , unsigned char *hash, int hashSize, unsigned char *signedHash, int *signedHashSize)
{
	int command = REQUEST_SIGN;

	//署名要求コマンド送信
	if(MiniSSL_Put(si , (const unsigned char *)&command , sizeof(int)) != sizeof(int)){
		return FALSE;
	}
	//ハッシュサイズ送信
	if(MiniSSL_Put(si , (const unsigned char *)&hashSize , sizeof(int)) != sizeof(int)){
		return FALSE;
	}
	//ハッシュ本体送信
	if(MiniSSL_Put(si , hash , hashSize) != hashSize){
		return FALSE;
	}
	if(MiniSSL_Flush(si) != sizeof(int)+sizeof(int)+hashSize){
		return FALSE;
	}

	//署名したハッシュサイズ受信
	if( MiniSSL_Receive(si , (unsigned char *)signedHashSize , sizeof(int)) != sizeof(int)){
		return FALSE;
	}
	if( *signedHashSize >= LN_MAX ){
		printf("too large signed hash size:%d\n",*signedHashSize);
		return FALSE;
	}
	//署名したハッシュ本体受信
	if( MiniSSL_Receive(si , signedHash , *signedHashSize) != *signedHashSize){
		return FALSE;
	}

	return TRUE;
}

int BlindSign(MiniSSL_INFO *si , unsigned char *sql ,Pubkey_RSA *pubKey, LNm *cert)
{
	unsigned char hash[MD5_SIZE];
	unsigned char blindedHash[LN_MAX];
	unsigned char signedHash[LN_MAX];
	int signedHashSize;
	LNm *bf,*ebf,*ubf,*lhash,*lblindedHash;
	int ret = FALSE;
	int sendBytes;

	//変数の初期化とゼロクリア
	ubf = LN_alloc();
	lhash = LN_alloc();
	bf = LN_alloc();
	ebf = LN_alloc();
	lblindedHash = LN_alloc();
	memset(blindedHash , 0 , sizeof(blindedHash));

	//ハッシュ生成
	OK_MD5(strlen(sql) ,sql, hash);

	//blinding factor生成
	GenerateBlindFactor(bf , pubKey->n);
#ifdef TRACE_ON 
	printf("bf: "); LN_print(bf); 
#endif
	//blinding factorを公開キーで暗号化
	LN_exp_mod(bf , pubKey->e ,pubKey->n, ebf );
#ifdef TRACE_ON 
	printf("encrypted bf: "); LN_print(ebf);
#endif
	//バイナリ列のハッシュを演算できるようにLNm型にする
	LN_set_num_c(lhash , MD5_SIZE, hash);
#ifdef TRACE_ON 
	printf("lhash:"); LN_print(lhash);
#endif
	//ハッシュをブラインド化(hash*rand^e mod n)
	LN_mul_mod( ebf , lhash , pubKey->n , lblindedHash);
#ifdef TRACE_ON 
	printf("toserver: "); LN_print(lblindedHash);
#endif
	sendBytes = LN_now_byte(lblindedHash);
	//送信のためにLNmからバイナリ列に変換
	LN_get_num_c(lblindedHash , sendBytes , blindedHash);

	//認証サーバに送って署名をもらう
	if( DoSign(si , blindedHash , sendBytes, signedHash , &signedHashSize) != TRUE ){
		goto FAIL;
	}
	//受信したバイナリ列をLNm型に
	LN_set_num_c(lblindedHash , signedHashSize , signedHash);

#ifdef TRACE_ON 
	printf("fromserver: "); LN_print(lblindedHash);
#endif

	//blinding factorの逆元を得る
	LN_mod_inverse(bf ,pubKey->n , ubf);

#ifdef TRACE_ON 
	printf("invbf: "); LN_print(ubf);
	//逆元が正しいかテスト
	LN_mul_mod(ubf , bf , pubKey->n , cert);
	printf("bf*invbf=1: "); LN_print(cert);
#endif

	//unblinding ブラインド解除
	LN_mul_mod(lblindedHash , ubf ,  pubKey->n , cert); 
#ifdef TRACE_ON
	printf("cert: "); LN_print(cert);
#endif

	//署名検証
	if( CheckCert(cert , lhash ,  pubKey) != TRUE){
		printf("invalid request cert.\n");
		goto FAIL;
	}else{
		SockFrame_DebugOut("cert check ok.\n");
	}
	ret = TRUE;

FAIL:
	LN_free(bf);
	LN_free(ebf);
	LN_free(ubf);
	LN_free(lhash);
	LN_free(lblindedHash);
	return ret;
}


int CheckCert(LNm *cert, LNm *hash, Pubkey_RSA *key)
{
	LNm *w;
	int ret;

	w = LN_alloc();
	//署名を公開キーで復号化してハッシュを得る
	LN_exp_mod(cert , key->e ,key->n, w );
	//元ハッシュと署名から得たハッシュを比較
	if( LN_cmp( w , hash) == LN_EQUAL ){
		ret = TRUE;
	}else{
		ret = FALSE;
	}

	LN_free(w);
	return ret;
}


//blinding factor生成
void GenerateBlindFactor(LNm *bf, LNm *n)
{
	LNm *ret;
	unsigned char c = 1;
	unsigned char d = 1;
	LNm *one;
	unsigned char rand[MD5_SIZE];

	ret = LN_alloc();
	//比較のための定数”１”を用意
	one = LN_alloc();
	LN_set_num_c(one , 1 , &c);

	do{
#if 1
		//ブラインド署名用の秘密の乱数生成
		RAND_bytes(rand , MD5_SIZE);
		LN_set_num_c(bf , MD5_SIZE, rand);
#else
		//ブラインドファクタを１にすると普通の署名になる
		memset(rand , 0 , sizeof(rand));
		LN_set_num_c(bf , 1, &d);
#endif
		
		//bfがnより小さい必要あり(bf < n)
		if( LN_cmp( bf , n ) != -1 ){
			break;
		}
		//nとblinding factorは互いに素である必要あり
		gcd(n , bf , ret);
		//LN_print(rer);
		if( LN_cmp( ret , one ) == LN_EQUAL ){
			break;
		}
	}while(1);

	LN_free(one);
	LN_free(ret);
}

//aとbの最大公約数をretに格納
//ユークリッドの互除法
void gcd(const LNm *_a ,const LNm *_b , LNm *ret)
{
	LNm *r,*a,*b;
	LNm *zero;

	r = LN_alloc();
	zero = LN_alloc();
	LN_clean(zero);

	//a > b
//	if( LN_cmp(_a ,_b ) == 1 ){
		//_aと_bはこの関数内ではいじらないのでconst修飾する。
		a = LN_clone((LNm *)_a);
		b = LN_clone((LNm *)_b);
//	}else{ //a < b
//		b = LN_clone(_a);
//		a = LN_clone(_b);
//	}
	//r > 0
	while(1){
		// r = a % b
		LN_mod(a , b , r);
		if( LN_cmp(r , zero) == 0 ){
			break;
		}
		// a = b
		LN_copy(b, a);
		// b = r
		LN_copy(r , b);
	}
	LN_copy(b , ret);
	LN_free(a);
	LN_free(b);
	LN_free(r);
	LN_free(zero);
}


Pubkey_RSA *LoadAuthorityPubKey(int authority)
{
	unsigned char *buf;
	char filename[256];
	Pubkey_RSA *ret;

	//秘密キー読み込み
	sprintf(filename, ".\\authority\\%d.key",authority);
	buf = ASN1_read_der(filename);
	if( buf == NULL ){
		//SockFrame_DebugOut("failed to load %s\n",filename);
		return NULL;
	}
	ret = ASN1_read_rsapub(buf);

	return ret;
}

//sizeバイト数の署名certと平文requestが正しいか検証する。
//\authorityフォルダ内の権限キーを昇順に使って検証する。
//検証に成功した場合は権限コード（正の整数）を返す。
//失敗した場合は負の整数を返す。
int VerifyRequest(int size, UCHAR *_cert, UCHAR *request)
{
	int count = 1;
	Pubkey_RSA *pub;
	LNm *hash;
	LNm *cert;
	unsigned char buf[MD5_SIZE];

	//ハッシュ生成
	OK_MD5(strlen(request) ,request, buf);
	//charからLNm型に変換
	hash = LN_alloc();
	LN_set_num_c(hash , MD5_SIZE, buf);
	cert = LN_alloc();
	LN_set_num_c(cert , size, _cert);

	do{
		pub = LoadAuthorityPubKey(count);
		if( pub == NULL ){
			//全てのキーで検証に失敗
			break;
		}
		//署名検証
		if( CheckCert(cert,hash,pub) == TRUE ){
			LN_free(cert);
			LN_free(hash);
			RSAkey_free((Key*)pub);
			return count;
		}
		RSAkey_free((Key*)pub);
		count++;
	}while(1);

	LN_free(cert);
	LN_free(hash);
	return -1;
}



