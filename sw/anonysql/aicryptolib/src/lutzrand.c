/*
 * Lutz's own PRNG :-)
 *
 * (Versions of "prngd" before 0.9.0 did use the OpenSSL internal PRNG.)
 *
 * Technical description:
 *
 * The entropy data is kept in a "pool" of large size (default size is 4kB
 * = 4096 bytes rounded up to full 20bytes = 4100 bytes) (* 8 bits).
 *
 * Adding seed:
 * ============
 *
 * Whenever entropy is added, an SHA1-hash of a (20+64)byte block at a
 * moving "position is created and a block of 20bytes of the new data is
 * hashed in. The 20byte hash is then written back (to be more precise:
 * XORed with the bytes at position) and position is advanced by 20bytes.
 *
 * Requesting random data:
 * =======================
 *
 * Whenever entropy is requested, the same (20+64)byte block is hashed. The
 * 20byte hash output is given back as "random data". The 20byte block is
 * also XORed into the bytes at position. Then position is advanced by 20bytes
 * to retrieve the next "random bytes" until the request is satisfied.
 *
 * In order to improve the mixing (and security), each time random data is
 * requested, the pool is mixed completly before and after serving the
 * request.
 *
 * Security:
 * =========
 *
 * Protection against unseeded PRNG:
 * - Random data is only returned, when enough entropy was seeded into the pool.
 *
 * Protection against reading PRNG state from memory/core dump:
 * - Whenever entropy is retrieved, the pool is completly mixed, entropy is
 *   retrieved, then the pool is again completly mixed. So retrieval of
 *   the state from memory would have to happen before the second mixing.
 *   Retrieval from core won't work anyway, since the second mixing will
 *   happen, even before rand_bytes() returns with the random bytes just
 *   generated.
 * - All memory locations temporarily used are memset() to 0 when finishing
 *   an operation.
 *
 * Acknowledgements:
 * =================
 *
 * First versions of PRNGD (before 0.9.0) utilized the OpenSSL PRNG by linking
 * libcrypto. Functionality like the "complete mix before retrieve" needed to
 * be done with a wrapper, the pool size was fixed and some other limitations
 * applied. Therefore the PRNG needed to be included into "prngd".
 *
 * Because the OpenSSL license is not as flexible as mine, I decided to create
 * my own PRNG. Its design is based on my experience with the OpenSSL PRNG
 * and additionally heavily inspired by Peter Gutmann's work.
 *   http://www.cs.auckland.ac.nz/~pgut001/
 * and especially the text
 *   http://www.cryptoengines.com/~peter/06_random.pdf
 * (See the last reference, section cryptlib-PRNG, for the "20+64"
 * technique :-)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ok_rand.h"
#include "ok_sha1.h"

static int position = 0, pool_size = 0, pool_seeded = 0;
static unsigned char *pool = NULL;
static double entropy = 0, entropy_needed;

void rand_flip_bits()
{
	int i;

	/*
	 * Flip all bits in the pool
	 */
	for (i = 0; i < pool_size; i++)
		pool[i] ^= 0xff;
}

int lutz_rand_add(const void *buf, int num, double add)
{
	int i, j, end;
	unsigned char temp_md[SHA_DIGEST_LENGTH];
	SHA1_CTX c;

	if(pool==NULL){
		OK_set_error(ERR_ST_RAND_NOPOOL,ERR_LC_RAND,ERR_PT_LUTZRAND,NULL);
		return -1;
	}

	/*
	 * Mix new bytes into the pool. To perform this operation, read
	 * SHA_DIGEST_LENGTH bytes starting from (position-SHA_DIGEST_LENGTH)
	 * and the next 64bytes. Then "add" the new bytes, finally write it back
	 * to "position" and advance "position".
	 */
	for (i = 0; i < num; i += SHA_DIGEST_LENGTH) {
		SHA1init(&c);
		/*
		 * Read back entropy from the pool while taking account of wrap around
		 * effects. First read 20bytes from "left of the current position",
		 * then 64bytes starting at position.
		 */
		if (position == 0)
			SHA1update(&c, pool + pool_size - SHA_DIGEST_LENGTH, SHA_DIGEST_LENGTH);
		else
			SHA1update(&c, pool + position - SHA_DIGEST_LENGTH, SHA_DIGEST_LENGTH);
    
		end = position + 64;
		if (end < pool_size)
			SHA1update(&c, pool + position, 64);

		else {
			end %= pool_size;
			SHA1update(&c, pool + position, pool_size - position);
			SHA1update(&c, pool, end);
		}

		SHA1update(&c, (unsigned char *)buf + i,
			(num - i > SHA_DIGEST_LENGTH) ? SHA_DIGEST_LENGTH : (num - i));
		SHA1final(temp_md,&c);

		for (j = 0; j < SHA_DIGEST_LENGTH; j++)
			pool[position + j] ^= temp_md[j];

		position += SHA_DIGEST_LENGTH;
		position %= pool_size;	/* wrap, if needed */
		if (position == 0)
			rand_flip_bits();		/* when wrapped, flip once */
	}

	memset(temp_md, 0, SHA_DIGEST_LENGTH);
	memset(&c, 0, sizeof(c));

	/*
	 * Register the weighted entropy, but of course there cannot be more
	 * entropy in the pool than its size.
	 */
	entropy += add;
	if (entropy > pool_size)
		entropy = pool_size;

	/*
	 * The "entropy" counter is incremented and decremented to reflect the
	 * entropy added or "used up" by querying. Once enough entropy was added
	 * to satisfy the minimum requirement, PRNGD will continue to serve
	 * random numbers using the "pseudo" RNG even if the entropy count goes
	 * back down below the minimum.
	 */
	if (entropy >= entropy_needed)
		pool_seeded = 1;

	return 0;
}

int lutz_rand_bytes(unsigned char *buf, int num)
{
	int i,j,lps;
	unsigned char temp_md[SHA_DIGEST_LENGTH];
	ULONG *lpool,*lmd;

	if(pool==NULL){
		OK_set_error(ERR_ST_RAND_NOPOOL,ERR_LC_RAND,ERR_PT_LUTZRAND+1,NULL);
		return -1;
	}

	/*
	 * Sanity: only return "random bytes", when the pool was successfully
	 * seeded.
	 */
	if (!pool_seeded){
		OK_set_error(ERR_ST_RAND_NOTSEEDED,ERR_LC_RAND,ERR_PT_LUTZRAND+1,NULL);
		return -1;
	}

	/*
	 * Lutz' PRNG has simple and efficient idea.
	 * see original code and comment in lutzrand.c.org.
	 * 1. mixing "rand pool" first.
	 * 2. get random bytes and return them.
	 * 3. mixing "rand pool" again.
	 * therefore, it will be hard to guess its memory bytes from returning
	 * value. moreover, if somebody could gain access to the memory, he would
	 * not find any (useful) traces of the pool state left.
	 */
	/* but original code is a little bit slow...
	 * so, I changed it faster and I hope that this doesn't have security hole X(
	 */
	OK_SHA1(256,pool,temp_md);

	lps   = (pool_size>>2);
	lpool = (ULONG*)pool;
	lmd   = (ULONG*)temp_md;

	lpool[0] ^= lpool[lps-1] ^ lmd[4];
	lpool[1] ^= lpool[lps-4] ^ lmd[0];
	lpool[2] ^= lpool[lps-2] ^ lmd[2];
	lpool[3] ^= lpool[lps-3] ^ lmd[1];
	lpool[4] ^= lpool[lps-5] ^ lmd[3];
	for (i = 5; i < lps; i+=5){
		lpool[i  ] ^= lpool[i-5] ^ lmd[3];
		lpool[i+1] ^= lpool[i-4] ^ lmd[2];
		lpool[i+2] ^= lpool[i-3] ^ lmd[1];
		lpool[i+3] ^= lpool[i-2] ^ lmd[0];
		lpool[i+4] ^= lpool[i-1] ^ lmd[4];
	}

	/*
	 * Ok, now retrieve the entropy requested!
	 */
	OK_SHA1(128,&pool[pool_size-128],temp_md);

	for (i = 0; i < num; ) {
		lps = ((i+SHA_DIGEST_LENGTH)>num)?(num):(i+SHA_DIGEST_LENGTH);

		for (j = 0; i < lps; i++,j++){
			buf[i] = pool[position + j];
			pool[position + j] ^= temp_md[j];
		}
		position += SHA_DIGEST_LENGTH;
		position %= pool_size;	/* wrap, if needed */
	}

	/*
	 * Now that the entropy has been retrieved, the pool is mixed again.
	 */
	j = clock();
	if(position == 0){
		j ^= (int)lpool[(pool_size>>2) - 1];
	}else{
		j ^= (int)lpool[(position>>2) - 1];
	}

	lps   = pool_size>>2;
	for (i = 0; i < lps; i++){
		lpool[i] ^= (ULONG)lps;
	}
	memset(temp_md, 0, SHA_DIGEST_LENGTH);

	/*
	 * When entropy was retrieved, reduce the "entropy counter". Do not go
	 * below 0, because this would not make sense.
	 */
	entropy -= num;
	if (entropy < 0) entropy = 0;

	return 0;
}

int lutz_is_initialized(){
	return (pool != NULL);
}

int lutz_is_seeded(){
	/*
	 * Return the amount of (weighted) entropy available in bits. If not
	 * enough entropy is available yet, return "-1" to flag that a call to
	 * rand_bytes() would fail.
	 */
	if (!pool_seeded){
		OK_set_error(ERR_ST_RAND_NOTSEEDED,ERR_LC_RAND,ERR_PT_LUTZRAND+2,NULL);
		return -1;
	}

	return (int)(entropy * BITS_PER_BYTE);
}

int lutz_rand_init(int set_pool_size, int set_entropy_needed){
	int i,j;

	/*
	 * Set the pool size. For simplicity (we must be able to walk back and
	 * forward), the pool_size shall be a multiple of SHA_DIGEST_LENGTH.
	 * In order to work appropriately (we always mix 20+64=84bytes) the
	 * minimum _technical_ pool size is set to 100bytes.
	 */
	pool_size = set_pool_size;
	if (pool_size < 100)
		pool_size = 100;
	if (pool_size % SHA_DIGEST_LENGTH)
		pool_size = ((pool_size/SHA_DIGEST_LENGTH) + 1) * SHA_DIGEST_LENGTH;

	if(pool) FREE(pool);
	if((pool=MALLOC(pool_size))==NULL){
		OK_set_error(ERR_ST_MEMALLOC,ERR_LC_RAND,ERR_PT_LUTZRAND+3,NULL);
		return -1;
	}
	/* initialize buffer */
	srand(clock());
	for(i=0;i<pool_size;i+=2){
		j = rand();
		pool[i  ] = (unsigned char)j;
		pool[i+1] = (unsigned char)(j>>8);
	}

	/*
	 * Remember the minimum seed needed.
	 */
	entropy_needed = set_entropy_needed;

	return 0;
}

void lutz_rand_clean(){

	if(pool){
		memset(pool,0,pool_size);
		FREE(pool);
		pool=NULL;
	}
	position = pool_size = pool_seeded = 0;
	entropy = entropy_needed = 0;
}

