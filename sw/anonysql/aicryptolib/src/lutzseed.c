 /*
  * Internal seed functions
  */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "ok_rand.h"
#include "lutzpath.h"

static const char *statfiles[] = {
#ifdef PATH_TMP
PATH_TMP,
#endif
#ifdef PATH_VAR_TMP
PATH_VAR_TMP,
#endif
#ifdef PATH_PASSWD
PATH_PASSWD,
#endif
#ifdef PATH_WTMP
PATH_WTMP,
#endif
#ifdef PATH_UTMP
PATH_UTMP,
#endif
#ifdef PATH_SYSLOG
PATH_SYSLOG,
#endif
#ifdef PATH_MAILLOG
PATH_MAILLOG,
#endif
NULL};

 /*
  * seed_internal: internal "cheap" seeding. Call statistic functions that
  * may provide some bits that are hard to predict:
  * - times() utilizes the cumulative computer time in TICKS, so hopefully
  *   the exact amount is not too easy to guess. Might give 1 or 2 bits of
  *   entropy.
  * - gettimeofday() can have the actual time in microseconds, the last
  *   bits might be "random".
  * - getpid() is probably not too hard to guess, but well, it won't hurt.
  * - getrusage(), if available, contains several statistical data that might
  *   be hard to guess.
  * This function is especially designed to be computationally cheap, so that
  * it can be called very often, especially every time when an event occurs
  * (a connection is opened etc), so that the usage of the real time values
  * might help increasing the entropy.
  *
  * Be careful anyhow, don't count the bits.
  *
  * This function may also be called to collect the data now and give it back
  * in the supplied memory for later usage.
  */
int seed_internal(seed_t *seed_p)
{
	seed_p->clock = clock();
#ifdef __WINDOWS__
	GetSystemTime(&(seed_p->tp));
	seed_p->pid = _getpid();
#else
	gettimeofday(&(seed_p->tp), NULL);
	seed_p->pid = getpid();
#endif

#ifdef HAVE_SYS_TIME_H
	times(&(seed_p->tmsbuf));
#endif
#ifdef HAVE_GETRUSAGE
	getrusage(RUSAGE_SELF, &(seed_p->usage));
#endif

	return lutz_rand_add(seed_p, sizeof(seed_t), sizeof(seed_t));
}

 /*
  * seed_stat(): Get seed by stat()ing files and directories on the system.
  * This is cheaper than doing an "ls", since no external process is needed.
  * The data returned includes size and access/modification times. The logfiles
  * should change in size quite often, while the TMP directories might
  * are changed quite often.
  * Why have /etc/passwd in the list??? Because a lot of programs need the
  * user information for the uid->name translation, so they must access
  * /etc/passwd (probably via getpwent) and hence impact the access time.
  *
  * We also do not count the bits.
  */

int seed_stat(void)
{
	struct stat buf;
	int i;
	char *sys_path,path[64];
	/*
	 * Run over the list of files with often changing status (access/modification
	 * time, length) and seed it into the PRNG. Since only certain parts of
	 * the information changes, we assume the amount of entropy to be rather
	 * small. Use 2bits=1/4byte per check.
	 */
#ifdef __WINDOWS__
	if (stat("c:\\winnt",&buf)){
		sys_path="c:\\windows";
	}else{
		sys_path="c:\\winnt";
	}
#endif

	for(i=0;statfiles[i];i++){
#ifdef __WINDOWS__
		SNPRINTF (path,62,"%s\\%s",sys_path,statfiles[i]);
		if (stat(path, &buf)==0){
#else
		if (stat(statfiles[i], &buf)==0){
#endif
			if (lutz_rand_add(&buf, sizeof(struct stat),sizeof(struct stat)/4))
				return -1;
		}
	}

	return 0;
}

int seed_env(){
	int i,len;

#ifdef __WINDOWS__
	for(i=0;_environ[i];i++){
		len = strlen(_environ[i]);

		if (lutz_rand_add(_environ[i],len,len/4))
			return -1;
	}
#endif

	return 0;
}


