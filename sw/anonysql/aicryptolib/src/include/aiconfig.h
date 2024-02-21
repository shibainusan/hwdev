/* aiconfig.h.  Generated automatically by configure.  */
/* aiconfig.h.in.  Generated automatically from configure.in by autoheader.  */

#ifndef __AICONFIG_H__
#define __AICONFIG_H__

/* Define if POSIX THREAD is used */
/* #undef USE_PTHREAD */

/* Define if you have the ANSI C header files.  */
#define STDC_HEADERS 1

/* Define if you have the <sys/time.h> header file.  */
#define HAVE_SYS_TIME_H 1
#undef HAVE_SYS_TIME_H
/* Define if you have the <sys/times.h> header file.  */
#define HAVE_SYS_TIMES_H 1
#undef HAVE_SYS_TIMES_H
/* Define if you have the <sys/ioctl.h> header file.  */
#define HAVE_SYS_IOCTL_H 1
#undef HAVE_SYS_IOCTL_H
/* Define if you have the <netinet/in.h> header file.  */
#define HAVE_NETINET_IN_H 1

/* Define if you have the <netdb.h> header file.  */
#define HAVE_NETDB_H 1
#undef HAVE_NETDB_H

/* Define if you have the <termio.h> header file.  */
#define HAVE_TERMIO_H 1
#undef HAVE_TERMIO_H

/* Define if you have the <termios.h> header file.  */
#define HAVE_TERMIOS_H 1
#undef HAVE_TERMIOS_H

/* Define if you have the <sys/resource.h> header file. */
#define HAVE_SYS_RESOURCE_H 1
#undef HAVE_SYS_RESOURCE_H

/* have getrusage ? -- it's used for seek_internal() */
#define HAVE_GETRUSAGE 1
#undef  HAVE_GETRUSAGE
/* timegm */
/* #undef HAVE_TIMEGM */

/* have snprintf() ? */
#define HAVE_SNPRINTF 1

/* Define OS */
/* #undef __SOLARIS2__ */
/* #undef __SUNOS__ */
/* #undef __LINUX__ */
/* #undef __DEC_ALPHA__ */
/* #undef __BSD__ */
/* #undef __IRIX__ */
/* #undef __HPUX__ */
/* #undef __DGUX__ */
#define __WINDOWS__
/* Define local caracter code */
#define UC_LOCAL_JCODE 3

/* Define if x509.strong.auth should be used */
/* #undef USE_SIGN_LOGIN */
/* #undef USE_SSL */

/* aicrypto common */

#ifdef  __cplusplus
extern "C" {
#endif

#ifdef __WINDOWS__
#define ULLONG unsigned _int64
#if 1
#define ULONG  unsigned long
#endif
#define RTN		"\r\n"
#define PATH_DELI	"\\"
#define SNPRINTF	_snprintf
#define UC_LOCAL_JCODE		3			/* sjis code */

#else /* UNIX */

# ifdef __DEC_ALPHA__
#  define ULLONG unsigned long
#  define ULONG  unsigned int
# else
#  define ULLONG unsigned long long
#  define ULONG  unsigned long
# endif
# define PATH_DELI	"/"
# define RTN    "\n"

# ifdef HAVE_SNPRINTF
#  define SNPRINTF	snprintf
# else 
#  define SNPRINTF	my_snprintf
# endif
#endif

#if defined(__WINDOWS__) && defined(_DEBUG)
# define MALLOC(num)	malloc((num))
# define FREE(mem)	free((mem))
# define AIMALLOC(num)	ai_malloc((num))
# define AIFREE(mem)	ai_free((mem))
# define STRDUP(a,b)	(a)=strdup_debug(b)
char *strdup_debug(char *b);
void *ai_malloc(int sz);
void ai_free(void *pt);

#else
# define MALLOC(num)	malloc((num))
# define FREE(mem)	free((mem))
# define AIMALLOC(num)	ai_malloc((num))
# define AIFREE(mem)	ai_free((mem))
# define STRDUP(a,b)	(a)=strdup(b)

#endif

#ifdef  __cplusplus
}
#endif

#endif /* __AICONFIG_H__ */
