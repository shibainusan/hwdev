
#ifdef __LINUX__
#define PATH_TMP	"/tmp"
#define PATH_VAR_TMP	"/var/tmp"
#define PATH_PASSWD	"/etc/passwd"
#define PATH_WTMP	"/var/log/wtmp"
#define PATH_UTMP	"/var/run/utmp"
#define PATH_SYSLOG	"/var/log/messages"
#define PATH_MAILLOG	"/var/log/mail"
#endif

#ifdef __HPUX__
#define PATH_TMP	"/tmp"
#define PATH_VAR_TMP	"/var/tmp"
#define PATH_PASSWD	"/etc/passwd"
#define PATH_WTMP	"/var/adm/wtmp"
#define PATH_UTMP	"/etc/utmp"
#define PATH_SYSLOG	"/var/adm/syslog/syslog.log"
#define PATH_MAILLOG	"/var/adm/syslog/mail.log"
#endif

#ifdef __DEC_ALPHA__
#define PATH_TMP	"/tmp"
#define PATH_VAR_TMP	"/var/tmp"
#define PATH_PASSWD	"/etc/passwd"
#define PATH_WTMP	"/var/adm/wtmp"
#define PATH_UTMP	"/var/adm/utmp"
#define PATH_SYSLOG	"/var/adm/syslog.dated/current/daemon.log"
#define PATH_MAILLOG	"/var/adm/syslog.dated/current/mail.log"
#endif

#ifdef __SUNOS__
#define PATH_TMP        "/tmp"
#define PATH_VAR_TMP    "/var/tmp"
#define PATH_PASSWD     "/etc/passwd"
#define PATH_WTMP       "/var/adm/wtmp"
#define PATH_UTMP       "/etc/utmp"
#define PATH_SYSLOG     "/var/log/syslog"
#endif

#ifdef __IRIX__
#define PATH_TMP        "/tmp"
#define PATH_VAR_TMP	"/var/tmp"
#define PATH_PASSWD     "/etc/passwd"
#define PATH_WTMP       "/var/adm/wtmpx"
#define PATH_UTMP       "/var/adm/utmpx"
#define PATH_SYSLOG     "/var/adm/SYSLOG"
#endif

#ifdef NEXTSTEP3
/* not supported */
#define SA_RESTART 0
#define O_RSYNC 0
/* select, ftruncate, fchmod */
#include <libc.h>
/* in ansi string.h but undefined in -posix */
#define bzero(b,len) memset(b,0,len)
#define SIZEOF_IS_LONG_INT
#define HAVE_GETRUSAGE
#define PATH_TMP        "/private/tmp"
#define PATH_PASSWD     "/etc/passwd"
#define PATH_WTMP       "/private/adm/wtmp"
#define PATH_UTMP       "/private/etc/utmp"
#define PATH_SYSLOG     "/private/adm/messages"
#endif

#ifdef UNIXWARE7
#define PATH_TMP        "/tmp"
#define PATH_VAR_TMP    "/var/tmp"
#define PATH_PASSWD     "/etc/passwd"
#define PATH_WTMP       "/var/adm/wtmp"
#define PATH_UTMP       "/etc/utmp"
#define PATH_SYSLOG     "/var/adm/syslog"
#endif

