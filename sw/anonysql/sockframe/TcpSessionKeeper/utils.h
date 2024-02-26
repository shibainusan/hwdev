#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <string>
#include <list>

typedef std::list<std::string> T_STRING_LIST;

extern bool RemoveLastNewline(char *str);
extern bool SplitString(T_STRING_LIST *dest,std::string src, std::string delim);
extern void ShowLastWin32Error();
extern void PromptAbort();

extern bool IsFileReadable(std::string filename);
extern bool IsFileWritable(std::string filename);

typedef struct {
	char	command[1024];
	HANDLE pfd_in[2], pfd_out[2], pfd_err[2];
	HANDLE fd_read, fd_write, fd_err;
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	SECURITY_ATTRIBUTES sa;
	DWORD exitCode;
} T_CHILD_CONSOLE_INFO;


extern bool StartChildConsoleProcess(T_CHILD_CONSOLE_INFO *ci, std::string cmd);
extern bool StopChildConsoleProcess(T_CHILD_CONSOLE_INFO *ci);
extern bool GetStdoutChildConsoleProcess(T_CHILD_CONSOLE_INFO *ci, std::string *out);

extern int HexStringToCharArray(const char *str, unsigned char *outbuf, int buflen);

extern double round(double number); //for MSVC2012 or older
extern float roundf(float number); //for MSVC2012 or older