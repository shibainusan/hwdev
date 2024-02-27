
#include "utils.h"

#define	 R 0
#define  W 1

#define LogDisp printf

extern void PromptAbort()
{
	char buf[1024];

	printf("press ENTER to abort.");
	fgets( buf, sizeof(buf), stdin );
}

extern bool IsFileReadable(std::string filename)
{
	FILE *fp;
	errno_t err = fopen_s( &fp, filename.c_str(), "r" );

	if( 0 != err ){
		LogDisp("[ERROR] failed to open %s", filename.c_str());
		return false;
	}

	fclose(fp);
	return true;
}

extern bool IsFileWritable(std::string filename)
{
	FILE *fp;
	errno_t err = fopen_s( &fp, filename.c_str(), "w" );

	if( 0 != err ){
		LogDisp("[ERROR] failed to write %s", filename.c_str());
		return false;
	}

	fclose(fp);
	return true;
}


extern bool SplitString(T_STRING_LIST *dest,std::string src, std::string delim)
{
	bool ret = false;
	char	*token, *context;
	char	*cstr = new char [src.size()+1];
	strcpy_s (cstr, src.size()+1, src.c_str());
	token = strtok_s( cstr, delim.c_str(), &context);

	while(NULL != token){
		ret = true;
		dest->push_back(token);
		token = strtok_s( NULL, delim.c_str(), &context);
	}
	delete [] cstr;
	return ret;
}


extern bool RemoveLastNewline(char *str)
{
	if( NULL == str ){
		return false;
	}
	while( 0 != *str ){
		if( 0x0D == *str || 0x0A == *str ){
			*str = '\0';
			return true;
		}
		str++;
	}
	return false;
	
}

extern bool CRLFtoSPLF(char *str)
{
	if( NULL == str ){
		return false;
	}
	while( 0 != *str ){
		if( 0x0D == *str ){
			*str = ' ';
		}
		str++;
	}
	return true;
	
}


extern void ShowLastWin32Error()
{
	LPVOID lpMsgBuf;
	DWORD ret;
	ret = FormatMessage( FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL,
			GetLastError(),
			MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US ), //english
			(LPTSTR) &lpMsgBuf,
			0,
			NULL );

	LogDisp("[WIN32] %s", lpMsgBuf);
	LocalFree(lpMsgBuf);
}


extern bool StartChildConsoleProcess(T_CHILD_CONSOLE_INFO *ci, std::string cmd)
{
	HANDLE hParent = GetCurrentProcess();

	memset( ci, 0, sizeof(*ci) );

	ci->sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	ci->sa.lpSecurityDescriptor = NULL;
	ci->sa.bInheritHandle = TRUE;

	//子プロセスの標準入出力を親プロセスのファイルデスクリプタにリダイレクトする
	CreatePipe(&ci->pfd_out[R], &ci->pfd_out[W], &ci->sa, 0);
	DuplicateHandle(hParent, ci->pfd_out[R], hParent, &ci->fd_write, 0, FALSE, DUPLICATE_SAME_ACCESS);
	CloseHandle(ci->pfd_out[R]);

	CreatePipe(&ci->pfd_err[R], &ci->pfd_err[W], &ci->sa, 0);
	DuplicateHandle(hParent, ci->pfd_err[R], hParent, &ci->fd_err, 0, FALSE, DUPLICATE_SAME_ACCESS);
	CloseHandle(ci->pfd_err[R]);

	CreatePipe(&ci->pfd_in[R], &ci->pfd_in[W], &ci->sa, 0); 
	DuplicateHandle(hParent, ci->pfd_in[W], hParent, &ci->fd_read, 0, FALSE, DUPLICATE_SAME_ACCESS);
	CloseHandle(ci->pfd_in[W]);

	ci->si.cb          = sizeof(STARTUPINFO);
	ci->si.dwFlags     = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
	ci->si.wShowWindow = SW_HIDE;
	ci->si.hStdInput   = ci->pfd_in[R];
	ci->si.hStdOutput  = ci->pfd_out[W];
	ci->si.hStdError   = ci->pfd_err[W];

	LogDisp("[INFO] launching %s", cmd.c_str() );
	strcpy( ci->command, cmd.c_str() );

	if(0 == CreateProcess(NULL, ci->command, NULL, NULL, TRUE, 
		0, //Consoleを共有する子プロセスとして起動 
		NULL, NULL, &ci->si, &ci->pi)) {
		ShowLastWin32Error();

		CloseHandle(ci->fd_read);
		CloseHandle(ci->fd_write);
		CloseHandle(ci->fd_err);

		CloseHandle(ci->pfd_in[R]);
		CloseHandle(ci->pfd_out[W]);
		CloseHandle(ci->pfd_err[W]);

		return false;
	}

	return true;
	
}

extern bool StopChildConsoleProcess(T_CHILD_CONSOLE_INFO *ci)
{
	int ret;

	if( 0 == ci->pi.hProcess ){
		return false;
	}

	SetConsoleCtrlHandler( NULL, TRUE ); //自プロセスのCTRL-Cハンドラを一時的に無効にする
	ret = GenerateConsoleCtrlEvent( CTRL_C_EVENT, 0 ); //CTRL-Cを生成
	Sleep(100);
	SetConsoleCtrlHandler( NULL, FALSE ); //自プロセスのCTRL-Cハンドラを再度有効にする

	// check process termimnate
	DWORD status = WaitForSingleObject(ci->pi.hProcess, 5000);
	if (status == WAIT_OBJECT_0) {
		DWORD exitCode;
		ret = GetExitCodeProcess( ci->pi.hProcess, &exitCode );
		if( 0 == ret ){
			ShowLastWin32Error();
		}
		LogDisp("[INFO] %s stopped with code:%d.", ci->command, exitCode);
	}else{
		//プロセス強制KILL
		LogDisp("[WARN] %s did not respond to CTRL-C.", ci->command );
		//DEBUG_ASSERT(FALSE);
		TerminateProcess(ci->pi.hProcess, -1);
	}

	CloseHandle(ci->pi.hProcess); ci->pi.hProcess = 0;
	CloseHandle(ci->pi.hThread);

	CloseHandle(ci->fd_read);
	CloseHandle(ci->fd_write); ci->fd_write = 0;
	CloseHandle(ci->fd_err);

	CloseHandle(ci->pfd_in[R]);
	CloseHandle(ci->pfd_out[W]);
	CloseHandle(ci->pfd_err[W]);

	return true;
}
extern bool GetStdoutChildConsoleProcess(T_CHILD_CONSOLE_INFO *ci, std::string *out)
{
	char buf[4096];
	DWORD dwByte;
	
	out->clear();

	//子プロセスの標準出力を読む
	dwByte = GetFileSize(ci->fd_write, NULL);
	if( 0xFFFFFFFF == dwByte ){
		return false; //子プロセスが終了した
	}
	if(0 < dwByte) {
		ReadFile(ci->fd_write,buf, sizeof(buf) - 1, &dwByte,NULL);
		buf[dwByte] = '\0';
		CRLFtoSPLF(buf);
		*out = buf;
		return true;
	}

	//子プロセスの標準エラー出力を読む
	dwByte = GetFileSize(ci->fd_err, NULL);
	if( 0xFFFFFFFF == dwByte ){
		return false; //子プロセスが終了した
	}
	if(0 < dwByte) {
		ReadFile(ci->fd_err,buf, sizeof(buf) - 1, &dwByte,NULL);
		buf[dwByte] = '\0';
		CRLFtoSPLF(buf);
		*out = buf;
		return true;
	}

	int ret = GetExitCodeProcess( ci->pi.hProcess, &ci->exitCode );
	if( 0 == ret ){
		ShowLastWin32Error();
		return false;
	}
	if( STILL_ACTIVE != ci->exitCode ){
		LogDisp("[INFO] %s stopped with code:%d.", ci->command, ci->exitCode);
		return false; //子プロセスが終了した
	}

	return true;
}

extern double round(double number)
{
    return number < 0.0 ? ceil(number - 0.5) : floor(number + 0.5);
}
extern float roundf(float number)
{
    return number < 0.0 ? ceilf(number - 0.5f) : floorf(number + 0.5f);
}

static int HexChar2Int(char c)
{
	int ret;
	if( c >= '0' && c <= '9' ){
		ret = c - '0';
	}else if( c >= 'A' && c <= 'F' ){
		ret = c - 'A' + 10;
	}else if( c >= 'a' && c <= 'f' ){
		ret = c - 'a' + 10;
	}else{
		ret = -1;
	}
	return ret;
}

extern int HexStringToCharArray(const char *str, unsigned char *outbuf, int buflen)
{
	int i;
	int v;

	if( NULL == str ){
		return 0;
	}
	if( NULL == outbuf ){
		return 0;
	}

	for( i = 0; i < buflen; i++ ){
		if( 0 == *str ){
			break;
		}
		v = HexChar2Int(*str);
		if( v < 0 ){
			break;
		}
		*outbuf = (v << 4);
		str++;
		if( 0 == *str ){
			break;
		}
		v = HexChar2Int(*str);
		if( v < 0 ){
			break;
		}
		*outbuf += v;
		str++;
		outbuf++;
	}
	return i;
}

extern int MacAddrStringToCharArray(const char* str, unsigned char* outbuf, int buflen)
{
	int i;
	int v;
	int nByte = 0;
	int nBuf = 0;

	if (NULL == str) {
		return 0;
	}
	if (NULL == outbuf) {
		return 0;
	}

	int len = strlen(str);

	for (i = 0; i < len; i++) {
		if (':' == str[i] || ' ' == str[i] || '-' == str[i]) {
			continue;
		}
		v = HexChar2Int(str[i]);
		if (v < 0) {
			break;
		}
		outbuf[nBuf] = (v << 4);
		v = HexChar2Int(str[i+1]);
		if (v < 0) {
			break;
		}
		outbuf[nBuf] += v;
		nBuf++;
		if (buflen <= nBuf) {
			break;
		}
		i++;
	}
	return nBuf;
}
