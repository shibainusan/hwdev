// CpuUsageForNT.cpp: CCpuUsageForNT クラスのインプリメンテーション
//
//////////////////////////////////////////////////////////////////////

/* 
 *  CpuUsageForNT.cpp
 *
 *	Copyright (C) 2000, DNA. - gwater@mail.goo.ne.jp
 *
 *  This file is part of 'After idol'
 *	
 *  After idol is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *   
 *  After idol is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *   
 *  You should have received a copy of the GNU General Public License
 *  along with GNU Make; see the file 'gnu.txt'.  If not, write to
 *  the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA. 
 *
 */


#include "CpuUsageForNT.h"


void ReleaseProc(void);
PROCNTQSI GetNTQSIProcAdrs(void);

PROCNTQSI m_pProcNTQSI;		// NtQuerySystemInformation への関数ポインタ
HMODULE m_hModuleForNTDLL;	// NTDLL.DLL への module handler

int m_NumberOfProcessors;	// システムに搭載されているCPUの個数


//////////////////////////////////////////////////////////////////////
// 構築/消滅
//////////////////////////////////////////////////////////////////////

void CCpuUsageForNT_init()
{
	m_pProcNTQSI			= (PROCNTQSI)GetNTQSIProcAdrs();
	m_NumberOfProcessors	= GetNumberOfProcessors();
}

void CCpuUsageForNT_cleanup()
{
	ReleaseProc();
}

///////////////////////////////////////////////////////////////////////////////
//　NtQuerySystemInformation への関数ポインタを NTDLL.DLL から得る
///////////////////////////////////////////////////////////////////////////////
// 引数:
//	なし
//
// 戻り値:
//	PROCNTQSI	NtQuerySystemInformation への関数ポインタ
//
PROCNTQSI GetNTQSIProcAdrs()
{
	PROCNTQSI NtQuerySystemInformation;
	HMODULE hModule;

	if( (hModule=GetModuleHandle("ntdll")) == NULL )
		return (PROCNTQSI)NULL;

	m_hModuleForNTDLL = hModule; // メンバ変数へDLLのハンドラをコピーする

    NtQuerySystemInformation = (PROCNTQSI)GetProcAddress(
                                          hModule,
                                         "NtQuerySystemInformation"
                                         );

    if (!NtQuerySystemInformation)
        return (PROCNTQSI)NULL;
	else
		return (PROCNTQSI)NtQuerySystemInformation;
}


///////////////////////////////////////////////////////////////////////////////
//　NtQuerySystemInformation への関数ポインタを解放する
///////////////////////////////////////////////////////////////////////////////
// 引数:
//	なし
//
// 戻り値:
//	なし
//
void ReleaseProc()
{
	if( m_hModuleForNTDLL != NULL )
	{
		FreeLibrary(m_hModuleForNTDLL);

		// 使い終わった変数は一応 NULL にセットしておく
		m_hModuleForNTDLL		= (HMODULE)NULL;
		m_pProcNTQSI			= (PROCNTQSI)NULL;
		m_NumberOfProcessors	= 0;
	}
}


///////////////////////////////////////////////////////////////////////////////
//　システムに搭載されている CPU の数を得ます。
///////////////////////////////////////////////////////////////////////////////
// 引数:
//	なし
//
// 戻り値:
//	int					0 エラー
//				
//			CPU の個数	1 - single processor
//						2 - dual processor
//
int GetNumberOfProcessors()
{
    SYSTEM_BASIC_INFORMATION       SysBaseInfo;
    LONG                           status;

    // get number of processors in the system
    status = m_pProcNTQSI(SystemBasicInformation,&SysBaseInfo,sizeof(SysBaseInfo),NULL);

    if (status != NO_ERROR)
        return 0;

	return (int)SysBaseInfo.bKeNumberProcessors;
}


///////////////////////////////////////////////////////////////////////////////
//　現在のCPU利用率を得ます
///////////////////////////////////////////////////////////////////////////////
// 引数:
//	なし
//
// 戻り値:
//	int		0-100 [%] のCPU利用率 (single processor のみ対応している)
//
//			0 が連続するのはエラーの可能性が高い
//
int GetCpuUsageForNT()
{
    SYSTEM_PERFORMANCE_INFORMATION SysPerfInfo;
	SYSTEM_TIME_INFORMATION        SysTimeInfo;
    double                         dbIdleTime;
    double                         dbSystemTime;
    LONG                           status;
    static LARGE_INTEGER           liOldIdleTime   = {0,0};
    static LARGE_INTEGER           liOldSystemTime = {0,0};

	int cpuUsage = 0; // CPU 使用率 [%]

	// get new system time
	status = m_pProcNTQSI(SystemTimeInformation,&SysTimeInfo,sizeof(SysTimeInfo),0);
	if (status!=NO_ERROR)
		return (int)0;
	
	// get new CPU's idle time
	status = m_pProcNTQSI(SystemPerformanceInformation,&SysPerfInfo,sizeof(SysPerfInfo),NULL);
	if (status != NO_ERROR)
		return (int)0;
	
	// if it's a first call - skip it
	if (liOldIdleTime.QuadPart != 0)
	{
		// CurrentValue = NewValue - OldValue
		dbIdleTime = Li2Double(SysPerfInfo.liIdleTime) - Li2Double(liOldIdleTime);
		dbSystemTime = Li2Double(SysTimeInfo.liKeSystemTime) - Li2Double(liOldSystemTime);
		
		// CurrentCpuIdle = IdleTime / SystemTime
		dbIdleTime = dbIdleTime / dbSystemTime;
		
		// CurrentCpuUsage% = 100 - (CurrentCpuIdle * 100) / NumberOfProcessors
		dbIdleTime = 100.0 - dbIdleTime * 100.0 / (double)m_NumberOfProcessors + 0.5;
		
		//printf("\b\b\b\b%3d%%",(UINT)dbIdleTime);
		cpuUsage = (int)dbIdleTime;
	}
	
	// store new CPU's idle and system time
	liOldIdleTime = SysPerfInfo.liIdleTime;
	liOldSystemTime = SysTimeInfo.liKeSystemTime;

	return (int)cpuUsage;
}


///////////////////////////////////////////////////////////////////////////////
//　NTDLL.DLL が開けたかどうか調べます。外部からの動作確認にお使いください
///////////////////////////////////////////////////////////////////////////////
// 引数:
//	なし
//
// 戻り値:
//	BOOL	TRUE	成功している。CPU の利用率を取得できる。
//			FALSE	失敗している。CPU の利用率を取得できない。
//
BOOL IsOpenDLL()
{
	return (m_hModuleForNTDLL != NULL) ? TRUE: FALSE;
}
