// CpuUsageForNT.cpp: CCpuUsageForNT �N���X�̃C���v�������e�[�V����
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

PROCNTQSI m_pProcNTQSI;		// NtQuerySystemInformation �ւ̊֐��|�C���^
HMODULE m_hModuleForNTDLL;	// NTDLL.DLL �ւ� module handler

int m_NumberOfProcessors;	// �V�X�e���ɓ��ڂ���Ă���CPU�̌�


//////////////////////////////////////////////////////////////////////
// �\�z/����
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
//�@NtQuerySystemInformation �ւ̊֐��|�C���^�� NTDLL.DLL ���瓾��
///////////////////////////////////////////////////////////////////////////////
// ����:
//	�Ȃ�
//
// �߂�l:
//	PROCNTQSI	NtQuerySystemInformation �ւ̊֐��|�C���^
//
PROCNTQSI GetNTQSIProcAdrs()
{
	PROCNTQSI NtQuerySystemInformation;
	HMODULE hModule;

	if( (hModule=GetModuleHandle("ntdll")) == NULL )
		return (PROCNTQSI)NULL;

	m_hModuleForNTDLL = hModule; // �����o�ϐ���DLL�̃n���h�����R�s�[����

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
//�@NtQuerySystemInformation �ւ̊֐��|�C���^���������
///////////////////////////////////////////////////////////////////////////////
// ����:
//	�Ȃ�
//
// �߂�l:
//	�Ȃ�
//
void ReleaseProc()
{
	if( m_hModuleForNTDLL != NULL )
	{
		FreeLibrary(m_hModuleForNTDLL);

		// �g���I������ϐ��͈ꉞ NULL �ɃZ�b�g���Ă���
		m_hModuleForNTDLL		= (HMODULE)NULL;
		m_pProcNTQSI			= (PROCNTQSI)NULL;
		m_NumberOfProcessors	= 0;
	}
}


///////////////////////////////////////////////////////////////////////////////
//�@�V�X�e���ɓ��ڂ���Ă��� CPU �̐��𓾂܂��B
///////////////////////////////////////////////////////////////////////////////
// ����:
//	�Ȃ�
//
// �߂�l:
//	int					0 �G���[
//				
//			CPU �̌�	1 - single processor
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
//�@���݂�CPU���p���𓾂܂�
///////////////////////////////////////////////////////////////////////////////
// ����:
//	�Ȃ�
//
// �߂�l:
//	int		0-100 [%] ��CPU���p�� (single processor �̂ݑΉ����Ă���)
//
//			0 ���A������̂̓G���[�̉\��������
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

	int cpuUsage = 0; // CPU �g�p�� [%]

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
//�@NTDLL.DLL ���J�������ǂ������ׂ܂��B�O������̓���m�F�ɂ��g����������
///////////////////////////////////////////////////////////////////////////////
// ����:
//	�Ȃ�
//
// �߂�l:
//	BOOL	TRUE	�������Ă���BCPU �̗��p�����擾�ł���B
//			FALSE	���s���Ă���BCPU �̗��p�����擾�ł��Ȃ��B
//
BOOL IsOpenDLL()
{
	return (m_hModuleForNTDLL != NULL) ? TRUE: FALSE;
}
