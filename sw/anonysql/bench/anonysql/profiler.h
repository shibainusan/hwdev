#ifndef PROFILER_HEADER
#define PROFILER_HEADER

//�ȉ��̊֐��͂��ׂăX���b�h�Z�[�t�łȂ����Ƃɒ��ӁB

//CPU�g�p�����v������v���t�@�C��������������
//�v���Z�X���ň�x�������s����B
extern void InitProfiler(void);
//���Ԍv���J�n�B
extern void BeginTime(void);
//BeginTime�Ăяo������o�߂������Ԃ��~���Z�J���h�P�ʂŕԂ��B
extern DWORD EndTime(void);
extern void PrintEndTime(void);
//CPU�g�p���̌v�����J�n����B
extern void StartProfile(void);
//StartProfile�Ăяo�������_����̕���CPU�g�p����\������
//�o�́F(CPU total%),(CPU user%),
extern void PrintCpuUsage(void);

#endif