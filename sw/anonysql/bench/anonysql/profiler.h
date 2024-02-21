#ifndef PROFILER_HEADER
#define PROFILER_HEADER

//以下の関数はすべてスレッドセーフでないことに注意。

//CPU使用率を計測するプロファイラを初期化する
//プロセス内で一度だけ実行する。
extern void InitProfiler(void);
//時間計測開始。
extern void BeginTime(void);
//BeginTime呼び出しから経過した時間をミリセカンド単位で返す。
extern DWORD EndTime(void);
extern void PrintEndTime(void);
//CPU使用率の計測を開始する。
extern void StartProfile(void);
//StartProfile呼び出した時点からの平均CPU使用率を表示する
//出力：(CPU total%),(CPU user%),
extern void PrintCpuUsage(void);

#endif