#include <pdh.h>
#include <stdio.h>

static DWORD timecount;
static HQUERY hQuery;
static HCOUNTER hUsertime,hCputime;
static PDH_FMT_COUNTERVALUE FmtValue;

void StartProfile(void)
{
	PdhCollectQueryData(hQuery);
}

void InitProfiler(void)
{
	/* 新規クエリーを作成 */
	PdhOpenQuery(NULL, 0, &hQuery);
	PdhAddCounter(hQuery, "\\Processor(_Total)\\% User Time", 0, &hUsertime);
	PdhAddCounter(hQuery, "\\Processor(_Total)\\% Processor Time", 0, &hCputime);
}

void PrintCpuUsage()
{
	//CPU負荷計測終了
	PdhCollectQueryData(hQuery);
	//total
	PdhGetFormattedCounterValue(hCputime, PDH_FMT_DOUBLE, NULL, &FmtValue);
	printf("%f,", FmtValue.doubleValue);
	//user
	PdhGetFormattedCounterValue(hUsertime, PDH_FMT_DOUBLE, NULL, &FmtValue);
	printf("%f,", FmtValue.doubleValue);
}
void BeginTime(void)
{
	timecount = timeGetTime();
}
DWORD EndTime(void)
{
	return (timeGetTime() - timecount);
}
void PrintEndTime(void)
{
	printf("%d,",EndTime());
}