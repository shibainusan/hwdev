#pragma once
#include <synchapi.h>
#include <stdbool.h>

typedef struct {
	char buf[256];
	int readPos;
	int writePos;
	int numUsed;
	int capacity;
	CRITICAL_SECTION cs;
	HANDLE event;
} T_RingBuf;

extern void RingBuf_Init(T_RingBuf* r);
extern void RingBuf_Clear(T_RingBuf* r);
extern bool RingBuf_Push(T_RingBuf* r, char c);
extern bool RingBuf_PushString(T_RingBuf* r, const char* c);
extern bool RingBuf_Pop(T_RingBuf* r, char* c);
extern bool RingBuf_BlockingPop(T_RingBuf* r, char* c);
extern bool RingBuf_BlockingPopLine(T_RingBuf* r, char* buf);
extern int RingBuf_GetNumUsed(T_RingBuf* r);
extern void RingBuf_UnblockPop(T_RingBuf* r);