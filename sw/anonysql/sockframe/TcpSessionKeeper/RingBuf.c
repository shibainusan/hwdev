#include <Windows.h>

#include "RingBuf.h"

extern void RingBuf_Init(T_RingBuf* r)
{
	InitializeCriticalSection(&r->cs);
	r->event = CreateEvent(NULL, TRUE, FALSE, NULL); //manual reset
	r->readPos = 0;
	r->writePos = 0;
	r->numUsed = 0;
	r->capacity = sizeof(r->buf);
}

extern void RingBuf_Clear(T_RingBuf* r)
{
	EnterCriticalSection(&r->cs);
	r->readPos = 0;
	r->writePos = 0;
	r->numUsed = 0;
	ResetEvent(r->event);
	LeaveCriticalSection(&r->cs);
}

extern bool RingBuf_Push(T_RingBuf* r, char c)
{
	bool ret = false;
	EnterCriticalSection(&r->cs);

	if (r->numUsed < r->capacity) {
		r->buf[r->writePos] = c;
		r->writePos++;
		if (r->capacity <= r->writePos) {
			r->writePos = 0;
		}
		if (0 == r->numUsed) {
			SetEvent(r->event);
		}
		r->numUsed++;
		ret = true;
	}

	LeaveCriticalSection(&r->cs);
	return ret;
}

extern bool RingBuf_PushString(T_RingBuf* r, const char *c)
{
	bool ret = false;
	EnterCriticalSection(&r->cs);

	int len = strlen(c);
	int i;
	if (r->numUsed + len < r->capacity) {
		for (i = 0; i < len; i++) {
			r->buf[r->writePos] = c[i];
			r->writePos++;
			if (r->capacity <= r->writePos) {
				r->writePos = 0;
			}
			if (0 == r->numUsed) {
				SetEvent(r->event);
			}
			r->numUsed++;
		}
		ret = true;
	}

	LeaveCriticalSection(&r->cs);
	return ret;
}

extern bool RingBuf_Pop(T_RingBuf* r, char* c)
{
	bool ret = false;
	EnterCriticalSection(&r->cs);

	if (0 != r->numUsed) {
		*c = r->buf[r->readPos];
		r->readPos++;
		if (r->capacity <= r->readPos) {
			r->writePos = 0;
		}
		r->numUsed--;
		if (0 == r->numUsed) {
			ResetEvent(r->event);
		}
		ret = true;

	}

	LeaveCriticalSection(&r->cs);
	return ret;
}

extern bool RingBuf_BlockingPop(T_RingBuf* r, char* c)
{
	DWORD res = WaitForSingleObject(r->event, INFINITE); //no timeout
	if (WAIT_OBJECT_0 == res) {
		bool ret = RingBuf_Pop(r, c);
		return ret;
	}
	else {
		return false;
	}
}

extern int RingBuf_GetNumUsed(T_RingBuf* r)
{
	return r->numUsed;
}

extern void RingBuf_UnblockPop(T_RingBuf* r)
{
	SetEvent(r->event);
}