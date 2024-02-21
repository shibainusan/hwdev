#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include "gunshuservice.h"

GUNSHU_SESSION_INFO list[GUNSHU_MAX_SESSION];
int currentIndex;
CRITICAL_SECTION csec;

GUNSHU_SESSION_INFO *FindList(int sid)
{
	GUNSHU_SESSION_INFO *ret;
	GUNSHU_SESSION_INFO *buf;
	TopListWithCriticalSec();

	do{
		buf = NextList();
		if( buf == NULL ){
			ret = NULL;
			break;
		}
		if( buf->sid == sid){
			ret = buf;
			break;
		}
	}while(1);
	LeaveListCriticalSec();
	return ret;
}
void InitList()
{
	InitializeCriticalSection(&csec);
	ClearList();
}

void ClearList()
{
	int i;
	EnterCriticalSection(&csec);
	for(i=0 ; i < GUNSHU_MAX_SESSION ; i++){
		list[i].sid = 0;
		list[i].timeStart = 0;
		list[i].isResponder = FALSE;
	}
	LeaveCriticalSection(&csec);
}
int AddList(const GUNSHU_SESSION_INFO *t)
{
	int i;

	EnterCriticalSection(&csec);

	for(i=0 ; i < GUNSHU_MAX_SESSION ; i++){
		if(list[i].sid== 0){
			list[i] = *t;
			list[i].timeStart = GetTickCount();
			LeaveCriticalSection(&csec);
			return TRUE;
		}
	}
	LeaveCriticalSection(&csec);
	printf("AddList failed.\n");
	return FALSE;
}



int DelList(int sid)
{
	GUNSHU_SESSION_INFO *gsi;
	gsi = FindList(sid);
	if( gsi == NULL ){
		return FALSE;
	}else{
		gsi->sid = 0;
		gsi->timeStart = 0;
		return TRUE;
	}
	return FALSE;
}
void TopListWithCriticalSec(void)
{
	EnterCriticalSection(&csec);
	currentIndex = 0;
}
void TopList(void)
{
	currentIndex = 0;
}
void LeaveListCriticalSec()
{
	LeaveCriticalSection(&csec);
}
const GUNSHU_SESSION_INFO *NextList(void)
{
	for(; currentIndex < GUNSHU_MAX_SESSION ; currentIndex++){
		if(list[currentIndex].sid != 0){
			currentIndex++;
			return (list + currentIndex - 1);
		}
	}
	return NULL;
}
int GetListCount(void)
{
	int i;
	int c;
	c = 0;

	EnterCriticalSection(&csec);
	for( i = 0; i < GUNSHU_MAX_SESSION ; i++){
		if( list[i].sid != 0){
			c++;
		}
	}
	LeaveCriticalSection(&csec);
	return c;
}