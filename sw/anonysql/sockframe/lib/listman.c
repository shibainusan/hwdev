#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "listman.h"

#define BUF_SIZE 1024

//���s�������k�������ɂ���
void CrLftoNull(char *t);

void InitService(ServiceList *sl)
{
	int i;

	sl->freeService = sl->workService;
	sl->topService = NULL;

	sl->workService[0].prev = NULL;
	sl->workService[0].next = (sl->workService + 1);

	for( i = 1 ; i < ServiceNode_MAX - 1 ; i++){
		sl->workService[i].prev = (sl->workService + i - 1);
		sl->workService[i].next = (sl->workService + i + 1);

	}
	sl->workService[ServiceNode_MAX-1].prev = (sl->workService + ServiceNode_MAX - 2);
	sl->workService[ServiceNode_MAX-1].next = NULL;

	for( i = 0 ; i < ServiceNode_MAX ; i++){
		sl->workService[i].name[0] = '\0';
	}
}

int AddService(ServiceList *sl,const char *name )
{
	ServiceNode *w;
	//Service�ɋ󂫂����邩�H
	if( sl->freeService == NULL ){
		return FALSE;
	}
	//�V�����󃊃X�g�̐擪���擾
	w = sl->freeService->next;
	//�Â��󃊃X�g�̐擪���g�p�ς݃��X�g�̐擪�ɓ����
	sl->freeService->next = sl->topService;
	sl->freeService->prev = NULL;
	if( sl->topService == NULL ){

	}else{
		sl->topService->prev = sl->freeService;
	}
	sl->topService = sl->freeService;
	//�󃊃X�g�擪�̐V��������
	sl->freeService = w;
	if( sl->freeService == NULL ){
		//���X�g���g���ʂ������ꍇ
	}else{
		sl->freeService->prev = NULL;
	}

	strcpy(sl->topService->name , name);

	return TRUE;
}
int DelService(ServiceList *sl,ServiceNode *w)
{
	
	if( w == NULL ){
		return TRUE;
	}
	w->name[0] = '\0';

	//�Ō�̈���폜
	if( w->prev == NULL && w->next == NULL ){
		sl->topService = NULL;
		goto LINK_FREE;
	}

	if(w->prev == NULL ){
		//�擪Service���폜
		w->next->prev = NULL;
		sl->topService = w->next;
	}else{
		//����Service���폜
		w->prev->next = w->next;
	}

	if(w->next == NULL){
		//�Ō��Service���폜
		w->prev->next = NULL;
	}else{
		//����Service���폜
		w->next->prev = w->prev;
	}

LINK_FREE:	//�󂫃��X�g�ɒǉ�
	if( sl->freeService == NULL ){
		w->next = NULL;
		w->prev = NULL;
		sl->freeService = w;
	}else{
		w->prev = NULL;
		w->next = sl->freeService;
		sl->freeService->prev = w;
		sl->freeService = w;
	}
	
	return TRUE;
}

ServiceNode *TopService(ServiceList *sl)
{
	return sl->topService;
}

//Service����name�Ŏw�肷��N���C�A���g�����邩�������A����Service�ւ̎Q�Ƃ�Ԃ�
//�Ȃ��ꍇ��NULL��Ԃ�
ServiceNode *FindService(ServiceList *sl,const char *name)
{
	ServiceNode *w;

	w = sl->topService;
	do{
		if( w == NULL ){
			return NULL;
		}
		if( strcmp(name , w->name) == 0 ){
			return w;
		}
		w = w->next;
	}while(1);
}

int LoadService(ServiceList *sl)
{
	FILE *fp;
	char buf[BUF_SIZE];
	int line = 0;

	fp = fopen(".\\gunshulist.txt" , "rt");
	if( fp == NULL ){
		printf("Service list(.\\gunshulist.txt) not found.\n");
		return FALSE;
	}

	InitService(sl);
	do{
		//Service����s����������
		if( fgets(buf ,BUF_SIZE ,fp) == NULL ){
			fclose(fp);
			break;
		}
		line++;
		CrLftoNull(buf);
		AddService(sl,buf);
	}while(1);

	printf("%d Service Nodes loaded\n",line);
	return TRUE;
}

int SaveService(ServiceList *sl)
{
	FILE *fp;
	int line = 0;
	ServiceNode *w;

	fp = fopen(".\\gunshulist.txt" , "w");
	if( fp == NULL ){
		printf("Service list(.\\gunshulist.txt) save failed.\n");
		return FALSE;
	}

	w = sl->topService;
	do{
		if( w == NULL ){
			fclose(fp);
			break;
		}
		line++;
		fprintf(fp , "%s\n" , w->name);
		w = w->next;
	}while(1);

	fclose(fp);
	printf("%d Service Nodes saved\n",line);
	return TRUE;
}

int GetServiceCount(ServiceList *sl)
{
	int line = 0;
	ServiceNode *w;

	w = sl->topService;
	do{
		if( w == NULL ){
			break;
		}
		line++;
		w = w->next;
	}while(1);

	return line;
}

void CrLftoNull(char *t)
{
	do{
		if(*t == 0xA || *t == 0xD ){
			*t = '\0';
		}else if(*t == '\0'){
			break;
		}
		t++;
	}while(1);
}

#if 0

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include "listman.h"

char list[NUM_LINE][BYTES_PER_LINE];
//int currentIndex;
//CRITICAL_SECTION csec;

//���s�������k�������ɂ���
void CrLftoNull(char *t);

const char *FindList(const char *t)
{
	int cur;
	const char *ret;
	const char *buf;
	TopList(&cur);

	do{
		buf = NextList(&cur);
		if( buf == NULL ){
			ret = NULL;
			break;
		}
		if( strcmp(buf , t) == 0){
			ret = buf;
			break;
		}
	}while(1);
	return ret;
}
void InitList()
{
	ClearList();
}

void ClearList()
{
	int i;
	for(i=0 ; i < NUM_LINE ; i++){
		list[i][0] = '\0';
	}
}
int AddList(const char *t)
{
	int i;
	if( strlen(t) >= BYTES_PER_LINE ){
		return FALSE;
	}

	for(i=0 ; i < NUM_LINE ; i++){
		if(list[i][0] == '\0'){
			strcpy(list[i] , t);
			return TRUE;
		}
	}
	printf("AddList failed.\n");
	return FALSE;
}

int SaveList(const char *file)
{
	FILE *fp;
	const char *t;
	int cur;

	fp = fopen(file , "w");
	if(fp == NULL ){
		printf("SaveList failed.\n");
		return FALSE;
	}
	TopList(&cur);
	do{
		t = NextList(&cur);
		if( t == NULL ){
			break;
		}
		fprintf(fp , "%s\n" , t);
	}while(1);

	fclose(fp);
	return TRUE;
}
int LoadList(const char *file)
{
	FILE *fp;
	char t[BYTES_PER_LINE];
	char *ret;

	fp = fopen(file , "r");
	if(fp == NULL ){
		printf("LoadList failed.\n");
		return FALSE;
	}

	ClearList();

	do{
		ret = fgets(t , BYTES_PER_LINE , fp);
		if( ret == NULL ){
			break;
		}
		CrLftoNull(t);
		AddList(t);
	}while(1);

	fclose(fp);
	return TRUE;
}

void CrLftoNull(char *t)
{
	do{
		if(*t == 0xA || *t == 0xD ){
			*t = '\0';
		}else if(*t == '\0'){
			break;
		}
		t++;
	}while(1);
}
int DelList(const char *t)
{
	int i;
	for(i=0 ; i < NUM_LINE ; i++){
		if(list[i][0] != '\0'){
			if(strcmp(t , list[i]) ==0){
				list[i][0] = '\0';
				return TRUE;
			}
		}
	}
	return FALSE;
}
void TopListWithCriticalSec(void)
{
	//EnterCriticalSection(&csec);
	//currentIndex = 0;
}
void TopList(int *cur)
{
	*cur = 0;
}

char const *NextList(int *cur)
{
	for(; *cur < NUM_LINE ; (*cur)++){
		if(list[*cur][0] != '\0'){
			(*cur)++;
			return list[(*cur)-1];
		}
	}
	return NULL;
}
int GetListCount(void)
{
	int i;
	int c;
	c = 0;

	for( i = 0; i < NUM_LINE ; i++){
		if( list[i][0] != '\0'){
			c++;
		}
	}
	return c;
}
#endif