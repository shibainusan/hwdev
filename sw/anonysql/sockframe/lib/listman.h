#ifndef _LIST_MAN
#define _LIST_MAN

//最大のノード数
#define ServiceNode_MAX 128
//一行あたりのバイト数
#define BYTES_PER_LINE 1024

#ifndef FALSE
#define FALSE               0
#endif

#ifndef TRUE
#define TRUE                1
#endif

typedef struct tag_ServiceNode{
	char name[BYTES_PER_LINE + 1];
	struct tag_ServiceNode *next, *prev;
} ServiceNode;

typedef struct {
	ServiceNode workService[ServiceNode_MAX];
	ServiceNode *freeService;	//空きリスト先頭
	ServiceNode *topService;	//使用済みリスト先頭
} ServiceList;


//リスト管理ライブラリの初期化
void InitService(ServiceList *sl);
//リストに要素を追加
int AddService(ServiceList *sl,const char *name );
//リストを削除する
//削除後のwは空きリストの先頭を指し示す。
int DelService(ServiceList *sl,ServiceNode *w);
//リストの先頭にカーソルを移動する
ServiceNode *TopService(ServiceList *sl);
ServiceNode *FindService(ServiceList *sl,const char *name);
//ファイルからリストを読み込む
int LoadService(ServiceList *sl);
//ファイルにリストの内容をセーブ
extern int SaveService(ServiceList *sl);
//リストの個数を返す
extern int GetServiceCount(ServiceList *sl);
#endif