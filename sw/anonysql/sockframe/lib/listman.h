#ifndef _LIST_MAN
#define _LIST_MAN

//�ő�̃m�[�h��
#define ServiceNode_MAX 128
//��s������̃o�C�g��
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
	ServiceNode *freeService;	//�󂫃��X�g�擪
	ServiceNode *topService;	//�g�p�ς݃��X�g�擪
} ServiceList;


//���X�g�Ǘ����C�u�����̏�����
void InitService(ServiceList *sl);
//���X�g�ɗv�f��ǉ�
int AddService(ServiceList *sl,const char *name );
//���X�g���폜����
//�폜���w�͋󂫃��X�g�̐擪���w�������B
int DelService(ServiceList *sl,ServiceNode *w);
//���X�g�̐擪�ɃJ�[�\�����ړ�����
ServiceNode *TopService(ServiceList *sl);
ServiceNode *FindService(ServiceList *sl,const char *name);
//�t�@�C�����烊�X�g��ǂݍ���
int LoadService(ServiceList *sl);
//�t�@�C���Ƀ��X�g�̓��e���Z�[�u
extern int SaveService(ServiceList *sl);
//���X�g�̌���Ԃ�
extern int GetServiceCount(ServiceList *sl);
#endif