#define _GNU_SOURCE //注意，这个宏必须在最前面，否则编译会报错
#include <sched.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/select.h>
#include <stdlib.h>

int value = 0;

int child_progress(void *arg)
{
	while(1)
	{
		printf("child,value = %d\r\n",value);
		value ++;
		sleep(1);
		if(value == 5)break;
	}
	return 0;
}

void main(int argc,char *argv[])
{
	int ret = -1;
	char *stack = NULL;
    pid_t tid = 0;

    stack = malloc(4096);
	if(NULL == stack)
	{
		printf("malloc fail]\r\n");
		return;
	}
	//子进程继承父进程的数据空间/在子进程结束后运行/将子进程的id存储到tid变量中
    int mask = CLONE_VM|CLONE_VFORK|CLONE_CHILD_SETTID;
	
	ret = clone(child_progress,stack+4096,mask,NULL,NULL,NULL,&tid);//栈地址向下增长，因此起始地址为stack+4096
	if(ret < 0)
	{
		printf("clone error\r\n");
		return;
	}
	printf("clone sucess,pid:%d %d\r\n",ret,tid);
    while(1)
	{
		printf("father,value = %d\r\n",value);
		value ++;
		sleep(1);
	}
}
