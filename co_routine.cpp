/*
* Tencent is pleased to support the open source community by making Libco available.

* Copyright (C) 2014 THL A29 Limited, a Tencent company. All rights reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License"); 
* you may not use this file except in compliance with the License. 
* You may obtain a copy of the License at
*
*	http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, 
* software distributed under the License is distributed on an "AS IS" BASIS, 
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
* See the License for the specific language governing permissions and 
* limitations under the License.
*/

#include "co_routine.h"
#include "co_routine_inner.h"
#include "co_epoll.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <string>
#include <map>

#include <poll.h>
#include <sys/time.h>
#include <errno.h>

#include <assert.h>

#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/syscall.h>
#include <unistd.h>

extern "C"
{
extern void coctx_swap(coctx_t *, coctx_t *) asm("coctx_swap");
};
using namespace std;
stCoRoutine_t *GetCurrCo(stCoRoutineEnv_t *env);
struct stCoEpoll_t;

struct stCoRoutineEnv_t {
  stCoRoutine_t *pCallStack[128]; //该线程内允许嵌套创建128个协程，即协程1内创建协程2，协程2内创建协程3，将其作为栈来使用，满足后进先出
  int iCallStackSize;             //该线程内部嵌套创建的协程的数目
  stCoEpoll_t *pEpoll;            //该线程内部的epoll实例,也用于该线程的事件循环eventloop中

  //for copy stack log lastco and nextco
  stCoRoutine_t *pending_co;
  stCoRoutine_t *ocupy_co;
};
//协程日志输出
//int socket(int domain, int type, int protocol);
void co_log_err(const char *fmt, ...) {
}

#if defined( __LIBCO_RDTSCP__)
static unsigned long long counter(void)
{
    register uint32_t lo, hi;
    register unsigned long long o;
    __asm__ __volatile__ (
            "rdtscp" : "=a"(lo), "=d"(hi)
            );
    o = hi;
    o <<= 32;
    return (o | lo);

}
static unsigned long long getCpuKhz()
{
    FILE *fp = fopen("/proc/cpuinfo","r");
    if(!fp) return 1;
    char buf[4096] = {0};
    fread(buf,1,sizeof(buf),fp);
    fclose(fp);

    char *lp = strstr(buf,"cpu MHz");
    if(!lp) return 1;
    lp += strlen("cpu MHz");
    while(*lp == ' ' || *lp == '\t' || *lp == ':')
    {
        ++lp;
    }

    double mhz = atof(lp);
    unsigned long long u = (unsigned long long)(mhz * 1000);
    return u;
}
#endif
//获取当前时间，毫秒级别
static unsigned long long GetTickMS() {
#if defined( __LIBCO_RDTSCP__)
  static uint32_t khz = getCpuKhz();
  return counter() / khz;
#else
  struct timeval now = {0};
  gettimeofday(&now, NULL);
  unsigned long long u = now.tv_sec;
  u *= 1000;
  u += now.tv_usec / 1000;
  return u;
#endif
}

//获取线程id
static pid_t GetPid() {
  // 线程局部变量
  static __thread pid_t pid = 0;
  static __thread pid_t tid = 0;
  if (!pid || !tid || pid != getpid()) {
    //获取当前进程id
    pid = getpid();
#if defined( __APPLE__ )
    tid = syscall( SYS_gettid );
    if( -1 == (long)tid )
    {
        tid = pid;
    }
#else
    // 执行系统调用，获取当前线程id
    tid = syscall(__NR_gettid);
#endif

  }
  return tid;

}
/*
static pid_t GetPid()
{
	char **p = (char**)pthread_self();
	return p ? *(pid_t*)(p + 18) : getpid();
}
*/
template<class T, class TLink>
void RemoveFromLink(T *ap) {
  TLink *lst = ap->pLink;
  if (!lst) return;
  assert(lst->head && lst->tail);

  if (ap == lst->head) {
    lst->head = ap->pNext;
    if (lst->head) {
      lst->head->pPrev = NULL;
    }
  } else {
    if (ap->pPrev) {
      ap->pPrev->pNext = ap->pNext;
    }
  }

  if (ap == lst->tail) {
    lst->tail = ap->pPrev;
    if (lst->tail) {
      lst->tail->pNext = NULL;
    }
  } else {
    ap->pNext->pPrev = ap->pPrev;
  }

  ap->pPrev = ap->pNext = NULL;
  ap->pLink = NULL;
}

template<class TNode, class TLink>
void inline AddTail(TLink *apLink, TNode *ap) {
  if (ap->pLink) {
    return;
  }
  if (apLink->tail) {
    apLink->tail->pNext = (TNode *) ap;
    ap->pNext = NULL;
    ap->pPrev = apLink->tail;
    apLink->tail = ap;
  } else {
    apLink->head = apLink->tail = ap;
    ap->pNext = ap->pPrev = NULL;
  }
  ap->pLink = apLink;
}
template<class TNode, class TLink>
void inline PopHead(TLink *apLink) {
  if (!apLink->head) {
    return;
  }
  TNode *lp = apLink->head;
  if (apLink->head == apLink->tail) {
    apLink->head = apLink->tail = NULL;
  } else {
    apLink->head = apLink->head->pNext;
  }

  lp->pPrev = lp->pNext = NULL;
  lp->pLink = NULL;

  if (apLink->head) {
    apLink->head->pPrev = NULL;
  }
}

template<class TNode, class TLink>
void inline Join(TLink *apLink, TLink *apOther) {
  //printf("apOther %p\n",apOther);
  if (!apOther->head) {
    return;
  }
  TNode *lp = apOther->head;
  while (lp) {
    lp->pLink = apLink;
    lp = lp->pNext;
  }
  lp = apOther->head;
  if (apLink->tail) {
    apLink->tail->pNext = (TNode *) lp;
    lp->pPrev = apLink->tail;
    apLink->tail = apOther->tail;
  } else {
    apLink->head = apOther->head;
    apLink->tail = apOther->tail;
  }

  apOther->head = apOther->tail = NULL;
}

/////////////////for copy stack //////////////////////////
stStackMem_t *co_alloc_stackmem(unsigned int stack_size) {
  stStackMem_t *stack_mem = (stStackMem_t *) malloc(sizeof(stStackMem_t));
  stack_mem->ocupy_co = NULL;
  stack_mem->stack_size = stack_size; // 堆栈大小
  stack_mem->stack_buffer = (char *) malloc(stack_size); //
  stack_mem->stack_bp = stack_mem->stack_buffer + stack_size;
  return stack_mem;
}

stShareStack_t *co_alloc_sharestack(int count, int stack_size) {
  stShareStack_t *share_stack = (stShareStack_t *) malloc(sizeof(stShareStack_t));
  share_stack->alloc_idx = 0;
  share_stack->stack_size = stack_size;

  //alloc stack array
  share_stack->count = count;
  stStackMem_t **stack_array = (stStackMem_t **) calloc(count, sizeof(stStackMem_t *));
  for (int i = 0; i < count; i++) {
    stack_array[i] = co_alloc_stackmem(stack_size);
  }
  share_stack->stack_array = stack_array;
  return share_stack;
}

static stStackMem_t *co_get_stackmem(stShareStack_t *share_stack) {
  if (!share_stack) {
    return NULL;
  }
  int idx = share_stack->alloc_idx % share_stack->count;
  share_stack->alloc_idx++;

  return share_stack->stack_array[idx];
}

// ----------------------------------------------------------------------------
struct stTimeoutItemLink_t;
struct stTimeoutItem_t;

//线程epoll实例,该结构存在stCoRoutineEnt_t结构之中
//同一线程内部所有的套接字都通过iEpollFd文件描述符向内核注册事件
struct stCoEpoll_t {
  int iEpollFd;
  static const int _EPOLL_SIZE = 1024 * 10;
  // point to timeout monitor list
  struct stTimeout_t *pTimeout;

  struct stTimeoutItemLink_t *pstTimeoutList;

  struct stTimeoutItemLink_t *pstActiveList;

  co_epoll_res *result;

};
typedef void (*OnPreparePfn_t)(stTimeoutItem_t *, struct epoll_event &ev, stTimeoutItemLink_t *active);
typedef void (*OnProcessPfn_t)(stTimeoutItem_t *);
struct stTimeoutItem_t {

  enum {
    eMaxTimeout = 40 * 1000 //20s
  };
  stTimeoutItem_t *pPrev;
  stTimeoutItem_t *pNext;
  stTimeoutItemLink_t *pLink;

  unsigned long long ullExpireTime;

  OnPreparePfn_t pfnPrepare;
  OnProcessPfn_t pfnProcess; // timeout function

  void *pArg; // routine
  bool bTimeout;
};
struct stTimeoutItemLink_t {
  stTimeoutItem_t *head;
  stTimeoutItem_t *tail;

};
struct stTimeout_t {
  stTimeoutItemLink_t *pItems;
  int iItemSize;

  unsigned long long ullStart;
  long long llStartIdx;
};
stTimeout_t *AllocTimeout(int iSize) {
  stTimeout_t *lp = (stTimeout_t *) calloc(1, sizeof(stTimeout_t));

  lp->iItemSize = iSize;
  lp->pItems = (stTimeoutItemLink_t *) calloc(1, sizeof(stTimeoutItemLink_t) * lp->iItemSize);

  lp->ullStart = GetTickMS();
  lp->llStartIdx = 0;

  return lp;
}
void FreeTimeout(stTimeout_t *apTimeout) {
  free(apTimeout->pItems);
  free(apTimeout);
}
int AddTimeout(stTimeout_t *apTimeout, stTimeoutItem_t *apItem, unsigned long long allNow) {
  if (apTimeout->ullStart == 0) {
    apTimeout->ullStart = allNow;
    apTimeout->llStartIdx = 0;
  }
  if (allNow < apTimeout->ullStart) {
    co_log_err("CO_ERR: AddTimeout line %d allNow %llu apTimeout->ullStart %llu",
               __LINE__, allNow, apTimeout->ullStart);

    return __LINE__;
  }
  if (apItem->ullExpireTime < allNow) {
    co_log_err("CO_ERR: AddTimeout line %d apItem->ullExpireTime %llu allNow %llu apTimeout->ullStart %llu",
               __LINE__, apItem->ullExpireTime, allNow, apTimeout->ullStart);

    return __LINE__;
  }
  int diff = apItem->ullExpireTime - apTimeout->ullStart;

  if (diff >= apTimeout->iItemSize) {
    co_log_err("CO_ERR: AddTimeout line %d diff %d",
               __LINE__, diff);

    return __LINE__;
  }
  AddTail(apTimeout->pItems + (apTimeout->llStartIdx + diff) % apTimeout->iItemSize, apItem);

  return 0;
}
inline void TakeAllTimeout(stTimeout_t *apTimeout, unsigned long long allNow, stTimeoutItemLink_t *apResult) {
  if (apTimeout->ullStart == 0) {
    apTimeout->ullStart = allNow;
    apTimeout->llStartIdx = 0;
  }

  if (allNow < apTimeout->ullStart) {
    return;
  }
  int cnt = allNow - apTimeout->ullStart + 1;
  if (cnt > apTimeout->iItemSize) {
    cnt = apTimeout->iItemSize;
  }
  if (cnt < 0) {
    return;
  }
  for (int i = 0; i < cnt; i++) {
    int idx = (apTimeout->llStartIdx + i) % apTimeout->iItemSize;
    Join<stTimeoutItem_t, stTimeoutItemLink_t>(apResult, apTimeout->pItems + idx);
  }
  apTimeout->ullStart = allNow;
  apTimeout->llStartIdx += cnt - 1;

}
//所有新协程第一次被调度执行时的入口函数,新协程在该入口函数中被执行
//co 第一次被调度的协程
static int CoRoutineFunc(stCoRoutine_t *co, void *) {
  if (co->pfn) {
    co->pfn(co->arg);
  }
  co->cEnd = 1;

  stCoRoutineEnv_t *env = co->env;

  co_yield_env(env);

  return 0;
}

//分配协程存储空间,并初始化其中的部分成员变量
//env 当前线程环境,用于初始化协程存储结构stCoRoutine_t
//pfn 协程函数,用于初始化协程存储结构stCoRoutine_t
//arg 协程函数的参数,用于初始化携程存储结构stCoRountine_t
struct stCoRoutine_t *co_create_env(stCoRoutineEnv_t *env, const stCoRoutineAttr_t *attr,
                                    pfn_co_routine_t pfn, void *arg) {

  stCoRoutineAttr_t at;
  // 如果指定了Routine attr, 将其设置为at
  if (attr) {
    memcpy(&at, attr, sizeof(at));
  }
  //如果设置的堆栈大小　小于等于０,　将其设置为128KB
  if (at.stack_size <= 0) {
    at.stack_size = 128 * 1024;
  }//保证堆栈大小上限为8G
  else if (at.stack_size > 1024 * 1024 * 8) {
    at.stack_size = 1024 * 1024 * 8;
  }
  // 堆栈的大小和4k对齐, 实际上只针对stack_size % 4096 = 4095的情况有效
  if (at.stack_size & 0xFFF) {
    at.stack_size &= ~0xFFF;
    at.stack_size += 0x1000;
  }

  stCoRoutine_t *lp = (stCoRoutine_t *) malloc(sizeof(stCoRoutine_t));

  lp->env = env;
  lp->pfn = pfn;
  lp->arg = arg;

  stStackMem_t *stack_mem = NULL;
  if (at.share_stack) {
    stack_mem = co_get_stackmem(at.share_stack);
    at.stack_size = at.share_stack->stack_size;
  } else {
    stack_mem = co_alloc_stackmem(at.stack_size);
  }
  lp->stack_mem = stack_mem;
  // 堆栈当前指针
  lp->ctx.ss_sp = stack_mem->stack_buffer;
  //堆栈大小
  lp->ctx.ss_size = at.stack_size;

  lp->cStart = 0;
  lp->cEnd = 0;
  lp->cIsMain = 0;
  lp->cEnableSysHook = 0;
  lp->cIsShareStack = at.share_stack != NULL;

  lp->save_size = 0;
  lp->save_buffer = NULL;

  return lp;
}

//创建协程
//ppco 协程指针的地址
//attr 携程属性
//pfn 协程函数
//arg 协程函数的参数
int co_create(stCoRoutine_t **ppco, const stCoRoutineAttr_t *attr, pfn_co_routine_t pfn, void *arg) {
  if (!co_get_curr_thread_env()) {
    co_init_curr_thread_env();
  }
  stCoRoutine_t *co = co_create_env(co_get_curr_thread_env(), attr, pfn, arg);
  *ppco = co;
  return 0;
}
// 无论协程处于什么状态,释放协程co占用的内存空间
// co 待释放的协程
void co_free(stCoRoutine_t *co) {
  free(co);
}
//如果协程处于执行结束状态,那么释放协程co占用的内存空间
void co_release(stCoRoutine_t *co) {
  if (co->cEnd) {
    free(co);
  }
}

//define in coctx_swap.S
void co_swap(stCoRoutine_t *curr, stCoRoutine_t *pending_co);

//执行协程
//co待切换的协程
void co_resume(stCoRoutine_t *co) {
  // 获取协程的调度器
  stCoRoutineEnv_t *env = co->env;
  // 在协程co的协程环境的协程数组末尾获取当前正在执行的协程lpCurrRoutine
  stCoRoutine_t *lpCurrRoutine = env->pCallStack[env->iCallStackSize - 1];
  if (!co->cStart) {
    //如果协程是第一次被调度,则通过入口函数CoRotutineFunc来为其构造上下文
    coctx_make(&co->ctx, (coctx_pfn_t) CoRoutineFunc, co, 0);
    co->cStart = 1;
  }
  //将协程co后加入到协程环境的协程数组末尾
  env->pCallStack[env->iCallStackSize++] = co;
  //保存当前上下文到lpCurrentRoutine->ctx,并切换到新的上下文co->ctx
  co_swap(lpCurrRoutine, co);

}

//删除协程环境的协程数组中最后一个协程(当前正在执行的协程)
//env当前线程的调度器
void co_yield_env(stCoRoutineEnv_t *env) {
  //上次切换协程时,被当前协程切换出去的协程
  stCoRoutine_t *last = env->pCallStack[env->iCallStackSize - 2];
  //当前协程
  stCoRoutine_t *curr = env->pCallStack[env->iCallStackSize - 1];
  //删除当前协程
  env->iCallStackSize--;
  //切换到上次被切换出去的协程last
  co_swap(curr, last);
}

//删除协程环境的协程数组中最后一个协程
void co_yield_ct() {

  co_yield_env(co_get_curr_thread_env());
}

void co_yield(stCoRoutine_t *co) {
  co_yield_env(co->env);
}

void save_stack_buffer(stCoRoutine_t *ocupy_co) {
  ///copy out
  stStackMem_t *stack_mem = ocupy_co->stack_mem;
  int len = stack_mem->stack_bp - ocupy_co->stack_sp;

  if (ocupy_co->save_buffer) {
    free(ocupy_co->save_buffer), ocupy_co->save_buffer = NULL;
  }

  ocupy_co->save_buffer = (char *) malloc(len); //malloc buf;
  ocupy_co->save_size = len;

  memcpy(ocupy_co->save_buffer, ocupy_co->stack_sp, len);
}

// 切换context
void co_swap(stCoRoutine_t *curr, stCoRoutine_t *pending_co) {
  stCoRoutineEnv_t *env = co_get_curr_thread_env();

  //get curr stack sp spi
  char c;
  curr->stack_sp = &c;

  if (!pending_co->cIsShareStack) {
    env->pending_co = NULL;
    env->ocupy_co = NULL;
  } else {
    env->pending_co = pending_co;
    //get last occupy co on the same stack mem
    stCoRoutine_t *ocupy_co = pending_co->stack_mem->ocupy_co;
    //set pending co to ocupy thest stack mem;
    pending_co->stack_mem->ocupy_co = pending_co;

    env->ocupy_co = ocupy_co;
    if (ocupy_co && ocupy_co != pending_co) {
      save_stack_buffer(ocupy_co);
    }
  }

  //swap context, swap from curr to pending
  coctx_swap(&(curr->ctx), &(pending_co->ctx));

  //stack buffer may be overwrite, so get again;
  stCoRoutineEnv_t *curr_env = co_get_curr_thread_env();
  stCoRoutine_t *update_ocupy_co = curr_env->ocupy_co;
  stCoRoutine_t *update_pending_co = curr_env->pending_co;

  if (update_ocupy_co && update_pending_co && update_ocupy_co != update_pending_co) {
    //resume stack buffer
    if (update_pending_co->save_buffer && update_pending_co->save_size > 0) {
      memcpy(update_pending_co->stack_sp, update_pending_co->save_buffer, update_pending_co->save_size);
    }
  }
}

//int poll(struct pollfd fds[], nfds_t nfds, int timeout);
// { fd,events,revents }
struct stPollItem_t;
// 继承了stTimeoutItem_t
struct stPoll_t : public stTimeoutItem_t {
  struct pollfd *fds;  //待检测的套接字描述符集合
  nfds_t nfds; // typedef unsigned long int nfds_t; 待检测的套接字描述符的个数

  stPollItem_t *pPollItems; //存储了待检测的每个文件描述符的信息

  int iAllEventDetach;

  int iEpollFd;  // 由epoll_create函数创建的epoll句柄, 检测事件通过该句柄向内核通知

  int iRaiseCnt;   // 发生事件的套接字数量

};
struct stPollItem_t : public stTimeoutItem_t {
  struct pollfd *pSelf;
  stPoll_t *pPoll;

  struct epoll_event stEvent;
};
/*
 *   EPOLLPRI 		POLLPRI    // There is urgent data to read.  
 *   EPOLLMSG 		POLLMSG
 *
 *   				POLLREMOVE
 *   				POLLRDHUP
 *   				POLLNVAL
 *
 * */
static uint32_t PollEvent2Epoll(short events) {
  uint32_t e = 0;
  if (events & POLLIN) e |= EPOLLIN;
  if (events & POLLOUT) e |= EPOLLOUT;
  if (events & POLLHUP) e |= EPOLLHUP;
  if (events & POLLERR) e |= EPOLLERR;
  return e;
}
static short EpollEvent2Poll(uint32_t events) {
  short e = 0;
  if (events & EPOLLIN) e |= POLLIN;
  if (events & EPOLLOUT) e |= POLLOUT;
  if (events & EPOLLHUP) e |= POLLHUP;
  if (events & EPOLLERR) e |= POLLERR;
  return e;
}
// 每个进程对应一个数组元素，进程pid不会超过102400
static stCoRoutineEnv_t *g_arrCoEnvPerThread[102400] = {0};
//为当前线程分配协程环境存储空间(stCoRoutineEnv_t)并初始化其中的部分成员变量
void co_init_curr_thread_env() {
  //获取线程id
  pid_t pid = GetPid();
  //为当前线程分配线程环境的存储空间
  g_arrCoEnvPerThread[pid] = (stCoRoutineEnv_t *) calloc(1, sizeof(stCoRoutineEnv_t));
  // 当前携程运行环境
  stCoRoutineEnv_t *env = g_arrCoEnvPerThread[pid];
  printf("init pid %ld env %p\n", (long) pid, env);

  env->iCallStackSize = 0;
  //将当前线程中的上下文包装成主协程
  struct stCoRoutine_t *self = co_create_env(env, NULL, NULL, NULL);
  self->cIsMain = 1;

  env->pending_co = NULL;
  env->ocupy_co = NULL;

  //将包装好的主协程的上下文置零
  coctx_init(&self->ctx);

  //将包装好的主协程加入调度器的协程数组中
  env->pCallStack[env->iCallStackSize++] = self;
  // 为调度器创建epoll文件描述符号并分配超时链表的存储空间
  stCoEpoll_t *ev = AllocEpoll();
  // 将ev加入到调度器中
  SetEpoll(env, ev);
}
//获取当前线程的协程环境
stCoRoutineEnv_t *co_get_curr_thread_env() {
  return g_arrCoEnvPerThread[GetPid()];
}

//事件发生时的回调函数,其主要功能是恢复pArg指向的协程
void OnPollProcessEvent(stTimeoutItem_t *ap) {
  stCoRoutine_t *co = (stCoRoutine_t *) ap->pArg;
  // 切换到这个协程
  co_resume(co);
}

void OnPollPreparePfn(stTimeoutItem_t *ap, struct epoll_event &e, stTimeoutItemLink_t *active) {
  stPollItem_t *lp = (stPollItem_t *) ap;
  lp->pSelf->revents = EpollEvent2Poll(e.events);

  stPoll_t *pPoll = lp->pPoll;
  pPoll->iRaiseCnt++;

  if (!pPoll->iAllEventDetach) {
    pPoll->iAllEventDetach = 1;

    RemoveFromLink<stTimeoutItem_t, stTimeoutItemLink_t>(pPoll);

    AddTail(active, pPoll);

  }
}

//事件循环,作用是检测套接字上的事件并且恢复相关协程来处理事件
void co_eventloop(stCoEpoll_t *ctx, pfn_co_eventloop_t pfn, void *arg) {
  if (!ctx->result) {
    ctx->result = co_epoll_res_alloc(stCoEpoll_t::_EPOLL_SIZE);
  }
  co_epoll_res *result = ctx->result;

  for (;;) {
    int ret = co_epoll_wait(ctx->iEpollFd, result, stCoEpoll_t::_EPOLL_SIZE, 1);
    // active list
    stTimeoutItemLink_t *active = (ctx->pstActiveList);
    // timeout list
    stTimeoutItemLink_t *timeout = (ctx->pstTimeoutList);

    memset(timeout, 0, sizeof(stTimeoutItemLink_t));

    for (int i = 0; i < ret; i++) {
      // get timeout items
      stTimeoutItem_t *item = (stTimeoutItem_t *) result->events[i].data.ptr;
      if (item->pfnPrepare) {
        // timeout prepare function
        item->pfnPrepare(item, result->events[i], active);
      } else {
        // add to active list
        AddTail(active, item);
      }
    }

    unsigned long long now = GetTickMS();
    //get timeout list
    TakeAllTimeout(ctx->pTimeout, now, timeout);

    stTimeoutItem_t *lp = timeout->head;
    while (lp) {
      // set timeout flag to show timeout occurred
      lp->bTimeout = true;
      lp = lp->pNext;
    }
    // join timeout to active list
    Join<stTimeoutItem_t, stTimeoutItemLink_t>(active, timeout);

    lp = active->head;
    while (lp) {

      PopHead<stTimeoutItem_t, stTimeoutItemLink_t>(active);
      if (lp->pfnProcess) {
        lp->pfnProcess(lp);
      }

      lp = active->head;
    }
    if (pfn) {
      if (-1 == pfn(arg)) {
        break;
      }
    }

  }
}
void OnCoroutineEvent(stTimeoutItem_t *ap) {
  stCoRoutine_t *co = (stCoRoutine_t *) ap->pArg;
  co_resume(co);
}

//为当前线程分配stCoEpoll_t类型的存储空间,并初始化
stCoEpoll_t *AllocEpoll() {
  stCoEpoll_t *ctx = (stCoEpoll_t *) calloc(1, sizeof(stCoEpoll_t));

  ctx->iEpollFd = co_epoll_create(stCoEpoll_t::_EPOLL_SIZE);
  ctx->pTimeout = AllocTimeout(60 * 1000);

  ctx->pstActiveList = (stTimeoutItemLink_t *) calloc(1, sizeof(stTimeoutItemLink_t));
  ctx->pstTimeoutList = (stTimeoutItemLink_t *) calloc(1, sizeof(stTimeoutItemLink_t));

  return ctx;
}
//释放当前线程中stCoEpoll_t类型的存储空间
void FreeEpoll(stCoEpoll_t *ctx) {
  if (ctx) {
    free(ctx->pstActiveList);
    free(ctx->pstTimeoutList);
    FreeTimeout(ctx->pTimeout);
    co_epoll_res_free(ctx->result);
  }
  free(ctx);
}
//获取某一协程环境中正在执行的协程
stCoRoutine_t *GetCurrCo(stCoRoutineEnv_t *env) {
  return env->pCallStack[env->iCallStackSize - 1];
}
//获取当前线程中正在执行的协程
stCoRoutine_t *GetCurrThreadCo() {
  stCoRoutineEnv_t *env = co_get_curr_thread_env();
  if (!env) return 0;
  return GetCurrCo(env);
}
//该函数向内核注册套接字上待监听的事件,然后切换协程,当该协程被恢复时即说明事件处理结束, 进行善后
int co_poll(stCoEpoll_t *ctx, struct pollfd fds[], nfds_t nfds, int timeout) {
  // timout should be less than eMaxTimeout
  if (timeout > stTimeoutItem_t::eMaxTimeout) {
    timeout = stTimeoutItem_t::eMaxTimeout;
  }
  int epfd = ctx->iEpollFd;
  // 当前协程
  stCoRoutine_t *self = co_self();

  //1.struct change
  stPoll_t &arg = *((stPoll_t *) malloc(sizeof(stPoll_t)));
  memset(&arg, 0, sizeof(arg));

  arg.iEpollFd = epfd;
  arg.fds = (pollfd *) calloc(nfds, sizeof(pollfd));
  arg.nfds = nfds;

  stPollItem_t arr[2];
  if (nfds < sizeof(arr) / sizeof(arr[0]) && !self->cIsShareStack) {
    arg.pPollItems = arr;
  } else {
    arg.pPollItems = (stPollItem_t *) malloc(nfds * sizeof(stPollItem_t));
  }
  memset(arg.pPollItems, 0, nfds * sizeof(stPollItem_t));
  // 当 epoll 事件被触发，就会调用该函数来 resume 相应的协程。
  arg.pfnProcess = OnPollProcessEvent;
  // pArg 保存当前的协程，pfnProcess 函数中用该字段来得到需要 resume 的协程对象。
  arg.pArg = GetCurrCo(co_get_curr_thread_env());
  //2.add timeout

  unsigned long long now = GetTickMS();
  // expireTime is now + timeout, timeout is the arg of pool function
  arg.ullExpireTime = now + timeout;
  int ret = AddTimeout(ctx->pTimeout, &arg, now);
  if (ret != 0) {
    co_log_err("CO_ERR: AddTimeout ret %d now %lld timeout %d arg.ullExpireTime %lld",
               ret, now, timeout, arg.ullExpireTime);
    errno = EINVAL;

    if (arg.pPollItems != arr) {
      free(arg.pPollItems);
      arg.pPollItems = NULL;
    }
    free(arg.fds);
    free(&arg);

    return -__LINE__;
  }
  //3. add epoll

  for (nfds_t i = 0; i < nfds; i++) {
    arg.pPollItems[i].pSelf = arg.fds + i;
    arg.pPollItems[i].pPoll = &arg;

    arg.pPollItems[i].pfnPrepare = OnPollPreparePfn;
    struct epoll_event &ev = arg.pPollItems[i].stEvent;

    if (fds[i].fd > -1) {
      ev.data.ptr = arg.pPollItems + i;
      ev.events = PollEvent2Epoll(fds[i].events);

      co_epoll_ctl(epfd, EPOLL_CTL_ADD, fds[i].fd, &ev);
    }
    //if fail,the timeout would work
  }

  // switch context
  co_yield_env(co_get_curr_thread_env());
  // 当该协程被恢复时即说明事件处理结束, 进行善后
  RemoveFromLink<stTimeoutItem_t, stTimeoutItemLink_t>(&arg);
  for (nfds_t i = 0; i < nfds; i++) {
    int fd = fds[i].fd;
    if (fd > -1) {
      co_epoll_ctl(epfd, EPOLL_CTL_DEL, fd, &arg.pPollItems[i].stEvent);
    }
    fds[i].revents = arg.fds[i].revents;
  }

  if (arg.pPollItems != arr) {
    free(arg.pPollItems);
    arg.pPollItems = NULL;
  }

  free(arg.fds);
  free(&arg);

  return arg.iRaiseCnt;
}

void SetEpoll(stCoRoutineEnv_t *env, stCoEpoll_t *ev) {
  env->pEpoll = ev;
}
//获取当前线程协程环境中的epoll实例
stCoEpoll_t *co_get_epoll_ct() {
  if (!co_get_curr_thread_env()) {
    co_init_curr_thread_env();
  }
  return co_get_curr_thread_env()->pEpoll;
}
struct stHookPThreadSpec_t {
  stCoRoutine_t *co;
  void *value;

  enum {
    size = 1024
  };
};
void *co_getspecific(pthread_key_t key) {
  stCoRoutine_t *co = GetCurrThreadCo();
  if (!co || co->cIsMain) {
    return pthread_getspecific(key);
  }
  return co->aSpec[key].value;
}
int co_setspecific(pthread_key_t key, const void *value) {
  stCoRoutine_t *co = GetCurrThreadCo();
  if (!co || co->cIsMain) {
    return pthread_setspecific(key, value);
  }
  co->aSpec[key].value = (void *) value;
  return 0;
}

//禁止hook系统调用
void co_disable_hook_sys() {
  stCoRoutine_t *co = GetCurrThreadCo();
  if (co) {
    co->cEnableSysHook = 0;
  }
}
// 判断协程中系统调用是否被hook
bool co_is_enable_sys_hook() {
  stCoRoutine_t *co = GetCurrThreadCo();
  return (co && co->cEnableSysHook);
}

stCoRoutine_t *co_self() {
  return GetCurrThreadCo();
}

//co cond
struct stCoCond_t;
struct stCoCondItem_t {
  stCoCondItem_t *pPrev;
  stCoCondItem_t *pNext;
  stCoCond_t *pLink;

  stTimeoutItem_t timeout;
};
struct stCoCond_t {
  stCoCondItem_t *head;
  stCoCondItem_t *tail;
};
static void OnSignalProcessEvent(stTimeoutItem_t *ap) {
  stCoRoutine_t *co = (stCoRoutine_t *) ap->pArg;
  co_resume(co);
}

stCoCondItem_t *co_cond_pop(stCoCond_t *link);
int co_cond_signal(stCoCond_t *si) {
  stCoCondItem_t *sp = co_cond_pop(si);
  if (!sp) {
    return 0;
  }
  RemoveFromLink<stTimeoutItem_t, stTimeoutItemLink_t>(&sp->timeout);

  AddTail(co_get_curr_thread_env()->pEpoll->pstActiveList, &sp->timeout);

  return 0;
}
int co_cond_broadcast(stCoCond_t *si) {
  for (;;) {
    stCoCondItem_t *sp = co_cond_pop(si);
    if (!sp) return 0;

    RemoveFromLink<stTimeoutItem_t, stTimeoutItemLink_t>(&sp->timeout);

    AddTail(co_get_curr_thread_env()->pEpoll->pstActiveList, &sp->timeout);
  }

  return 0;
}

int co_cond_timedwait(stCoCond_t *link, int ms) {
  stCoCondItem_t *psi = (stCoCondItem_t *) calloc(1, sizeof(stCoCondItem_t));
  psi->timeout.pArg = GetCurrThreadCo();
  psi->timeout.pfnProcess = OnSignalProcessEvent;

  if (ms > 0) {
    unsigned long long now = GetTickMS();
    psi->timeout.ullExpireTime = now + ms;

    int ret = AddTimeout(co_get_curr_thread_env()->pEpoll->pTimeout, &psi->timeout, now);
    if (ret != 0) {
      free(psi);
      return ret;
    }
  }
  AddTail(link, psi);

  co_yield_ct();

  RemoveFromLink<stCoCondItem_t, stCoCond_t>(psi);
  free(psi);

  return 0;
}
stCoCond_t *co_cond_alloc() {
  return (stCoCond_t *) calloc(1, sizeof(stCoCond_t));
}
int co_cond_free(stCoCond_t *cc) {
  free(cc);
  return 0;
}

stCoCondItem_t *co_cond_pop(stCoCond_t *link) {
  stCoCondItem_t *p = link->head;
  if (p) {
    PopHead<stCoCondItem_t, stCoCond_t>(link);
  }
  return p;
}

