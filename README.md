# context 切换

函数定义：`extern void coctx_swap( coctx_t * cur,coctx_t* pending) asm("coctx_swap")`


首先列出coctx_t的定义：
```
struct coctx_t
{
#if defined(__i386__)
	void *regs[ 8 ];
#else
	void *regs[ 14 ]; // 14 * 8 = 112
#endif
	size_t ss_size;
	char *ss_sp;

};
```

初始函数堆栈内存布局：

```
pending
cur
return address
```


以下以64位为例讲解：
```
leaq 8(%rsp),%rax // cur
leaq 112(%rdi),%rsp //指向 regs末尾
pushq %rax
pushq %rbx
pushq %rcx
pushq %rdx

pushq -8(%rax) //ret func addr

pushq %rsi
pushq %rdi
pushq %rbp
pushq %r8
pushq %r9
pushq %r12
pushq %r13
pushq %r14
pushq %r15

movq %rsi, %rsp // pending
popq %r15
popq %r14
popq %r13
popq %r12
popq %r9
popq %r8
popq %rbp
popq %rdi
popq %rsi
popq %rax //ret func addr
popq %rdx
popq %rcx
popq %rbx
popq %rsp // 设置rsp指向返回地址上面
pushq %rax // 压入返回地址

xorl %eax, %eax // 清零eax
ret // 从此函数中返回
```

# co_eventloop实现

首先分配`co_epoll_res`结构用于`epoll_wait`。根据`epoll_wait`返回的事件，获取对应`stTimeoutItem_t`对象，若定义了pfnPrepare函数，调用，否则，将item加入active链表之中。接下来，获取当前时间，转动时间轮盘，获取所有超时的item，将他们加入timeout链表，设置超时flag为true。将timeout链表中所有元素加入active链表之中。遍历active链表，没有超时的加入时间轮，调用每个结点的pfnProcess函数，唤醒对应协程。

# poll实现
若超时时间为0，直接调用系统调用poll。将poll关注的事件注册给epoll处理。设定触发对应事件的时候，更新返回的事件的数目，记录返回事件类型，并且取消对poll超时的关注，（只有一次）将其加入active链表，以便后续唤醒当前协程。根据给定的timeout参数，将其加入时间轮盘监听超时。若超时发生，则会恢复到此协程context。完成添加超时，就会让出cpu，交由epoll进行处理。若被恢复继续执行，执行清理，从epoll中取消事件监听，并且设置返回的事情类型，返回触发的事件的个数。

# cond实现
timewait: 将当前协程加入等待链表，设置超时，让出控制权。
signal: 从等待链表弹出头结点，取消其超时事件，并且加入epoll就绪队列，等待对应协程被恢复运行。

# setenv实现
将之前指定的环境变量作为协程context的一部分，进行记录。未提前指定的环境变量调用系统调用进行get和set。

# 协程私有变量
`gethostbyname_r`需要一块协程specific的内存，用于存储返回的结果，所以有必要实现协程私有变量。组合使用`pthread_once`和`pthread_key_create`创建一个唯一的key，根据这个key，在每个协程的context的aSpec数组中记录和获取对应的私有变量。

# gethostbyname实现
glibc实现`gethostbyname_r`利用了poll方法，不过是自定义的`__poll`方法，所以需要hook `__poll`方法，再结合协程私有变量，就能保证每个协程上运行的`gethostbyname_r`互不影响。

# "同步阻塞式的"系统调用 - read
1. 将当前协程注册到定时器上，处理read()函数超时。
2. 调用`epoll_ctl`将自己注册到当前执行环境的epoll实例上。 以上两个都需要指定一个回调函数，唤醒当前协程。
3. 调用`co_yield_env`函数让出cpu。
4. 主协程`epoll_wait`得知read操作的文件描述符可读，则会执行原read协程注册的回调将其唤醒。工作协程被唤醒之后，调用原glibc内被hook替换掉的，真正的read系统调用。

# hook 原理：

```
static socket_pfn_t g_sys_socket_func = (socket_pfn_t) dlsym(RTLD_NEXT, "socket");
static connect_pfn_t g_sys_connect_func = (connect_pfn_t) dlsym(RTLD_NEXT, "connect");
static close_pfn_t g_sys_close_func = (close_pfn_t) dlsym(RTLD_NEXT, "close");

static read_pfn_t g_sys_read_func = (read_pfn_t) dlsym(RTLD_NEXT, "read");
static write_pfn_t g_sys_write_func = (write_pfn_t) dlsym(RTLD_NEXT, "write");

static sendto_pfn_t g_sys_sendto_func = (sendto_pfn_t) dlsym(RTLD_NEXT, "sendto");
static recvfrom_pfn_t g_sys_recvfrom_func = (recvfrom_pfn_t) dlsym(RTLD_NEXT, "recvfrom");

static send_pfn_t g_sys_send_func = (send_pfn_t) dlsym(RTLD_NEXT, "send");
static recv_pfn_t g_sys_recv_func = (recv_pfn_t) dlsym(RTLD_NEXT, "recv");

static poll_pfn_t g_sys_poll_func = (poll_pfn_t) dlsym(RTLD_NEXT, "poll");

static setsockopt_pfn_t g_sys_setsockopt_func
    = (setsockopt_pfn_t) dlsym(RTLD_NEXT, "setsockopt");
static fcntl_pfn_t g_sys_fcntl_func = (fcntl_pfn_t) dlsym(RTLD_NEXT, "fcntl");
```

> 特殊句柄 RTLD_NEXT 允许从调用方链接映射列表中的下一个关联目标文件获取符号
