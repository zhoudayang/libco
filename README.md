
# libco

是一个基于非对称协程的网络库，每个协程只能返回调用它的那个协程，由main协程执行epoll，根据返回的事件，重新激活对应的协程，继续执行过程。

## 时间轮盘机制
一个简单的时间轮盘机制，每次调用epoll时，首先处理epoll返回的事件，然后转动时间轮盘，将未超时的事件放置到轮盘上正确的位置上，超时的时间加入active list, 一起处理。

## poll实现
若超时时间为０，则直接调用poll系统调用。将poll关注的事件转给epoll进行处理。设置事件触发的时候，更新返回的有效事件的数目和类型。根据给定的timeout参数，加入timeout时间轮盘。有事件触发，从时间轮盘中删除此超时事件。然后yield出让控制权，交由epoll处理。触发事件切换回当前context, 执行相关清理，返回触发的事件的数目。

## context 切换
[context切换解析](https://zhuanlan.zhihu.com/p/27409164)

## cond实现
	timewait: 将当前协程加入等待链表，设置超时，出让控制权。
	signal: 从等待链表中弹出头节点，取消其超时事件，并且加入就绪队列，以便后续被调用。

## setenv实现
	将之前指定的环境变量作为协程context的一部分，进行记录。未提前指定的环境变量调用系统调用来进行get和set。

## gethostbyname实现

glibc实现gethostbyname利用了pool方法等待事件，是自定义的__pool方法，所以需要hook __pool方法。同时，因为gethostbyname使用了线程私有变量，不同协程之间切换可能会出现问题，所以在libco中用到了协程私有变量。

## 参考

[libco原理](https://github.com/zhoudayang/libco/blob/master/C%2B%2B%E5%BC%80%E6%BA%90%E5%8D%8F%E7%A8%8B%E5%BA%93libco-%E5%8E%9F%E7%90%86%E4%B8%8E%E5%BA%94%E7%94%A8.pdf)
