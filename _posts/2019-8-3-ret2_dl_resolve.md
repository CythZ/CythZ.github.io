---
title: ret2_dl_resolve
date: 2019-08-03
categories:
- stack_advanced_rop
tags: stack ret2_dl_resolve rop
---

**<font style='font-size:25px'>ret2_dl_resolve</font>**

# GOT & PLT

## 动态链接需要考虑的两点

- 需要存放外部函数的数据段（GOT）
- 获取数据段存放函数地址的一小段额外代码（PLT）

## PLT

`PLT`内容是一段代码，所以`PLT`位于代码段，不可更改

## GOT

`GOT`是一个表，表里面存的是函数的地址。    

`GOT`表项中还保存了三个公共表项     

`got[0]`: 本ELF动态段`.dynamic`的装载地址    
`got[1]`: 本ELF的`link_map`数据结构描述符地址   
`got[2]`: `dl_rumtime_resolve`函数的地址    

## 流程

![pic](https://c-ssl.duitang.com/uploads/item/201908/03/20190803124657_UzUQt.png)

## 延迟重定向

在函数第一次调用前，`got`表项的内容都是链接器生成的，他的值指向对应的`plt`中`jmp`代码的下一条指令。
```armasm
jmp func@got
; ↓got指向的位置
push 0x0 ;或者其他数字
jmp <common@plt>
```  

最后都会跳到`<common@plt>`【也就是plt[0]】中去执行代码。   
这是动态链接做符号解析和重定位的公共入口。    
- `common@plt`内容

```armasm
pushl 0x080496f0 ;将某个函数的got表地址压栈,调用完成后就把真正的函数地址写入这里
jmp *GOT[2] ;跳入能够解析动态链接库函数地址的函数
; 也就是dl_runtime_resolve函数
```  

所有动态链接库函数在第一次调用时都会通过   
`xxx@plt` ===> `common@plt` ===> `dl_runtime_resolve()` 完成调用。      

# dl_runtime_resolve

## 调用流程 


![pic](https://c-ssl.duitang.com/uploads/item/201907/18/20190718171653_JuHvd.png)

## 两个参数

1. `link_map`的指针    

包含了`.dynamic`的指针，使`dl_runtime_resolve`可以访问到这个段。     

2. offset  

```armasm
jmp func@got
; ↓got指向的位置
push 0x0 ;或者其他数字
jmp <common@plt>
```    

这里`push`的数字其实是函数的ID，这个ID就是offset。    

这也就解释了，`dl_runtime_resolve`如何知道是查找哪个函数。    

# 攻击手段

## 改写`.dynstr`节的指针
让这个指针指向我们需要的函数名字符串，例如`system`字符串
- 缺陷
    只有在NO RELRO时候才有权限更改`.dynstr`。

## 伪造结构体    

通过栈溢出，让函数返回到`<common@plt>`中，利用伪造的参数达到调用函数的目的。    

因为函数的执行过程就是不断地寻找结构体，从结构体中拿数据，而在函数源码中，并不会检查offset是否会过界，所以我们可以在可控制的地方伪造结构体来达到目的。

0. 计算fake_rel和`.rel.plt`的距离偏移量作为offset，注意64位需要除以`sizeof(ELF32_REL)`。

1. 伪造一`fake_rel`，使他的rel_info字段成为`0x******07`，这个07是导入函数的参数。暂时不知道干嘛的，但最好不要改。

2. `******`是指fake_sym距离`.dynsym`的`偏移/sizeof(ELF32_SYM)`。

3. `fake_sym`中`st_name`是fake_string距离`.dynstr`的偏移量。
