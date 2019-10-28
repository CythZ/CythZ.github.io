---
title: rand & srand
date: 2019-10-28
categories:
- synthesis
tags: others
---

# 关于随机数绕过

## 随机数

程序里面没有真正的随机数，随机数来源于一段周期很长的数字序列，在小范围内可以看做随机数。  
`srand`是随机数使用前的初始化函数，需要传入不同的参数（种子）。如果种子是一样的话，每次产生的“随机数”也是一样的。

## 绕过

pwn题里面如果有类似需要猜测随机数或者绕过某个随机数的问题，可以先看一下他的`srand`中传入的数字是否可以覆盖或者可见，这样在得到了`libc`的情况下是可以使用 `ctypes`这个库来调用其中的`rand`函数获取和程序相同的随机数序列。

## ctypes

是一个第三方库，可以使用`dll`里面的函数。

```python
from ctypes import *

libc = cdll.LoadLibrary('libc.so.6')
#这里不可以用‘./libc.so.6'，会出现非法硬件指令的错误
```