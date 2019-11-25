---
title: __malloc_hook
date: 2019-11-25
categories: 
- synthesis
tags: heap
---

# __malloc_hook

这是一个在调用`malloc`时总是会被调用的函数。看源码：

```C
__libc_malloc (size_t bytes)
{
  mstate ar_ptr;
  void *victim;

  void *(*hook) (size_t, const void *)
    = atomic_forced_read (__malloc_hook);
  if (__builtin_expect (hook != NULL, 0))
    return (*hook)(bytes, RETURN_ADDRESS (0));
  
  ......
}
```  
`malloc`在调用之前首先会检查`__malloc_hook`这个函数是否为空。不为空则调用他。  
`__malloc_hook`的初始值是`malloc_hook_init`  

```C
static Void_t*
#if __STD_C
malloc_hook_ini(size_t sz, const __malloc_ptr_t caller)
#else
malloc_hook_ini(sz, caller)
size_t sz; const __malloc_ptr_t caller;
#endif
{
__malloc_hook = NULL;
ptmalloc_init();
return __libc_malloc(sz);
}
```

# 利用

在CTF中，如果可以覆盖掉`__malloc_hook`的值，则可以控制程序流程了。