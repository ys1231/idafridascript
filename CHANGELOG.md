fix(frida_tools): 解决 func 为 None 导致的异常
- 在遍历 Xrefs 时增加 func 为空的判断
- 添加日志记录 func 为空的情况及地址信息
