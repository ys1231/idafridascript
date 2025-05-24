# 项目描述

*   这是一个基于 `IDA Pro 9.1` 的插件脚本，可以在汇编窗口一键生成 `frida hook` 函数的 `js` 代码

# 如何使用

*   只要在汇编窗口中按下快捷键 `F` ，就可以生成当前指针所在函数的 `hook` 代码。

## Linux 和 Mac
```shell
rm -rf $HOME/.idapro/plugins/frida && git clone https://github.com/ys1231/idafridascript.git $HOME/.idapro/plugins/frida
```

## 功能列表

1. 生成对函数的 hook 代码
2. 生成针对 flutter ssl bypass frida hook 代码

# 如何继续发展

1. 使用 `clone` 项目后，用 `Pycharm` 打开项目，添加 `IDA Pro` 插件开发环境

![image](resources/screenshot-20250407-020045.png)