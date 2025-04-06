# -*- coding: utf-8 -*-
# @Author iyue
# @Time 2025/4/5 22:16
# @File main.py
# @Software: PyCharm
import ida_ida
import sys
import ida_idaapi
from loguru import logger

from frida import FridaPlugmod

logger.remove()
'''
DEBUG INFO 
'''
logger.add(sys.stdout, level="DEBUG")

class FridaPlugin(ida_idaapi.plugin_t):
    __plugin_name = "Frida Tools"
    __version = "0.0.1"
    flags = ida_idaapi.PLUGIN_FIX | ida_idaapi.PLUGIN_MULTI
    comment = f"Generate frida hook script!"
    help = "Generate frida hook script, hotkey is Shift-F"
    wanted_name = __plugin_name
    wanted_hotkey = "Shift-F"

    def __init__(self):
        self.__frida_plugin = FridaPlugmod()

    def init(self):
        """
        1. ida 启动插件被加载时被调用
        2. 注册各种动作以及初始化 ui 钩子都在这里
        :return:
        """
        logger.info(">>>FridaPlugin: 插件初始化.")
        self.__frida_plugin.run(1)
        return self.__frida_plugin

def PLUGIN_ENTRY():
    logger.info(f">>>FridaPlugin: Frida Tools install")
    if 910 != ida_ida.inf_get_version():
        logger.warning(">>>plugin: Plug-ins only support IDA 9.1.0 and above.")
    return FridaPlugin()
