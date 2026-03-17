# -*- coding: utf-8 -*-
# @Author iyue
# @Time 2025/4/5 22:16
# @File main.py
# @Software: PyCharm
import ida_ida
import sys
import ida_idaapi
from loguru import logger
from flutter_ssl_bypass import FlutterPlugmod
from frida_ui import FridaPlugmod

logger.remove()
"""
DEBUG INFO 
"""
logger.add(sys.stdout, level="INFO")


class FridaPlugin(ida_idaapi.plugin_t):
    __plugin_name = "Frida_Tools"
    flags = ida_idaapi.PLUGIN_FIX | ida_idaapi.PLUGIN_MULTI
    comment = f"Generate frida hook script!"
    help = "Generate frida hook script, hotkey is Shift-F"
    wanted_name = __plugin_name
    wanted_hotkey = "Shift-F"

    def __init__(self):
        self.__frida_plugin = FridaPlugmod()
        self.__flutter_plugin = FlutterPlugmod()

    def init(self):
        logger.info("[frida_tools] init.")
        self.__frida_plugin.create_popup_menu(1)
        self.__flutter_plugin.create_popup_menu()
        return self.__frida_plugin

    def term(self):
        self.__frida_plugin.unload()
        self.__flutter_plugin.unload()


def PLUGIN_ENTRY():
    logger.info(f"[frida_tools] Frida Tools install")
    if 910 > ida_ida.inf_get_version():
        logger.warning("[frida_tools] Plug-ins support IDA 9.0 and above.")
    return FridaPlugin()
