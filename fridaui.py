# -*- coding: utf-8 -*-
# @Author iyue
# @Time 2025/4/5 22:25
# @File frida.py
# @Software: PyCharm
import os

import ida_kernwin
from PyQt5.QtGui import QClipboard
from PyQt5.QtWidgets import QApplication
from ida_funcs import get_func, func_t
from ida_idaapi import plugmod_t
from ida_kernwin import action_desc_t
from ida_nalt import get_root_filename
from loguru import logger


class FridaHandler(ida_kernwin.action_handler_t):

    def __init__(self):
        current_path = os.path.dirname(os.path.abspath(__file__))
        self.__template_script_path = current_path + "/resources/inject.js"
        logger.debug(f">>>FridaHandler: Template script path is {self.__template_script_path}")

    def update(self, ctx: ida_kernwin.action_ctx_base_t):
        if ctx.widget_type == ida_kernwin.BWN_DISASM:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        else:
            return ida_kernwin.AST_DISABLE_FOR_WIDGET

    def activate(self, ctx):
        """
            Click on the menu to execute
        Returns:
            object:
        """
        data = self.__get_func_info(ctx)
        if data is None:
            return
        script = self.__generate_script(data)
        if script is None:
            return
        clipboard: QClipboard = QApplication.clipboard()
        clipboard.setText(script)
        logger.info(f">>>FridaHandler: Copy script to clipboard")

    def __get_func_info(self, ctx):

        # 1. 获取当前指针地址
        ea = ida_kernwin.get_screen_ea()
        func: func_t = get_func(ea)
        if func is None:
            logger.error(f">>>FridaHandler: ea not in function")
            return None
        func_type = func.prototype

        logger.debug(f"func name: {func.get_name()}")
        logger.debug(f"func offset: {hex(func.start_ea)}")

        args_list = []
        for arg in func_type.iter_func():
            logger.debug(f"args: {arg.type} {arg.name}")
            args_list.append({"type": str(arg.type), "name": str(arg.name)})
        return_type = func_type.get_rettype()
        logger.debug(f"return type: {return_type}")

        return {
            "module_name": get_root_filename(),
            "func_name": func.get_name(),
            "func_offset": hex(func.start_ea),
            "args": args_list,
            "return_type": str(return_type)
        }

    def __generate_script(self, data):
        try:
            module_name = data["module_name"]
            func_name = data["func_name"]
            func_offset = data["func_offset"]
            args_list = data["args"]
            return_type = data["return_type"]
            with open(self.__template_script_path, "r") as f:
                jscode = f.read()
                jscode = jscode.replace("MODULE_NAME", f'"{module_name}"')
                jscode = jscode.replace("FUNC_NAME", f'"{func_name}"')
                jscode = jscode.replace("FUNC_OFFSET", str(func_offset))
                jscode = jscode.replace("ARGS_LIST", str(args_list))
                jscode = jscode.replace("RETURN_TYPE", f'"{return_type}"')

                return jscode
        except Exception as e:
            logger.error(f"FridaHandler: generate script error: {e}")
            return None


class FridaUIHooks(ida_kernwin.UI_Hooks):

    def __init__(self, action_name):
        ida_kernwin.UI_Hooks.__init__(self)
        self.__action_name = action_name

    def finish_populating_widget_popup(self, widget, popup_handle, ctx):
        if ida_kernwin.get_widget_type(widget) == ida_kernwin.BWN_DISASM:
            ida_kernwin.attach_action_to_popup(widget, popup_handle, self.__action_name)


class FridaPlugmod(plugmod_t):

    def __del__(self):
        logger.info("Frida Plugmod is unloaded")

    def __init__(self):

        self.__action_name = "iyue:frida_helper"
        self.__popup_menu_name = "Copy frida script"
        self.__action_handler = FridaHandler()
        self.__shortcut = "F"
        self.__tooltip = "Frida Helper"
        self.__ui_hook = FridaUIHooks(self.__action_name)

    @staticmethod
    def __custon_icon():
        current_path = os.path.dirname(os.path.abspath(__file__))
        logger.debug(f"FridaPlugmod: Custon icon path is {current_path}/resources/frida.png")
        return ida_kernwin.load_custom_icon(file_name=current_path + "/resources/frida.png", format="png")

    def run(self, arg):
        logger.info(f"Frida Plugmod is loaded arg: {arg}")
        try:
            action_desc = action_desc_t(
                self.__action_name,
                self.__popup_menu_name,
                self.__action_handler,
                self.__shortcut,
                self.__tooltip,
                self.__custon_icon()
            )
            register_status = ida_kernwin.register_action(action_desc)
            if register_status:
                logger.success(f"Frida Plugmod is loaded: {register_status}")
                self.__ui_hook.hook()
            # else:
            #     logger.error("Frida Plugmod is loaded error")
            #     if not ida_kernwin.unregister_action(self.__action_name):
            #         logger.error("Frida Plugmod unregister error")
            #     if self.__ui_hook is not None:
            #         self.__ui_hook.unhook()

        except Exception as e:
            logger.error(f"Frida Plugmod load error: {e.args}")
