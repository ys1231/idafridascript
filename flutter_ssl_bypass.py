# -*- coding: utf-8 -*-
# @Author iyue
# @Time 2025/5/11 21:07
# @File flutter_ssl_bypass.py
# @Software: PyCharm
import os
import ida_kernwin
import idautils
from PyQt5.QtGui import QClipboard
from PyQt5.QtWidgets import QApplication
from ida_funcs import get_func, func_t
from ida_idaapi import plugmod_t
from ida_kernwin import action_desc_t
from ida_nalt import get_root_filename
from loguru import logger


class FlutterHandler(ida_kernwin.action_handler_t):

    def __init__(self):
        current_path = os.path.dirname(os.path.abspath(__file__))
        self.__template_script_path = current_path + "/resources/hook_flutter_ssl_bypass.js"
        logger.debug(f">>> FlutterHandler: Template script path is {self.__template_script_path}")

    def update(self, ctx: ida_kernwin.action_ctx_base_t):

        if ctx.widget_type == ida_kernwin.BWN_DISASM:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        else:
            return ida_kernwin.AST_DISABLE_FOR_WIDGET if get_root_filename()=='libflutter.so' else ida_kernwin.AST_DISABLE_FOR_WIDGET

    def activate(self, ctx):
        """
            Click on the menu to execute
        Returns:
            object:
        """
        ssl_client_ea = None
        from_ssl_client_ea = None
        data = {
            "module_name": get_root_filename(),
            "func_start_offset": from_ssl_client_ea
        }
        s = idautils.Strings()
        for i in s:
            if str(i) == "ssl_client":
                ssl_client_ea = i.ea
                break
        if ssl_client_ea is None:
            return
        for xref in idautils.XrefsTo(ssl_client_ea, 0):
            func: func_t = get_func(xref.frm)
            logger.debug(f"func start offset: {hex(func.start_ea)}")
            # 取第一个
            from_ssl_client_ea = hex(func.start_ea)
            data["func_start_offset"] = from_ssl_client_ea
            break
        if from_ssl_client_ea is None:
            return
        script = self.__generate_script(data)
        if script is None:
            return
        clipboard: QClipboard = QApplication.clipboard()
        clipboard.setText(script)
        logger.info(f">>> FlutterHandler: Copy script to clipboard")

    def __generate_script(self, data):
        try:
            module_name = data["module_name"]
            func_start_offset = data["func_start_offset"]

            with open(self.__template_script_path, "r") as f:
                jscode = f.read()
                jscode = jscode.replace("MODULE_NAME", f'"{module_name}"')
                jscode = jscode.replace("FUNC_START_OFFSET", str(func_start_offset))
                return jscode
        except Exception as e:
            logger.error(f">>> FlutterHandler: generate script error: {e}")
            return None


class FlutterUIHooks(ida_kernwin.UI_Hooks):

    def __init__(self, action_name):
        ida_kernwin.UI_Hooks.__init__(self)
        self.__action_name = action_name

    def finish_populating_widget_popup(self, widget, popup_handle, ctx):
        if ida_kernwin.get_widget_type(widget) == ida_kernwin.BWN_DISASM:
            ida_kernwin.attach_action_to_popup(widget, popup_handle, self.__action_name,"Frida Tools/")


class FlutterPlugmod(plugmod_t):

    def __del__(self):
        logger.info(">>> Flutter Plugmod is unloaded")

    def __init__(self):

        self.__action_name = "iyue:flutter_helper"
        self.__popup_menu_name = "Copy flutter bypass ssl script"
        self.__action_handler = FlutterHandler()
        self.__shortcut = ""
        self.__tooltip = "Flutter bypass ssl helper"
        self.__ui_hook = FlutterUIHooks(self.__action_name)

    @staticmethod
    def __custon_icon():
        current_path = os.path.dirname(os.path.abspath(__file__))
        logger.debug(f">>> Flutter Plugmod: Custon icon path is {current_path}/resources/flutter.png")
        return ida_kernwin.load_custom_icon(file_name=current_path + "/resources/flutter.png", format="png")

    def create_popup_menu(self):
        logger.info(f">>> Flutter Plugmod is loaded")
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
                logger.success(f">>> Flutter Plugmod is loaded: {register_status}")
                self.__ui_hook.hook()



        except Exception as e:
            logger.error(f">>> Flutter Plugmod load error: {e.args}")
