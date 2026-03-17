# -*- coding: utf-8 -*-
# @Author iyue
# @Time 2025/5/11 21:07
# @File flutter_ssl_bypass.py
# @Software: PyCharm
import os
from typing import List
import ida_kernwin
import ida_lines
import idautils
from ida_bytes import next_head
from ida_shim import *
from ida_funcs import get_func, func_t
from ida_idaapi import plugmod_t
from ida_kernwin import action_desc_t
from ida_nalt import get_root_filename
from loguru import logger


class FlutterHandler(ida_kernwin.action_handler_t):

    def __init__(self):
        current_path = os.path.dirname(os.path.abspath(__file__))
        self.__template_script_path = current_path + "/resources/hook_flutter_ssl_bypass.js"
        logger.debug(f"[frida_tools] Template script path is {self.__template_script_path}")
        self.__script_data = None

    def update(self, ctx: ida_kernwin.action_ctx_base_t):

        if ctx.widget_type == ida_kernwin.BWN_DISASM:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        else:
            return ida_kernwin.AST_DISABLE_FOR_WIDGET if get_root_filename() == 'libflutter.so' else ida_kernwin.AST_DISABLE_FOR_WIDGET

    def get_script_data(self):
        return self.__script_data

    def activate(self, ctx=None, get_data: bool = False):
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
            return 0
        ea_list = []
        for xref in idautils.XrefsTo(ssl_client_ea, 0):
            func: func_t = get_func(xref.frm)
            logger.debug(f"[frida_tools] func start offset: {hex(func.start_ea)}")
            ea_list.append(func)
        data["func_start_offset"] = self.__check_func(ea_list)
        if data["func_start_offset"] is None:
            logger.error(f"[frida_tools] No function found")
            return 0
        script = self.__generate_script(data)
        if script is None:
            return 0
        clipboard: QClipboard = QApplication.clipboard()
        clipboard.setText(script)
        if get_data:
            self.__script_data = script
        logger.info(f"[frida_tools] Copy script to clipboard")
        return 0

    def __generate_script(self, data):
        try:
            module_name = data["module_name"]
            func_start_offset = data["func_start_offset"]

            with open(self.__template_script_path, "r", encoding="utf-8") as f:
                jscode = f.read()
                jscode = jscode.replace("MODULE_NAME", f'"{module_name}"')
                jscode = jscode.replace("FUNC_START_OFFSET", str(func_start_offset))
                return jscode
        except Exception as e:
            logger.error(f"[frida_tools] generate script error: {e}")
            return None

    def __check_func(self,ea_list:List[func_t] = []):
        is_find = False
        for func in ea_list:
            line = func.start_ea
            while line < func.end_ea:
                disasm = ida_lines.generate_disasm_line(line)
                disasm_text = ida_lines.tag_remove(disasm)
                logger.debug(f"[frida_tools] line:{hex(line)}, disasm: {disasm_text}")
                if "'P'" in disasm_text:
                    logger.info(f"[frida_tools] find func line:{hex(line)}, disasm: {disasm_text}")
                    is_find = True
                    break
                line = next_head(line,func.end_ea)
        if not is_find:
            return None
        logger.info(f"[frida_tools] find func: {hex(func.start_ea)}")
        return hex(func.start_ea)

class FlutterUIHooks(ida_kernwin.UI_Hooks):

    def __init__(self, action_name):
        ida_kernwin.UI_Hooks.__init__(self)
        self.__action_name = action_name

    def finish_populating_widget_popup(self, widget, popup_handle, ctx):
        if ida_kernwin.get_widget_type(widget) == ida_kernwin.BWN_DISASM:
            ida_kernwin.attach_action_to_popup(widget, popup_handle, self.__action_name, "Frida Tools/")


class FlutterPlugmod(plugmod_t):

    def __del__(self):
        logger.info(">>> Flutter Plugmod is unloaded")

    def __init__(self):

        self.__action_name = "iyue:flutter_helper"
        self.__popup_menu_name = "Copy flutter bypass ssl script"
        self.__action_handler = FlutterHandler()
        self.__shortcut = ""
        self.__tooltip = "拷贝 Flutter SSL 绕过脚本"
        self.__ui_hook = FlutterUIHooks(self.__action_name)

    @staticmethod
    def __custon_icon():
        current_path = os.path.dirname(os.path.abspath(__file__))
        logger.debug(f"[frida_tools] Custon icon path is {current_path}/resources/flutter.png")
        return ida_kernwin.load_custom_icon(file_name=current_path + "/resources/flutter.png", format="png")

    def create_popup_menu(self):
        logger.info(f"[frida_tools] Flutter Plugmod is loaded")
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
                logger.success(f"[frida_tools] Flutter Plugmod is loaded: {register_status}")
                self.__ui_hook.hook()

        except Exception as e:
            logger.error(f"[frida_tools] Flutter Plugmod load error: {e.args}")

    def unload(self):
        logger.info("[frida_tools] Flutter Plugmod is unloaded")
        if self.__ui_hook is not None:
            self.__ui_hook.unhook()
        if not ida_kernwin.unregister_action(self.__action_name):
            logger.error("[frida_tools] Flutter Plugmod unregister error ")


if __name__ == "__main__":
    handler = FlutterHandler() 
    handler.activate(get_data=True)  
    print(handler.get_script_data())