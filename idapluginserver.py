# -*- coding: utf-8 -*-
# @Author l
# @Time 2025/5/24 20:11
# @File idapluginserver.py
# @Software: PyCharm
import os
import threading
import ida_kernwin
import idautils
from ida_funcs import get_func, func_t
from ida_nalt import get_root_filename
from loguru import logger
from mcp.server.fastmcp import FastMCP

from flutter_ssl_bypass import FlutterHandler

mcp = FastMCP("Frida_Tools")


def execute() -> str | None:
    handler = FlutterHandler()
    handler.activate(get_data=True)
    return handler.get_script_data()


@mcp.tool()
def generate_flutter_bypass_ssl_frida_script():
    """
    Generate Flutter bypass ssl frida hook script
    :return: script or None
    """
    logger.info("[frida_tools] generate_flutter_bypass_ssl_frida_script")
    # 使用列表存储结果
    result = [None]

    def wrapper():
        result[0] = execute()
        return 1

    ida_kernwin.execute_sync(wrapper, ida_kernwin.MFF_FAST)
    logger.info(f"[frida_tools] script: {result[0]}")
    return result[0]


@mcp.tool()
def how_to_use():
    return """
    1. Open the IDA Pro and load the libflutter.so file.
    2. Press the Edit->Plugins->Frida Tools menu ,Start mcp server.
    3. Help me generate a Flutter bypass SSL Frida hook script and save it to a new JS file
    """


def startASYNC():
    mcp.settings.host = "0.0.0.0"
    mcp.settings.port = 12345
    mcp.run(transport="sse")


def start_server():
    server_thread = threading.Thread(target=startASYNC, daemon=True)
    server_thread.start()
