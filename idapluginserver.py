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

mcp = FastMCP("Frida Tools")


def execute() -> str | None:
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
        return None
    for xref in idautils.XrefsTo(ssl_client_ea, 0):
        func: func_t = get_func(xref.frm)
        logger.debug(f"func start offset: {hex(func.start_ea)}")
        # 取第一个
        from_ssl_client_ea = hex(func.start_ea)
        data["func_start_offset"] = from_ssl_client_ea
        break
    if from_ssl_client_ea is None:
        return None
    script = __generate_script(data)
    if script is None:
        return None
    logger.info(f"script: {script}")
    return script


def __generate_script(data):
    try:
        module_name = data["module_name"]
        func_start_offset = data["func_start_offset"]
        current_path = os.path.dirname(os.path.abspath(__file__))
        __template_script_path = current_path + "/resources/hook_flutter_ssl_bypass.js"
        with open(__template_script_path, "r", encoding="utf-8") as f:
            jscode = f.read()
            jscode = jscode.replace("MODULE_NAME", f'"{module_name}"')
            jscode = jscode.replace("FUNC_START_OFFSET", str(func_start_offset))
            return jscode
    except Exception as e:
        logger.error(f">>> FlutterHandler: generate script error: {e}")
        return e.args

@mcp.tool()
def generate_flutter_bypass_ssl_frida_script():
    """
    Generate Flutter bypass ssl frida hook script
    :return: script or None
    """
    logger.info(">>> FlutterHandler: generate_flutter_bypass_ssl_frida_script")
    # 使用列表存储结果
    result = [None]
    
    def wrapper():
        result[0] = execute()
        return 1
    
    ida_kernwin.execute_sync(wrapper, ida_kernwin.MFF_FAST)
    logger.info(f"script1: {result[0]}")
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