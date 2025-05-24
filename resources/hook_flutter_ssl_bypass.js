/**
 * Created by iyue on 2025/5/11 22:15.
 * 优先使用附加模式 spwan 可能会导致 app 异常
 */

var module_name = MODULE_NAME
var func_start_offset = FUNC_START_OFFSET

function hook_ssl_verify_result(address) {
    console.log(">> Hooking ssl_verify_result at: " + address.toString());
    Interceptor.attach(address, {
        onEnter: function (args) {
            console.log(">> Disabling SSL validation")
        },
        onLeave: function (retval) {
            console.log("Retval: " + retval);
            retval.replace(0x1);
            console.log("Retval replace: " + retval);
        }
    });
}

function main() {
    var libflutter = Process.findModuleByName(module_name)
    console.log("libflutter base address: 0x", libflutter.base.toString(16))
    hook_ssl_verify_result(libflutter.base.add(func_start_offset))
}

setTimeout(main,0)
