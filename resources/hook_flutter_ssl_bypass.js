/**
 * Created by iyue on 2025/5/11 22:15.
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

function hook_android_dlopen_ext() {
    const android_dlopen_extPtr = Module.findExportByName('libc.so', 'android_dlopen_ext')
    Interceptor.attach(android_dlopen_extPtr, {
        onEnter: function (args) {
            const pathptr = args[0]
            if (pathptr != 0 && pathptr != undefined && pathptr != null) {
                var path = pathptr.readCString()
                if (path.indexOf(module_name) != -1) {
                    console.log(`call android_dlopen_ext(${path})`)
                    this.isloadso = true
                }
            }
        }, onLeave: function (retval) {
            // do something
            if (this.isloadso) {
                this.isloadso = false
                var libflutter = Process.findModuleByName(module_name)
                console.log("libflutter base address: 0x", libflutter.base.toString(16))
                hook_ssl_verify_result(libflutter.base.add(func_start_offset));
            }

        }
    })
}

hook_android_dlopen_ext()

