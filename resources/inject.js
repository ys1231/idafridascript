/**
 * module_name "readelf"
 * func_name   "main"
 * func_offset hex(0x24091)
 * args_list || [{"type":"int","name": "argc"},{"type":"const char **","name": "argv"},{"type":"const char **","name": "envp"}]
 * return_type "int"
 */


var module_name = MODULE_NAME
var func_name = FUNC_NAME
var func_offset = FUNC_OFFSET
var args_list = ARGS_LIST
var return_type = RETURN_TYPE

function hookFunc(address, argsList) {
    Interceptor.attach(address, {
        onEnter: function (args) {
            console.log(">> Hooking " + address.toString());
            if (argsList.length>0) {
                for (var i = 0; i < argsList.length; i++) {
                    console.log(">> args[" + i + "]: " + argsList[i].type + " " + argsList[i].name+" : "+args[i])
                }
            }
        }, onLeave: function (retval) {
            console.log("Retval: " + retval);
            // retval.replace(0x1);
            // console.log("Retval replace: " + retval);
        }
    })
}

/**
 * hook main script func
 */
function hookMainScript() {
    var libModule = Process.findModuleByName(module_name)
    if (libModule) {
        console.log(">> libModule base address: 0x", libModule.base.toString(16))
        console.log(">> hook func: " + func_name)
        console.log(">> hook func offset: " + func_offset)
        console.log(">> args list: " + args_list)
        console.log(">> func return type: " + return_type)
        hookFunc(libModule.base.add(func_offset), args_list)
    } else {
        console.log(`>> ${module_name} not found`)
    }
}