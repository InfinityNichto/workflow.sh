import idaapi
import idautils
import idc
import ida_hexrays
import os
import hashlib

output_dir = os.path.join(idc.get_idb_path() + "_export")

if not os.path.exists(output_dir):
    os.makedirs(output_dir)

if not ida_hexrays.init_hexrays_plugin():
    print("Hex-Rays decompiler not available")
    idc.qexit(1)

hxe = ida_hexrays.hexrays_vars()
hxe.max_func_size = 16_777_216 # 16 MB

for func_ea in idautils.Functions():
    func = idaapi.get_func(func_ea)
    if not func:
        continue

    func_name = idc.get_func_name(func_ea)

    if len(func_name) > 100:
        name_hash = hashlib.md5(func_name.encode()).hexdigest()[:8]
        short_name = func_name[:50] + "_" + name_hash
    else:
        short_name = func_name

    short_name = idaapi.validate_name(short_name, idaapi.VNT_VISIBLE)

    filename = f"{short_name}_{func_ea:X}.c"
    filepath = os.path.join(output_dir, filename)

    try:
        cfunc = ida_hexrays.decompile(func_ea)
        if cfunc:
            with open(filepath, "w") as f:
                f.write('#include "all_types.h"\n\n')
                f.write(f"// Function: {func_name}\n")
                f.write(f"// Address: 0x{func_ea:X}\n\n")
                f.write(str(cfunc))
    except ida_hexrays.DecompilationFailure:
        pass

print(f"Exported decompiled functions to {output_dir}")
idc.qexit(0)
