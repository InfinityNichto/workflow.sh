import idaapi
import idautils
import idc
import ida_name
import ida_hexrays
import os

lib_name = idaapi.get_root_filename()
output_dir = os.path.join(os.getcwd(), f"{lib_name}_decomp")

if not os.path.exists(output_dir):
    os.makedirs(output_dir)

ida_hexrays.hexrays_failure_t.set_funcsize_limit(16 * 1024 * 1024)

if not ida_hexrays.init_hexrays_plugin():
    print("Decompiler not available")
else:
    total_funcs = len(list(idautils.Functions()))
    current = 0
    success = 0
    failed = 0
    
    for func_ea in idautils.Functions():
        current += 1
        func = idaapi.get_func(func_ea)
        if not func:
            continue
        
        func_name = idc.get_func_name(func_ea)
        demangled = ida_name.demangle_name(func_name, idc.get_inf_attr(idc.INF_SHORT_DN))
        
        if demangled:
            parts = demangled.replace("(", " ").split()
            if parts:
                full_path = parts[0]
                path_parts = full_path.split("::")
                
                if len(path_parts) > 1:
                    namespace_parts = path_parts[:-1]
                    func_simple_name = path_parts[-1]
                    subdir = os.path.join(output_dir, *namespace_parts)
                else:
                    func_simple_name = path_parts[0]
                    subdir = output_dir
            else:
                func_simple_name = func_name
                subdir = output_dir
        else:
            func_simple_name = func_name
            subdir = output_dir
        
        if not os.path.exists(subdir):
            os.makedirs(subdir)
        
        filename = f"{func_simple_name}.c"
        filepath = os.path.join(subdir, filename)
        
        print(f"[{current}/{total_funcs}] Decompiling {func_name}")
        
        try:
            cfunc = ida_hexrays.decompile(func_ea)
            if cfunc:
                with open(filepath, "w") as f:
                    f.write(f"// Function: {func_name}\n")
                    f.write(f"// Address: 0x{func_ea:X}\n\n")
                    f.write(str(cfunc))
                success += 1
            else:
                print(f"  Failed to decompile")
                with open(filepath, "w") as f:
                    f.write(f"// Function: {func_name}\n")
                    f.write(f"// Address: 0x{func_ea:X}\n\n")
                    f.write(f"// decompilation failed")
                failed += 1
        except Exception as e:
            print(f"  Error: {e}")
            failed += 1
    
    print(f"\n{success} success, {failed} failed, total {total_funcs}")
