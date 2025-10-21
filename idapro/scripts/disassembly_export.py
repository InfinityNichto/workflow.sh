import idaapi
import idautils
import idc
import ida_kernwin
import ida_name
import os

output_dir = ida_kernwin.ask_str("disasm_export", 0, "Enter output directory:")
if not output_dir:
    output_dir = "disasm_export"

if not os.path.exists(output_dir):
    os.makedirs(output_dir)

total_funcs = len(list(idautils.Functions()))
current = 0

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

    filename = f"{func_simple_name}.asm"
    filepath = os.path.join(subdir, filename)

    print(f"[{current}/{total_funcs}] Exporting {func_name} -> {filepath}")

    with open(filepath, "w") as f:
        f.write(f"; Function: {func_name}\n")
        f.write(f"; Address: 0x{func_ea:X}\n\n")

        for head in idautils.Heads(func.start_ea, func.end_ea):
            disasm = idc.generate_disasm_line(head, 0)
            f.write(f"{head:X}  {disasm}\n")

print(f"\nExported {total_funcs} functions to {output_dir}")
