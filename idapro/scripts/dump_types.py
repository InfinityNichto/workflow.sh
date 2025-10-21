import idc
import idautils

def dump_all_types():
    for ea in idautils.Functions():
        func_name = idc.get_func_name(ea)
        func_type = idc.get_type(ea)
        if func_type:
            print(f"{func_type};\n")
        else:
            print(f"void {func_name}(void);\n")

dump_all_types()
