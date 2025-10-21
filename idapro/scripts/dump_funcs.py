import ida_funcs
import ida_typeinf
import ida_name
import ida_nalt
import idc

def enumerate_filtered_functions(name_filter=""):
    func_count = ida_funcs.get_func_qty()

    for i in range(func_count):
        func = ida_funcs.getn_func(i)
        if not func:
            continue

        func_name = ida_name.get_name(func.start_ea)

        if name_filter and name_filter.lower() not in func_name.lower():
            continue

        tinfo = ida_typeinf.tinfo_t()
        if ida_nalt.get_tinfo(tinfo, func.start_ea):
            func_details = ida_typeinf.func_type_data_t()
            if tinfo.get_func_details(func_details):
                ret_type = str(func_details.rettype)

                params = []
                for j in range(func_details.size()):
                    param = func_details[j]
                    param_type = str(param.type)
                    param_name = param.name if param.name else f"arg{j}"
                    params.append(f"{param_type} {param_name}")

                param_str = ", ".join(params) if params else "void"
                print(f"{func_name}: {ret_type} ({param_str})")
            else:
                print(f"{func_name}: <no type info>")
        else:
            func_type = idc.get_type(func.start_ea)
            if func_type:
                print(f"{func_name}: {func_type}")
            else:
                print(f"{func_name}: <raw function at 0x{func.start_ea:x}>")

enumerate_filtered_functions("il2cpp_")
