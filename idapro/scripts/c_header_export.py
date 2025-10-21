import idaapi
import idautils
import idc
import ida_typeinf
import ida_kernwin

def find_type_by_name(type_name):
    til = ida_typeinf.get_idati()
    tif = ida_typeinf.tinfo_t()
    if tif.get_named_type(til, type_name, ida_typeinf.BTF_STRUCT):
        return tif
    return None

def get_struct_members(tif):
    members = []
    if not tif.is_udt():
        return members

    udt_data = ida_typeinf.udt_type_data_t()
    if not tif.get_udt_details(udt_data):
        return members

    for i in range(udt_data.size()):
        member = udt_data[i]
        mname = member.name
        mtype = member.type
        moffset = member.offset // 8
        msize = mtype.get_size()
        members.append((moffset, mname, mtype, msize))

    return members

def resolve_type_name(tinfo):
    if tinfo.is_ptr():
        pointed = tinfo.get_pointed_object()
        return resolve_type_name(pointed) + "*"
    elif tinfo.is_array():
        elem_type = tinfo.get_array_element()
        array_size = tinfo.get_array_nelems()
        return f"{resolve_type_name(elem_type)}[{array_size}]"
    else:
        type_name = str(tinfo)
        if "::Il2CppObject" in type_name:
            return "Il2CppObject*"
        elif "::Il2CppClass" in type_name:
            return "Il2CppClass*"
        elif "::MethodInfo" in type_name:
            return "MethodInfo*"
        elif type_name.startswith("uint64_t"):
            return "uint64_t"
        elif type_name.startswith("uint32_t"):
            return "uint32_t"
        elif type_name.startswith("uint16_t"):
            return "uint16_t"
        elif type_name.startswith("uint8_t"):
            return "uint8_t"
        return type_name

def find_related_types(base_type):
    related_names = set()
    related_names.add(base_type)
    related_names.add(f"{base_type}__Boxed")
    related_names.add(f"{base_type}__Class")
    related_names.add(f"{base_type}__VTable")

    structs = []
    for name in related_names:
        tif = find_type_by_name(name)
        if tif:
            structs.append((name, tif))

    dependencies = set()
    for name, tif in structs:
        members = get_struct_members(tif)
        for offset, mname, mtype, msize in members:
            if mtype and mtype.is_udt():
                dep_name = mtype.get_type_name()
                if dep_name and dep_name != name and not dep_name.startswith("_"):
                    clean_dep = dep_name.replace("::", "")
                    dependencies.add(clean_dep)

    for dep in dependencies:
        tif = find_type_by_name(dep)
        if tif:
            structs.append((dep, tif))

    return structs

def generate_header(target_type):
    header = f"// Generated header for {target_type}\n"
    header += f"#pragma once\n\n"
    header += f"#include <stdint.h>\n\n"

    structs = find_related_types(target_type)

    if not structs:
        return header + f"// Type {target_type} not found\n"

    for name, tif in structs:
        header += f"struct {name};\n"
    header += "\n"

    for name, tif in structs:
        header += f"struct {name} {{\n"

        members = get_struct_members(tif)
        if not members:
            size = tif.get_size()
            if size > 0:
                header += f"    char _data[{size}];\n"
        else:
            for offset, mname, mtype, msize in members:
                type_str = resolve_type_name(mtype)
                header += f"    {type_str} {mname};\n"

        header += f"}};\n\n"

    return header

def main():
    target_type = ida_kernwin.ask_str("", 0, "Enter target type name:")
    if not target_type:
        return

    header_content = generate_header(target_type)

    output_file = ida_kernwin.ask_file(1, "*.h", "Save header as:")
    if output_file:
        with open(output_file, 'w') as f:
            f.write(header_content)
        print(f"Header saved to: {output_file}")
    else:
        print("Header content:")
        print(header_content)

if __name__ == "__main__":
    main()
