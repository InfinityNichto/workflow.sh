import idaapi
import idautils
import idc
import ida_kernwin
import ida_typeinf
import os

output_dir = ida_kernwin.ask_str("types_export", 0, "Enter output directory:")
if not output_dir:
    output_dir = "types_export"

if not os.path.exists(output_dir):
    os.makedirs(output_dir)

tinfo = ida_typeinf.tinfo_t()
til = ida_typeinf.get_idati()

ordinal = 1
max_ordinal = ida_typeinf.get_ordinal_limit(til)
all_types = []

print(f"Exporting types (limit: {max_ordinal})...")

while ordinal < max_ordinal:
    if tinfo.get_numbered_type(til, ordinal):
        type_name = tinfo.get_type_name()

        if type_name:
            decl = ida_typeinf.print_tinfo('', 0, 0, ida_typeinf.PRTYPE_MULTI | ida_typeinf.PRTYPE_TYPE | ida_typeinf.PRTYPE_SEMI, tinfo, type_name, '')

            if decl:
                all_types.append(decl)

                filename = f"{type_name}.h"
                filepath = os.path.join(output_dir, filename)

                print(f"[{ordinal}/{max_ordinal}] Exporting {type_name}")

                with open(filepath, "w") as f:
                    f.write(decl)
                    f.write("\n")

    ordinal += 1

libil2cpp_path = os.path.join(output_dir, "libil2cpp.h")
print(f"\nWriting combined header to {libil2cpp_path}")

with open(libil2cpp_path, "w") as f:
    for decl in all_types:
        f.write(decl)
        f.write("\n\n")

print(f"\nExported {len(all_types)} types")
