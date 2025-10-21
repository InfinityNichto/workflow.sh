import idc
import idaapi
import idautils
import pickle
import hashlib

sigpath = '/home/lisa/Downloads/sigs.pkl'

def get_function_signature(ea):
    func = idaapi.get_func(ea)
    size = func.end_ea - func.start_ea

    # Get instruction mnemonics (ignoring operands/addresses)
    insns = []
    for head in idautils.Heads(func.start_ea, func.end_ea):
        if idc.is_code(idc.get_full_flags(head)):
            mnem = idc.print_insn_mnem(head)
            insns.append(mnem)

    # Collect string and constant references
    refs = set()
    for head in idautils.Heads(func.start_ea, func.end_ea):
        for ref in idautils.DataRefsFrom(head):
            s = idc.get_strlit_contents(ref)
            if s:
                refs.add(s)
        op_val = idc.get_operand_value(head, 1)
        if op_val > 0x1000:
            refs.add(op_val)

    return (tuple(insns), frozenset(refs), size)
#
# # EXPORT
# functions = {}
# for ea in idautils.Functions():
#     name = idc.get_func_name(ea)
#     if name.startswith('sub_'):
#         continue
#     sig = get_function_signature(ea)
#     functions[sig] = name
#     print(f"done exporting signature for {name}")
#
# with open(sigpath, 'wb') as f:
#     pickle.dump(functions, f)
# print(f"exported {len(functions)} functions")

# IMPORT
with open(sigpath, 'rb') as f:
    sigs = pickle.load(f)

matched = 0
for ea in idautils.Functions():
    name = idc.get_name(ea)
    if not name.startswith('sub_') and not name.startswith('nullsub_'):
        continue;
    sig = get_function_signature(ea)
    if sig in sigs:
        print(f"{matched}: {idc.get_name(ea)} -> {sigs[sig]} -> {idc.demangle_name(sigs[sig], idc.get_inf_attr(INF_SHORT_DN))}")
        idc.set_name(ea, sigs[sig], idc.SN_NOWARN)
        matched += 1
print(f"matched {matched} functions")

