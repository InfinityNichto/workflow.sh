import json
import idaapi
import idc
import idautils
import ida_hexrays
import ida_funcs
import re

def parse_value(value_str):
    if isinstance(value_str, (int, float)):
        return value_str

    s = str(value_str).strip()

    if s.endswith('f'):
        return float(s[:-1])

    try:
        if '.' in s:
            return float(s)
        return int(s)
    except:
        return None

def find_function(full_name):
    parts = full_name.split("::")
    if len(parts) != 2:
        return None

    type_name = parts[0].split('.')[-1]
    method_name = parts[1]

    for ea in idautils.Functions():
        func_name = idc.get_func_name(ea)
        if method_name in func_name and type_name in func_name:
            return ea

    search_patterns = [
        f"{type_name}::{method_name}",
        f"{method_name}",
        method_name.replace('.', '_')
    ]

    for pattern in search_patterns:
        for ea in idautils.Functions():
            if pattern in idc.get_func_name(ea):
                return ea

    return None

def find_literal_in_decompiled(func_ea, target_value):
    matches = []

    try:
        cfunc = ida_hexrays.decompile(func_ea)
        if not cfunc:
            return matches

        pseudocode = str(cfunc)

        search_patterns = []
        if isinstance(target_value, float):
            search_patterns.append(f"{target_value:.1f}")
            search_patterns.append(f"{target_value:.2f}")
            search_patterns.append(f"{target_value}")
        else:
            search_patterns.append(str(target_value))
            search_patterns.append(f"0x{target_value:X}")
            search_patterns.append(f"#{target_value}")

        found_lines = set()
        for pattern in search_patterns:
            for line_num, line in enumerate(pseudocode.split('\n')):
                if pattern in line:
                    found_lines.add((line_num, line.strip()))

        if not found_lines:
            return matches

        treeitems = cfunc.treeitems
        ea_map = {}
        for item in treeitems:
            if hasattr(item, 'ea') and item.ea != idc.BADADDR:
                ea_map[item.ea] = True

        for line_num, line_text in found_lines:
            class visitor_t(ida_hexrays.ctree_visitor_t):
                def __init__(self):
                    ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
                    self.matches = []

                def visit_expr(self, expr):
                    if expr.op == ida_hexrays.cot_num:
                        num_val = expr.numval()
                        if isinstance(target_value, float):
                            if abs(float(num_val) - target_value) < 0.0001:
                                if expr.ea != idc.BADADDR:
                                    self.matches.append((expr.ea, num_val))
                        else:
                            if num_val == target_value:
                                if expr.ea != idc.BADADDR:
                                    self.matches.append((expr.ea, num_val))
                    return 0

            v = visitor_t()
            v.apply_to(cfunc.body, None)

            for ea, val in v.matches:
                disasm = idc.generate_disasm_line(ea, 0)
                matches.append({
                    "address": hex(ea),
                    "instruction": disasm,
                    "decompiled_line": line_text,
                    "value": val
                })

    except Exception as e:
        print(f"    [!] Decompilation failed: {e}")

    return matches

def main():
    json_path = idaapi.ask_file(0, "*.json", "Select JSON results file")
    if not json_path:
        return

    with open(json_path, 'r') as f:
        data = json.load(f)

    results = {}

    for type_name, fields in data.items():
        if not isinstance(fields, dict):
            continue

        for field_name, field_data in fields.items():
            if not isinstance(field_data, dict) or field_data.get("status") != "NonConstant":
                continue

            hollow_value_raw = field_data.get("hollowValue")
            hollow_value = parse_value(hollow_value_raw)

            if hollow_value is None:
                print(f"[!] Could not parse value: {hollow_value_raw}")
                continue

            refs = field_data.get("refs", [])

            if not refs:
                continue

            print(f"\n{'='*60}")
            print(f"Processing: {type_name}.{field_name}")
            print(f"Expected value: {hollow_value} (raw: {hollow_value_raw})")
            print(f"References: {len(refs)}")

            found_addresses = []

            for ref in refs:
                func_ea = find_function(ref)
                if func_ea is None:
                    print(f"  [!] Function not found: {ref}")
                    continue

                print(f"\n  Checking: {ref} @ {hex(func_ea)}")

                matches = find_literal_in_decompiled(func_ea, hollow_value)

                if not matches:
                    print(f"    No matching literals found")
                    continue

                print(f"    Found {len(matches)} matches:")

                for match in matches:
                    found_addresses.append({
                        "address": match["address"],
                        "instruction": match["instruction"],
                        "decompiled_line": match["decompiled_line"],
                        "function": ref
                    })
                    ea = int(match["address"], 16)
                    idc.set_cmt(ea, f"const {field_name} = {hollow_value}", 0)
                    print(f"      {match['address']}: {match['instruction']}")
                    print(f"        -> {match['decompiled_line']}")

            if found_addresses:
                if type_name not in results:
                    results[type_name] = {}
                results[type_name][field_name] = {
                    "value": hollow_value_raw,
                    "occurrences": found_addresses
                }

    output_path = json_path.replace(".json", "_resolved.json")
    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2)

    print(f"\n{'='*60}")
    print(f"Results saved to: {output_path}")
    print("Done!")

if __name__ == "__main__":
    main()
