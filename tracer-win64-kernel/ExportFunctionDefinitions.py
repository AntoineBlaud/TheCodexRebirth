import idc
import re
import idaapi
import idautils
import tempfile

code_segm = [".text", "PAGE"]



def compute_function_coverage(func, parent_func=set()):
    """Compute the coverage of a function in the binary."""
    # get all sub calls
    sub_calls = set()
    for ea in idautils.FuncItems(func.start_ea):
        mnem = idc.print_insn_mnem(ea)
        if mnem == "call":
            addr = idc.get_operand_value(ea, 0)
            # get function name
            name = idc.get_func_name(addr)
            # check addr is in code section
            if idc.get_segm_name(addr) in code_segm:
                sub_calls.add((name, addr))
                
    for sub_call_name, sub_call_addr in sub_calls.copy():
        
        not_explored = True
        # check not already explored
        for _, parent_func_addr in parent_func:
            if sub_call_addr == parent_func_addr:
                not_explored = False
                break
            
        # check if its not the same function
        if sub_call_name != idc.get_func_name(func.start_ea) and not_explored:
            sub_func = idaapi.get_func(sub_call_addr)
            sub_calls |= compute_function_coverage(sub_func)
            
    return sub_calls

# rebase program to 0x0
offset = idaapi.get_imagebase()
idaapi.rebase_program(-offset, idaapi.MSF_NOFIX)

funcs = [idaapi.getn_func(i) for i in range(idaapi.get_func_qty()) ]
# keep only functions in .text section
funcs = [f for f in funcs if idc.get_segm_name(f.start_ea)  in code_segm]
# sort by size
funcs = sorted(funcs, key=lambda f: f.end_ea - f.start_ea, reverse=True)
# now do a second sort by function coverage
funcs_coverage = []

for i in range(len(funcs)):
    f = funcs[i]
    f_name = idc.get_func_name(f.start_ea)
    f_size = f.end_ea - f.start_ea
    sub_calls = compute_function_coverage(f)
    funcs_coverage.append((f_name, f.start_ea, f_size, len(sub_calls)))
    
print("=====================================")
print("Function coverage:")
print("=====================================")

funcs_coverage = sorted(funcs_coverage, key=lambda f: f[3], reverse=True)
for i in range(len(funcs_coverage)):
    f_name, f_addr, f_size, f_cache_coverages = funcs_coverage[i]
    if i < 50:
        print(f"Function {f_name} has size {hex(f_size)} and coverage {f_cache_coverages}")
    elif i == 50:
        print('...')
        
# get binary open in IDA
bin_name = idc.get_root_filename().split('.')[0]
    
# export function to file
with tempfile.NamedTemporaryFile(mode="w", delete=False, prefix=f"{bin_name}_export_", suffix=".txt") as f:
    for i in range(len(funcs_coverage)):
        f_name, f_addr, f_size, f_cache_coverages = funcs_coverage[i]
        f.write(f"{hex(f_addr)} {f_name}\n")
    # print file name
    print(f"Function coverage exported to {f.name}")
        
