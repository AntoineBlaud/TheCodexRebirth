import idaapi
import idc 
import ida_kernwin
import tempfile
import pickle
import idaapi
import ida_kernwin
import idc 
import os 
import idautils
import ida_bytes
import time 
import random
import ida_segment

# Dictionary to store loop 
# counters
loop_count = {}
jumps = {}
breakpoints = {}
func_breakpoints = {}
loop_already_skipped = {}
seen_insn_count = {}
# Number of instructions to allow before removing breakpoints
MAX_INSTRUCTIONS = 0x2
WATCH_ADDR = {}
tenet_trace = [["slide=0"]]
last_data_buffer = {}
arch = None
MR_DUMP_SIZE = 10
RESET_SEGMENT_INC = 20
RUN_TIMEOUT = 250

class ArchX86:
    """
    x86 CPU Architecture Definition.
    """
    MAGIC = 0x386

    POINTER_SIZE = 4

    IP = "EIP"
    SP = "ESP"

    REGISTERS = \
    [
        "EAX",
        "EBX",
        "ECX",
        "EDX",
        "EBP",
        "ESP",
        "ESI",
        "EDI",
        "EIP"
    ]
    
class ArchAMD64:
    """
    AMD64 CPU Architecture Definition.
    """
    MAGIC = 0x41424344

    POINTER_SIZE = 8

    IP = "RIP"
    SP = "RSP"

    REGISTERS = \
    [
        "RAX",
        "RBX",
        "RCX",
        "RDX",
        "RBP",
        "RSP",
        "RSI",
        "RDI",
        "R8",
        "R9",
        "R10",
        "R11",
        "R12",
        "R13",
        "R14",
        "R15",
        "RIP"
    ]
    



inf_struct = idaapi.get_inf_structure()

if inf_struct.is_64bit():
    arch = ArchAMD64()
else:
    arch = ArchX86()


class JHook():
    def __init__(self):
        self.j_next = None
        self.j_target = None
        self.j_addr = None
        self.enabled = True
        

def get_pc():
    try:
        return idaapi.get_reg_val(arch.IP)
    except:
        return 0



def show_message(msg):
    print("===> %s" % msg)
    
    
def get_temp_dir():
    # Create a temporary directory to store the snapshot
    temp_dir = tempfile.gettempdir()
    # get current binary name
    file_name = os.path.splitext(idc.get_root_filename())[0]
    temp_dir = os.path.join(temp_dir, file_name)
    # create it
    if not os.path.exists(temp_dir):
        os.mkdir(temp_dir)
        
    return temp_dir
    
    

def patch_different_bytes(segments):
    for seg, (seg_start, seg_end, seg_name, pc, seg_data) in segments.items():
        existing_bytes = idc.get_bytes(seg_start, seg_end - seg_start)
        
        # Compare the existing bytes with the bytes to be restored
        differing_indices = [i for i, (a, b) in enumerate(zip(existing_bytes, seg_data)) if a != b]
        
        # Group consecutive differing indices into data chunks
        data_chunks = []
        i = 0
        while i < len(differing_indices):
            start_index = differing_indices[i]
            end_index = start_index
            
            # While consecutive indices are found, extend the chunk
            while i + 1 < len(differing_indices) and differing_indices[i + 1] == end_index + 1:
                end_index = differing_indices[i + 1]
                i += 1
            
            byte_address_start = seg_start + start_index
            byte_address_end = seg_start + end_index + 1  # end index is exclusive
            bytes_to_patch = seg_data[start_index:end_index + 1]
            ida_bytes.patch_bytes(byte_address_start, bytes_to_patch) 
            data_chunks.append((start_index, end_index))
            i += 1
               

        print(f"Restored segment {seg_name} {hex(seg_start)}, {hex(seg_end)}")
          

def take_ida_execution_snapshot():
        # Get the current state of segments and registers
        segments = {}
        for seg in idautils.Segments():
            seg_start = idc.get_segm_start(seg)
            seg_end = idc.get_segm_end(seg)
            if abs(seg_end - seg_start) < 0xFFFFFF:
                seg_name = idaapi.get_segm_name(idaapi.getseg(seg))
                pc = get_pc()
                segments[seg] = (
                    seg_start,
                    seg_end,
                    seg_name,
                    pc,
                    idc.get_bytes(seg_start, seg_end - seg_start),
                )
                print(f"Saving segment {seg_name} {hex(seg_start)}, {hex(seg_end)}")

        registers = {}
        for reg in idautils.GetRegisterList():
            try:
                registers[reg] = idc.get_reg_value(reg)
            except:
                pass
        # Create a temporary directory to store the snapshot
        temp_dir = get_temp_dir()
        if pc == 0:
            pc = "unknown"
        else:
            pc = hex(pc)
        snapshot_file = os.path.join(temp_dir, f"ida_snapshot_{pc}.pkl")
        # Serialize and save the data to a file
        with open(snapshot_file, "wb") as f:
            snapshot_data = (segments, registers)
            pickle.dump(snapshot_data, f)

        print(f"Execution snapshot saved to {snapshot_file}, pc={pc}")
        return os.path.join(temp_dir, "ida_snapshot.pkl")
        
  
def restore_ida_execution_snapshot():
        # ask the user to select the snapshot file
        snapshot_file = ida_kernwin.ask_file(1, "(*.pkl)", "Select a snapshot file")
        if snapshot_file is None or len(snapshot_file) < 5:
            snapshot_file = None
            raise Exception("No config selected")

        if not os.path.exists(snapshot_file):
            snapshot_file = None
            print("Snapshot file not found")
            return

        # Deserialize the snapshot data
        with open(snapshot_file, "rb") as f:
            segments, registers = pickle.load(f)
            
        show_message("Make sur to set UNDO_MAXSIZE and UNDO_DEPTH to 0 in ida.cfg")

        patch_different_bytes(segments)

        # Restore registers
        for reg, value in registers.items():
            idc.set_reg_value(value, reg)

        print("Execution snapshot restored")
        
        
def take_memory_snapshot():
    # ask ida to take memory snapshot
    idaapi.take_memory_snapshot(ida_segment.SNAP_ALL_SEG)



def set_breakpoint(ea):
    print("add bp at %x" % ea)
    breakpoints[ea] = 1
    idaapi.add_bpt(ea)
    idaapi.enable_bpt(ea, True)

def remove_breakpoint(ea):
    if ea in breakpoints:
        print("remove bp at %x" % ea)
        del breakpoints[ea]
        idaapi.enable_bpt(ea, False)
        idaapi.del_bpt(ea)

def disable_breakpoint(ea):
    idaapi.enable_bpt(ea, False)
    
def enable_breakpoint(ea):
    idaapi.enable_bpt(ea, True)
    
def reset_segment_code(ea, hard=False):
    seg = get_seg(ea)
    seg_start = idc.get_segm_start(seg)
    seg_end = idc.get_segm_end(seg)
    seg_name = idaapi.get_segm_name(idaapi.getseg(seg))
    for addr in range(seg_start, seg_end):
        # undefined data DELIT_EXPAND del_items
        idc.del_items(addr, idc.DELIT_EXPAND)
    #print(f"Reset segment {seg_name} {hex(seg_start)}, {hex(seg_end)}")        
    # do not convert directly
    if not hard:
        return
    curr_addr = seg_start
    while curr_addr < seg_end:
        idc.create_insn(curr_addr)  
        curr_addr += idaapi.get_item_size(curr_addr)  
        
def get_seg(ea):
    for seg in idautils.Segments():
        seg_start = idc.get_segm_start(seg)
        seg_end = idc.get_segm_end(seg)
        if seg_start <= ea <= seg_end:
            return seg

def get_jump_target(ea):
    # Get the target address of the jump instruction
    # check insn start by j
    insn = idaapi.print_insn_mnem(ea)
    if insn is None:
        if random.randint(0, 10) == 0:
            reset_segment_code(ea, hard=False)
        idc.create_insn(ea) 
        insn = idaapi.print_insn_mnem(ea)
        # make second try after reseting segment
        if insn is None:
            print("Cannot get insn at %x" % ea)
            return None
        
    if (insn.startswith("j") and not insn.startswith("jmp")):
        target = idc.get_operand_value(ea, 0)
        return target if target != idaapi.BADADDR else None
    return None
    
def print_skipped():
    print("="*20)
    print("\tSkipped loops")
    print("="*20)
    
    
def skip_same_pc(ea, last_ea):
    if ea != last_ea:
        return
    next_addr = ea+idaapi.get_item_size(ea)
    set_breakpoint(next_addr)
    idaapi.continue_process()
    idaapi.wait_for_next_event(idaapi.WFNE_SUSP, -1)
    remove_breakpoint(next_addr)
    print(f"Skipped same pc {hex(ea)}")

def skip_lib_function(ea, seg_name):
    if ".dll" in seg_name.lower() or ".so" in seg_name.lower():
        idaapi.step_until_ret()
        idaapi.wait_for_next_event(idaapi.WFNE_SUSP, -1)
        # get function name
        func_name = idc.get_func_name(ea)
        print(f"Found Lib function {func_name} at {hex(ea)}, skipping")

def inc_seen_insn_count(ea):
    if ea not in seen_insn_count:
        seen_insn_count[ea] = 0
    seen_insn_count[ea] +=1
    
def add_bp_on_all_functions():
    for func_ea in idautils.Functions():
        func_name = idc.get_func_name(func_ea)
        if func_name.startswith("sub_"):
            idaapi.enable_bpt(func_ea, False)
            idaapi.add_bpt(func_ea)
            func_breakpoints[func_ea] = 1
    
def add_trace_entry(ea):
    
    trace_entry = []
    PTR_SIZE = 8
    
    if len(last_data_buffer) > 200000:
        last_data_buffer.clear()
    
    
    def mr(reg_value):
        try:
            if not idaapi.is_mapped(reg_value):
                return
        except:
            return
        mem_value = idc.get_bytes(reg_value,  PTR_SIZE)
        if mem_value == last_data_buffer.get(reg_value, None):
            return
        hex_mem_value = "".join([f"{byte:x}" for byte in mem_value])
        hex_mem_value = hex_mem_value.ljust(PTR_SIZE*2, "0")
        trace_entry.append(f"mr={hex(reg_value)}:{hex_mem_value}")
        last_data_buffer[reg_value] = mem_value
    
    

    for reg in arch.REGISTERS:
        reg_value = idc.get_reg_value(reg)
        if reg_value == last_data_buffer.get(reg, None):
            continue
        trace_entry.append(f"{reg.lower()}={hex(reg_value)}")
        last_data_buffer[reg] = reg_value
        
    # for each register, read 5 memory values before and after
    for reg in arch.REGISTERS:
        reg_value = idc.get_reg_value(reg) + idc.get_reg_value(reg)%8
        saved_reg_value = reg_value
        for _ in range(MR_DUMP_SIZE):
            mr(reg_value)
            reg_value -= PTR_SIZE
        reg_value = saved_reg_value +  PTR_SIZE
        for _ in range(MR_DUMP_SIZE):
            mr(reg_value)
            reg_value += PTR_SIZE
        
            
    tenet_trace.append(trace_entry)
    
    
def save_trace():
    global tenet_trace

    tenet_trace = [",".join(entry) for entry in tenet_trace]
    
    temp_dir = get_temp_dir()
    trace_file = os.path.join(temp_dir, f"ida_trace_{hex(get_pc())}.tenet")
    with open(trace_file, "w") as f:
        f.write("\n".join(tenet_trace))
        
    print(f"Trace saved to {trace_file}")
        
    
    

def step_and_check_loop():
    # Get the current instruction address
    current_address = get_pc()
    if random.randint(0, RESET_SEGMENT_INC) == 0:
        reset_segment_code(current_address, hard=True)
    # Already skipped loop are stored in skipped dict
    # If we are in a skipped loop, we just continue the process
    # until we are stopped by a breakpoint
    if current_address in loop_already_skipped:
        print_skipped()
        idaapi.continue_process()
        idaapi.wait_for_next_event(idaapi.WFNE_SUSP, -1)
        ea = get_pc()
        remove_breakpoint(ea)
        return

    # Check if the current instruction is a jump (conditional)
    j_target_address = get_jump_target(current_address)
    if j_target_address is not None and current_address not in jumps and current_address not in loop_already_skipped:
            j_next = current_address+idaapi.get_item_size(current_address)
            # store current j address, target address and next address
            j = JHook()
            j.j_addr = current_address
            j.j_target = j_target_address
            j.j_next = j_next
            jumps[current_address] = j
            loop_count[current_address] = 0
            # set breakpoint on next and target address
            set_breakpoint(j_next)
            set_breakpoint(j_target_address)
            print(f"Identified loop at {hex(current_address)}, j_target={hex(j_target_address)}, j_next={hex(j_next)}")
            

    # remove breakpoint if one of the j_next or j_target is reached
    for j in jumps.values():
        if current_address == j.j_next:
            print(f"Disable j_next {hex(j.j_next)}")
            j.j_next = None
            remove_breakpoint(current_address)
            if j.j_target == None:
                j.enabled = False
                
    for j in jumps.values():
        if current_address == j.j_target:
            print(f"Disable j_target {hex(j.j_target)}")
            j.j_target = None
            remove_breakpoint(current_address)
            if j.j_next == None:
                j.enabled = False
           
    # if current address is in jumps and enabled, increment loop counter 
    # jumps are enabled while one of the j_next or j_target is not None (not reached)
    if current_address in jumps:
        if jumps[current_address].enabled:
            j = jumps[current_address]
            loop_count[current_address] += 1
            
            # if loop counter is greater than MAX_INSTRUCTIONS, we found a loop
            # we continue the process until we are stopped by a breakpoint
            if loop_count[current_address] > MAX_INSTRUCTIONS:
                print("Found loop at %x" % current_address)        
                idaapi.continue_process()
                idaapi.wait_for_next_event(idaapi.WFNE_SUSP, -1)
                ea = get_pc()
                remove_breakpoint(ea)
                jumps.clear()
                print_skipped()
                loop_already_skipped[current_address] = 1
                return
            
    # step into the next instruction
    idaapi.step_into()
    idaapi.wait_for_next_event(idaapi.WFNE_SUSP, -1)
    
def exit():
    ea = get_pc()
    reset_segment_code(ea, hard=True)
    take_memory_snapshot()
    take_ida_execution_snapshot()
    save_trace()
    
    
# Example of stepping through the code
def run_script():
    # Run the script until the end of the function
    start = time.time()
    add_bp_on_all_functions()
    while True:
        
        if ida_kernwin.user_cancelled():
            print("User cancelled")
            exit()
            break
            
        if time.time() - start > RUN_TIMEOUT:
            print("Timeout")
            exit()
            break
        
        last_ea = get_pc()
        step_and_check_loop()
                
        ea = get_pc()
        if ea in func_breakpoints:
                idaapi.enable_bpt(ea, False)
                idaapi.del_bpt(ea)
                del func_breakpoints[ea]
         # get current segment
        seg = get_seg(ea)
        seg_name = idaapi.get_segm_name(idaapi.getseg(seg))
        inc_seen_insn_count(ea)
        
        # skip when we are at the same address or in a lib function
        skip_same_pc(ea, last_ea)
        skip_lib_function(ea, seg_name)
        
        instr = idc.generate_disasm_line(ea, idc.GENDSM_FORCE_CODE)
        print (f'[{seg_name}] {hex(ea)} :\t {instr}  \t\t\t\t# {seen_insn_count[ea]}')
        
        add_trace_entry(ea)
        
        if hex(ea).endswith("84ed"):
            exit()
            break

                            
        if ea in WATCH_ADDR:
            print(f"Watched address {hex(ea)} : {WATCH_ADDR[ea]}")
            exit()
            break
            

            

run_script()

