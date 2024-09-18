import idaapi
import idautils
import idc
from unicorn import *
from unicorn.x86_const import *
from capstone import *
import hashlib
import time
import struct
from keystone import *
from keystone.x86_const import *

# Dictionnaire global pour stocker les adresses visitées
visited_addresses = {}
visited_addresses_extended = set()

PAGE_SIZE = 0x1000
FIRST_RUN_INSTRUCTION_COUNT = 0x4000
MAX_JUMP_RANGE = 0x80000000  # ±2 GB range for 32-bit or rel32 in 64-bit


# Comprehensive mapping of IDA register names to Unicorn constants for both 32-bit and 64-bit registers
REGISTER_MAP = {
    # 32-bit General Purpose Registers
    'EAX': UC_X86_REG_EAX, 'EBX': UC_X86_REG_EBX, 'ECX': UC_X86_REG_ECX, 'EDX': UC_X86_REG_EDX,
    'ESI': UC_X86_REG_ESI, 'EDI': UC_X86_REG_EDI, 'ESP': UC_X86_REG_ESP, 'EBP': UC_X86_REG_EBP, 'EIP': UC_X86_REG_EIP,
    
    # 64-bit General Purpose Registers
    'RAX': UC_X86_REG_RAX, 'RBX': UC_X86_REG_RBX, 'RCX': UC_X86_REG_RCX, 'RDX': UC_X86_REG_RDX,
    'RSI': UC_X86_REG_RSI, 'RDI': UC_X86_REG_RDI, 'RSP': UC_X86_REG_RSP, 'RBP': UC_X86_REG_RBP, 'RIP': UC_X86_REG_RIP,
    'R8': UC_X86_REG_R8, 'R9': UC_X86_REG_R9, 'R10': UC_X86_REG_R10, 'R11': UC_X86_REG_R11, 'R12': UC_X86_REG_R12,
    'R13': UC_X86_REG_R13, 'R14': UC_X86_REG_R14, 'R15': UC_X86_REG_R15,
    
    # Segment Registers
    'CS': UC_X86_REG_CS, 'DS': UC_X86_REG_DS, 'ES': UC_X86_REG_ES, 'FS': UC_X86_REG_FS, 'GS': UC_X86_REG_GS, 'SS': UC_X86_REG_SS,
    
    # Flags Register
    'EFLAGS': UC_X86_REG_EFLAGS, 'RFLAGS': UC_X86_REG_EFLAGS,  # EFLAGS and RFLAGS are the same in Unicorn
    
    # Control Registers
    'CR0': UC_X86_REG_CR0, 'CR2': UC_X86_REG_CR2, 'CR3': UC_X86_REG_CR3, 'CR4': UC_X86_REG_CR4,
    
    # Debug Registers
    'DR0': UC_X86_REG_DR0, 'DR1': UC_X86_REG_DR1, 'DR2': UC_X86_REG_DR2, 'DR3': UC_X86_REG_DR3,
    'DR6': UC_X86_REG_DR6, 'DR7': UC_X86_REG_DR7
}

# Determine whether we are in 32-bit or 64-bit mode
is_64bit = idaapi.get_inf_structure().is_64bit()
is_32bit = not is_64bit

# Initialize Unicorn Engine based on the binary mode (32-bit or 64-bit)
if is_64bit:
    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    ks = Ks(KS_ARCH_X64, KS_MODE_64)
    print("Running in 64-bit mode.")
else:
    mu = Uc(UC_ARCH_X86, UC_MODE_32)
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    print("Running in 32-bit mode.")



def get_segment_data():
    """
    Retrieve memory segments from IDA and return as a list of dictionaries with base, size, and permissions.
    """
    segments = []
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        name = idaapi.get_segm_name(seg)
        base = seg.start_ea
        size = seg.end_ea - seg.start_ea
        perm = seg.perm  # Permissions: (Read, Write, Execute)
        segments.append({
            'base': base,
            'size': size,
            'perm': perm,
            'name': name,
            'end' : base + size
        })
    return segments

def get_unicorn_segment_data():
    """
    Retrieve memory segments from Unicorn and return as a list of dictionaries with base, size, and data.
    """
    segments = []
    try:
        for seg in mu.mem_regions():
            base = seg[0]
            end = seg[1]
            size = end - base
            try:
                data = mu.mem_read(base, size)
                segments.append({
                    'base': base,
                    'size': size,
                    'data': data
                })
            except UcError as e:
                print(f"Error reading memory at base 0x{base:x} with size 0x{size:x}: {e}")
    except UcError as e:
        print(f"Error retrieving memory regions: {e}")
    return segments


def print_visited_address_ranges(mu):
    """
    Print all contiguous address ranges that are inside visited_addresses.
    The addresses will be sorted and merged into ranges before printing.
    For each address range, disassemble and display instructions.
    """
    if not visited_addresses_extended:
        print("No visited addresses to display.")
        return

    # Sort the visited addresses
    sorted_addresses = sorted(list(visited_addresses_extended))

    # Initialize variables for tracking ranges
    start_addr = sorted_addresses[0]
    prev_addr = sorted_addresses[0]

    print("\nVisited address ranges and disassembled instructions:")
    for addr in sorted_addresses[1:]:
        if addr != prev_addr + 1:
            # If the current address is not contiguous with the previous, print the range
            print(f"0x{start_addr:x} - 0x{prev_addr:x}")
            
            # Disassemble instructions in this range (up to 0x20 bytes after the start of the range)
            disassemble_code(mu, start_addr, 0x20)
            print("")  # Blank line between ranges
            
            # Start a new range
            start_addr = addr
        # Update previous address
        prev_addr = addr

    # Print the final range and disassemble it
    print(f"0x{start_addr:x} - 0x{prev_addr:x}")
    disassemble_code(mu, start_addr, 0x20)
    

def list_find(list, key, value):
    for e in list:
        if e.get(key, None) == value:
            return e
    return None


def determine_diff_range(ida_data, unicorn_data):
    """
    Determine the start and end indices of the difference range between IDA and Unicorn memory data.
    """
    size = min(len(ida_data), len(unicorn_data))
    diff_start = size
    diff_end = -1

    for i in range(size):
        if ida_data[i] != unicorn_data[i]:
            if diff_start == size:
                diff_start = i
            diff_end = i

    # If no differences were found, return the full range of the data
    if diff_end == -1:
        return None, None

    return diff_start, diff_end
        
def print_side_by_side_diff(ida_data, unicorn_data, start_address):
    """
    Print a side-by-side comparison of IDA and Unicorn memory dumps with hexadecimal and ASCII representations.
    """
    line_length = 16  # Number of bytes per line
    for i in range(0, len(ida_data), line_length):
        ida_chunk = ida_data[i:i + line_length]
        unicorn_chunk = unicorn_data[i:i + line_length]
        
        ida_hex = " ".join(f"{byte:02x}" for byte in ida_chunk)
        unicorn_hex = " ".join(f"{byte:02x}" for byte in unicorn_chunk)
        
        ida_ascii = "".join(chr(byte) if 32 <= byte <= 126 else '.' for byte in ida_chunk)
        unicorn_ascii = "".join(chr(byte) if 32 <= byte <= 126 else '.' for byte in unicorn_chunk)
        
        # Print each line of the dump
        print(f"0x{start_address + i:08x}  {ida_hex:<{line_length * 3}}  {ida_ascii:<{line_length}} | {unicorn_hex:<{line_length * 3}}  {unicorn_ascii}")


def fill_bp_on_unvisited_memory(mu, segment_start, segment_end):
    for address in range(segment_start, segment_end):
        if address not in visited_addresses_extended:
            mu.mem_write(address, b'\xcc')  # Write zero byte at this address


def compare_segments(ida_segments, unicorn_segments):
    """
    Compare writable memory segments between IDA and Unicorn and print differences with a hexdump and hash signature.
    """
    # Create a dictionary for Unicorn segments for quick access
    unicorn_segments_dict = {(seg['base'], seg['size']): seg['data'] for seg in unicorn_segments}

    for seg in ida_segments:
        base = seg['base']
        size = seg['size']
        name = seg['name']
        perm = seg['perm']

        # Only compare writable segments
        if not (perm & idaapi.SEGPERM_WRITE):
            continue

        ida_data = idaapi.get_bytes(base, size)
        unicorn_seg = list_find(unicorn_segments, "base", base)
        if not unicorn_seg: 
            continue
            
        unicorn_data = unicorn_seg["data"]
        size = min(size, unicorn_seg["size"])
        
        if unicorn_data:
            if ida_data != unicorn_data:

                diff_start, diff_end = determine_diff_range(ida_data, unicorn_data)

                if diff_start is not None and diff_end is not None and diff_end >= diff_start:
                    print(f"\nDifference found in writable segment '{name}' at base 0x{base:x}")
                    
                    print(f"Difference range: 0x{base + diff_start:x} - 0x{base + diff_end + 1:x}")

                    ida_diff = ida_data[diff_start:diff_end + 1]
                    unicorn_diff = unicorn_data[diff_start:diff_end + 1]
                    dlen = diff_end - diff_start
                    plen = min(dlen, 256)
                        
                    print("IDA Memory Dump and Unicorn Memory Dump (128):")
                    print_side_by_side_diff(ida_diff[:plen], unicorn_diff[:plen], base + diff_start)
                    
                    diff_hash = hashlib.sha256(unicorn_diff).hexdigest()
                    print(f"Unicorn Difference Hash: {diff_hash}")
            else :
                print(f"\nNo differences found in writable segment '{name}' at base 0x{base:x}")
        else:
            print("unicorn_data is None")
            



def map_segments(mu, segments):
    """
    Map each segment in Unicorn's memory and copy the contents from IDA.
    """
    for seg in segments:
        base = seg['base']
        size = seg['size']
        perm = seg['perm']
        name = seg['name']
        
        # Translate IDA permissions to Unicorn permissions
        uc_perm = 0
        if perm & idaapi.SEGPERM_READ:
            uc_perm |= UC_PROT_READ
        if perm & idaapi.SEGPERM_WRITE:
            uc_perm |= UC_PROT_WRITE
        if perm & idaapi.SEGPERM_EXEC:
            uc_perm |= UC_PROT_EXEC

        if size < 0xFFFFFFFF:
            # Map the memory segment in Unicorn
            print(f"Mapping segment {name} at 0x{base:x} with size 0x{size:x} and permissions {uc_perm}")
            mu.mem_map(base, size, uc_perm)
    
            # Copy the segment content from IDA to Unicorn
            segment_data = idaapi.get_bytes(base, size)
            if segment_data:
                mu.mem_write(base, segment_data)

def restore_segments_writable(mu, segments):
    """
    Map only writable segments in Unicorn's memory and copy the contents from IDA.
    This avoids the overhead of mapping non-writable segments.
    """
    for seg in segments:
        base = seg['base']
        size = seg['size']
        perm = seg['perm']
        name = seg['name']
        
        # Only map writable segments
        if perm & idaapi.SEGPERM_WRITE:
            # Translate IDA permissions to Unicorn permissions
            uc_perm = UC_PROT_READ | UC_PROT_WRITE  # Writable segments should have at least read and write

            if perm & idaapi.SEGPERM_EXEC:
                uc_perm |= UC_PROT_EXEC

            if size < 0xFFFFFFFF:
                # Map the memory segment in Unicorn
                print(f"Resync writable segment {name} at 0x{base:x} with size 0x{size:x} and permissions {uc_perm}")
        
                # Copy the segment content from IDA to Unicorn
                segment_data = idaapi.get_bytes(base, size)
                if segment_data:
                    mu.mem_write(base, segment_data)


def copy_registers_from_ida(mu):
    """
    Copy all general-purpose and special registers from IDA to Unicorn using idautils.GetRegisterList().
    This includes 32-bit and 64-bit registers, segment registers, control registers, and flags.
    """
    for reg in REGISTER_MAP.keys():
        reg_name = reg.upper()  # Normalize the register name to uppercase
        
        if reg_name in REGISTER_MAP:
            try:
                print(f"Mapping {reg_name}")
                # Fetch the register value from IDA
                reg_value = idc.get_reg_value(reg)
    
                # Write the register value to Unicorn using the mapped constant
                uc_reg = REGISTER_MAP[reg_name]
                mu.reg_write(uc_reg, reg_value)
                    
            except (unicorn.UcError, Exception) as e:
                print(f"Skipping unsupported register: {reg_name}")
        else:
            print(f"Skipping unsupported register: {reg_name}")

    print("Registers copied from IDA to Unicorn.")

def dump_registers(mu):
    """
    Print the state of the registers after emulation using idautils.GetRegisterList().
    This will handle general-purpose registers, control registers, and flags.
    """
    print("Register state after emulation:")

    for reg in REGISTER_MAP.keys():
        reg_name = reg.upper()  # Normalize the register name to uppercase
        if reg_name in REGISTER_MAP:
            # Read the register value from Unicorn and print it
            uc_reg = REGISTER_MAP[reg_name]
            reg_value = mu.reg_read(uc_reg)
            print(f"{reg}: 0x{reg_value:x}", end=', ')
        else:
            pass



def disassemble_code(mu, start_addr, size, arg=None):
    """
    Disassemble the code using Capstone and display it.
    """
    # Initialize Capstone disassembler based on architecture    
    code = mu.mem_read(start_addr, size)
    for i in md.disasm(code, start_addr):
        print(f"0x{i.address:x}: {i.mnemonic} {i.op_str} ", end="")
        print(str(arg)) if arg else print("")
        
        


def hook_code(mu, address, size, user_data):
    """
    Hook callback function to capture executed instructions and their addresses.
    For each executed instruction, mark a range of addresses as visited.
    """
    # Ajouter l'adresse de l'instruction et celles dans la plage [address, address + 0x16]
    for addr in range(address, address + 0x16):
        visited_addresses_extended.add(addr)
    
    visited_addresses.setdefault(address, 0)
    visited_addresses[address] +=1
    
    disassemble_code(mu, address, size, arg=visited_addresses[address])


    

def emulate_code(mu, max_instructions, hook=False):
    """
    Start the Unicorn emulation with optional hooking to capture instruction addresses.
    """
    start_eip = idc.get_reg_value('RIP' if is_64bit else 'EIP')
    
    try:
        print(f"Starting emulation at EIP: 0x{start_eip:x}")

        # Attach the hook for the first emulation if requested
        if hook:
            mu.hook_add(UC_HOOK_CODE, hook_code)

        mu.emu_start(start_eip, 0, timeout=1000 * UC_SECOND_SCALE, count=max_instructions)
    except UcError as e:
        print(f"Unicorn error: {e}")


def align_to_page(addr):
    """Align an address to the start of its page (0x1000 byte boundaries)."""
    return addr & ~(PAGE_SIZE - 1)

def protect_unvisited_memory(mu, segment_start, segment_end):
    """
    Protect memory regions by pages (0x1000 size).
    Pages with no visited addresses will be set as read-write (no execute).
    Accumulate contiguous unvisited pages to reduce the number of protection calls.
    """
    # Get all the pages in the segment
    segment_start_page = align_to_page(segment_start)
    segment_end_page = align_to_page(segment_end - 1) + PAGE_SIZE

    # Track which pages have visited addresses
    visited_pages = set()

    # Group visited addresses by pages
    for addr in visited_addresses_extended:
        if segment_start <= addr < segment_end:
            page_start = align_to_page(addr)
            visited_pages.add(page_start)

    current_page = segment_start_page
    protect_start = None

    while current_page < segment_end_page:
        if current_page not in visited_pages:
            if protect_start is None:
                # Start a new range of unvisited pages
                protect_start = current_page
        else:
            if protect_start is not None:
                # Protect the accumulated range of unvisited pages
                try:
                    size = current_page - protect_start
                    mu.mem_protect(protect_start, size, UC_PROT_READ | UC_PROT_WRITE)
                    # print(f"Protected unvisited range: 0x{protect_start:x} - 0x{current_page-1:x} as READ/WRITE")
                except UcError as e:
                    print(f"Error setting memory protection for range 0x{protect_start:x} - 0x{current_page-1:x}: {e}")
                protect_start = None
                
            print(f"Filling breakpoint on unvisited instructions on page : 0x{current_page:x}")
            fill_bp_on_unvisited_memory(mu, current_page, current_page + PAGE_SIZE)

        current_page += PAGE_SIZE

    # If there's an unprotected range left at the end
    if protect_start is not None:
        try:
            size = current_page - protect_start
            mu.mem_protect(protect_start, size, UC_PROT_READ | UC_PROT_WRITE)
            # print(f"Protected unvisited range: 0x{protect_start:x} - 0x{current_page-1:x} as READ/WRITE")
        except UcError as e:
            print(f"Error setting memory protection for range 0x{protect_start:x} - 0x{current_page-1:x}: {e}")


def is_address_within_jump_range(target_addr, candidate_addr):
    """
    Check if a candidate address is within the jump range of the target address.
    """
    distance = abs(candidate_addr - target_addr)
    return distance <= MAX_JUMP_RANGE

def find_free_space_near(target_addr, min_size=PAGE_SIZE, max_results=10):
    """
    Find free regions of memory that are not covered by any section, within jump range
    from the target address.
    
    Args:
        target_addr: The address of the instruction we are hooking.
        section_name: The name of the section we're operating near.
        min_size: Minimum size of the free space to consider (default: 1 page).
        max_results: Maximum number of results to return (default: 10).
        
    Returns:
        A list of addresses that are free, within jump range, and fit the minimum size.
    """
    # Get all segments (sections) in the binary
    segments = []
    for i in range(idaapi.get_segm_qty()):
        seg = idaapi.getnseg(i)
        segments.append((seg.start_ea, seg.end_ea))

    # Sort segments by their start addresses
    segments.sort(key=lambda s: s[0])

    # Look for gaps between segments
    free_spaces = []
    for i in range(len(segments) - 1):
        seg_end = segments[i][1]
        next_seg_start = segments[i + 1][0]
        
        # Gap between two segments
        gap_start = seg_end
        gap_end = next_seg_start
        
        # If the gap is large enough and within the jump range of the target address
        gap_size = gap_end - gap_start
        if gap_size >= min_size and is_address_within_jump_range(target_addr, gap_start):
            free_spaces.append((gap_start, gap_size))
            if len(free_spaces) >= max_results:
                break
    
    # Return only the addresses (start of free spaces)
    return [space[0] for space in free_spaces]



def patch_and_run_shellcode(mu, address, shellcode, new_section_base):
    """
    Patch the given address to jump to a new executable section with shellcode,
    execute the shellcode, and then jump back to the next instruction after the original instructions.
    
    Args:
        mu (U)     : Unicorn Engine instance.
        address (int) : The address to hook (where to insert the initial jump).
        shellcode (bytes): The shellcode to execute.
    """

    # Step 1: Disassemble the instruction at the target address
    instr_size = 0
    instructions_to_copy = []
    max_patch_size = 5  # Minimum size we need to write the JMP instruction
    
    # Fetch a block of code to disassemble
    code = mu.mem_read(address, 15)  # Read up to 15 bytes in case we need to copy multiple instructions

    # Disassemble instructions until we have at least 5 bytes of code
    for instr in md.disasm(code, address):
        instructions_to_copy.append(instr)
        instr_size += instr.size
        if instr_size >= max_patch_size:
            break

    # Step 2: Copy the instructions to be patched
    original_code = b''.join(instr.bytes for instr in instructions_to_copy)
    jump_back_address = address + instr_size  # Address to jump back to after the shellcode

    # Step 3: Map a new executable section for the shellcode
    shellcode_size = len(shellcode)
    
    new_section_size = 0x1000    # Map at least one page (4096 bytes)
    
    # Align the base address
    aligned_base = new_section_base & ~0xFFF

    # Map the section as RWX (read, write, execute)
    mu.mem_map(aligned_base, new_section_size, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)

    # Step 4: Write the shellcode into the new section
    mu.mem_write(aligned_base, shellcode)

    # Step 5: Append the copied original instructions to the end of the shellcode
    mu.mem_write(aligned_base + shellcode_size, original_code)

    # Step 6: Add a jump back to the next instruction after the hook at the end of the shellcode
    # The relative jump is calculated as the difference between the end of the original instructions
    # and the address to jump back to (jump_back_address).
    total_shellcode_size = shellcode_size + len(original_code)
    jump_back_offset = jump_back_address - (aligned_base + total_shellcode_size)

    # x86/x64 unconditional jump opcode is 0xE9 followed by a 32-bit signed relative offset
    jmp_back_instruction = b'\xE9' + struct.pack('<i', jump_back_offset)
    
    # Append this jump back instruction to the end of the shellcode
    mu.mem_write(aligned_base + total_shellcode_size, jmp_back_instruction)

    # Step 7: Patch the original address with a jump to the shellcode's new location
    # Calculate the relative jump offset from the original address to the shellcode base
    jump_offset = aligned_base - (address + 5)  # 5 bytes is the length of a JMP instruction
    jmp_instruction = b'\xE9' + struct.pack('<i', jump_offset)

    # Patch the original address with this jump
    mu.mem_write(address, jmp_instruction)

    # Step 8: Execute the code starting from the original address
    print(f"Jumping to shellcode at 0x{aligned_base:x} from 0x{address:x}")
    mu.emu_start(address, jump_back_address)  # Continue execution until after the shellcode is executed

    print("Shellcode execution finished. Returned to original flow.")
    

def run_until_crash(mu):
    """
    Measure the time of the second emulation and estimate the number of executed instructions until crash.
    """
    start_time = time.time()
    
    try:
        # Attempt to emulate indefinitely until crash
        emulate_code(mu, 0xFFFFFFFF)  # Large instruction count to emulate until crash
    except UcError as e:
        print(f"Program crashed due to memory access violation or other error: {e}")

    # Measure time taken
    end_time = time.time()
    elapsed_time = end_time - start_time
    print(f"Execution time during second run: {elapsed_time:.4f} seconds")

    # Estimate the number of executed instructions
    estimated_instructions = elapsed_time * 10_000_000  # 10M instructions per second
    print(f"Estimated number of instructions executed before crash: {int(estimated_instructions)}")


def assemble_shellcode(code):

    encoding, count = ks.asm(code)
    instructions = ""
    
    for dec in encoding:
        instructions += "\\x{0:02x}".format(int(dec)).rstrip("\n")

    print("Opcodes = (\"" + instructions + "\")")

    return instructions


def emulate_and_find_loop_exit():
    # Step 1: Get memory segments from IDA and map them into Unicorn
    ida_segments = get_segment_data()
    map_segments(mu, ida_segments)

    # Step 2: Copy register states from IDA to Unicorn
    copy_registers_from_ida(mu)

    # Step 3: First run to capture executed instruction addresses
    print("Starting first run to capture executed instruction addresses...")
    emulate_code(mu, FIRST_RUN_INSTRUCTION_COUNT, hook=True)
    print_visited_address_ranges(mu)

    # Step 4: Find the segment where the EIP/RIP is located
    ip = 'RIP' if is_64bit else 'EIP'
    eip_value = mu.reg_read(REGISTER_MAP[ip])

    # Identify the segment where the current EIP/RIP is located
    current_segment = None
    for segment in ida_segments:
        segment_start, segment_end = segment['base'], segment['end']
        if segment_start <= eip_value < segment_end:
            current_segment = (segment_start, segment_end)
            break

    if current_segment:
        segment_start, segment_end = current_segment
        # Step 5: Zero out unused memory in the current segment
        print(f"Changing protection of unused memory in the segment 0x{segment_start:x}-0x{segment_end:x} where EIP/RIP is located...")
        protect_unvisited_memory(mu, segment_start, segment_end)
    else:
        print("Error: Could not find the segment where EIP/RIP is located.")
        return

    # **NEW STEP: Resync writable segments and registers before second run**
    # Resync writable memory segments from IDA to Unicorn
    print("Resyncing writable memory segments before second run...")
    restore_segments_writable(mu, ida_segments)

    # Resync register states from IDA to Unicorn
    print("Resyncing register states before second run...")
    copy_registers_from_ida(mu)

    # Step 6: Second run until crash
    print("Starting second run to measure execution until crash...")
    run_until_crash(mu)

    # Step 7: Optionally, dump the register state or disassemble the code around the crash
    dump_registers(mu)
    
    print("Emulation crashed at the following address :")
    
    start_eip = mu.reg_read(REGISTER_MAP[ip])
    disassemble_code(mu, start_eip, 0x20)  # Disassemble 0x20 bytes after EIP



def emulate():
    # Step 1: Get memory segments from IDA and map them into Unicorn
    ida_segments = get_segment_data()
    map_segments(mu, ida_segments)

    # Step 2: Copy register states from IDA to Unicorn
    copy_registers_from_ida(mu)

    # Step 3: Start Unicorn emulation
    emulate_code(mu, 0xFFFFFF)

    # Step 4: Dump the state of the registers after emulation
    dump_registers(mu)

    # Step 5: Retrieve memory segments from Unicorn and compare with IDA segments
    unicorn_segments = get_unicorn_segment_data()
    compare_segments(ida_segments, unicorn_segments)

    ip = 'RIP' if is_64bit else 'EIP'
    # Step 6: Disassemble and display the executed instructions
    start_eip = mu.reg_read(REGISTER_MAP[ip])
    disassemble_code(mu, start_eip, 0x20)  # Disassemble 0x20 bytes after EIP


if __name__ == '__main__':
    free_addresses = find_free_space_near(0x0)
    # Output the potential addresses for shellcode
    for addr in free_addresses:
        print(f"Free space at: 0x{addr:X}")

    # emulate_and_find_loop_exit()

