import idaapi
import idautils
import idc
from unicorn import *
from unicorn.x86_const import *
from capstone import *
import hashlib

REGISTER_MAP = {
    'EAX': UC_X86_REG_EAX, 'EBX': UC_X86_REG_EBX, 'ECX': UC_X86_REG_ECX, 'EDX': UC_X86_REG_EDX,
    'ESI': UC_X86_REG_ESI, 'EDI': UC_X86_REG_EDI, 'ESP': UC_X86_REG_ESP, 'EBP': UC_X86_REG_EBP, 'EIP': UC_X86_REG_EIP,
    'RAX': UC_X86_REG_RAX, 'RBX': UC_X86_REG_RBX, 'RCX': UC_X86_REG_RCX, 'RDX': UC_X86_REG_RDX,
    'RSI': UC_X86_REG_RSI, 'RDI': UC_X86_REG_RDI, 'RSP': UC_X86_REG_RSP, 'RBP': UC_X86_REG_RBP, 'RIP': UC_X86_REG_RIP,
    'EFLAGS': UC_X86_REG_EFLAGS, 'RFLAGS': UC_X86_REG_EFLAGS
}

is_64bit = idaapi.get_inf_structure().is_64bit()
is_32bit = not is_64bit

if is_64bit:
    mu = Uc(UC_ARCH_X86, UC_MODE_64)
else:
    mu = Uc(UC_ARCH_X86, UC_MODE_32)

def copy_registers_from_ida(mu):
    for reg in REGISTER_MAP.keys():
        reg_name = reg.upper()
        if reg_name in REGISTER_MAP:
            try:
                reg_value = idc.get_reg_value(reg)
                uc_reg = REGISTER_MAP[reg_name]
                mu.reg_write(uc_reg, reg_value)
            except (unicorn.UcError, Exception) as e:
                print(f"Error copying register {reg_name}: {e}")

def compare_registers(mu):
    """
    Compare the values of registers in Unicorn and IDA. If there is a mismatch, stop the emulation.
    """
    for reg in REGISTER_MAP.keys():
        reg_name = reg.upper()
        if reg_name in REGISTER_MAP:
            try:
                uc_reg = REGISTER_MAP[reg_name]
                uc_value = mu.reg_read(uc_reg)
                ida_value = idc.get_reg_value(reg_name)

                if uc_value != ida_value:
                    print(f"Register mismatch found: {reg_name}")
                    print(f"IDA: 0x{ida_value:x}, Unicorn: 0x{uc_value:x}")
                    return False
            except Exception as e:
                pass
    return True

def hook_code(mu, address, size, user_data):
    """
    Hook callback for every executed instruction. Compare registers and stop if a mismatch is found.
    """

    if not compare_registers(mu):
        print(f"Stopping emulation due to register mismatch at address 0x{address:x}")
        mu.emu_stop()
    else:
        disassemble_code(mu, address, size)
        
    idaapi.step_into()
    idaapi.wait_for_next_event(idc.WFNE_SUSP, -1)

def disassemble_code(mu, start_addr, size):
    """
    Disassemble code using Capstone and display it.
    """
    if is_64bit:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
    else:
        md = Cs(CS_ARCH_X86, CS_MODE_32)

    code = mu.mem_read(start_addr, size)
    for i in md.disasm(code, start_addr):
        print(f"0x{i.address:x}: {i.mnemonic} {i.op_str}")

def map_segments(mu, segments):
    """
    Map each segment in Unicorn's memory and copy the contents from IDA.
    """
    for seg in segments:
        base = seg['base']
        size = seg['size']
        perm = seg['perm']
        
        uc_perm = 0
        if perm & idaapi.SEGPERM_READ:
            uc_perm |= UC_PROT_READ
        if perm & idaapi.SEGPERM_WRITE:
            uc_perm |= UC_PROT_WRITE
        if perm & idaapi.SEGPERM_EXEC:
            uc_perm |= UC_PROT_EXEC

        if size < 0xFFFFFFFF:
            print(f"Mapping segment at 0x{base:x} with size 0x{size:x} and permissions {uc_perm}")
            mu.mem_map(base, size, uc_perm)
            segment_data = idaapi.get_bytes(base, size)
            if segment_data:
                mu.mem_write(base, segment_data)

def get_segment_data():
    """
    Retrieve memory segments from IDA and return them as a list of dictionaries.
    """
    segments = []
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        base = seg.start_ea
        size = seg.end_ea - seg.start_ea
        perm = seg.perm
        segments.append({
            'base': base,
            'size': size,
            'perm': perm
        })
    return segments

def emulate_code(mu, max_instructions):
    """
    Start the emulation and hook into executed instructions.
    """
    start_eip = idc.get_reg_value('RIP' if is_64bit else 'EIP')

    try:
        print(f"Starting emulation at EIP: 0x{start_eip:x}")
        mu.hook_add(UC_HOOK_CODE, hook_code)
        mu.emu_start(start_eip, 0, count=max_instructions)
    except UcError as e:
        print(f"Unicorn error: {e}")

def emulate():
    # Step 1: Get memory segments from IDA and map them into Unicorn
    ida_segments = get_segment_data()
    map_segments(mu, ida_segments)

    # Step 2: Copy registers from IDA to Unicorn
    copy_registers_from_ida(mu)

    # Step 3: Start emulation
    emulate_code(mu, 0xFFFFFF)

if __name__ == '__main__':
    emulate()
