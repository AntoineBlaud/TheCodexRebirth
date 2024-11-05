import idc
import idaapi
import idautils

MACRO_SAVE_REG = """
        .macro pushaq
            push rax
            push rbx
            push rcx
            push rdx
            push rbp
            push rsi
            push rdi
            push r8
            push r9
            push r10
        .endm

        .macro popaq
            pop r10
            pop r9
            pop r8
            pop rdi
            pop rsi
            pop rbp
            pop rdx
            pop rcx
            pop rbx
            pop rax
        .endm
"""

cmp_reg_map = {
        # 64-bit registers
        "RAX": "RBX", "RBX": "RAX",
        "RCX": "RAX", "RDX": "RAX",
        "RSI": "RAX", "RDI": "RAX",
        "R8": "RAX", "R9": "RAX",
        "R10": "RAX", "R11": "RAX",
        "R12": "RAX", "R13": "RAX",
        "R14": "RAX", "R15": "RAX",

        # 32-bit registers
        "EAX": "EBX", "EBX": "EAX",
        "ECX": "EAX", "EDX": "EAX",
        "ESI": "EAX", "EDI": "EAX",
        "R8D": "EAX", "R9D": "EAX",
        "R10D": "EAX", "R11D": "EAX",
        "R12D": "EAX", "R13D": "EAX",
        "R14D": "EAX", "R15D": "EAX",

        # 16-bit registers (if applicable)
        "AX": "BX", "BX": "AX",
        "CX": "AX", "DX": "AX",
        "SI": "AX", "DI": "AX",
        "R8W": "AX", "R9W": "AX",
        "R10W": "AX", "R11W": "AX",
        "R12W": "AX", "R13W": "AX",
        "R14W": "AX", "R15W": "AX",

        # 8-bit registers
        "AL": "BL", "BL": "AL",
        "CL": "AL", "DL": "AL",
        "SIL": "AL", "DIL": "AL",
        "R8B": "AL", "R9B": "AL",
        "R10B": "AL", "R11B": "AL",
        "R12B": "AL", "R13B": "AL",
        "R14B": "AL", "R15B": "AL",
    }

def get_names_address(base, size, desirednames):
    currentaddress = base
    result = {}
    while currentaddress <= base + size:
        for fname in desirednames:
            target_name_splited = idc.get_name(currentaddress).split("_")
            if fname in target_name_splited:
                result[fname] = currentaddress   
        currentaddress+= 1
    return result


def find_routines(themodule, desirednames):
    for m in idautils.Modules():
        if themodule.lower() in m.name.lower():
            base = m.base
            size = m.size
            idc.plan_and_wait(base, base + size)
            return get_names_address(base, size, desirednames)

    return {}

def get_virtualalloc_offset():
    # Find kernel32.dll base address
    kernel32 = idaapi.get_module_base('kernel32.dll')
    if kernel32 == idaapi.BADADDR:
        raise Exception("Cannot find kernel32.dll")

    # Get the address of VirtualAlloc in kernel32.dll
    virtual_alloc = idaapi.get_import_function(kernel32, 'VirtualAlloc')
    if virtual_alloc == idaapi.BADADDR:
        raise Exception("Cannot find VirtualAlloc in kernel32.dll")

    return virtual_alloc - idc.get_reg_value("RIP")

class Linux_64_SM():

    ALLOC_RESULT_OFFSET = -0xd
    ALLOC_RESULT_REG = "RAX"

    def build_allocate_memory(zone_address, size):
       return f"""
            {MACRO_SAVE_REG}

                pushaq
                mov rdi,  {zone_address}
                mov rax, 0x9
                cdq
                mov dh, 0x10
                mov rsi, {size}
                xor r9, r9
                mov r10, 0x22
                mov dl, 0x7
                syscall
                popaq
            """
    
    def build_macros():
        return f"""
            {MACRO_SAVE_REG}
            pushaq
        """

    def build_compare(cmp_op_reg,  past_target, target_op_reg):
        return f"\nmov {cmp_op_reg}, {hex(past_target)}\ncmp {cmp_op_reg}, {target_op_reg}\nje already_seen"
    
    def build_nop_sled():
        return """
            new:
                nop
                nop
                nop 
                nop
                nop
                nop
                nop
                nop
            already_seen:
                popaq
        """
    
    def get_cmp_reg(op_reg):
        return "RAX" if op_reg.upper() != "RAX" else "RBX"
    



class Windows_64_SM():

    ALLOC_RESULT_OFFSET = -0xd
    ALLOC_RESULT_REG = "RAX"
    



    def build_allocate_memory(zone_address, size):
                
        routines = find_routines("KERNEL32.dll", ["VirtualAlloc"])
     
        return f"""
            {MACRO_SAVE_REG}

            start:
                pushaq   
                mov rcx, {zone_address}      
                mov rdx, {size}                      
                mov r8, 0x3000                 
                mov r9, 0x40                 
                xor rax, rax   
                mov rax,  {routines["VirtualAlloc"]}     
                call rax
                popaq              

        """


    def build_macros():
        return f"""
            {MACRO_SAVE_REG}
            pushaq
        """

    def build_compare(cmp_op_reg,  past_target, target_op_reg):
        return f"\nmov {cmp_op_reg}, {hex(past_target)}\ncmp {cmp_op_reg}, {target_op_reg}\nje already_seen"
    
    def build_nop_sled():
        return """
            new:
                nop
                nop
                nop 
                nop
                nop
                nop
                nop
                nop
            already_seen:
                popaq
        """
    
    def get_cmp_reg(op_reg):
        return cmp_reg_map[op_reg.upper()]