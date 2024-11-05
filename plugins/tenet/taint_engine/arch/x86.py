from tenet.taint_engine.values_taint import SymRegister


def create_sym_register_factory():
    """
    CREATE A DICTIONARY OF SYMBOLIC REGISTERS AND THEIR PARTS.
    USED ALSO TO LINK A REGISTER PART TO ITS PARENT REGISTER.
    """
    rax = SymRegister("RAX", 63, 0)
    rcx = SymRegister("RCX", 63, 0)
    rdx = SymRegister("RDX", 63, 0)
    rbx = SymRegister("RBX", 63, 0)
    rsi = SymRegister("RSI", 63, 0)
    rdi = SymRegister("RDI", 63, 0)
    r8 = SymRegister("R8", 63, 0)
    r9 = SymRegister("R9", 63, 0)
    r10 = SymRegister("R10", 63, 0)
    r11 = SymRegister("R11", 63, 0)
    r12 = SymRegister("R12", 63, 0)
    r13 = SymRegister("R13", 63, 0)
    r14 = SymRegister("R14", 63, 0)
    r15 = SymRegister("R15", 63, 0)
    eax = SymRegister("EAX", 31, 0, rax)
    ecx = SymRegister("ECX", 31, 0, rcx)
    edx = SymRegister("EDX", 31, 0, rdx)
    ebx = SymRegister("EBX", 31, 0, rbx)
    edi = SymRegister("EDI", 31, 0, rdi)
    esi = SymRegister("ESI", 31, 0, rsi)
    r8d = SymRegister("R8D", 31, 0, r8)
    r9d = SymRegister("R9D", 31, 0, r9)
    r10d = SymRegister("R10D", 31, 0, r10)
    r11d = SymRegister("R11D", 31, 0, r11)
    r12d = SymRegister("R12D", 31, 0, r12)
    r13d = SymRegister("R13D", 31, 0, r13)
    r14d = SymRegister("R14D", 31, 0, r14)
    r15d = SymRegister("R15D", 31, 0, r15)
    ax = SymRegister("AX", 15, 0, eax)
    cx = SymRegister("CX", 15, 0, ecx)
    dx = SymRegister("DX", 15, 0, edx)
    bx = SymRegister("BX", 15, 0, ebx)
    si = SymRegister("SI", 15, 0, esi)
    di = SymRegister("DI", 15, 0, edi)
    r8w = SymRegister("R8W", 15, 0, r8d)
    r9w = SymRegister("R9W", 15, 0, r9d)
    r10w = SymRegister("R10W", 15, 0, r10d)
    r11w = SymRegister("R11W", 15, 0, r11d)
    r12w = SymRegister("R12W", 15, 0, r12d)
    r13w = SymRegister("R13W", 15, 0, r13d)
    r14w = SymRegister("R14W", 15, 0, r14d)
    r15w = SymRegister("R15W", 15, 0, r15d)
    al = SymRegister("AL", 7, 0, ax)
    cl = SymRegister("CL", 7, 0, cx)
    dl = SymRegister("DL", 7, 0, dx)
    bl = SymRegister("BL", 7, 0, bx)
    dil = SymRegister("DIL", 7, 0, di)
    sil = SymRegister("SIL", 7, 0, si)
    r8b = SymRegister("R8B", 7, 0, r8w)
    r9b = SymRegister("R9B", 7, 0, r9w)
    r10b = SymRegister("R10B", 7, 0, r10w)
    r11b = SymRegister("R11B", 7, 0, r11w)
    r12b = SymRegister("R12B", 7, 0, r12w)
    r13b = SymRegister("R13B", 7, 0, r13w)
    r14b = SymRegister("R14B", 7, 0, r14w)
    r15b = SymRegister("R15B", 7, 0, r15w)
    ah = SymRegister("AH", 15, 8, ax)
    ch = SymRegister("CH", 15, 8, cx)
    dh = SymRegister("DH", 15, 8, dx)
    bh = SymRegister("BH", 15, 8, bx)

    SYM_REGISTER_FACTORY = {
        "AH": [rax, eax, ax, ah, al],
        "AL": [rax, eax, ax, ah, al],
        "AX": [rax, eax, ax, ah, al],
        "BH": [rbx, ebx, bx, bh, bl],
        "BL": [rbx, ebx, bx, bh, bl],
        "BX": [rbx, ebx, bx, bh, bl],
        "CH": [rcx, ecx, cx, ch, cl],
        "CL": [rcx, ecx, cx, ch, cl],
        "CX": [rcx, ecx, cx, ch, cl],
        "DH": [rdx, edx, dx, dh, dl],
        "DI": [rdi, edi, di, dil],
        "DIL": [rdi, edi, di, dil],
        "DL": [rdx, edx, dx, dh, dl],
        "DX": [rdx, edx, dx, dh, dl],
        "EAX": [rax, eax, ax, ah, al],
        "EBX": [rbx, ebx, bx, bh, bl],
        "ECX": [rcx, ecx, cx, ch, cl],
        "EDI": [rdi, edi, di, dil],
        "EDX": [rdx, edx, dx, dh, dl],
        "ESI": [rsi, esi, si, sil],
        "R10": [r10, r10d, r10w, r10b],
        "R10B": [r10, r10d, r10w, r10b],
        "R10D": [r10, r10d, r10w, r10b],
        "R10W": [r10, r10d, r10w, r10b],
        "R11": [r11, r11d, r11w, r11b],
        "R11B": [r11, r11d, r11w, r11b],
        "R11D": [r11, r11d, r11w, r11b],
        "R11W": [r11, r11d, r11w, r11b],
        "R12": [r12, r12d, r12w, r12b],
        "R12B": [r12, r12d, r12w, r12b],
        "R12D": [r12, r12d, r12w, r12b],
        "R12W": [r12, r12d, r12w, r12b],
        "R13": [r13, r13d, r13w, r13b],
        "R13B": [r13, r13d, r13w, r13b],
        "R13D": [r13, r13d, r13w, r13b],
        "R13W": [r13, r13d, r13w, r13b],
        "R14": [r14, r14d, r14w, r14b],
        "R14B": [r14, r14d, r14w, r14b],
        "R14D": [r14, r14d, r14w, r14b],
        "R14W": [r14, r14d, r14w, r14b],
        "R15": [r15, r15d, r15w, r15b],
        "R15B": [r15, r15d, r15w, r15b],
        "R15D": [r15, r15d, r15w, r15b],
        "R15W": [r15, r15d, r15w, r15b],
        "R8": [r8, r8d, r8w, r8b],
        "R8B": [r8, r8d, r8w, r8b],
        "R8D": [r8, r8d, r8w, r8b],
        "R8W": [r8, r8d, r8w, r8b],
        "R9": [r9, r9d, r9w, r9b],
        "R9B": [r9, r9d, r9w, r9b],
        "R9D": [r9, r9d, r9w, r9b],
        "R9W": [r9, r9d, r9w, r9b],
        "RAX": [rax, eax, ax, ah, al],
        "RBX": [rbx, ebx, bx, bh, bl],
        "RCX": [rcx, ecx, cx, ch, cl],
        "RDI": [rdi, edi, di, dil],
        "RDX": [rdx, edx, dx, dh, dl],
        "RSI": [rsi, esi, si, sil],
        "SI": [rsi, esi, si, sil],
        "SIL": [rsi, esi, si, sil],
    }
    return SYM_REGISTER_FACTORY


def get_parent_register(register_name, arch_size):
    register_name = register_name.upper()
    if arch_size == 64:
        return {
            "RAX": "RAX",
            "EAX": "RAX",
            "AX": "RAX",
            "AH": "RAX",
            "AL": "RAX",
            "RBX": "RBX",
            "EBX": "RBX",
            "BX": "RBX",
            "BH": "RBX",
            "BL": "RBX",
            "RCX": "RCX",
            "ECX": "RCX",
            "CX": "RCX",
            "CH": "RCX",
            "CL": "RCX",
            "RDX": "RDX",
            "EDX": "RDX",
            "DX": "RDX",
            "DH": "RDX",
            "DL": "RDX",
            "RSI": "RSI",
            "ESI": "RSI",
            "SI": "RSI",
            "SIL": "RSI",
            "RDI": "RDI",
            "EDI": "RDI",
            "DI": "RDI",
            "DIL": "RDI",
            "RBP": "RBP",
            "EBP": "RBP",
            "BP": "RBP",
            "BPL": "RBP",
            "RSP": "RSP",
            "ESP": "RSP",
            "SP": "RSP",
            "SPL": "RSP",
            "R8": "R8",
            "R8D": "R8",
            "R8W": "R8",
            "R8B": "R8",
            "R9": "R9",
            "R9D": "R9",
            "R9W": "R9",
            "R9B": "R9",
            "R10": "R10",
            "R10D": "R10",
            "R10W": "R10",
            "R10B": "R10",
            "R11": "R11",
            "R11D": "R11",
            "R11W": "R11",
            "R11B": "R11",
            "R12": "R12",
            "R12D": "R12",
            "R12W": "R12",
            "R12B": "R12",
            "R13": "R13",
            "R13D": "R13",
            "R13W": "R13",
            "R13B": "R13",
            "R14": "R14",
            "R14D": "R14",
            "R14W": "R14",
            "R14B": "R14",
            "R15": "R15",
            "R15D": "R15",
            "R15W": "R15",
            "R15B": "R15",
        }[register_name]
    elif arch_size == 32:
        return {
            "EAX": "EAX",
            "AX": "EAX",
            "AH": "EAX",
            "AL": "EAX",
            "EBX": "EBX",
            "BX": "EBX",
            "BH": "EBX",
            "BL": "EBX",
            "ECX": "ECX",
            "CX": "ECX",
            "CH": "ECX",
            "CL": "ECX",
            "EDX": "EDX",
            "DX": "EDX",
            "DH": "EDX",
            "DL": "EDX",
            "ESI": "ESI",
            "SI": "ESI",
            "EDI": "EDI",
            "DI": "EDI",
            "EBP": "EBP",
            "BP": "EBP",
            "ESP": "ESP",
            "SP": "ESP",
            "R8D": "R8",
            "R8W": "R8",
            "R8B": "R8",
            "R9D": "R9",
            "R9W": "R9",
            "R9B": "R9",
            "R10D": "R10",
            "R10W": "R10",
            "R10B": "R10",
            "R11D": "R11",
            "R11W": "R11",
            "R11B": "R11",
            "R12D": "R12",
            "R12W": "R12",
            "R12B": "R12",
            "R13D": "R13",
            "R13W": "R13",
            "R13B": "R13",
            "R14D": "R14",
            "R14W": "R14",
            "R14B": "R14",
            "R15D": "R15",
            "R15W": "R15",
            "R15B": "R15",
            "R8": "R8",
            "R9": "R9",
            "R10": "R10",
            "R11": "R11",
            "R12": "R12",
            "R13": "R13",
            "R14": "R14",
            "R15": "R15",
        }[register_name].upper()
    else:
        raise ValueError("UNKNOWN ARCHITECTURE TYPE")
