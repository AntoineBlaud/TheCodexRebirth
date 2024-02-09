
from tenet.taint.value import SymRegister

def create_sym_register_factory():
    """
    Create a dictionary of symbolic registers and their parts.
    Used also to link a register part to its parent register.
    """
    rax = SymRegister("rax", 63, 0)
    rcx = SymRegister("rcx", 63, 0)
    rdx = SymRegister("rdx", 63, 0)
    rbx = SymRegister("rbx", 63, 0)
    rsi = SymRegister("rsi", 63, 0)
    rdi = SymRegister("rdi", 63, 0)
    r8 = SymRegister("r8", 63, 0)
    r9 = SymRegister("r9", 63, 0)
    r10 = SymRegister("r10", 63, 0)
    r11 = SymRegister("r11", 63, 0)
    r12 = SymRegister("r12", 63, 0)
    r13 = SymRegister("r13", 63, 0)
    r14 = SymRegister("r14", 63, 0)
    r15 = SymRegister("r15", 63, 0)
    eax = SymRegister("eax", 31, 0, rax)
    ecx = SymRegister("ecx", 31, 0, rcx)
    edx = SymRegister("edx", 31, 0, rdx)
    ebx = SymRegister("ebx", 31, 0, rbx)
    edi = SymRegister("edi", 31, 0, rdi)
    esi = SymRegister("esi", 31, 0, rsi)
    r8d = SymRegister("r8d", 31, 0, r8)
    r9d = SymRegister("r9d", 31, 0, r9)
    r10d = SymRegister("r10d", 31, 0, r10)
    r11d = SymRegister("r11d", 31, 0, r11)
    r12d = SymRegister("r12d", 31, 0, r12)
    r13d = SymRegister("r13d", 31, 0, r13)
    r14d = SymRegister("r14d", 31, 0, r14)
    r15d = SymRegister("r15d", 31, 0, r15)
    ax = SymRegister("ax", 15, 0, eax)
    cx = SymRegister("cx", 15, 0, ecx)
    dx = SymRegister("dx", 15, 0, edx)
    bx = SymRegister("bx", 15, 0, ebx)
    si = SymRegister("si", 15, 0, esi)
    di = SymRegister("di", 15, 0, edi)
    r8w = SymRegister("r8w", 15, 0, r8d)
    r9w = SymRegister("r9w", 15, 0, r9d)
    r10w = SymRegister("r10w", 15, 0, r10d)
    r11w = SymRegister("r11w", 15, 0, r11d)
    r12w = SymRegister("r12w", 15, 0, r12d)
    r13w = SymRegister("r13w", 15, 0, r13d)
    r14w = SymRegister("r14w", 15, 0, r14d)
    r15w = SymRegister("r15w", 15, 0, r15d)
    al = SymRegister("al", 7, 0, ax)
    cl = SymRegister("cl", 7, 0, cx)
    dl = SymRegister("dl", 7, 0, dx)
    bl = SymRegister("bl", 7, 0, bx)
    dil = SymRegister("dil", 7, 0, di)
    sil = SymRegister("sil", 7, 0, si)
    r8b = SymRegister("r8b", 7, 0, r8w)
    r9b = SymRegister("r9b", 7, 0, r9w)
    r10b = SymRegister("r10b", 7, 0, r10w)
    r11b = SymRegister("r11b", 7, 0, r11w)
    r12b = SymRegister("r12b", 7, 0, r12w)
    r13b = SymRegister("r13b", 7, 0, r13w)
    r14b = SymRegister("r14b", 7, 0, r14w)
    r15b = SymRegister("r15b", 7, 0, r15w)
    ah = SymRegister("ah", 15, 8, ax)
    ch = SymRegister("ch", 15, 8, cx)
    dh = SymRegister("dh", 15, 8, dx)
    bh = SymRegister("bh", 15, 8, bx)

    SYM_REGISTER_FACTORY = {
        "ah": [rax, eax, ax, ah, al],
        "al": [rax, eax, ax, ah, al],
        "ax": [rax, eax, ax, ah, al],
        "bh": [rbx, ebx, bx, bh, bl],
        "bl": [rbx, ebx, bx, bh, bl],
        "bx": [rbx, ebx, bx, bh, bl],
        "ch": [rcx, ecx, cx, ch, cl],
        "cl": [rcx, ecx, cx, ch, cl],
        "cx": [rcx, ecx, cx, ch, cl],
        "dh": [rdx, edx, dx, dh, dl],
        "di": [rdi, edi, di, dil],
        "dil": [rdi, edi, di, dil],
        "dl": [rdx, edx, dx, dh, dl],
        "dx": [rdx, edx, dx, dh, dl],
        "eax": [rax, eax, ax, ah, al],
        "ebx": [rbx, ebx, bx, bh, bl],
        "ecx": [rcx, ecx, cx, ch, cl],
        "edi": [rdi, edi, di, dil],
        "edx": [rdx, edx, dx, dh, dl],
        "esi": [rsi, esi, si, sil],
        "r10": [r10, r10d, r10w, r10b],
        "r10b": [r10, r10d, r10w, r10b],
        "r10d": [r10, r10d, r10w, r10b],
        "r10w": [r10, r10d, r10w, r10b],
        "r11": [r11, r11d, r11w, r11b],
        "r11b": [r11, r11d, r11w, r11b],
        "r11d": [r11, r11d, r11w, r11b],
        "r11w": [r11, r11d, r11w, r11b],
        "r12": [r12, r12d, r12w, r12b],
        "r12b": [r12, r12d, r12w, r12b],
        "r12d": [r12, r12d, r12w, r12b],
        "r12w": [r12, r12d, r12w, r12b],
        "r13": [r13, r13d, r13w, r13b],
        "r13b": [r13, r13d, r13w, r13b],
        "r13d": [r13, r13d, r13w, r13b],
        "r13w": [r13, r13d, r13w, r13b],
        "r14": [r14, r14d, r14w, r14b],
        "r14b": [r14, r14d, r14w, r14b],
        "r14d": [r14, r14d, r14w, r14b],
        "r14w": [r14, r14d, r14w, r14b],
        "r15": [r15, r15d, r15w, r15b],
        "r15b": [r15, r15d, r15w, r15b],
        "r15d": [r15, r15d, r15w, r15b],
        "r15w": [r15, r15d, r15w, r15b],
        "r8": [r8, r8d, r8w, r8b],
        "r8b": [r8, r8d, r8w, r8b],
        "r8d": [r8, r8d, r8w, r8b],
        "r8w": [r8, r8d, r8w, r8b],
        "r9": [r9, r9d, r9w, r9b],
        "r9b": [r9, r9d, r9w, r9b],
        "r9d": [r9, r9d, r9w, r9b],
        "r9w": [r9, r9d, r9w, r9b],
        "rax": [rax, eax, ax, ah, al],
        "rbx": [rbx, ebx, bx, bh, bl],
        "rcx": [rcx, ecx, cx, ch, cl],
        "rdi": [rdi, edi, di, dil],
        "rdx": [rdx, edx, dx, dh, dl],
        "rsi": [rsi, esi, si, sil],
        "si": [rsi, esi, si, sil],
        "sil": [rsi, esi, si, sil],
    }
    return SYM_REGISTER_FACTORY


def get_parent_register(register_name, arch_size):
    if arch_size == 64:
        return {
            "rax": "rax",
            "eax": "rax",
            "ax": "rax",
            "ah": "rax",
            "al": "rax",
            "rbx": "rbx",
            "ebx": "rbx",
            "bx": "rbx",
            "bh": "rbx",
            "bl": "rbx",
            "rcx": "rcx",
            "ecx": "rcx",
            "cx": "rcx",
            "ch": "rcx",
            "cl": "rcx",
            "rdx": "rdx",
            "edx": "rdx",
            "dx": "rdx",
            "dh": "rdx",
            "dl": "rdx",
            "rsi": "rsi",
            "esi": "rsi",
            "si": "rsi",
            "sil": "rsi",
            "rdi": "rdi",
            "edi": "rdi",
            "di": "rdi",
            "dil": "rdi",
            "rbp": "rbp",
            "ebp": "rbp",
            "bp": "rbp",
            "bpl": "rbp",
            "rsp": "rsp",
            "esp": "rsp",
            "sp": "rsp",
            "spl": "rsp",
            "r8": "r8",
            "r8d": "r8",
            "r8w": "r8",
            "r8b": "r8",
            "r9": "r9",
            "r9d": "r9",
            "r9w": "r9",
            "r9b": "r9",
            "r10": "r10",
            "r10d": "r10",
            "r10w": "r10",
            "r10b": "r10",
            "r11": "r11",
            "r11d": "r11",
            "r11w": "r11",
            "r11b": "r11",
            "r12": "r12",
            "r12d": "r12",
            "r12w": "r12",
            "r12b": "r12",
            "r13": "r13",
            "r13d": "r13",
            "r13w": "r13",
            "r13b": "r13",
            "r14": "r14",
            "r14d": "r14",
            "r14w": "r14",
            "r14b": "r14",
            "r15": "r15",
            "r15d": "r15",
            "r15w": "r15",
            "r15b": "r15",
        }[register_name]
    elif arch_size == 32:
        return {
            "eax": "eax",
            "ax": "eax",
            "ah": "eax",
            "al": "eax",
            "ebx": "ebx",
            "bx": "ebx",
            "bh": "ebx",
            "bl": "ebx",
            "ecx": "ecx",
            "cx": "ecx",
            "ch": "ecx",
            "cl": "ecx",
            "edx": "edx",
            "dx": "edx",
            "dh": "edx",
            "dl": "edx",
            "esi": "esi",
            "si": "esi",
            "edi": "edi",
            "di": "edi",
            "ebp": "ebp",
            "bp": "ebp",
            "esp": "esp",
            "sp": "esp",
            "r8d": "r8",
            "r8w": "r8",
            "r8b": "r8",
            "r9d": "r9",
            "r9w": "r9",
            "r9b": "r9",
            "r10d": "r10",
            "r10w": "r10",
            "r10b": "r10",
            "r11d": "r11",
            "r11w": "r11",
            "r11b": "r11",
            "r12d": "r12",
            "r12w": "r12",
            "r12b": "r12",
            "r13d": "r13",
            "r13w": "r13",
            "r13b": "r13",
            "r14d": "r14",
            "r14w": "r14",
            "r14b": "r14",
            "r15d": "r15",
            "r15w": "r15",
            "r15b": "r15",
            "r8": "r8",
            "r9": "r9",
            "r10": "r10",
            "r11": "r11",
            "r12": "r12",
            "r13": "r13",
            "r14": "r14",
            "r15": "r15",
        }[register_name]
    else:
        raise ValueError("Unknown architecture type")
