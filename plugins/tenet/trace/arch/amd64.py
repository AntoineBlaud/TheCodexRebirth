class ArchAMD64:
    """
    AMD64 CPU Architecture Definition.
    """
    MAGIC = 0x41424344

    POINTER_SIZE = 8
    MAX_INT_VALUE = 0xFFFFFFFFFFFFFFFF

    IP = "RIP"
    SP = "RSP"
    
    CALL_INSTRUCTION = "call"
    JUMP_INSTRUCTION = "jmp"
    COND_JUMP_INSTRUCTION = "j"

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
        "RIP",
        "EAX",
        "EBX",
        "ECX",
        "EDX",
        "EBP",
        "ESP",
        "ESI",
        "EDI",
        "R8D",
        "R9D",
        "R10D",
        "R11D",
        "R12D",
        "R13D",
        "R14D",
        "R15D",
        "AX",
        "BX",
        "CX",
        "DX",
        "SI",
        "DI",
        "R9W",
        "R10W",
        "R11W",
        "R12W",
        "R13W",
        "R14W",
        "R15W",
        "AL",
        "BL",
        "CL",
        "DL",
        "SIL",
        "DIL",
        "R8B",
        "R9B",
        "R10B",
        "R11B",
        "R12B",
        "R13B",
        "R14B",
        "R15B",
        "AH",
        "BH",
        "CH",
        "DH"
    ]
    
    REGISTERS_MAIN = \
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
    