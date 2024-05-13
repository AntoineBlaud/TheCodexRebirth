class ArchX86:
    """
    x86 CPU Architecture Definition.
    """

    MAGIC = 0x386

    POINTER_SIZE = 4
    MAX_INT_VALUE = 0xFFFFFFFF

    IP = "EIP"
    SP = "ESP"

    CALL_INSTRUCTION = "call"
    JUMP_INSTRUCTION = "jmp"
    COND_JUMP_INSTRUCTION = "j"

    REGISTERS = [
        "EAX",
        "EBX",
        "ECX",
        "EDX",
        "EBP",
        "ESP",
        "ESI",
        "EDI",
        "EIP" "R8D",
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
        "DH",
    ]

    REGISTERS_MAIN = ["EAX", "EBX", "ECX", "EDX", "EBP", "ESP", "ESI", "EDI", "EIP"]
