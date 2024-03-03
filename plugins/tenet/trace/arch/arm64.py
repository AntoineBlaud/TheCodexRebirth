class ArchARM64:
    """
    ARM CPU Architecture Definition.
    """
    MAGIC = 0x42424242

    POINTER_SIZE = 8
    MAX_INT_VALUE = 0xFFFFFFFFFFFFFFFF

    IP = "PC"
    SP = "SP"

    CALL_INSTRUCTION = "bl"
    JUMP_INSTRUCTION = "b"
    COND_JUMP_INSTRUCTION = "b"
    
    REGISTERS = \
    [
        "X0",
        "X1",
        "X2",
        "X3",
        "X4",
        "X5",
        "X6",
        "X7",
        "X8",
        "X9",
        "X10",
        "X11",
        "X12",
        "X13",
        "X14",
        "X15",
        "X16",
        "X17",
        "X18",
        "X19",
        "X20",
        "X21",
        "X22",
        "X23",
        "X24",
        "X25",
        "X26",
        "X27",
        "X28",
        "FP",
        "SP",
        "LR",
        "PC"
    ]
    
    REGISTERS_MAIN = \
    [
        "X0",
        "X1",
        "X2",
        "X3",
        "X4",
        "X5",
        "X6",
        "X7",
        "X8",
        "X9",
        "X10",
        "X11",
        "X12",
        "X13",
        "X14",
        "X15",
        "X16",
        "X17",
        "X18",
        "X19",
        "X20",
        "X21",
        "X22",
        "X23",
        "X24",
        "X25",
        "X26",
        "X27",
        "X28",
        "FP",
        "SP",
        "LR",
        "PC"
    ]
    