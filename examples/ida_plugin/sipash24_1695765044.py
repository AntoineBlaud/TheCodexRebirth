from qiling import *
from qiling.const import QL_VERBOSE
from superglobals import setglobal
from sys import argv

# Set global variable 'BINARY_ARCH' to x64 or x86
setglobal('BINARY_ARCH', "x64")


from codexrebirth.core import CodexRebirth, DebugLevel


def jump_to_next_instruction(ql):
    """
    Jump to the next instruction by incrementing the RIP register.

    Args:
        ql: The Qiling instance.
    """
    current_rip = ql.arch.regs.read("rip")
    next_rip = current_rip + 0x5
    ql.arch.regs.write("rip", next_rip)


# Define a callback for the 'rand' function
def rand_callback(codex):
    """
    Callback for the 'rand' function.

    Args:
        codex: The Codex instance.
    """
    ql = codex.ql
    print("rand_callback")
    ql.arch.regs.write("rax", 0x1)
    # Move to the next instruction
    jump_to_next_instruction(ql)

    

def taint_memory_with_string(codex, value, addr, name_pattern, chunk_size=1):
    """
    Taint memory with a string in chunks of a specified size.

    Args:
        codex: The Codex instance.
        value: The input string to taint.
        addr: The starting memory address to write the string.
        name_pattern: A name pattern for tainting.
        chunk_size: The size of each chunk (default is 1 byte).
    """
    for i in range(0, len(value), chunk_size):
        chunk = value[i:i + chunk_size]
        name = f"{name_pattern}_{i}"
        _taint_memory_with_string_chunk(codex, addr, chunk, name)
        addr += chunk_size

def _taint_memory_with_string_chunk(codex, addr, chunk, name):
    """
    Taint memory with a string.

    Args:
        codex: The Codex instance.
        offset: The memory offset to write the string.
        value: The input string to taint.
        name_pattern: A name pattern for tainting.
    """
    mask = 0xff << ((len(chunk) -1) * 8)
    print(hex(mask))
    value_bytes = chunk.encode()
    codex.ql.mem.write(addr, value_bytes)
    value = int.from_bytes(value_bytes, byteorder='little')
    codex.taint_memory(addr, name, value, mask)




####################################################################################################
# IMPORTANT: The two functions below are called by the IDA plugin. Do not change the function names.
####################################################################################################

def configure_and_register_callbacks(codex):
    """
    Configure and register callbacks for the Codex instance. Called by the IDA plugin.

    Args:
        codex: The Codex instance.
    """
    codex.set_register("rdi", 9888)
    codex.taint_register("rdi", "num", 9888)
    
    

def initialize_codex_rebirth(binary_path):
    """
    Initialize the CodexRebirth instance and Qiling. Called by the IDA plugin.

    Args:
        binary_path: Path to the binary.
        rootfs_path: Path to the root file system.

    Returns:
        CodexRebirth: The initialized CodexRebirth instance.
    """
    # rootfs_path, change it to your own path
    rootfs_path = r"C:/Users/antoi/source/rootfs/x8664_linux"
    # Configure Qiling with verbose logging
    ql = Qiling([binary_path], rootfs_path, log_plain=True)
    debug_level = DebugLevel.INFO
    # Initialize the CodexRebirth instance
    return CodexRebirth(ql, debug_level, symbolic_check=False)

    
    






