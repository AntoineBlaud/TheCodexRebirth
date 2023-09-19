
from qiling import *
from qiling.const import QL_VERBOSE
from superglobals import setglobal
import sys 

setglobal('BINARY_ARCH', 'x64')
from codexrebirth import CodexRebirth, DebugLevel

##############################################################################################
# IMPORTANT: address depend of you system, you need to change the address and disable aslr 
# or use qiling base + offset
##############################################################################################


INPUT_STR = "A"*9

# Define a function to register a string in memory and set rdi to the address of the string
# This function is called just before the call to 'SECRET'


def register_str(codex):
    print("Registering string")
    rbp = codex.ql.arch.regs.read("rbp")
    value_addr = rbp - 0x80
    index = 0
    for i in range(len(INPUT_STR)):
        value = INPUT_STR[i].encode()
        c0dex.ql.mem.write(value_addr + index, value)
        # For each byte of the string, taint the memory and apply a mask of 0xff
        # IMPORTANT: Depending of the binary, you may group str bytes in a single int symbolic value
        # You will need to convert str to array of int
            # Size 1 : 0xff
            # Size 4 : 0xffffffff
            # Size 8 : 0xffffffffffffffff

        codex.taint_memory(value_addr + index, "in_" + str(index), ord(INPUT_STR[i]) , 0xff)
        index += 1
        
    print(codex.codex_state)
        
    ql.arch.regs.write("rdi", value_addr)
    

def strlen(codex):
    codex.ql.arch.regs.write("rax", 9)
    codex.ql.arch.regs.write("rip", codex.ql.arch.regs.read("rip") + 5)
    codex.codex_state.delete_symbolic_var("rax")
    
def printf(codex):
    codex.ql.arch.regs.write("rip", codex.ql.arch.regs.read("rip") + 5)
    
    


sys.argv.append("examples/tigress/binaries/mix")
sys.argv.append("0")

if __name__ == "__main__":
    
    ql = Qiling(sys.argv[1:], r"/opt/qiling/examples/rootfs/x8664_linux", verbose=QL_VERBOSE.DEBUG)
    debug_level = DebugLevel.DEBUG
    # we disable strict_symbolic_check because we want to run the emulation even if we find a 
    # incorrect symbolic value
    # But in case of debugging, you should enable it and also set symbolic_check_interval to a low value
    c0dex = CodexRebirth(ql, debug_level, strict_symbolic_check=False, symbolic_check = True)
    c0dex.set_register("rsi", 8888)
    c0dex.taint_register("rsi", "num", 8888)
    c0dex.set_emu_start(0x00005555555558D9) # call to SECRET
    c0dex.register_callback(0x00005555555558DD, register_str)
    
    c0dex.register_callback(0x0000555555555952, printf)
    c0dex.register_callback(0x000055555555582C, printf)
    
    
    

   
    c0dex.run_emulation()
    
    print(c0dex.codex_state)
   