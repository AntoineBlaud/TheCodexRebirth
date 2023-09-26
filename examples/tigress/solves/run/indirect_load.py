
from qiling import *
from qiling.const import QL_VERBOSE
from superglobals import setglobal
import sys 

setglobal('BINARY_ARCH', 'x64')
from codexrebirth.core import CodexRebirth, DebugLevel


##############################################################################################
# IMPORTANT: address depend of you system, you need to change the address and disable aslr 
# or use qiling base + offset
##############################################################################################


if __name__ == "__main__":
    
    ql = Qiling(sys.argv[1:], r"/", verbose=QL_VERBOSE.DEBUG)
    debug_level = DebugLevel.DEBUG
    c0dex = CodexRebirth(ql, debug_level)
    c0dex.set_register("rdi", 0x5)
    c0dex.taint_register("rdi", "num", 0x5)
    c0dex.set_emu_start(0x000055555555516C)
    c0dex.run_emulation()
    
    print(c0dex.state)
   
