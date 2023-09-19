
from qiling import *
from qiling.const import QL_VERBOSE
from superglobals import setglobal
import sys 

setglobal('BINARY_ARCH', 'x64')
from codexrebirth import *

##############################################################################################
# IMPORTANT: address depend of you system, you need to change the address and disable aslr 
# or use qiling base + offset
##############################################################################################


if __name__ == "__main__":
    
    ql = Qiling(sys.argv[1:], r"/", verbose=QL_VERBOSE.DEBUG)
    debug_level = DebugLevel.INFO
    # we disable strict_symbolic_check because we want to run the emulation even if we find a 
    # incorrect symbolic value
    # But in case of debugging, you should enable it and also set symbolic_check_interval to a low value
    c0dex = CodexRebirth(ql, debug_level,  strict_symbolic_check=False, symbolic_check = False)
    c0dex.set_register("rdi", 9888)
    c0dex.taint_register("rdi",  "num", 9888)
    
    # depend of you system, you need to change the address and disable aslr
    c0dex.set_emu_start(0x0000555555556330)
   
    c0dex.run_emulation()
    
    print(c0dex.codex_state)
   
   