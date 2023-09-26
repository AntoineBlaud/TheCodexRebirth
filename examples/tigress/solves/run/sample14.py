
from qiling import *
from qiling.const import QL_VERBOSE
from superglobals import setglobal
import sys 

setglobal('BINARY_ARCH', 'x64')
from codexrebirth.core import *

##############################################################################################
# IMPORTANT: address depend of you system, you need to change the address and disable aslr 
# or use qiling base + offset
##############################################################################################

def register(codex):
    # (char *) is converted to (long *)
    # so we give long value to our memory
    value = "000000001111111122222222333333334444444455555555666666666"
    rbp = codex.get_register("rbp")
    addr = rbp - 0x1000
    # set rdi to rbp
    codex.set_register("rdi", addr)
    
    for i in range(0, len(value), 8):
        # get long value from string
        long_value = int(value[i:i+8], 16)
        c0dex.taint_memory(addr,  f"num{i}", long_value)
        c0dex.set_memory(addr, long_value.to_bytes(8, byteorder='little'))
        addr += 8
        

        
if __name__ == "__main__":
    
    ql = Qiling(sys.argv[1:], r"/", verbose=QL_VERBOSE.DEBUG)
    debug_level = DebugLevel.DEBUG
    # we disable strict_symbolic_check because we want to run the emulation even if we find a 
    # incorrect symbolic value
    # But in case of debugging, you should enable it and also set symbolic_check_interval to a low value
    c0dex = CodexRebirth(ql, debug_level,  strict_symbolic_check=False)
    c0dex.set_register("rdi", 0xeeefffff)
    c0dex.taint_register("rdi",  "num", 0xeeefffff)
    
    # depend of you system, you need to change the address and disable aslr
    c0dex.set_emu_start(0x0000555555556652)
    c0dex.register_callback(0x000555555556656, register)
   
    c0dex.run_emulation()
    
    print(c0dex.state)
   
   