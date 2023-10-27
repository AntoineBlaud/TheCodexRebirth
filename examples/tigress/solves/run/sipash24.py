
from qiling import *
from qiling.const import QL_VERBOSE
from superglobals import setglobal
import sys 

from codexrebirth.backend import *

##############################################################################################
# IMPORTANT: address depend of you system, you need to change the address and disable aslr 
# or use qiling base + offset
##############################################################################################


if __name__ == "__main__":
    
    ql = Qiling(sys.argv[1:], r"C:/Users/antoi/source/rootfs/x8664_linux", verbose=QL_VERBOSE.DEBUG)
    debug_level = DebugLevel.INFO
    # we disable strict_symbolic_check because we want to run the emulation even if we find a 
    # incorrect symbolic value
    # But in case of debugging, you should enable it and also set symbolic_check_interval to a low value
    c0dex = QilingRunner(ql, debug_level)
    # depend of you system, you need to change the address and disable aslr
    c0dex.set_emu_start(0x0000555555556330)
    c0dex.run_emulation()
    print(c0dex.state)
   
   