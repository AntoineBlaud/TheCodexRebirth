import random
import os
from capstone.x86_const import *
from capstone.arm_const import *
import time
import gdb
import tempfile

import pwndbg.color
import pwndbg.commands
import pwndbg.gdblib


try:
    import pwndbg.disasm
    import pwndbg.disasm.arm
    import pwndbg.disasm.jump
    import pwndbg.disasm.mips
    import pwndbg.disasm.ppc
    import pwndbg.disasm.riscv
    import pwndbg.disasm.sparc
    import pwndbg.disasm.x86
    import pwndbg.heap
    import pwndbg.lib.regs
except ModuleNotFoundError:
    pass

RUN_TIMEOUT = 15000
DUMP_SIZE = 10

def tohex(val):
      return hex((val + (1 << nbits)) % (1 << nbits))
  
def execute_command(command):
    gdb.execute(command)
    

COND_JUMP_INSTRUCTION = {
    "aarch64": "b",
    "x86-64": "j",
    "arm": "b",
    "i386": "j"
}

JUMP_INSTRUCTION = {
    "aarch64": "b",
    "x86-64": "jmp",
    "arm": "b",
    "i386": "jmp"
}

CALL_INSTRUCTION = {
    "aarch64": "bl",
    "x86-64": "call",
    "arm": "bl",
    "i386": "call"
}

def get_temp_dir(root_filename):
    # Create a temporary directory to store the snapshot
    temp_dir = tempfile.gettempdir()
    # get current binary name
    file_name = os.path.splitext(root_filename)[0]
    temp_dir = os.path.join(temp_dir, file_name)
    # create it
    if not os.path.exists(temp_dir):
        os.mkdir(temp_dir)
        
    return temp_dir

class DisasmContext:
    
    def __init__(self) -> None:
        global nbits
        self.arch = pwndbg.gdblib.arch.current
        self.reg_sets = pwndbg.lib.regs.reg_sets[self.arch]
        self.reg_pc = self.reg_sets.pc
        self.cs = self.get_disassembler(self.ea)
        self.ptr_size = pwndbg.gdblib.arch.ptrsize
        self.max_int_value = 2 ** (self.ptr_size * 8)
        nbits = self.ptr_size * 8
        self.cache_pages = list(pwndbg.gdblib.vmmap.get())
        self.min_vaddr, self.max_vaddr = self.get_min_max_vaddr()
        self._registers = self.reg_sets.gpr + (self.reg_sets.pc, self.reg_sets.stack)
        if self.reg_sets.frame:
            self._registers += (self.reg_sets.frame,)
            
        self.total_mem_read = 0
        
        
    def get_min_max_vaddr(self):
        min_vaddr = 0xffffffffffffffff
        max_vaddr = 0
        for page in self.cache_pages:
            if page.start < min_vaddr:
                min_vaddr = page.start
            if page.end > max_vaddr:
                max_vaddr = page.end
        return min_vaddr, max_vaddr
    
    def get_disassembler(self, pc):
        return pwndbg.disasm.get_disassembler(pc)
    
    @property
    def ea(self):
        return int(gdb.parse_and_eval(f"${self.reg_pc}"))
    
    
    def set_breakpoint(self, ea):
        execute_command(f"break *{tohex(ea)}")
        
        
    def delete_breakpoint(self, ea):
        try:
            execute_command(f"clear *{tohex(ea, self.ptr_size)}")
        except Exception as e:
            pass
        
    def wait_until_stopped(self):
        try:
            while not gdb.selected_thread().is_stopped():
                time.sleep(0.001)
        except AttributeError:
            pass

    def continue_process(self):
        execute_command("continue")
        return self.wait_until_stopped()
        


class Ultimap(gdb.Command):
    """Ultimap command to trace the execution of the program."""
    
    def __init__(self):
        super(Ultimap, self).__init__("ultimap", gdb.COMMAND_USER)
        self.dctx = DisasmContext()
        self.imported_functions = {}
        self.offsets_functions = {}
        print("Ultimap command created")
        print(f"Usage: ultimap <file> <module_base> <timeout>")
        
        
        
        
    def process_line(self, lines):
        for line in lines:
            line = line.strip()
            offset, name = line.split(" ")
            offset = int(offset[2:], 16)
            self.imported_functions[name] = offset
            self.offsets_functions[offset] = name
                
    def invoke(self, arg, from_tty):
        # get first argument
        arg = arg.split()
        file = arg[0]
        module_base = int(arg[1])
        timeout = int(arg[2])
        gdb.execute("delete")
        
        with open(file, "r") as f:
            lines = f.read().splitlines()
            self.process_line(lines)
    
        
        for name, offset in self.imported_functions.items():
            ea = module_base + offset
            self.dctx.set_breakpoint(ea)
            print(f"Breakpoint set at {hex(ea)}")
            
        print(f"Starting to trace for {timeout} seconds")
        start = time.time()
        while time.time() - start < timeout:
            self.dctx.continue_process()
            ea = self.dctx.ea
            offset = ea - module_base
            print(f"Function {self.offsets_functions[offset]} called")
            self.dctx.delete_breakpoint(ea)
            
        
try:   
    Ultimap()
except Exception as e:
    import traceback
    traceback.print_exc()
    print("[ERROR] Please attach gdb to a process before loading the script")