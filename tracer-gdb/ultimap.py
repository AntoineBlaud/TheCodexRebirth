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
import line_profiler
profile = line_profiler.LineProfiler()


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
        self.arch = pwndbg.gdblib.arch.current
        self.reg_sets = pwndbg.lib.regs.reg_sets[self.arch]
        self.reg_pc = self.reg_sets.pc
        self.cs = self.get_disassembler(self.ea)
        self.ptr_size = pwndbg.gdblib.arch.ptrsize
        self.max_int_value = 2 ** (self.ptr_size * 8)
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
    
    def registers(self):
        return self._registers
    
    def get_reg_value(self, reg):
        return int(gdb.parse_and_eval(f"${reg}"))
    
    @property
    def ea(self):
        return int(gdb.parse_and_eval(f"${self.reg_pc}"))
    
    
    def read_memory(self, ea, size):
        self.total_mem_read += 1
        return pwndbg.gdblib.memory.read(ea, size)
    
    def get_instruction(self, ea):
        return next(self.cs.disasm(self.read_memory(ea, 10), ea))
    
    def print_insn_mnemonic(self, ea):
        insn = self.get_instruction(ea)
        return insn.mnemonic
    
    
    def get_operand_value(self, ea, op):
        insn =  self.get_instruction(ea)
        op = insn.operands[op]
        if op.type in (X86_OP_IMM, ARM_OP_IMM):
            return op.imm
        
        if op.type in (X86_OP_REG, ARM_OP_REG):
            return self.get_reg_value(self.cs.reg_name(op.reg))
        
        else:
            raise Exception(f"Unsupported operand type {op.type}")
        
    def compute_mem_access(self, cinsn):
        mem_access = 0
        try:
            for op in cinsn.operands:
                if op.type in (X86_OP_MEM, ARM_OP_MEM):
                    base = self.cs.reg_name(op.mem.base)
                    index = self.cs.reg_name(op.mem.index)
                    mem_access += self.dctx.get_reg_value(base) if base != 0 else 0
                    mem_access += (
                        self.dctx.get_reg_value(index) if op.mem.index != 0 else 0
                    )
                    mem_access += op.mem.disp
                    mem_access *= op.mem.scale if op.mem.scale > 1 else 1

        except Exception as e:
            return 0
        return mem_access
        
    def delete_breakpoint(self, ea):
        try:
            gdb.execute(f"clear *{hex(ea)}")
        except Exception as e:
            pass
        
    def set_breakpoint(self, ea):
        gdb.execute(f"break *{hex(ea)}")
        
    def get_item_size(self, ea):
        # return size of the instruction
        return self.get_instruction(ea).size
    
    def wait_until_stopped(self):
        while not gdb.selected_thread().is_stopped():
            time.sleep(0.001)
    
    def step_into(self):
        gdb.execute("stepi")
        return self.wait_until_stopped()
        
    def continue_process(self):
        gdb.execute("continue")
        return self.wait_until_stopped()
        
    def is_process_running(self):
        return not gdb.selected_thread().is_stopped()
    
    def get_module_name(self, ea):
        pages = self.cache_pages
        for page in pages:
            if page.start <= ea <= page.end:
                return os.path.basename(str(page.objfile)).lower()
            
    def get_current_module_name(self):
        return self.get_module_name(self.ea)
               
    def get_module_text_base(self, module_name):
        pages = self.cache_pages
        for page in pages:
            print(page.objfile)
            if os.path.basename(str(page.objfile)).lower() == module_name:
                if page.execute:
                    return page.start
                
    def get_root_filename(self):
        f_name = gdb.current_progspace().filename
        if not f_name:
            return "unknown"
        
    def generate_disasm_line(self, ea):
        insn = self.get_instruction(ea)
        return f"{insn.mnemonic} {insn.op_str}"
    
    def is_mapped(self, ea):
        pages = self.cache_pages
        if ea < self.min_vaddr or ea > self.max_vaddr:
            return False
        for page in pages:
            if page.start <= ea <= page.end:
                # place the page at the top of the cache
                pages.remove(page)
                pages.insert(0, page)
                return True
        return False
    
    
class Ultimap(gdb.Command):
    """Ultimap command to trace the execution of the program."""
    
    def __init__(self):
        super(Ultimap, self).__init__("ultimap", gdb.COMMAND_USER)
        self.dctx = DisasmContext()
        self.arch = self.dctx.arch
        self.cs = self.dctx.get_disassembler(None)
        self.imported_functions = {}
        self.offsets_functions = {}
        print("Ultimap command created")
        print(f"Usage: ultimap <file> <module> <timeout>")
        
        
        
        
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
        mod = arg[1]
        timeout = int(arg[2])
        gdb.execute("delete")
        
        with open(file, "r") as f:
            lines = f.read().splitlines()
            self.process_line(lines)
        
        # get module base
        module_base = self.dctx.get_module_text_base(mod)
        if not module_base:
            print(f"Module {mod} not found")
            return
        
        for name, offset in self.imported_functions.items():
            ea = module_base + offset
            self.dctx.set_breakpoint(ea)
            print(f"Breakpoint set at {hex(ea)}")
            
        print(f"Starting to trace {mod} for {timeout} seconds")
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