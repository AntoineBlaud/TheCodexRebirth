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
        
class JHook:
    def __init__(self):
        self.j_next = None
        self.j_target = None
        self.j_addr = None
        self.enabled = True

class StepTracerModel:
    def __init__(self):
        self.run_timeout = RUN_TIMEOUT
        self.dump_size = DUMP_SIZE
        self.max_step_inside_loop = 2
        self.counter = 1
        self.module_to_trace = ""
        self.reset()

    def reset(self):
        self.loop_already_skipped = {}
        self.current_jumps = {}
        self.loop_counts = {}
        self.breakpoints = {}
        self.seen_instructions_count = {}
        self.temp_data_buffer = {}
        self.tenet_trace = []
        

class StepTracer(gdb.Command):
    def __init__(self):
        super(StepTracer, self).__init__("step_tracer", gdb.COMMAND_USER)
        self.dctx = DisasmContext()
        self.model = StepTracerModel()
        self.prev_ea = None
        self.cs = self.dctx.get_disassembler(self.ea)

    @property
    def ea(self):
        return self.dctx.ea

    @property
    def arch(self):
        return self.dctx.arch

    def log(self, msg):
        print(f"[StepTracer] {msg}")

    def get_jump_target(self, ea):
        mnemonic = self.dctx.print_insn_mnemonic(ea)
        if (mnemonic.startswith(COND_JUMP_INSTRUCTION[self.arch]) and 
            mnemonic != JUMP_INSTRUCTION[self.arch] and not mnemonic.startswith("bic")):
            j_target_address = self.dctx.get_operand_value(ea, 0)
            return j_target_address if j_target_address != 0 else None
        return None

    def delete_breakpoint(self, ea):
        if ea in self.model.breakpoints:
            del self.model.breakpoints[ea]
            self.dctx.delete_breakpoint(ea)

    def set_breakpoint(self, ea):
        if ea not in self.model.breakpoints:
            self.model.breakpoints[ea] = True
            self.dctx.set_breakpoint(ea)

    def stop(self):
        self.trace_file = self.save_trace()

    def reset_soft(self):
        gdb.execute("delete")
        self.model.breakpoints.clear()
        self.model.temp_data_buffer.clear()
        self.model.loop_already_skipped = {}
        self.model.current_jumps = {}
        self.model.loop_counts = {}

    
    def add_trace_entry(self):
        PTR_SIZE = self.dctx.ptr_size
        cache_buffer = self.model.temp_data_buffer
        dump_size = self.model.dump_size

        
        def batch_read_mem_and_add_entry(reg_value, size):
            try:
                mem_value = self.dctx.read_memory(reg_value, size)
            except Exception as e:
                return
            
            for i in range(0, len(mem_value), 8):
                chunk = mem_value[i:i+8]
                reg_value = reg_value + PTR_SIZE
                hex_mem_value = "".join([f"{byte:x}" for byte in chunk])
                hex_mem_value = hex_mem_value.ljust(PTR_SIZE * 2, "0")
                if cache_buffer.get(reg_value, None) == hex_mem_value:
                    continue
                new_entry.append(f"mr={hex(reg_value)}:{hex_mem_value}")
                cache_buffer[reg_value] = chunk
            
        new_entry = []
        reg_detected = self.dctx.registers()

        for reg in reg_detected:
            reg_value = self.dctx.get_reg_value(reg)
            if reg_value == cache_buffer.get(reg, None):
                continue
            new_entry.append(f"{reg.lower()}={hex(reg_value)}")
            cache_buffer[reg] = reg_value

        for reg in reg_detected:
            v = self.dctx.get_reg_value(reg)
            reg_value = v + v % 8
            saved_reg_value = reg_value

            reg_value = saved_reg_value - PTR_SIZE * dump_size
            batch_read_mem_and_add_entry(reg_value, self.model.dump_size)

            reg_value = saved_reg_value + PTR_SIZE
            batch_read_mem_and_add_entry(reg_value, self.model.dump_size)
 

        insn = self.dctx.get_instruction(self.ea)
        if insn is not None:
            mem_access = self.dctx.compute_mem_access(insn)
            batch_read_mem_and_add_entry(mem_access, PTR_SIZE)
        self.model.tenet_trace.append(new_entry)

    def save_trace(self):
        trace = [",".join(entry) for entry in self.model.tenet_trace]
        temp_dir = get_temp_dir(self.dctx.get_root_filename())
        trace_file = os.path.join(temp_dir, f"ida_trace_{hex(self.prev_ea)}.tenet")
        with open(trace_file, "w") as f:
            f.write("\n".join(trace))
        self.log(f"Trace saved to {trace_file}")
        return trace_file

    def log_instr_exec(self, new_ea):
        instr = self.dctx.generate_disasm_line(new_ea)
        seg_name = self.dctx.get_module_name(new_ea).lower()
        percent = int((time.time() - self.start) * 100 / self.model.run_timeout)
        line = f"{percent}% [{seg_name}] {hex(new_ea)} :\t {instr}".ljust(100, " ")
        
        line += f"# {self.model.seen_instructions_count[new_ea]}"
        return line

    def finalize_step(self, ea, prev_ea):
        if ea not in self.model.seen_instructions_count:
            self.model.seen_instructions_count[ea] = 0
        self.model.seen_instructions_count[ea] += 1

        nmemonic = self.dctx.print_insn_mnemonic(ea)
        if nmemonic.startswith(CALL_INSTRUCTION[self.arch]):
            next_insn = ea + self.dctx.get_item_size(ea)
            self.set_breakpoint(next_insn)

        mod_name = self.dctx.get_module_name(ea)
        if mod_name != self.model.module_to_trace.lower():
            line = self.log_instr_exec(ea)
            self.log(line)
            self.log(f"Skipping library {mod_name}")
            gdb.execute("context")
            self.dctx.continue_process()

        if ea == prev_ea:
            next_insn = ea + self.dctx.get_item_size(ea)
            self.set_breakpoint(next_insn)
            self.delete_breakpoint(ea)
            self.log(f"Skipping instruction at {hex(ea)}")
            self.dctx.continue_process()

    
    def step_loop(self):
        ea = self.ea
        self.delete_breakpoint(ea)
        
        if ea in self.model.loop_already_skipped:
            self.log(f"Already skipped loop at {hex(ea)}")
            self.dctx.continue_process()
            return

        j_target_address = self.get_jump_target(ea)
        if (j_target_address is not None):
            if ea not in self.model.current_jumps:
                j_next = ea + self.dctx.get_item_size(ea)
                j = JHook()
                j.j_addr = ea
                j.j_target = j_target_address
                j.j_next = j_next
                self.model.current_jumps[ea] = j
                self.model.loop_counts[ea] = 0
                self.set_breakpoint(j_next)
                self.set_breakpoint(j_target_address)
                self.log(f"Identified loop at {hex(ea)}, j_target={hex(j_target_address)}, j_next={hex(j_next)}")
            else:
                self.log("ea already in current_jumps")

        for j in self.model.current_jumps.values():
            if ea == j.j_next:
                self.log(f"Disable j_next {hex(j.j_next)}")
                j.j_next = None
                if j.j_target == None:
                    j.enabled = False

        for j in self.model.current_jumps.values():
            if ea == j.j_target:
                self.log(f"Disable j_target {hex(j.j_target)}")
                j.j_target = None
                if j.j_next == None:
                    j.enabled = False

        if ea in self.model.current_jumps:
            if self.model.current_jumps[ea].enabled:
                self.model.loop_counts[ea] += 1
            if self.model.loop_counts[ea] >= self.model.max_step_inside_loop:
                self.log("Loop found, skipping")
                self.dctx.continue_process()
                self.model.current_jumps.clear()
                self.model.loop_already_skipped[ea] = True
                return

        self.dctx.step_into()
        
    def initialize(self):
        gdb.execute("delete")
        gdb.execute("set scheduler-locking on")
        self.model.module_to_trace = self.dctx.get_current_module_name()
        base = self.dctx.get_module_text_base(self.model.module_to_trace)
        if not base:
            raise Exception(f"Module {self.model.module_to_trace} not found")
        
        self.log(f"Module {self.model.module_to_trace} found at {hex(base)}")
        self.model.tenet_trace.append([f"slide={hex(base)}"])
        
        if self.dctx.is_process_running():
            msg = "Please continue process until we reach a breakpoint before starting StepTracer"
            raise Exception(msg)
    
        return True
        

    def invoke(self, arg, from_tty):
        if not self.initialize():
            return
        self.log(f"Module to trace: {self.model.module_to_trace}")
        self.log(f"Timeout: {self.model.run_timeout} seconds")
        self.log(f"Dump size: {self.model.dump_size}")
        self.log(f"Max step inside loop: {self.model.max_step_inside_loop}")
        self.log(f"Root filename: {self.dctx.get_root_filename()}")
        self.log("Set Locking Scheduler on (disable multi-threading)")
        try:
            self._run()
        except Exception as e:
            # show traceback
            import traceback
            traceback.print_exc()
        finally:
            self.stop()
            profile.print_stats()

    
    def _run(self):
        self.log("Start StepTracer")
        self.start = time.time()
        while True:
            self.prev_ea = self.ea
            
            if time.time() - self.start > self.model.run_timeout:
                self.log("Timeout")
                return

            if self.model.counter % 500 == 0:
                self.save_trace()

            self.step_loop()
            new_ea = self.ea

            self.finalize_step(new_ea, self.prev_ea)
            line = self.log_instr_exec(new_ea)
            self.log(line)

            self.add_trace_entry()
            self.model.counter += 1


try:
    StepTracer().invoke("", False)
except Exception as e:
    import traceback
    traceback.print_exc()
    print("[ERROR] Please attach gdb to a process before loading the script")