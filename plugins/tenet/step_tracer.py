from tenet.util.qt import *
from tenet.util.common import *
from tenet.ui import *
from tenet.integration.api import disassembler
from tenet.util.misc import get_temp_dir
import random
import os
from capstone.x86_const import *
from capstone.arm_const import *




class JHook:
    def __init__(self):
        self.j_next = None
        self.j_target = None
        self.j_addr = None
        self.enabled = True


class Watcher:
    def __init__(self, address):
        self.address = address
        self.is_saved = False
        self.path = None


class StepTracerModel:
    def __init__(self, pctx):
        self.pctx = pctx
        self.isDynamicShellcode = False
        self.runTimeout = 20
        self.resetSegmentInc = 0xFFFFFFFF
        self.dumpSize = 10
        self.maxStepInsideLoop = 2
        self.counter = 0
        self.moduleToTrace = ""
        self.watchers = []
        self.reset()

    def reset(self):
        self.loopAlreadySkipped = {}
        self.currentJumps = {}
        self.loopCounts = {}
        self.breakpoints = {}
        self.seenInstructionsCount = {}
        self.tempDataBuffer = {}
        self.tenetTrace = []

    def add_watcher(self, address):
        self.watchers.append(Watcher(address))

    def update_watcher(self, index, address):
        w = self.watchers[index]
        w.address = address
        
    def init_segment_inf(self):
        if not self.isDynamicShellcode:
            self.resetSegmentInc = 0xFFFFFFFF
        else:
            self.resetSegmentInc = 20

    def on_watcher(self, ea):
        for w in self.watchers:
            hex_addr = hex(w.address)
            hex_ea = hex(ea)
            # get last 2 bytes of ea
            ea_last_bytes = hex_ea[-4:]
            if hex_addr.endswith(ea_last_bytes):
                return w


class StepTracerController(object):
    def __init__(self, pctx):
        self.pctx = pctx
        self.dctx = disassembler[self.pctx]
        self.model = StepTracerModel(self.pctx)
        self.view = StepTracerView(self, self.model)
        self.view.show()
        self.arch = self.pctx.arch
        self.prev_ea = None
        self.cs = self.dctx.get_capstone_md(self.arch)
        self.ks = self.dctx.get_keystone_md(self.arch)

    @property
    def ea(self):
        return self.dctx.get_pc(self.arch)

    def show(self):
        self.view.show()

    def log(self, msg):
        print(f"[StepTracer] {msg}")


    def get_jump_target(self, ea):
        mnemonic = self.dctx.print_insn_mnem(ea)
        if mnemonic is None:
            if random.randint(0, self.model.resetSegmentInc) == 0:
                self.dctx.reset_code_segment(ea, hard=False)
                self.dctx.create_insn(ea)
                mnemonic = self.dctx.print_insn_mnem(ea)
                if mnemonic is None:
                    print("Cannot create instruction at %x" % ea)
                    return None
        j_target_address = None
        if (
            mnemonic.startswith(self.arch.COND_JUMP_INSTRUCTION)
            and mnemonic != self.arch.JUMP_INSTRUCTION
            and not mnemonic.startswith("bic")
        ):
            j_target_address = self.dctx.get_operand_value(ea, 0)
            
        elif mnemonic.startswith("cbz") or mnemonic.startswith("cbnz"):
            j_target_address = self.dctx.get_operand_value(ea, 1)
            
        return j_target_address if j_target_address != 0 else None

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
        w = self.model.on_watcher(self.prev_ea)
        if w is not None:
            w.saved = True
            w.path = self.trace_file
        # self.dctx.take_memory_snapshot()
        # self.log("Memory snapshot taken")
        # add a watcher on the current address
        self.model.add_watcher(self.prev_ea)
        self.model.watchers[-1].is_saved = True
        self.model.watchers[-1].path = self.trace_file
        self.view._refresh()
        # self.dctx.reset_code_segment(self.prev_ea, hard=True)

    def clear(self):
        for bp in self.model.breakpoints.keys():
            self.dctx.delete_breakpoint(bp)

        self.model.breakpoints.clear()
        self.prev_ea = None

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

    def add_trace_entry(self):
        PTR_SIZE = self.arch.POINTER_SIZE
        cacheBuffer = self.model.tempDataBuffer
        dumpSize = self.model.dumpSize

        if len(cacheBuffer) > 200000:
            cacheBuffer.clear()

        def read_memory_and_append_entry(reg_value):
            try:
                if not self.dctx.is_mapped(reg_value):
                    return
                # check value is lower than INT_MAX
                if self.arch.MAX_INT_VALUE < reg_value:
                    return
            except:
                return

            mem_value = self.dctx.read_memory(reg_value, PTR_SIZE)
            if mem_value == cacheBuffer.get(reg_value, None):
                return

            hex_mem_value = "".join([f"{byte:x}" for byte in mem_value])
            hex_mem_value = hex_mem_value.ljust(PTR_SIZE * 2, "0")
            new_entry.append(f"mr={hex(reg_value)}:{hex_mem_value}")
            cacheBuffer[reg_value] = mem_value

        new_entry = []
        for reg in self.arch.REGISTERS_MAIN:
            reg_value = self.dctx.get_reg_value(reg)
            if reg_value == cacheBuffer.get(reg, None):
                continue
            new_entry.append(f"{reg.lower()}={hex(reg_value)}")
            cacheBuffer[reg] = reg_value

        # for each register, read 5 memory values before and after
        for reg in self.arch.REGISTERS_MAIN:
            v = self.dctx.get_reg_value(reg)
            reg_value = v + v % 8
            saved_reg_value = reg_value

            for _ in range(dumpSize):
                read_memory_and_append_entry(reg_value)
                reg_value -= PTR_SIZE

            reg_value = saved_reg_value + PTR_SIZE
            for _ in range(dumpSize):
                read_memory_and_append_entry(reg_value)
                reg_value += PTR_SIZE

        # add memory read for the current instruction
        disasm = self.dctx.disasm(self.ea, self.arch)
        if disasm is not None:
            mem_access = self.compute_mem_access(disasm)
            read_memory_and_append_entry(mem_access)
        self.model.tenetTrace.append(new_entry)

    def save_trace(self):
        trace = [",".join(entry) for entry in self.model.tenetTrace]
        temp_dir = get_temp_dir(self.dctx.get_root_filename())
        trace_file = os.path.join(temp_dir, f"ida_trace_{hex(self.prev_ea)}.tenet")
        with open(trace_file, "w") as f:
            f.write("\n".join(trace))
        self.log(f"Trace saved to {trace_file}")
        return trace_file

    def log_instr_exec(self, new_ea):
        instr = self.dctx.generate_disasm_line(new_ea)
        seg_name = self.dctx.get_segm_name(self.dctx.get_segm(new_ea)).lower()
        line = f"[{seg_name}] {hex(new_ea)} :\t {instr}".ljust(100, " ")
        line += f"# {self.model.seenInstructionsCount[new_ea]}"
        return line

    def finalize_step(self, ea, prev_ea):
        if ea not in self.model.seenInstructionsCount:
            self.model.seenInstructionsCount[ea] = 0
        self.model.seenInstructionsCount[ea] += 1

        # add bp to next instruction, then we continue the process if
        # we are in a library the next instruction
        nmemonic = self.dctx.print_insn_mnem(ea)
        if nmemonic.startswith(self.arch.CALL_INSTRUCTION):
            next_insn = ea + self.dctx.get_item_size(ea)
            self.dctx.set_breakpoint(next_insn)

        # check we are not in a library # TO CHANGE
        mod_name = self.dctx.get_module_name(ea)
        if mod_name != self.model.moduleToTrace.lower():
            self.dctx.continue_process()
            self.log(f"Skipping {mod_name} functions")

        if ea == prev_ea:
            next_insn = ea + self.dctx.get_item_size(ea)
            self.set_breakpoint(next_insn)
            self.delete_breakpoint(ea)
            self.dctx.continue_process()
            self.log(f"Skipping instruction at {hex(ea)}")


    def step_loop(self):
        ea = self.ea
        self.delete_breakpoint(self.ea)
        if random.randint(0, self.model.resetSegmentInc) == 0:
            self.dctx.reset_code_segment(ea, hard=True)
        # Already skipped loop are stored in skipped dict
        # If we are in a skipped loop, we just continue the process
        # until we are stopped by a breakpoint
        if ea in self.model.loopAlreadySkipped:
            self.log(f"Already skipped loop at {hex(ea)}")
            self.dctx.continue_process()
            return

        # Check if the current instruction is a jump (conditional)
        j_target_address = self.get_jump_target(ea)
        if (
            j_target_address is not None
            and ea not in self.model.currentJumps
        ):
            j_next = ea + self.dctx.get_item_size(ea)
            # store current j address, target address and next address
            j = JHook()
            j.j_addr = ea
            j.j_target = j_target_address
            j.j_next = j_next
            self.model.currentJumps[ea] = j
            self.model.loopCounts[ea] = 0
            # set breakpoint on next and target address
            self.set_breakpoint(j_next)
            self.set_breakpoint(j_target_address)
            self.log(
                f"Identified loop at {hex(ea)}, j_target={hex(j_target_address)}, j_next={hex(j_next)}"
            )

        # remove breakpoint if one of the j_next or j_target is reached
        for j in self.model.currentJumps.values():
            if ea == j.j_next:
                self.log(f"Disable j_next {hex(j.j_next)}")
                j.j_next = None
                if j.j_target == None:
                    j.enabled = False

        for j in self.model.currentJumps.values():
            if ea == j.j_target:
                self.log(f"Disable j_target {hex(j.j_target)}")
                j.j_target = None
                if j.j_next == None:
                    j.enabled = False

        # if current address is in jumps and enabled, increment loop counter
        # jumps are enabled while one of the j_next or j_target is not None (not reached)
        if ea in self.model.currentJumps:
            if self.model.currentJumps[ea].enabled:
                self.model.loopCounts[ea] += 1
            # if loop counter is greater than MAX_INSTRUCTIONS, we found a loop
            # we continue the process until we are stopped by a breakpoint
            if self.model.loopCounts[ea] >= self.model.maxStepInsideLoop:
                self.log("Loop found, skipping")
                self.dctx.continue_process()
                self.model.currentJumps.clear()
                self.model.loopAlreadySkipped[ea] = True
                return

        # step into the next instruction
        self.dctx.step_into()
        
    def initialize(self):
        
        self.model.init_segment_inf()
        
        # check moduleToTrace exists
        base = self.dctx.get_module_text_base(self.model.moduleToTrace)
        if not base:
            raise Exception(f"Module {self.model.moduleToTrace} not found")
        
        self.log(f"Module {self.model.moduleToTrace} found at {hex(base)}")
        self.model.tenetTrace.append([f"slide={hex(base)}"])
           
        # continue until we reach a breakpoint
        if self.dctx.is_process_running():
            msg = "Please continue process until we reach a breakpoint before starting StepTracer"
            show_msgbox(msg, "StepTracer - Error")
            raise Exception(msg)
    
        return True
        

    def run(self):
                
        if not self.initialize():
            return
        try:
            self._run()
        finally:
            self.stop()

    def _run(self):
       
        self.clear()
        self.log("Start StepTracer")
        start = time.time()
        # self.set_bp_on_all_functions()
        # check debugged process is running
        while True:
            self.prev_ea = self.ea
            if self.dctx.user_cancelled():
                self.log("User cancelled")
                return

            if time.time() - start > self.model.runTimeout:
                self.log("Timeout")
                return

            if self.model.on_watcher(self.prev_ea):
                self.log("Watcher reached")
                return

            if self.model.counter % 3000 == 0 and self.model.counter != 0:
                self.save_trace()

            self.step_loop()
            new_ea = self.ea


            self.finalize_step(new_ea, self.prev_ea)
            line = self.log_instr_exec(new_ea)
            self.log(line)

            # save the trace step
            self.add_trace_entry()

            percent = int((time.time() - start) * 100 / self.model.runTimeout)
            self.model.counter += 1

            # update ui
            self.dctx.update_ui()
            self.view.update_progress(percent)
