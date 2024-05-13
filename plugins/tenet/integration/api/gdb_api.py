from __future__ import annotations
import os
from capstone.x86_const import *
from capstone.arm_const import *
import time
import gdb
import os
import time
import pathlib
import pwndbg
from tenet.util.disasm import compute_mem_access
from tenet.util.misc import tohex


def execute_command(cmd):
    gdb.execute(cmd)


class GDBContextAPI:

    def __init__(self) -> None:
        self.arch = pwndbg.gdblib.arch.current
        self.reg_sets = pwndbg.lib.regs.reg_sets[self.arch]
        self.reg_pc = self.reg_sets.pc
        self.cs = self.get_disassembler(self.get_reg_value(self.reg_pc))
        self.ptr_size = pwndbg.gdblib.arch.ptrsize
        self.max_int_value = 2 ** (self.ptr_size * 8)
        self.cache_pages = list(pwndbg.gdblib.vmmap.get())
        self.min_vaddr, self.max_vaddr = self.get_min_max_vaddr()
        self._registers = self.reg_sets.gpr + (self.reg_sets.pc, self.reg_sets.stack)
        if self.reg_sets.frame:
            self._registers += (self.reg_sets.frame,)

        self.total_mem_read = 0

    def get_min_max_vaddr(self):
        min_vaddr = 0xFFFFFFFFFFFFFFFF
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
        return int(gdb.parse_and_eval(f"${reg.lower()}"))

    def read_memory(self, ea, size):
        self.total_mem_read += 1
        return pwndbg.gdblib.memory.read(ea, size)

    def get_instruction(self, ea):
        return next(self.cs.disasm(self.read_memory(ea, 0x10), ea))

    def print_insn_mnemonic(self, ea):
        insn = self.get_instruction(ea)
        return insn.mnemonic

    def get_operand_value(self, ea, op):
        insn = self.get_instruction(ea)
        op = insn.operands[op]
        if op.type in (X86_OP_IMM, ARM_OP_IMM):
            return op.imm

        if op.type in (X86_OP_REG, ARM_OP_REG):
            return self.get_reg_value(self.cs.reg_name(op.reg))

        elif op.type in (X86_OP_MEM, ARM_OP_MEM):
            return compute_mem_access(insn, self, self.arch)

        else:
            return 0

    def delete_breakpoint(self, ea):
        try:
            execute_command(f"clear *{tohex(ea, self.ptr_size)}")
        except Exception as e:
            pass

    def set_breakpoint(self, ea):
        execute_command(f"break *{tohex(ea, self.ptr_size)}")

    def delete(self):
        execute_command("delete")

    def get_item_size(self, ea):
        # return size of the instruction
        return self.get_instruction(ea).size

    def wait_until_stopped(self):
        try:
            while not gdb.selected_thread().is_stopped():
                time.sleep(0.001)
        except AttributeError:
            pass

    def step_into(self):
        execute_command("stepi")
        return self.wait_until_stopped()

    def continue_process(self):
        execute_command("continue")
        return self.wait_until_stopped()

    def get_root_filename_dir(self):
        # return current directory
        return str(pathlib.Path().resolve())

    def get_function_name_at(self, ea):
        return gdb.execute(f"info symbol {tohex(ea, self.ptr_size)}", to_string=True).split(" ")[0]

    def is_process_running(self):
        try:
            return not gdb.selected_thread().is_stopped()
        except AttributeError:
            return False

    def get_segm_name(self, ea):
        pages = self.cache_pages
        for page in pages:
            if page.start <= ea <= page.end:
                return os.path.basename(str(page.objfile)).lower()

    def get_module_base(self, ea):
        pages = self.cache_pages
        for page in pages:
            if page.start <= ea <= page.end:
                if not page.execute:
                    self.log("[WARNING] Page is not executable")
                return page.start

    def get_module_base_by_name(self, name):
        pages = self.cache_pages
        for page in pages:
            if name in str(page.objfile).lower():
                return page.start

    def get_module_end(self, ea):
        pages = self.cache_pages
        for page in pages:
            if page.start <= ea <= page.end:
                if not page.execute:
                    self.log("[WARNING] Page is not executable")
                return page.end

    def get_root_filename(self):
        f_name = gdb.current_progspace().filename
        if f_name is None:
            return "unknown"
        return os.path.basename(f_name)

    def generate_disasm_line(self, ea):
        insn = self.get_instruction(ea)
        try:
            return f"{insn.mnemonic} {insn.op_str}"
        except AttributeError:
            return ""

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

    def get_pc(self, arch):
        return self.get_reg_value(arch.IP)
