from qiling.const import QL_ARCH
from typing import Mapping
from superglobals import *
import abc


class EngineWrapper(abc.ABC):
    def get_ea(self):
        raise NotImplementedError()

    def get_currrent_instruction_disass(self):
        raise NotImplementedError()

    def get_instruction_from_address(self, addr):
        raise NotImplementedError()

    def get_stack_pointer(self):
        raise NotImplementedError()

    def read_memory_int(self, address):
        raise NotImplementedError()

    def is_mapped(self, address):
        raise NotImplementedError()

    def read_while_ptr(self, addr):
        raise NotImplementedError()

    def map_regs(self):
        raise NotImplementedError()

    def read_reg(self, regname):
        raise NotImplementedError()

    def write_reg(self, regname, value):
        raise NotImplementedError()

    def check_instruction_scope(self, text_base, text_end):
        raise NotImplementedError()

    def clear(self):
        raise NotImplementedError()

    def map(self, start, size):
        raise NotImplementedError()

    def write(self, start, data):
        raise NotImplementedError()

    def unmap_all(self):
        raise NotImplementedError()

    def clone(self):
        raise NotImplementedError()


class QilingEngine(EngineWrapper):
    def __init__(self, ql):
        self.ql = ql
        # Configure the disassembler for detailed information
        self.ql.arch.disassembler.detail = True

    def get_ea(self):
        if self.ql.arch.type == QL_ARCH.X8664:
            return self.ql.arch.regs.rip
        elif self.ql.arch.type == QL_ARCH.X86:
            return self.ql.arch.regs.eip

        raise ValueError("Unknown architecture type")

    def get_currrent_instruction_disass(self):
        pc = self.get_ea()
        md = self.ql.arch.disassembler
        buf = self.ql.mem.read(pc, 0x10)
        return next(md.disasm(buf, pc))

    def get_instruction_from_address(self, addr):
        pc = addr
        md = self.ql.arch.disassembler
        buf = self.ql.mem.read(pc, 0x10)
        return next(md.disasm(buf, pc))

    def get_stack_pointer(self):
        if self.ql.arch.type == QL_ARCH.X8664:
            return self.ql.arch.regs.rsp
        elif self.ql.arch.type == QL_ARCH.X86:
            return self.ql.arch.regs.esp
        raise ValueError("Unknown architecture type")

    def read_memory_int(self, address):
        if not self.is_mapped(address):
            return 0
        return int.from_bytes(
            self.ql.mem.read(address, self.ql.arch.bits // 8), byteorder="little"
        )

    def is_mapped(self, address):
        if not isinstance(address, int):
            return False
        for start, end, _, _, _ in self.ql.mem.map_info:
            if start <= address <= end:
                return True
        return False

    def read_while_ptr(self, addr):
        real_value = addr
        if self.is_mapped(addr):
            real_value = self.read_memory_int(addr)
            while self.is_mapped(real_value):
                real_value = self.read_memory_int(real_value)
        return real_value

    def read_reg(self, regname):
        try:
            return self.ql.arch.regs.read(regname)
        except KeyError:
            return 0

    def write_reg(self, regname, value):
        self.ql.arch.regs.write(regname, value)

    def check_instruction_scope(self, text_base, text_end):
        if self.ql.arch.type == QL_ARCH.X8664:
            pc = self.ql.arch.regs.rip
        else:
            pc = self.ql.arch.regs.eip

        if pc < text_base or pc >= text_end:
            return False
        return True

    def clear(self):
        self.ql.clear_hooks()
        self.ql.clear_ql_hooks()

    def map(self, start, size):
        self.ql.mem.map(start, size)

    def write(self, start, data):
        self.ql.mem.write(start, data)

    def unmap_all(self):
        self.ql.mem.unmap_all()
        self.ql.mem.map_info = []

    def map_regs(self) -> Mapping[int, int]:
        """Map Capstone x86 regs definitions to Unicorn's."""

        from capstone import x86_const as cs_x86_const
        from unicorn import x86_const as uc_x86_const

        def __canonicalized_mapping(module, prefix: str) -> Mapping[str, int]:
            return dict(
                (k[len(prefix) :], getattr(module, k))
                for k in dir(module)
                if k.startswith(prefix)
            )

        cs_x86_regs = __canonicalized_mapping(cs_x86_const, "X86_REG")
        uc_x86_regs = __canonicalized_mapping(uc_x86_const, "UC_X86_REG")

        return dict(
            (cs_x86_regs[k], uc_x86_regs[k]) for k in cs_x86_regs if k in uc_x86_regs
        )
