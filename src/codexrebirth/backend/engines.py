from qiling.const import QL_ARCH
from typing import Mapping
from superglobals import *
import abc 

class EngineWrapper(abc.ABC):
    
    def get_current_instruction_address(self):
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


class QilingEngine(EngineWrapper):
    
    def __init__(self, ql):
        self.ql = ql

    def get_current_instruction_address(self):
        if self.ql.arch.type == QL_ARCH.X8664:
            return self.ql.arch.regs.rip
        elif self.ql.arch.type == QL_ARCH.X86:
            return self.ql.arch.regs.eip

        raise ValueError("Unknown architecture type")


    def get_currrent_instruction_disass(self):
        pc = self.get_current_instruction_address()
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
            real_value = self.read_memory_int( addr)
            while self.is_mapped(real_value):
                real_value = self.read_memory_int(real_value)
        return real_value
    
    def read_reg(self, regname):
        return self.ql.arch.regs.read(regname)
    
        

    def map_regs() -> Mapping[int, int]:
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