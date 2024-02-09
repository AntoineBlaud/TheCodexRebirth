from typing import Mapping
from superglobals import *
import abc
from tenet.trace.arch import ArchAMD64, ArchX86, ArchARM, ArchARM64

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


class TextEngine(EngineWrapper):
    def __init__(self, arch, cs, ks):
        self.cs = cs
        self.ks = ks
        self.arch = arch
        
    def map_regs(self) -> Mapping[int, int]:
        """Map Capstone x86 regs definitions to Unicorn's."""

        from capstone import x86_const as cs_x86_const
        from capstone import arm_const as cs_arm_const
        from unicorn import x86_const as uc_x86_const
        from unicorn import arm_const as uc_arm_const
        

        def __canonicalized_mapping(module, prefix: str) -> Mapping[str, int]:
            return dict((k[len(prefix) :], getattr(module, k)) for k in dir(module) if k.startswith(prefix))

    
        cs_x86_regs = __canonicalized_mapping(cs_x86_const, "X86_REG")
        uc_x86_regs = __canonicalized_mapping(uc_x86_const, "UC_X86_REG")
        cs_arm_regs = __canonicalized_mapping(cs_arm_const, "ARM_REG")
        uc_arm_regs = __canonicalized_mapping(uc_arm_const, "UC_ARM_REG")
        
        if isinstance(self.arch, ArchAMD64) or isinstance(self.arch, ArchX86):
            return dict((cs_x86_regs[k], uc_x86_regs[k]) for k in cs_x86_regs if k in uc_x86_regs)
        elif isinstance(self.arch, ArchARM) or isinstance(self.arch, ArchARM64):
            return dict((cs_arm_regs[k], uc_arm_regs[k]) for k in cs_arm_regs if k in uc_arm_regs)
        raise ValueError("Unknown architecture type")
        
