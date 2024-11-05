from typing import Mapping
from superglobals import *
from tenet.util.disasm import *
import abc
from tenet.trace.arch import ArchAMD64, ArchX86, ArchARM, ArchARM64
import binascii


class EngineWrapper(abc.ABC):
    def get_ea(self):
        raise NotImplementedError()

    def get_currrent_instruction_disass(self):
        raise NotImplementedError()

    def get_stack_pointer(self):
        raise NotImplementedError()

    def read_memory_int(self, address):
        raise NotImplementedError()

    def is_mapped(self, address):
        raise NotImplementedError()

    def map_regs(self):
        raise NotImplementedError()

    def read_reg(self, regname):
        raise NotImplementedError()

    def clear(self):
        raise NotImplementedError()

    def clone(self):
        raise NotImplementedError()

    def is_next(self):
        raise NotImplementedError()

    def step(self):
        raise NotImplementedError()


class TextEngine(EngineWrapper):
    def __init__(self, arch, dctx, cs, ks, reader):
        self.dctx = dctx
        self.cs = cs
        self.ks = ks
        self.arch = arch
        self.trace = reader.trace
        self.reader = reader
        self.idx = 0

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

    def is_next(self):
        return self.idx < self.trace.length

    def step(self):
        self.idx += 1

    def get_ea(self):
        return self.trace.get_ip(self.idx)

    def get_currrent_instruction_disass(self):
        ea = self.get_ea()
        return disasm(self.dctx, self.arch, ea)

    def is_mapped(self, address):
        return self.dctx.is_mapped(address)

    def log(self, msg):
        print(f"[TextEngine] {msg}")

    def read_memory_int(self, address, idx=0):

        # disabled because it's not used and to slow
        return 0

        # Must get the correct idx for the memory read
        memory = self.reader.get_memory(address, 8, self.idx)
        if isinstance(self.arch, ArchAMD64) or isinstance(self.arch, ArchX86):
            return int.from_bytes(memory.data, byteorder="little")
        elif isinstance(self.arch, ArchARM) or isinstance(self.arch, ArchARM64):
            return int.from_bytes(memory.data, byteorder="big")

    def read_reg(self, regname):
        regname = regname.upper()
        if regname == "X29":
            regname = "FP"
        if regname == "X30":
            regname = "LR"
        if regname not in self.arch.REGISTERS_MAIN:
            self.log(f"Register {regname} is not a Main register")
            return 0
        try:
            return self.reader.get_register(regname, self.idx)
        except ValueError:
            self.log(f"Register {regname} not found")
            return 0

    def get_stack_pointer(self):
        return self.read_reg(self.arch.SP)

    def clear(self):
        pass

    def clone():
        pass
