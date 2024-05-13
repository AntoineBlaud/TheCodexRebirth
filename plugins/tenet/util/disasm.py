from tenet.trace.arch import ArchAMD64, ArchX86, ArchARM, ArchARM64
from capstone import *
from keystone import *
from capstone.x86_const import *
from capstone.arm_const import *
from tenet.util.common import *
import logging

logger = logging.getLogger(f"Tenet.{__name__}")


def get_capstone_md(arch):
    md = None
    if isinstance(arch, ArchAMD64):
        md = Cs(CS_ARCH_X86, CS_MODE_64)
    elif isinstance(arch, ArchX86):
        md = Cs(CS_ARCH_X86, CS_MODE_32)
    elif isinstance(arch, ArchARM):
        md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    elif isinstance(arch, ArchARM64):
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

    if md is None:
        return None
    md.detail = True
    return md


def get_keystone_md(arch):
    ks = None
    if isinstance(arch, ArchAMD64):
        ks = Ks(KS_ARCH_X86, KS_MODE_64)
    elif isinstance(arch, ArchX86):
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
    elif isinstance(arch, ArchARM):
        ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)
    elif isinstance(arch, ArchARM64):
        ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
    if ks is None:
        return None
    ks.detail = True
    return ks


def get_pc(dctx, arch):
    return dctx.get_reg_value(arch.IP)


def get_register_name(arch, register):
    md = get_capstone_md(arch)
    return md.reg_name(register).upper()


def disasm(dctx, arch, address):
    md = get_capstone_md(arch)
    raw_insn = bytes(dctx.read_memory(address, 16))
    try:
        insn = next(md.disasm(raw_insn, address))
    except StopIteration:
        return None
    return insn


def compute_mem_access(cinsn, dctx, arch):
    mem_access = 0
    md = get_capstone_md(arch)
    try:
        for op in cinsn.operands:
            if op.type in (X86_OP_MEM, ARM_OP_MEM):
                base = md.reg_name(op.mem.base)
                index = md.reg_name(op.mem.index)
                mem_access += dctx.get_reg_value(base) if base != 0 else 0
                mem_access += dctx.get_reg_value(index) if op.mem.index != 0 else 0
                mem_access += op.mem.disp
                mem_access *= op.mem.scale if op.mem.scale > 1 else 1
            elif op.type == X86_OP_IMM:
                # Handle immediate value
                mem_access += op.imm

    except Exception as e:
        print(e)
        return 0
    return mem_access


def get_item_size(dctx, arch, address):
    md = get_capstone_md(arch)
    raw_insn = bytes(dctx.read_memory(address, 16))
    try:
        insn = next(md.disasm(raw_insn, address))
    except StopIteration:
        return 0
    return insn.size


def generate_disasm_line(dctx, arch, address):
    insn = disasm(dctx, arch, address)
    return f"{insn.mnemonic} {insn.op_str}"


def get_operand_value(self, insn, op):
    op = insn.operands[op]
    if op.type in (X86_OP_IMM, ARM_OP_IMM):
        return op.imm

    if op.type in (X86_OP_REG, ARM_OP_REG):
        return self.get_reg_value(self.cs.reg_name(op.reg))

    if op.type in (X86_OP_MEM, ARM_OP_MEM):
        logger.warning("Memory operand not supported")
        raise Exception(f"Unsupported operand type {op.type}")
