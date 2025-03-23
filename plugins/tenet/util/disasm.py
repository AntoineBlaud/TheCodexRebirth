import logging
from tenet.trace_analysis.arch import ArchAMD64, ArchX86, ArchARM, ArchARM64
from tenet.util.common import *

from capstone import *
from keystone import *
from capstone.x86_const import *
from capstone.arm_const import *

logger = logging.getLogger(f"Tenet.{__name__}")


def _create_capstone_from_arch(arch):
    if isinstance(arch, ArchAMD64):
        return Cs(CS_ARCH_X86, CS_MODE_64)
    elif isinstance(arch, ArchX86):
        return Cs(CS_ARCH_X86, CS_MODE_32)
    elif isinstance(arch, ArchARM):
        return Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    elif isinstance(arch, ArchARM64):
        return Cs(CS_ARCH_ARM64, CS_MODE_ARM)


def _create_keystone_from_arch(arch):
    if isinstance(arch, ArchAMD64):
        return Ks(KS_ARCH_X86, KS_MODE_64)
    elif isinstance(arch, ArchX86):
        return Ks(KS_ARCH_X86, KS_MODE_32)
    elif isinstance(arch, ArchARM):
        return Ks(KS_ARCH_ARM, CS_MODE_THUMB)  # Corrected the mode here.
    elif isinstance(arch, ArchARM64):
        return Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)


def get_capstone_md_from_arch(arch):
    md = _create_capstone_from_arch(arch)
    if md is None:
        return None
    md.detail = True
    return md


def get_keystone_md_from_arch(arch):
    ks = _create_keystone_from_arch(arch)
    if ks is None:
        return None
    ks.detail = True
    return ks


def get_pc(dctx, arch):
    """Get the Program Counter."""
    return dctx.get_reg_value(arch.IP)


def get_register_name(arch, register):
    """Get the Register Name."""
    md = get_capstone_md_from_arch(arch)
    if md is None:
        raise ValueError("Capstone instance not created")

    # We need to check the operand type here as well.
    return md.reg_name(register).upper()


def disasm(dctx, arch, address):
    """Disassemble a raw instruction."""
    md = get_capstone_md_from_arch(arch)
    if md is None:
        raise ValueError("Capstone instance not created")

    raw_insn = bytes(dctx.read_memory(address, 16))
    try:
        insn = next(md.disasm(raw_insn, address))
    except StopIteration:
        return None
    return insn


def compute_mem_access(cinsn, dctx, arch):
    """Compute memory access."""
    mem_access = 0

    md = get_capstone_md_from_arch(arch)
    if md is None:
        raise ValueError("Capstone instance not created")

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

    return mem_access


def get_item_size(dctx, arch, address):
    """Get item size."""
    md = get_capstone_md_from_arch(arch)
    if md is None:
        raise ValueError("Capstone instance not created")

    raw_insn = bytes(dctx.read_memory(address, 16))
    try:
        insn = next(md.disasm(raw_insn, address))
    except StopIteration:
        return 0
    return insn.size


def generate_disasm_line(dctx, arch, address):
    """Generate disassembly line."""
    insn = disasm(dctx, arch, address)
    if insn is None:
        raise ValueError("Disassembled instruction not found")
    return f"{insn.mnemonic} {insn.op_str}"


def get_operand_value(self, insn, op):
    """Get operand value."""
    op = insn.operands[op]
    if op.type in (X86_OP_IMM, ARM_OP_IMM):
        return op.imm

    elif op.type in (X86_OP_REG, ARM_OP_REG):
        logger.warning("Memory operand not supported")
        raise Exception(f"Unsupported operand type {op.type}")

    elif op.type in (X86_OP_MEM, ARM_OP_MEM):
        # Memory operand is unsupported here as well.
        logger.warning("Memory operand not supported")
        raise Exception(f"Unsupported operand type {op.type}")


def get_jump_target(dctx, arch, ea):
    """Get jump target."""
    mnemonic = dctx.print_insn_mnemonic(ea)
    if mnemonic.startswith(arch.COND_JUMP_INSTRUCTION) and not mnemonic.startswith("bic"):
        try:
            j_target_address = dctx.get_operand_value(ea, 0)
            return j_target_address if j_target_address != 0 else None
        except Exception as e:
            pass

    return None
