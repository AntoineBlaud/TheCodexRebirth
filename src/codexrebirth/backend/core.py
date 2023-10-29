#########################################################
# Author: @d0raken - Antoine Blaud
# Date: 2023-09-18
# CodexRebirth is a symbolic execution engine based on Qiling
# It is used to emulate a binary and to extract the symbolic execution trace
#########################################################


from capstone.x86_const import X86_OP_MEM, X86_OP_REG, X86_OP_IMM
from capstone import *
from unicorn.unicorn_const import UC_MEM_READ, UC_MEM_WRITE
from unicorn import unicorn
from qiling import Qiling
from qiling.const import QL_ARCH
from keystone import *
from superglobals import *

from codexrebirth.util.log import log
from codexrebirth.util.color import Color, ANSIColors
from codexrebirth.util.exceptions import SetupError, UserStoppedExecution


from codexrebirth.backend.instruction import (
    Instruction,
    InstructionSet
)
from codexrebirth.backend.trace import (
    Trace,
    TraceEntry
)

from codexrebirth.backend.value import (
    SymValue,
    RealValue,
    ASymValue,
    SymRegister,
    SymMemory
)
from codexrebirth.util.ustring import (
    create_name_from_addr,
)
from codexrebirth.util.misc import (
    check_memory_access
)
from codexrebirth.util.counter import alt_count

from codexrebirth.backend.engines import (
    QilingEngine
)
from codexrebirth.backend.datastore import DataStoreManager
from z3 import (
    set_option,
    BitVec
)
import sys
import time
import re
import contextlib
import itertools
import textwrap
import uuid
import traceback
import line_profiler
import atexit
profile = line_profiler.LineProfiler()

__all__ = ["DebugLevel", "QilingRunner"]


# Set z3 options
set_option(rational_to_decimal=True)
set_option(
    max_args=0xFFFF,
    max_lines=0xFFFF,
    max_depth=0xFFFF,
    max_visited=0xFFFF,
)

class DebugLevel:
    ERROR = 0
    INFO = 1
    DEBUG = 2


BAD_OPERANDS_X86_64 =  [".*pl", ".*il", ".*z", ".*h"]
SUPPORTED_INSTRUCTIONS_X86_64 = [".?mov.*", "lea", "add","sub","xor","and","or",
                                 "imul","shl","shr","sar","cdq","rol","ror","mul",
                                 "not","cmp","test", "push","pop", "sete", "cdq"]
INSN_EXECUTED_COUNT = alt_count()
VAR_COUNTER = alt_count()

rax = SymRegister("rax", 63, 0)
rcx = SymRegister("rcx", 63, 0)
rdx = SymRegister("rdx", 63, 0)
rbx = SymRegister("rbx", 63, 0)
rbp = SymRegister("rbp", 63, 0)
rsi = SymRegister("rsi", 63, 0)
rdi = SymRegister("rdi", 63, 0)
rsp = SymRegister("rsp", 63, 0)
r8 = SymRegister("r8", 63, 0)
r9 = SymRegister("r9", 63, 0)
r10 = SymRegister("r10", 63, 0)
r11 = SymRegister("r11", 63, 0)
r12 = SymRegister("r12", 63, 0)
r13 = SymRegister("r13", 63, 0)
r14 = SymRegister("r14", 63, 0)
r15 = SymRegister("r15", 63, 0)
eax = SymRegister("eax", 31, 0, rax)
ecx = SymRegister("ecx", 31, 0, rcx)
edx = SymRegister("edx", 31, 0, rdx)
ebx = SymRegister("ebx", 31, 0, rbx)
ebp = SymRegister("ebp", 31, 0, rbp)
esi = SymRegister("esi", 31, 0, rsi)
edi = SymRegister("edi", 31, 0, rdi)
esp = SymRegister("esp", 31, 0, rsp)
r8d = SymRegister("r8d", 31, 0, r8)
r9d = SymRegister("r9d", 31, 0, r9)
r10d = SymRegister("r10d", 31, 0, r10)
r11d = SymRegister("r11d", 31, 0, r11)
r12d = SymRegister("r12d", 31, 0, r12)
r13d = SymRegister("r13d", 31, 0, r13)
r14d = SymRegister("r14d", 31, 0, r14)
r15d = SymRegister("r15d", 31, 0, r15)
ax = SymRegister("ax", 15, 0, eax)
cx = SymRegister("cx", 15, 0, ecx)
dx = SymRegister("dx", 15, 0, edx)
bx = SymRegister("bx", 15, 0, ebx)
bp = SymRegister("bp", 15, 0, ebp)
si = SymRegister("si", 15, 0, esi)
di = SymRegister("di", 15, 0, edi)
r8w = SymRegister("r8w", 15, 0, r8d)
r9w = SymRegister("r9w", 15, 0, r9d)
r10w = SymRegister("r10w", 15, 0, r10d)
r11w = SymRegister("r11w", 15, 0, r11d)
r12w = SymRegister("r12w", 15, 0, r12d)
r13w = SymRegister("r13w", 15, 0, r13d)
r14w = SymRegister("r14w", 15, 0, r14d)
r15w = SymRegister("r15w", 15, 0, r15d)
sp = SymRegister("sp", 15, 0, esp)
al = SymRegister("al", 7, 0, ax)
cl = SymRegister("cl", 7, 0, cx)
dl = SymRegister("dl", 7, 0, dx)
bl = SymRegister("bl", 7, 0, bx)
bpl = SymRegister("bpl", 7, 0, bp)
sil = SymRegister("sil", 7, 0, si)
dil = SymRegister("dil", 7, 0, di)
spl = SymRegister("spl", 7, 0, sp)
r8b = SymRegister("r8b", 7, 0, r8w)
r9b = SymRegister("r9b", 7, 0, r9w)
r10b = SymRegister("r10b", 7, 0, r10w)
r11b = SymRegister("r11b", 7, 0, r11w)
r12b = SymRegister("r12b", 7, 0, r12w)
r13b = SymRegister("r13b", 7, 0, r13w)
r14b = SymRegister("r14b", 7, 0, r14w)
r15b = SymRegister("r15b", 7, 0, r15w)
ah = SymRegister("ah", 15, 8, ax)
ch = SymRegister("ch", 15, 8, cx)
dh = SymRegister("dh", 15, 8, dx)
bh = SymRegister("bh", 15, 8, bx)
rip = SymRegister("rip", 63, 0)
eip = SymRegister("eip", 31, 0, rip)



SymRegisterFactory = {
    "ah": [rax, eax, ax, ah, al],
    "al": [rax, eax, ax, ah, al],
    "ax": [rax, eax, ax, ah, al],
    "bh": [rbx, ebx, bx, bh, bl],
    "bl": [rbx, ebx, bx, bh, bl],
    "bp": [rbp, ebp, bp, bpl],
    "bpl": [rbp, ebp, bp, bpl],
    "bx": [rbx, ebx, bx, bh, bl],
    "ch": [rcx, ecx, cx, ch, cl],
    "cl": [rcx, ecx, cx, ch, cl],
    "cx": [rcx, ecx, cx, ch, cl],
    "dh": [rdx, edx, dx, dh, dl],
    "di": [rdi, edi, di, dil],
    "dil": [rdi, edi, di, dil],
    "dl": [rdx, edx, dx, dh, dl],
    "dx": [rdx, edx, dx, dh, dl],
    "eax": [rax, eax, ax, ah, al],
    "ebp": [rbp, ebp, bp, bpl],
    "ebx": [rbx, ebx, bx, bh, bl],
    "ecx": [rcx, ecx, cx, ch, cl],
    "edi": [rdi, edi, di, dil],
    "edx": [rdx, edx, dx, dh, dl],
    "esi": [rsi, esi, si, sil],
    "r10": [r10, r10d, r10w, r10b],
    "r10b": [r10, r10d, r10w, r10b],
    "r10d": [r10, r10d, r10w, r10b],
    "r10w": [r10, r10d, r10w, r10b],
    "r11": [r11, r11d, r11w, r11b],
    "r11b": [r11, r11d, r11w, r11b],
    "r11d": [r11, r11d, r11w, r11b],
    "r11w": [r11, r11d, r11w, r11b],
    "r12": [r12, r12d, r12w, r12b],
    "r12b": [r12, r12d, r12w, r12b],
    "r12d": [r12, r12d, r12w, r12b],
    "r12w": [r12, r12d, r12w, r12b],
    "r13": [r13, r13d, r13w, r13b],
    "r13b": [r13, r13d, r13w, r13b],
    "r13d": [r13, r13d, r13w, r13b],
    "r13w": [r13, r13d, r13w, r13b],
    "r14": [r14, r14d, r14w, r14b],
    "r14b": [r14, r14d, r14w, r14b],
    "r14d": [r14, r14d, r14w, r14b],
    "r14w": [r14, r14d, r14w, r14b],
    "r15": [r15, r15d, r15w, r15b],
    "r15b": [r15, r15d, r15w, r15b],
    "r15d": [r15, r15d, r15w, r15b],
    "r15w": [r15, r15d, r15w, r15b],
    "r8": [r8, r8d, r8w, r8b],
    "r8b": [r8, r8d, r8w, r8b],
    "r8d": [r8, r8d, r8w, r8b],
    "r8w": [r8, r8d, r8w, r8b],
    "r9": [r9, r9d, r9w, r9b],
    "r9b": [r9, r9d, r9w, r9b],
    "r9d": [r9, r9d, r9w, r9b],
    "r9w": [r9, r9d, r9w, r9b],
    "rax": [rax, eax, ax, ah, al],
    "rbp": [rbp, ebp, bp, bpl],
    "rbx": [rbx, ebx, bx, bh, bl],
    "rcx": [rcx, ecx, cx, ch, cl],
    "rdi": [rdi, edi, di, dil],
    "rdx": [rdx, edx, dx, dh, dl],
    "rsi": [rsi, esi, si, sil],
    "si": [rsi, esi, si, sil],
    "sil": [rsi, esi, si, sil],
    "sp": [rsp, esp, sp, spl],
    "spl": [rsp, esp, sp, spl],
    "rsp": [rsp, esp, sp, spl],
    "esp": [rsp, esp, sp, spl],
    "rip": [rip, eip],
    "eip": [rip, eip]
}


class TaintedVariableState(dict):
    def __init__(self):
        super().__init__()

    def __contains__(self, key_object: object) -> bool:
        # Check if a key_object (possibly processed) exists in the dictionary
        if isinstance(key_object, int):
            key_object =  "mem_" + hex(key_object)
        return super().__contains__(key_object)
    
    def __setitem__(self, key, value):
            # Set an item in the dictionary after processing the key
        processed_key = create_name_from_addr(key)
        super().__setitem__(processed_key, value)

    def __getitem__(self, key):
        # Get an item from the dictionary after processing the key
        processed_key = create_name_from_addr(key)
        return super().__getitem__(processed_key)

    
    def create_sym_reg(self, name) -> SymRegister:
        global INSN_EXECUTED_COUNT, SymRegisterFactory
        # Create a new symbolic register and propagate the value to its parts 
        # (e.g., 'ah' to ['rax', 'eax', 'ax', 'ah', 'al'])
        for reg in SymRegisterFactory[name]:
            self[reg.name] = reg.reset()
            self[reg.name].id = INSN_EXECUTED_COUNT.current
        return self[name]


    def create_sym_mem(self, address, value=None):
        global INSN_EXECUTED_COUNT
        # Create a new symbolic memory object
        name = create_name_from_addr(address)
        self[name] = SymMemory(name, value)
        self[name].id = INSN_EXECUTED_COUNT
        return self[name]

    def del_sym_var(self, name):
        # Delete a symbolic variable, handling register parts and 
        # individual variables
        name = create_name_from_addr(name)
            
        if name in self:
            if isinstance(self[name], SymRegister):
                for reg in SymRegisterFactory[name]:
                    try:
                        del self[reg.name]
                    except KeyError:
                        pass
            else:
                del self[name]

    def __repr__(self) -> str:
        pass
    
    def clone(self):
        clone = TaintedVariableState()
        for key, value in self.items():
            clone[key] = value.clone()
        return clone
    

class OperationEngineX86_64:
    
    def __init__(self, cs, engine, Insn, insn, mem_access, symbolic_state):
        self.cs = cs
        self.Insn = Insn
        self.insn = insn
        self.mem_access = mem_access
        self.symbolic_state = symbolic_state
        self.engine = engine
        self.tainted_var_name = self.get_tainted_var_name(Insn, mem_access)
                
    
    def get_tainted_var_name(self, Insn: Instruction, mem_access: int):
        return mem_access if Insn.op1.type == X86_OP_MEM else self.cs.reg_name(Insn.op1.reg)

    
    def _add(self, Insn, symbolic_state, **kwargs):
        return symbolic_state[self.tainted_var_name].update(Insn.v_op1 + Insn.v_op2, **kwargs)

    def _imul(self, Insn, symbolic_state, **kwargs):
        if Insn.v_op3 is not None:
            return symbolic_state[self.tainted_var_name].update(Insn.v_op2 * Insn.v_op3, **kwargs)
        if Insn.v_op2 is not None:
            return symbolic_state[self.tainted_var_name].update(Insn.v_op1 * Insn.v_op2, **kwargs)
        else:
            if "rax" in symbolic_state:
                return symbolic_state["rax"].update((symbolic_state["rax"] * Insn.v_op1))

    def _sub(self, Insn, symbolic_state, **kwargs):
        return symbolic_state[self.tainted_var_name].update(Insn.v_op1 - Insn.v_op2, **kwargs)

    def _xor(self, Insn, symbolic_state, **kwargs):
        return symbolic_state[self.tainted_var_name].update(Insn.v_op1 ^ Insn.v_op2, **kwargs)

    def _and(self, Insn, symbolic_state, **kwargs):
        return symbolic_state[self.tainted_var_name].update(Insn.v_op1 & Insn.v_op2, **kwargs)

    def _or(self, Insn, symbolic_state, **kwargs):
        return symbolic_state[self.tainted_var_name].update(Insn.v_op1 | Insn.v_op2, **kwargs)

    def _shl(self, Insn, symbolic_state, **kwargs):
        return symbolic_state[self.tainted_var_name].update(Insn.v_op1 << Insn.v_op2, **kwargs)

    def _shr(self, Insn, symbolic_state, **kwargs):
        return symbolic_state[self.tainted_var_name].update(Insn.v_op1 >> Insn.v_op2, **kwargs)

    def _ror(self, Insn, symbolic_state, **kwargs):
        return symbolic_state[self.tainted_var_name].update(Insn.v_op1.ror(Insn.v_op2, **kwargs))
    
    def _rol(self, Insn, symbolic_state, **kwargs):
        return symbolic_state[self.tainted_var_name].update(Insn.v_op1.rol(Insn.v_op2, **kwargs))

    def _mul(self, Insn, symbolic_state, **kwargs):
        return symbolic_state["rax"].update(symbolic_state[self.tainted_var_name] * Insn.v_op1, **kwargs)

    def _not(self, Insn, symbolic_state, **kwargs):
        return symbolic_state[self.tainted_var_name].update(Insn.v_op1._not(), **kwargs)
        
    def _cdq(self, Insn, symbolic_state, **kwargs):
        symbolic_state.del_sym_var("rdx")
        return None

    def _push(self, Insn, symbolic_state, **kwargs):
        stack_pointer = self.engine.get_stack_pointer()
        symbolic_state[stack_pointer] = Insn.v_op1.clone()

    def _pop(self, Insn, symbolic_state, **kwargs):
        stack_pointer = self.engine.get_stack_pointer()
        reg = self.cs.reg_name(Insn.op1.reg)
        # Delete the symbolic register
        if reg in symbolic_state:
            symbolic_state.del_sym_var(reg)
        # Copy the value from the stack to the register
        if stack_pointer in symbolic_state:
            symbolic_state[reg] = symbolic_state[stack_pointer]
            symbolic_state.del_sym_var(stack_pointer)
            return symbolic_state[reg]
        
    def _mov(self, Insn, symbolic_state, **kwargs):
        # instanciate a new symbolic register if needed
        # if condition is not met, then delete the symbolic register
        mem_access = kwargs.get("mem_access")
        to_delete = False
        
        # operand 2 is not a symbolic value but a real one
        if not (isinstance(Insn.v_op2, SymValue) or isinstance(Insn.v_op2, ASymValue)):
            to_delete = True
        
        if Insn.op1.type == X86_OP_REG:
            regname = self.cs.reg_name(Insn.op1.reg)
            if to_delete:
                symbolic_state.del_sym_var(regname)
                return None
            symbolic_state[regname].update(Insn.v_op2.sym_value, **kwargs)
            return symbolic_state[regname]

        elif Insn.op1.type == X86_OP_MEM:
            if to_delete:
                symbolic_state.del_sym_var(mem_access)
                return None
            symbolic_state[mem_access].update(Insn.v_op2.sym_value, **kwargs)
            return symbolic_state[mem_access]

        raise Exception(f"Operation {Insn.cinsn.mnemonic} not supported")

    
    def process(self):
        kwargs = {
            "mem_access": self.mem_access,
            "SymRegisterFactory": SymRegisterFactory,
        }
        if "mov" in self.insn.mnemonic or self.insn.mnemonic.startswith("lea"):
            return self._mov(self.Insn, self.symbolic_state, **kwargs)
        elif self.insn.mnemonic.startswith("add"):
            return self._add(self.Insn, self.symbolic_state, **kwargs)
        elif self.insn.mnemonic.startswith("imul"):
            return self._imul(self.Insn, self.symbolic_state, **kwargs)
        elif self.insn.mnemonic.startswith("sub"):
            return self._sub(self.Insn, self.symbolic_state, **kwargs)
        elif self.insn.mnemonic.startswith("xor"):
            return self._xor(self.Insn, self.symbolic_state, **kwargs)
        elif self.insn.mnemonic.startswith("and"):
            return self._and(self.Insn, self.symbolic_state, **kwargs)
        elif self.insn.mnemonic.startswith("or"):
            return self._or(self.Insn, self.symbolic_state, **kwargs)
        elif self.insn.mnemonic.startswith("shl"):
            return self._shl(self.Insn, self.symbolic_state, **kwargs)
        elif self.insn.mnemonic.startswith("shr") or self.insn.mnemonic.startswith("sar"):
            return self._shr(self.Insn, self.symbolic_state, **kwargs)
        elif self.insn.mnemonic.startswith("ror"):
            return self._ror(self.Insn, self.symbolic_state, **kwargs)
        elif self.insn.mnemonic.startswith("rol"):
            return self._rol(self.Insn, self.symbolic_state, **kwargs)
        elif self.insn.mnemonic.startswith("mul"):
            return self._mul(self.Insn, self.symbolic_state, **kwargs)
        elif self.insn.mnemonic.startswith("not"):
            return self._not(self.Insn, self.symbolic_state, **kwargs)
        elif self.insn.mnemonic.startswith("push"):
            return self._push(self.Insn, self.symbolic_state, **kwargs)
        elif self.insn.mnemonic.startswith("pop"):
            return self._pop(self.Insn, self.symbolic_state, **kwargs)
        elif self.insn.mnemonic.startswith("cdq"):
            return self._cdq(self.Insn, self.symbolic_state, **kwargs)
        else:
            return None

        


class InstructionEngineX86_64:
    """
    A class for performing symbolic execution on x86-64 machine code using Qiling.

    Args:
        ql_instance (Qiling): An instance of the Qiling emulator.
        debug_level (int): The level of debugging to use during execution.
    """

    def __init__(
        self, ql_instance, debug_level):
        # Store the Qiling instance and configure Capstone disassembler and Keystone assembler
        self.engine = ql_instance
        self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
        self.cs.detail = True
        self.ks = Ks(KS_ARCH_X86, KS_MODE_64)
        self.ks.detail = True

        # Initialize variables for tracking the last executed instruction
        self.last_instruction_executed = None
        self.is_last_instruction_symbolic = False

        # Set the debug level and symbolic execution check interval
        self.debug_level = debug_level
        
        self.config = None
        
    def set_config(self, config):
        self.config = config
        

    def check_symop_div(self, insn, symbolic_state: TaintedVariableState):
        if insn.mnemonic == "div":
            for reg in SymRegisterFactory["rax"]:
                if reg in symbolic_state:
                    log(
                        DebugLevel.DEBUG,
                        f"Symbolic register found in {reg.name} => {symbolic_state[reg.name]}",
                        self.debug_level,
                        ANSIColors.PURPLE,
                    )
                    return True
            op1 = insn.operands[0]
            regname = self.cs.reg_name(op1.reg)
            if regname in symbolic_state:
                log(
                    DebugLevel.DEBUG,
                    f"Symbolic register found in {regname} => {symbolic_state[regname]}",
                    self.debug_level,
                    ANSIColors.PURPLE,
                )
                return True
            return False

    
    def process_mem_access(self, op, symbolic_state: TaintedVariableState):
        # Return the symbolic register that is used in the mem_access instruction (ex: lea rbx, [rax + 5]) with
        # rax symbolic
        # if no symbolic register is used, Create a symbolic memory object
        value = RealValue(0)

        if op.mem.base != 0:
            reg_name = self.cs.reg_name(op.mem.base)
            # if the register is symbolic, fetch it from the symbolic_state
            if reg_name in symbolic_state:
                value = symbolic_state[reg_name].clone()
            else:
                value = symbolic_state.create_sym_reg(reg_name)

        if op.mem.index != 0:
            reg_name = self.cs.reg_name(op.mem.base)
            index = self.engine.read_reg(reg_name)
            if self.cs.reg_name(op.mem.index) in symbolic_state:
                if not value:
                    value = symbolic_state[self.cs.reg_name(op.mem.index)].clone()
                else:
                    # process in this order to avoid adding a SymValue to a RealValue
                    value = symbolic_state[self.cs.reg_name(op.mem.index)].clone() + value
            else:
                if not value:
                    value = RealValue(index)
                else:
                    value += RealValue(index)

        if op.mem.disp != 0:
            value += RealValue(op.mem.disp)

        if op.mem.scale > 1:
            value *= RealValue(op.mem.scale)

        return value

    
    def parse_insn_operands(
        self, insn: CsInsn, mem_access: int, symbolic_state: TaintedVariableState
    ) -> Instruction:
        # Parse the operands of the instruction, create symbolic values if needed, and return the Instruction object
        Insn = Instruction(insn)
        if len(Insn.cinsn.operands) == 0:
            return Insn
        
        Insn.mem_access = mem_access

        # Check if the operand is a symbolic memory access and create a symbolic value
        for op in insn.operands:
            if op.type == X86_OP_MEM:
                sym_access = self.process_mem_access(op, symbolic_state)
                if isinstance(sym_access, SymValue):
                    log(
                        DebugLevel.DEBUG,
                        f"Adding symbolic memory {hex(mem_access)} => {sym_access.sym_value}",
                        self.debug_level,
                        ANSIColors.PURPLE,
                    )
                    symbolic_state[mem_access] = sym_access
                    break
        #
        # Process the symbolic data of the operands
        #
        for i in range(min(len(Insn.cinsn.operands), 3)):
            operand = Insn.cinsn.operands[i]
            setattr(Insn, f"op{i+1}", operand)

            # Process REG operands
            if operand.type == X86_OP_REG:
                regname = self.cs.reg_name(operand.reg)
                if regname not in symbolic_state:
                    symbolic_state.create_sym_reg(regname)
                setattr(Insn, f"v_op{i+1}", symbolic_state[regname])

            # Process IMM operands
            elif operand.type == X86_OP_IMM:
                setattr(Insn, f"v_op{i+1}", RealValue(operand.imm))

            # Process MEM operands
            elif operand.type == X86_OP_MEM:
                if mem_access not in symbolic_state and self.engine.is_mapped(mem_access):
                    symbolic_state.create_sym_mem(mem_access, self.engine.read_memory_int(mem_access))
                if mem_access in symbolic_state:
                    setattr(Insn, f"v_op{i+1}", symbolic_state[mem_access])
                else:
                    setattr(Insn, f"v_op{i+1}", RealValue(0))
   
            assert getattr(Insn, f"v_op{i+1}") is not None
            
        #
        # Parse real values of the operands
        # 
        for i, op in enumerate(insn.operands):
            
            if op.type == X86_OP_REG:
                regname = self.cs.reg_name(op.reg)
                reg_value = self.engine.read_reg(regname.upper())
                setattr(Insn, f"r_op{i + 1}", reg_value)
                
            elif op.type == X86_OP_MEM and self.engine.is_mapped(mem_access):
                mem_value = self.engine.read_memory_int(mem_access)
                setattr(Insn, f"r_op{i + 1}", hex(mem_value))

        return Insn

    
    def make_var_substitutions(self, symbolic_state: TaintedVariableState, tainted_var_name: str):
        
        # we do not fetch from global config because it is to slow
        BINARY_ARCH_SIZE = self.config["BINARY_ARCH_SIZE"]
        MAX_RAW_REPR_LENGTH = self.config["MAX_RAW_REPR_LENGTH"]
        global VAR_COUNTER
        
        kwargs = { "SymRegisterFactory": SymRegisterFactory }
        
        if tainted_var_name not in symbolic_state:
            return
        
        tainted_var_value = symbolic_state[tainted_var_name]

        if not isinstance(tainted_var_value, ASymValue):
            return 
        
        raw_repr = tainted_var_value.sym_value.__raw_repr__()

        # if not, then we didn't updated yet, so we create a new varname and assign it to the tainted_var_value
        if len(raw_repr) > MAX_RAW_REPR_LENGTH:
            new_var_name = f"var_{next(VAR_COUNTER):05d}"
            symbolic_state[new_var_name] = tainted_var_value.sym_value.clone()
            log(
                DebugLevel.DEBUG,
                f"Creating new varname {new_var_name} for {tainted_var_name}=>{tainted_var_value.sym_value}",
                self.debug_level,
                ANSIColors.PURPLE,
            )
            symbolic_state[tainted_var_name].update(
                SymValue(BitVec(str(new_var_name), BINARY_ARCH_SIZE)),  **kwargs
            )
         

    def log_previous_operation(self, symbolic_state: TaintedVariableState):
        # Get the address of the last executed instruction
        insn_addr = self.last_instruction_executed
        
        if insn_addr is None:
            return
        # Get the instruction object for the last executed instruction
        insn = self.engine.get_instruction_from_address(insn_addr)

        # Iterate through the operands of the instruction
        for operand in insn.operands:
            if operand.type == X86_OP_REG:
                # If the operand is a register, retrieve and log its value
                reg_name = self.cs.reg_name(operand.reg)
                reg_value = hex(self.engine.read_reg(reg_name.upper()))
                log(
                    DebugLevel.DEBUG,
                    f"{reg_name} => {reg_value}",
                    self.debug_level,
                    ANSIColors.OKBLUE,
                )
            elif operand.type == X86_OP_MEM and self.engine.is_mapped(self.last_mem_access):
                # If the operand is a memory location, retrieve and log its value
                mem_value = hex(self.engine.read_memory_int(self.last_mem_access))
                log(
                    DebugLevel.DEBUG,
                    f"{hex(self.last_mem_access)} => {mem_value}",
                    self.debug_level,
                    ANSIColors.OKBLUE,
                )
                
    def compute_mem_access(self, insn):
        mem_access = 0
        try:
            for op in insn.operands:
                if op.type == X86_OP_MEM:
                    mem_access += (
                        self.engine.read_reg(self.cs.reg_name(op.mem.base))
                        if op.mem.base != 0
                        else 0
                    )
                    mem_access += (
                        self.engine.read_reg(self.cs.reg_name(op.mem.index))
                        if op.mem.index != 0
                        else 0
                    )
                    mem_access += op.mem.disp
                    mem_access *= op.mem.scale if op.mem.scale > 1 else 1

        except Exception as e:
            log(
                DebugLevel.ERROR,
                f"Exception occurred while computing memory access: {e}",
                self.debug_level,
                ANSIColors.ERROR,
            )
            raise e

        return mem_access

    
    def evaluate_instruction(self, mem_access, symbolic_state: TaintedVariableState):
        
        BAD_OPERANDS = self.config["BAD_OPERANDS"]
        SUPPORTED_INSTRUCTIONS = self.config["SUPPORTED_INSTRUCTIONS"]
        # Get the current instruction
        insn = self.engine.get_currrent_instruction_disass()
        insn_addr = self.engine.get_current_instruction_address()
        # Check if the instruction is the same as the last one executed
        if insn_addr == self.last_instruction_executed:
            return None
        # check if the operands are not supported
        for bad_op_pattern in BAD_OPERANDS:
            if re.match(bad_op_pattern, insn.op_str):
                return None
        # check if the instruction is in the current list of supported instructions
        if insn.mnemonic not in SUPPORTED_INSTRUCTIONS:
            log(
                DebugLevel.DEBUG,
                f"Instrution is not supported",
                self.debug_level,
                ANSIColors.WARNING,
            )
            return None
        
        # mem_access can be calculated from insn of directly
        # read base, index, disp and scale from insn operands
        if mem_access is None:
            mem_access = self.compute_mem_access(insn)
            
        # store the last instruction executed
        self.last_instruction_executed = insn_addr
        self.last_mem_access = mem_access

        # Parse operands do a lot of things, like creating symbolic values, fetching values from memory
        # All the results are stored in the Instruction object (v_op1, v_op2, v_op3)
        Insn = self.parse_insn_operands(insn, mem_access, symbolic_state)
        # Compute the result of the operation
        op_engine = OperationEngineX86_64(self.cs, self.engine, Insn, insn, mem_access, symbolic_state)
        op_result = op_engine.process()
        Insn.v_op_result = op_result
        print(hex(insn_addr), Insn)
        
        # Update variables in symbolic_state
        self.make_var_substitutions(symbolic_state, op_engine.tainted_var_name)
        

        return Insn


    


class Runner:

    def __init__(self, debug_level, timeout, *args, **kwargs):
        # Set the debug level and create a TaintedVariableState instance
        self.debug_level = debug_level
        self.timeout = timeout
        self.taint_st = TaintedVariableState()
        # Create an empty dictionary for callbacks
        self.callbacks = {}
        # Initialize start and end addresses for emulation
        self.addr_emu_start = None
        self.addr_emu_end = []
        self.trace_records = Trace()
        self.insn_executed_count = INSN_EXECUTED_COUNT
        self.reg_sm = DataStoreManager()
        self.mem_sm = DataStoreManager()
        
    def register_callback(self, address: int, fn: callable):
        assert isinstance(address, int)
        assert callable(fn)
        self.callbacks[address] = fn
        
    def set_emu_start(self, address: int):
        assert isinstance(address, int)
        self.addr_emu_start = address

    def set_emu_end(self, address: int):
        assert isinstance(address, int)
        self.addr_emu_end.append(address)
        
    def add_emu_end(self, address: int):
        assert isinstance(address, int)
        self.addr_emu_end.append(address)
        
    def clone(self):
        raise NotImplementedError("clone method not implemented")
    
    def initialize_configuration(self):
        raise NotImplementedError("initialize_configuration method not implemented")


        
        
class QilingRunner(Runner):
    def __init__(self, ql_instance, debug_level, timeout, *args, **kwargs):
        super().__init__(debug_level, timeout, *args, **kwargs)
        # Store the Qiling instance
        self.ql = ql_instance
        # instantiate the engine
        self.engine = QilingEngine(ql_instance)
        # Check if the architecture is 32-bit or 64-bit
        if ql_instance.arch.type == QL_ARCH.X8664:
            self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
            self.ks = Ks(KS_ARCH_X86, KS_MODE_64)
        elif ql_instance.arch.type == QL_ARCH.X86:
            self.cs = Cs(CS_ARCH_X86, CS_MODE_32)
            self.ks = Ks(KS_ARCH_X86, KS_MODE_32)
        # Create an instance of the CodexInstructionEngine
        self.instruction_engine = InstructionEngineX86_64(
                self.engine, debug_level, *args, **kwargs
            )
        # Find the base and end address of the text section
        self.text_base = ql_instance.loader.images[0].base
        self.text_end = ql_instance.loader.images[0].end
        # Configure the disassembler for detailed information
        self.ql.arch.disassembler.detail = True
        
    def register_operations(self, Insn):
        if Insn is None:
            return
        insn_addr = self.engine.get_current_instruction_address()
        self.update_datastore(Insn)
        return self.trace_records.register(
            insn_addr, Insn
        )

    def memory_write_hook(
        self, ql: Qiling, access: int, address: int, size: int, value: int
    ):
        assert access == UC_MEM_WRITE
        # process instruction only if it is in the text section
        if not self.check_instruction_scope(ql):
            return

        insn_addr = self.engine.get_current_instruction_address()
        self.register_operations(self.instruction_engine.evaluate_instruction(address, self.taint_st))

    def memory_read_hook(
        self, ql: Qiling, access: int, address: int, size: int, value: int
    ):
        assert access == UC_MEM_READ
        # process instruction only if it is in the text section
        if not self.check_instruction_scope(ql):
            return

        insn_addr = self.engine.get_current_instruction_address()
        self.register_operations(self.instruction_engine.evaluate_instruction(address, self.taint_st))
            
            
    def check_instruction_scope(self, ql):
        if ql.arch.type == QL_ARCH.X8664:
            pc = ql.arch.regs.rip
        else:
            pc = ql.arch.regs.eip

        if pc < self.text_base or pc >= self.text_end:
            return False
        return True
    
    def set_register(self, register: str, value: int):
        self.ql.arch.regs.write(register, value)

    def get_register(self, register: str):
        return self.ql.arch.regs.read(register)

    
    def code_execution_hook(self, ql: Qiling, address: int, size):
        try:
            
            if time.time() - self.start_time > self.timeout:
                raise UserStoppedExecution(f"Reached timeout of {self.timeout} seconds")
            
            # Get the current instruction and its address
            insn, insn_addr = self.engine.get_currrent_instruction_disass(), self.engine.get_current_instruction_address()

            # Check if we have reached the user-defined end address for emulation
            if insn_addr in self.addr_emu_end:
                raise UserStoppedExecution("Reached user-defined end address")

            # Check if the instruction is a call instruction
            if insn.mnemonic.startswith("call"):
                # Get the address of the function being called
                if insn.operands[0].type == X86_OP_IMM:
                    fn_addr = insn.operands[0].imm
                    if fn_addr in self.callbacks:
                        # Execute the callback associated with the function address
                        self.callbacks[fn_addr](ql)

            # If the instruction involves memory access, delegate to dedicated functions (mem_read, mem_write)
            if check_memory_access(insn):
                return

            # Evaluate the instruction with the current codex state
            Insn = self.instruction_engine.evaluate_instruction(address, self.taint_st)
            self.register_operations(Insn)
                
        finally:
            # Increment the instruction executed count
            next(self.insn_executed_count)
            

    def get_current_pc(self):
        return self.engine.get_current_instruction_address()
    
    
    def update_datastore(self, Insn):
        for i in range(min(len(Insn.cinsn.operands), 3)):
            operand = Insn.cinsn.operands[i]
            if operand.type == X86_OP_REG:
                regname = self.cs.reg_name(operand.reg)
                self.reg_sm.register(self.insn_executed_count.current, regname, self.engine.read_reg(regname.upper()))
            elif operand.type == X86_OP_MEM:
                self.mem_sm.register(self.insn_executed_count.current, Insn.mem_access, self.engine.read_memory_int(Insn.mem_access))


    def clone(self):        
        # delete current ql hooks
        self.ql.clear_hooks()
        self.ql.clear_ql_hooks()
        new_runner = QilingRunner(self.ql, self.debug_level)
        # Copy the state of TaintedVariableState
        new_runner.state = self.taint_st.clone()
        # Copy architecture-specific attributes
        new_runner.cs = self.cs
        new_runner.ks = self.ks
        new_runner.instruction_engine = self.instruction_engine
        # Copy text section attributes
        new_runner.text_base = self.text_base
        new_runner.text_end = self.text_end
        # Copy the callbacks dictionary
        new_runner.callbacks = self.callbacks
        # Copy emulation start and end addresses
        new_runner.addr_emu_start = self.addr_emu_start
        new_runner.addr_emu_end = self.addr_emu_end
        # Copy address book and trace records
        new_runner.trace_records = self.trace_records.clone()
        # Copy executed instructions count
        new_runner.insn_executed_count = self.insn_executed_count
        # copy data store
        new_runner.reg_sm = self.reg_sm.clone()
        new_runner.mem_sm = self.mem_sm.clone()
        return new_runner
    
    
    def initialize_configuration(self):
        CONFIG = {
            "BINARY_ARCH": None,
            "BINARY_ARCH_SIZE": None,
            "BINARY_MAX_MASK": None,
            "MAX_RAW_REPR_LENGTH": 44,
            "SUPPORTED_INSTRUCTIONS": None,
            "BAD_OPERANDS": None,
            "CS_UC_REGS": None,
            "TRACE_RECORDS": self.trace_records,
        }

        BINARY_ARCH = self.ql.arch.type
        
        if BINARY_ARCH in (QL_ARCH.X86, QL_ARCH.X8664):
            CONFIG["SUPPORTED_INSTRUCTIONS"] = InstructionSet(SUPPORTED_INSTRUCTIONS_X86_64)
            CONFIG["BAD_OPERANDS"] = BAD_OPERANDS_X86_64
            
        if BINARY_ARCH == QL_ARCH.X8664:
            CONFIG["BINARY_MAX_MASK"] = 0xFFFFFFFFFFFFFFFF
            CONFIG["BINARY_ARCH_SIZE"] = 64
            
        elif BINARY_ARCH == QL_ARCH.X86:
            CONFIG["BINARY_MAX_MASK"] = 0xFFFFFFFF
            CONFIG["BINARY_ARCH_SIZE"] = 32
            
        setglobal("CONFIG", CONFIG)
        self.config = CONFIG
            
        

    def run_emulation(self):
        
        # Synchronize config with the global config
        self.initialize_configuration()
        self.instruction_engine.set_config(self.config)
        
        # Set up memory read, memory write, and code hooks
        self.ql.hook_mem_read(self.memory_read_hook)
        self.ql.hook_mem_write(self.memory_write_hook)
        self.ql.hook_code(self.code_execution_hook)

        # Start measuring emulation time
        self.start_time = time.time()
        
        try:

            # Start Qiling engine emulation within the specified address range
            if self.addr_emu_start:
                self.ql.run(self.addr_emu_start)
            else:
                self.ql.run()
                
        except UserStoppedExecution as e:
            log(
                DebugLevel.ERROR,
                f"Emulation stopped: {e}",
                self.debug_level,
                ANSIColors.ERROR,
            )

        # Calculate emulation time and instructions per second
        end_time = time.time()
        emulation_time = end_time - self.start_time
        instructions_per_second = self.insn_executed_count.current / emulation_time

        # Create a separator line for output formatting
        separator_line = "=" * 80

        # Format the output message
        output = "\n".join([
        f"{separator_line}",
        f"Emulation time: {emulation_time:.1f} seconds",
        f"{self.insn_executed_count.current} instructions executed",
        f"Instructions per second: {instructions_per_second:.1f}",
        f"{separator_line}"
        ])

        # Log emulation results
        log(DebugLevel.ERROR, output, self.debug_level, ANSIColors.OKGREEN)
        
        global profile
        profile.print_stats()

        return True
