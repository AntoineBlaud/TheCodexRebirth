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

from ..tools import *


from .operation import (
    Operation,
)
from .trace import Trace, TraceEntry

from .value import SymValue, RealValue, IndirectSymValue, SymRegister, SymMemory

from .datastore import DataStoreManager

from z3 import set_option, BitVec
import time
import re
import line_profiler

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


BAD_OPERANDS_X86_64 = [".*pl", ".*il", ".*z", ".*h"]
INSN_EXECUTED_COUNT = alt_count()
VAR_COUNTER = alt_count()


def create_sym_register_factory():
    """
    Create a dictionary of symbolic registers and their parts.
    Used also to link a register part to its parent register.
    """
    global SYM_REGISTER_FACTORY
    rax = SymRegister("rax", 63, 0)
    rcx = SymRegister("rcx", 63, 0)
    rdx = SymRegister("rdx", 63, 0)
    rbx = SymRegister("rbx", 63, 0)
    rsi = SymRegister("rsi", 63, 0)
    rdi = SymRegister("rdi", 63, 0)
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
    edi = SymRegister("edi", 31, 0, rdi)
    esi = SymRegister("esi", 31, 0, rsi)
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
    al = SymRegister("al", 7, 0, ax)
    cl = SymRegister("cl", 7, 0, cx)
    dl = SymRegister("dl", 7, 0, dx)
    bl = SymRegister("bl", 7, 0, bx)
    dil = SymRegister("dil", 7, 0, di)
    sil = SymRegister("sil", 7, 0, si)
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

    SYM_REGISTER_FACTORY = {
        "ah": [rax, eax, ax, ah, al],
        "al": [rax, eax, ax, ah, al],
        "ax": [rax, eax, ax, ah, al],
        "bh": [rbx, ebx, bx, bh, bl],
        "bl": [rbx, ebx, bx, bh, bl],
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
        "rbx": [rbx, ebx, bx, bh, bl],
        "rcx": [rcx, ecx, cx, ch, cl],
        "rdi": [rdi, edi, di, dil],
        "rdx": [rdx, edx, dx, dh, dl],
        "rsi": [rsi, esi, si, sil],
        "si": [rsi, esi, si, sil],
        "sil": [rsi, esi, si, sil],
    }
    return SYM_REGISTER_FACTORY


class VariableStates(dict):
    """
    This class is a wrapper around a dictionary that stores symbolic tainted variables.
    Symbolic variables are instance of SymValue or RealValue.
    """

    def __init__(self):
        super().__init__()

    def __contains__(self, key_object: object) -> bool:
        # Check if a key_object (possibly processed) exists in the dictionary
        key_object = create_name_from_address(key_object)
        return super().__contains__(key_object)

    def __setitem__(self, key_object, value):
        # Set an item in the dictionary after processing the key
        key_object = create_name_from_address(key_object)
        print(f"Set {key_object} to {value}")
        super().__setitem__(key_object, value)

    def __getitem__(self, key_object):
        # Get an item from the dictionary after processing the key
        key_object = create_name_from_address(key_object)
        return super().__getitem__(key_object)

    def create_sym_reg(self, name) -> SymRegister:
        # we reset the register to a new symbolic value
        # each register parts are reset to a new symbolic value
        global INSN_EXECUTED_COUNT, SYM_REGISTER_FACTORY
        # Create a new symbolic register and propagate the value to its parts
        # (e.g., 'ah' to ['rax', 'eax', 'ax', 'ah', 'al'])
        print(f"Create symbolic register {name}")
        for reg in SYM_REGISTER_FACTORY[name]:
            self[reg.name] = reg.reset()
            self[reg.name].id = INSN_EXECUTED_COUNT.value
        return self[name]

    def create_sym_mem(self, address, value):
        global INSN_EXECUTED_COUNT
        # Create a new symbolic memory object
        name = create_name_from_address(address)
        self[name] = SymMemory(name, value)
        self[name].id = INSN_EXECUTED_COUNT.value
        print(f"Create symbolic memory {name} with value {value}")
        return self[name]

    def del_sym_var(self, name):
        # Delete a symbolic variable, handling register parts and
        # individual variables
        name = create_name_from_address(name)
        
        print(f"Delete symbolic variable {name}")

        if name not in self:
            return

        if name in SYM_REGISTER_FACTORY:
            for reg in SYM_REGISTER_FACTORY[name]:
                if reg.name in self:
                    del self[reg.name]
        else:
            del self[name]

    def __repr__(self) -> str:
        res = ""
        for key, value in self.items():
            res += f"{key} = {value}\n"
        return res

    def clone(self):
        clone = VariableStates()
        for key, value in self.items():
            clone[key] = value.clone()
        return clone


class OperationX86_64:
    """
    A class for performing a symbolic operations on x86-64 machine code.
    """

    def __init__(self, config, cs, engine, operation, mem_access, symbolic_taint_store):
        self.config = config
        self.cs = cs
        self.operation = operation
        self.mem_access = mem_access
        self.symbolic_taint_store = symbolic_taint_store
        self.engine = engine
        self.tainted_var_name = self.find_var_name_tainted(operation, mem_access)

    def find_var_name_tainted(self, operation: Operation, mem_access: int):
        if not operation.op1:
            return None
        return (
            mem_access
            if operation.op1.type == X86_OP_MEM
            else self.cs.reg_name(operation.op1.reg)
        )

    def _add(self, operation, symbolic_taint_store):
        return symbolic_taint_store[self.tainted_var_name].update(
            operation.v_op1 + operation.v_op2
        )

    def _imul(self, operation, symbolic_taint_store):
        if operation.v_op3 is not None:
            return symbolic_taint_store[self.tainted_var_name].update(
                operation.v_op2 * operation.v_op3
            )
        if operation.v_op2 is not None:
            return symbolic_taint_store[self.tainted_var_name].update(
                operation.v_op1 * operation.v_op2
            )
        else:
            if "rax" in symbolic_taint_store:
                return symbolic_taint_store["rax"].update(
                    (symbolic_taint_store["rax"] * operation.v_op1)
                )

    def _sub(self, operation, symbolic_taint_store):
        return symbolic_taint_store[self.tainted_var_name].update(
            operation.v_op1 - operation.v_op2
        )

    def _xor(self, operation, symbolic_taint_store):
        return symbolic_taint_store[self.tainted_var_name].update(
            operation.v_op1 ^ operation.v_op2
        )

    def _and(self, operation, symbolic_taint_store):
        return symbolic_taint_store[self.tainted_var_name].update(
            operation.v_op1 & operation.v_op2
        )

    def _or(self, operation, symbolic_taint_store):
        return symbolic_taint_store[self.tainted_var_name].update(
            operation.v_op1 | operation.v_op2
        )

    def _shl(self, operation, symbolic_taint_store):
        destination = operation.v_op1
        bsize = self.config["BINARY_ARCH_SIZE"]
        if operation.v_op3 is not None:
            source = operation.v_op2
            count = operation.v_op3.value % bsize
            shifted_bits = (destination << RealValue(count)) 
            shifted_bits |= (source >> RealValue(bsize - count))
        else:
            count = operation.v_op2
            shifted_bits = (destination << count) 
        return symbolic_taint_store[self.tainted_var_name].update(shifted_bits)

    def _shr(self, operation, symbolic_taint_store):
        destination = operation.v_op1
        bsize = self.config["BINARY_ARCH_SIZE"]
        if operation.v_op3 is not None:
            source = operation.v_op2
            count = operation.v_op3.value % bsize
            shifted_bits = (destination >> RealValue(count)) 
            shifted_bits |= (source << RealValue(bsize - count))
        else:
            count = operation.v_op2
            shifted_bits = (destination >> count) 
        return symbolic_taint_store[self.tainted_var_name].update(shifted_bits)

    def _ror(self, operation, symbolic_taint_store):
        return symbolic_taint_store[self.tainted_var_name].update(
            operation.v_op1.ror(operation.v_op2)
        )

    def _rol(self, operation, symbolic_taint_store):
        return symbolic_taint_store[self.tainted_var_name].update(
            operation.v_op1.rol(operation.v_op2)
        )

    def _mul(self, operation, symbolic_taint_store):
        return symbolic_taint_store["rax"].update(
            symbolic_taint_store[self.tainted_var_name] * operation.v_op1
        )

    def _not(self, operation, symbolic_taint_store):
        return symbolic_taint_store[self.tainted_var_name].update(
            operation.v_op1._not()
        )

    def _cdq(self, operation, symbolic_taint_store):
        symbolic_taint_store.del_sym_var("rdx")
        return None

    def _push(self, operation, symbolic_taint_store):
        stack_pointer = self.engine.get_stack_pointer()
        symbolic_taint_store.create_sym_mem(stack_pointer, 0)
        symbolic_taint_store[stack_pointer].update(operation.v_op1)
        return symbolic_taint_store[stack_pointer]

    def _pop(self, operation, symbolic_taint_store):
        stack_pointer = self.engine.get_stack_pointer()
        reg = self.cs.reg_name(operation.op1.reg)
        # Delete the symbolic register
        if reg in symbolic_taint_store:
            symbolic_taint_store.del_sym_var(reg)
        # Copy the value from the stack to the register
        if stack_pointer in symbolic_taint_store:
            symbolic_taint_store[reg] = symbolic_taint_store[stack_pointer]
            symbolic_taint_store.del_sym_var(stack_pointer)
            return symbolic_taint_store[reg]

    def _mov(self, operation, symbolic_taint_store, mem_access):
        # instanciate a new symbolic register if needed
        # if condition is not met, then delete the symbolic register
        if operation.op1.type == X86_OP_REG:
            regname = self.cs.reg_name(operation.op1.reg)
            symbolic_taint_store[regname].update(operation.v_op2)
            symbolic_taint_store[regname].id = operation.v_op2.id
            return symbolic_taint_store[regname]

        elif operation.op1.type == X86_OP_MEM:
            symbolic_taint_store[mem_access].update(operation.v_op2)
            symbolic_taint_store[mem_access].id = operation.v_op2.id
            return symbolic_taint_store[mem_access]

        raise Exception(f"Operation {operation.cinsn.mnemonic} not supported")

    def _lea(self, operation, symbolic_taint_store, mem_access):
        regname = self.cs.reg_name(operation.op1.reg)
        # round mem_access to next 4 bytes
        mem_access = mem_access + (mem_access % 4)
        symbolic_taint_store[regname].update(RealValue(mem_access))
        symbolic_taint_store[regname].id = -1
        return symbolic_taint_store[regname]

    
    def process(self):
        if self.tainted_var_name not in self.symbolic_taint_store:
            return None
        cinsn = self.operation.cinsn
        if "mov" in cinsn.mnemonic:
            return self._mov(self.operation, self.symbolic_taint_store, self.mem_access)
        elif "lea" in cinsn.mnemonic:
            return self._lea(self.operation, self.symbolic_taint_store, self.mem_access)
        elif cinsn.mnemonic.startswith("add"):
            return self._add(self.operation, self.symbolic_taint_store)
        elif cinsn.mnemonic.startswith("imul"):
            return self._imul(self.operation, self.symbolic_taint_store)
        elif cinsn.mnemonic.startswith("sub"):
            return self._sub(self.operation, self.symbolic_taint_store)
        elif cinsn.mnemonic.startswith("xor"):
            return self._xor(self.operation, self.symbolic_taint_store)
        elif cinsn.mnemonic.startswith("and"):
            return self._and(self.operation, self.symbolic_taint_store)
        elif cinsn.mnemonic.startswith("or"):
            return self._or(self.operation, self.symbolic_taint_store)
        elif cinsn.mnemonic.startswith("shl"):
            return self._shl(self.operation, self.symbolic_taint_store)
        elif cinsn.mnemonic.startswith("shr") or cinsn.mnemonic.startswith("sar"):
            return self._shr(self.operation, self.symbolic_taint_store)
        elif cinsn.mnemonic.startswith("ror"):
            return self._ror(self.operation, self.symbolic_taint_store)
        elif cinsn.mnemonic.startswith("rol"):
            return self._rol(self.operation, self.symbolic_taint_store)
        elif cinsn.mnemonic.startswith("mul"):
            return self._mul(self.operation, self.symbolic_taint_store)
        elif cinsn.mnemonic.startswith("not"):
            return self._not(self.operation, self.symbolic_taint_store)
        elif cinsn.mnemonic.startswith("push"):
            return self._push(self.operation, self.symbolic_taint_store)
        elif cinsn.mnemonic.startswith("pop"):
            return self._pop(self.operation, self.symbolic_taint_store)
        elif cinsn.mnemonic.startswith("cdq"):
            return self._cdq(self.operation, self.symbolic_taint_store)
        elif cinsn.mnemonic.startswith("test") or cinsn.mnemonic.startswith("cmp"):
            return self.operation.v_op1
        elif cinsn.mnemonic.startswith("call") or cinsn.mnemonic.startswith("j"):
            return self.operation.v_op1
        else:
            return None


class OperationEngineX86_64:
    """
    A class for performing symbolic execution on x86-64 machine code using Qiling.

    Args:
        engine (Qiling): An instance of the Qiling emulator.
        debug_level (int): The level of debugging to use during execution.
    """

    def __init__(self, engine, debug_level):
        # Store the Qiling instance and configure Capstone disassembler and Keystone assembler
        self.engine = engine
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

    
    def discover_indirect_access(self, op, mem_access, symbolic_taint_store: VariableStates):
        # Create an IndirectSymValue object from mem_access instruction

        ind = IndirectSymValue(mem_access)

        def fetch_symbolic_register(reg_name):
            # Helper function to fetch a symbolic register from symbolic_taint_store
            if reg_name in symbolic_taint_store and isinstance(symbolic_taint_store[reg_name], SymValue):
                ind.id = symbolic_taint_store[reg_name].id
                return ind

        if op.mem.base != 0:
            reg_name_base = self.cs.reg_name(op.mem.base)
            return fetch_symbolic_register(reg_name_base)

        if op.mem.index != 0:
            reg_name_index = self.cs.reg_name(op.mem.index)
            return fetch_symbolic_register(reg_name_index)

        return None


    
    def parse_operation_operands(
        self, cinsn, mem_access: int, symbolic_taint_store: VariableStates
    ) -> Operation:
        # Parse the operands of the instruction, create symbolic values if needed, and return the Operation object
        operation = Operation(cinsn)
        operation.mem_access = mem_access
        
        if len(operation.cinsn.operands) == 0:
            return operation

        # Check if the operand is a symbolic memory access and create a symbolic value 
        for i, op in enumerate(cinsn.operands):
            if op.type == X86_OP_MEM and mem_access not in symbolic_taint_store:
                sym_access = self.discover_indirect_access(op, mem_access, symbolic_taint_store)
                if isinstance(sym_access, IndirectSymValue):
                    print(f"Found a indirect sym memory")
                    # set the mem_access to the indirect sym value. 
                    # The indirect sym value is equal to the value of the register + the displacement
                    symbolic_taint_store[mem_access] = sym_access
        
        #
        # Process the tainted data of the operands
        #
        for i in range(min(len(cinsn.operands), 3)):
            operand = cinsn.operands[i]
            setattr(operation, f"op{i+1}", operand)
            # Process REG operands
            if operand.type == X86_OP_REG:
                regname = self.cs.reg_name(operand.reg)
                if (
                    regname not in symbolic_taint_store
                    and regname in SYM_REGISTER_FACTORY
                ):
                    symbolic_taint_store.create_sym_reg(regname)
                if regname in symbolic_taint_store:
                    setattr(operation, f"v_op{i+1}", symbolic_taint_store[regname])
                else:
                    setattr(
                        operation,
                        f"v_op{i+1}",
                        RealValue(self.engine.read_reg(regname.upper())),
                    )
            # Process IMM operands
            elif operand.type == X86_OP_IMM:
                setattr(operation, f"v_op{i+1}", RealValue(operand.imm))
                
            # Process MEM operands
            elif operand.type == X86_OP_MEM:
                if mem_access not in symbolic_taint_store and self.engine.is_mapped(
                    mem_access
                ):
                    symbolic_taint_store.create_sym_mem(
                        mem_access, self.engine.read_memory_int(mem_access)
                    )
                if mem_access in symbolic_taint_store:
                    setattr(operation, f"v_op{i+1}", symbolic_taint_store[mem_access])
                else:
                    setattr(operation, f"v_op{i+1}", RealValue(0))

            assert getattr(operation, f"v_op{i+1}") is not None

        #
        # Parse real values of the operands
        #
        for i, op in enumerate(cinsn.operands):
            if op.type == X86_OP_REG:
                regname = self.cs.reg_name(op.reg)
                reg_value = self.engine.read_reg(regname.upper())
                setattr(operation, f"r_op{i + 1}", reg_value)

            elif op.type == X86_OP_MEM and self.engine.is_mapped(mem_access):
                mem_value = self.engine.read_memory_int(mem_access)
                setattr(operation, f"r_op{i + 1}", hex(mem_value))

        return operation

    def make_var_substitutions(
        self, symbolic_taint_store: VariableStates, tainted_var_name: str
    ):
        # we do not fetch from global config because it is to slow
        global VAR_COUNTER

        tainted_var_value = symbolic_taint_store.get(tainted_var_name, None)
        if not isinstance(tainted_var_value, SymValue):
            return

        raw_repr = tainted_var_value.v_wrapper.__raw_repr__()
        # if not, then we didn't updated yet, so we create a new varname and assign it to the tainted_var_value
        if len(raw_repr) > self.config["MAX_RAW_REPR_LENGTH"]:
            new_var = f"var_{next(VAR_COUNTER):06d}"
            symbolic_taint_store[new_var] = tainted_var_value.v_wrapper.clone()
            symbolic_taint_store[tainted_var_name].update(
                SymValue(new_var, id=tainted_var_value.id)
            )

    def compute_mem_access(self, cinsn):
        mem_access = 0
        try:
            for op in cinsn.operands:
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
            raise e
        return mem_access

    
    def evaluate_instruction(self, mem_access, symbolic_taint_store: VariableStates):
        if self.config is None:
            raise Exception("Config not set")

        # Get the current instruction
        cinsn = self.engine.get_currrent_instruction_disass()
        cinsn_addr = self.engine.get_ea()
        # Check if the instruction is the same as the last one executed
        if cinsn_addr == self.last_instruction_executed:
            print(f"Instruction {hex(cinsn_addr)} already executed\n")
            return None

        # check if the operands are not supported
        for bad_op_pattern in self.config["BAD_OPERANDS"]:
            if re.match(bad_op_pattern, cinsn.op_str):
                print(f"Bad operand: {hex(cinsn_addr)} {cinsn.op_str}, the result operation may be wrong")

        # mem_access can be calculated from cinsn of directly
        # read base, index, disp and scale from cinsn operands
        mem_access = (
            self.compute_mem_access(cinsn) if mem_access is None else mem_access
        )

        # store the last instruction executed
        self.last_instruction_executed = cinsn_addr
        self.last_mem_access = mem_access

        # Parse operands do a lot of things, like creating symbolic values, fetching values from memory
        # All the results are stored in the Operation object (v_op1, v_op2, v_op3)
        operation = self.parse_operation_operands(
            cinsn, mem_access, symbolic_taint_store
        )
        # Compute the result of the operation
        op_engine = OperationX86_64(
            self.config,
            self.cs,
            self.engine,
            operation,
            mem_access,
            symbolic_taint_store,
        )
        operation.v_result = op_engine.process()
        print(hex(cinsn_addr), operation)

        # Update variables in symbolic_taint_store
        self.make_var_substitutions(symbolic_taint_store, op_engine.tainted_var_name)

        return operation.clone()


class Runner:
    def __init__(self, engine, debug_level, timeout, symbolic_check, *args):
        # Set the debug level and create a VariableStates instance
        self.debug_level = debug_level
        self.timeout = timeout
        self.symbolic_check = symbolic_check
        self.symbolic_taint_store = VariableStates()
        # Create an empty dictionary for callbacks
        self.callbacks = {}
        # Initialize start and end addresses for emulation
        self.addr_emu_start = None
        self.addr_emu_end = []
        self.trace_records = Trace()
        self.operation_executed_count = INSN_EXECUTED_COUNT
        self.registers_state = DataStoreManager()
        self.memory_state = DataStoreManager()
        # instantiate the engine
        self.engine = engine
        # Create an instance of the CodexOperationEngine
        self.operation_engine = OperationEngineX86_64(self.engine, debug_level, *args)

        self.cs = None
        self.ks = None
        self.text_base = None
        self.text_end = None

        self.emulation_time = 0

        self.CONFIG = {
            "BINARY_ARCH_SIZE": None,
            "BINARY_MAX_MASK": None,
            "MAX_RAW_REPR_LENGTH": 44,
            "BAD_OPERANDS": None,
            "CS_UC_REGS": None,
            "TRACE_RECORDS": self.trace_records,
            "SYM_REGISTER_FACTORY": None,
            "INSN_EXECUTED_COUNT": INSN_EXECUTED_COUNT,
            "IS_INITIALIZED": False,
        }

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

    def set_register(self, register: str, value: int):
        self.engine.write_reg(register.upper(), value)

    def get_register(self, register: str):
        return self.engine.read_reg(register.upper())

    def get_current_pc(self):
        return self.engine.get_ea()

    def memory_write_hook(
        self, ql: Qiling, access: int, address: int, size: int, value: int
    ):
        assert access == UC_MEM_WRITE
        self.register_operations(
            self.operation_engine.evaluate_instruction(
                address, self.symbolic_taint_store
            )
        )

    def memory_read_hook(
        self, ql: Qiling, access: int, address: int, size: int, value: int
    ):
        assert access == UC_MEM_READ
        self.register_operations(
            self.operation_engine.evaluate_instruction(
                address, self.symbolic_taint_store
            )
        )

    def code_execution_hook(self, ql: Qiling, address: int, size):
        try:
            if time.time() - self.start_time > self.timeout:
                raise UserStoppedExecution(f"Reached timeout of {self.timeout} seconds")

            # Get the current instruction and its address
            cinsn, cinsn_addr = (
                self.engine.get_currrent_instruction_disass(),
                self.engine.get_ea(),
            )
            # Check if we have reached the user-defined end address for emulation
            if cinsn_addr in self.addr_emu_end:
                raise UserStoppedExecution("Reached user-defined end address")

            # Check if the instruction is a call instruction
            if cinsn.mnemonic.startswith("call"):
                # Get the address of the function being called
                if cinsn.operands[0].type == X86_OP_IMM:
                    fn_addr = cinsn.operands[0].imm
                    if fn_addr in self.callbacks:
                        # Execute the callback associated with the function address
                        self.callbacks[fn_addr](ql)

            # If the instruction involves memory access, delegate to dedicated functions (mem_read, mem_write)
            if check_memory_access(cinsn):
                return

            # Evaluate the instruction with the current codex state
            operation = self.operation_engine.evaluate_instruction(
                None, self.symbolic_taint_store
            )
            self.register_operations(operation)
        finally:
            pass

    
    def register_operations(self, operation: Operation):
        idx = self.operation_executed_count.value
        if operation is None:
            cinsn = self.engine.get_currrent_instruction_disass()
            operation = Operation(cinsn)

        last_trace = self.trace_records.get_last_entry()
        last_operation = last_trace.operation if last_trace else None

        # Register the current and last instruction register and memory changes
        self.register_execution_state(operation, last_operation)

        if self.symbolic_check:
            # first evaluate the current symbolic state (registers, memory and intermediate variables)
            self.evaluate_current_symbolic_state(operation)
            # make the last evaluation of the last symbolic result and store it in the Operation
            self.store_evaluation_result()

        self.trace_records.register(self.engine.get_ea(), operation, idx)
        next(self.operation_executed_count)

    def initialize_symbolic_evaluator(self):
        # We fetching the value of the registers before triggering the run
        # and store them in the global scope
        for reg_id in self.engine.map_regs():
            reg_name = self.cs.reg_name(reg_id)
            if not reg_name:
                continue
            try:
                value = self.engine.read_reg(reg_name.upper())
                globals()[reg_name] = value
            except KeyError:
                pass

    def store_evaluation_result(self):
        """
        Now that qiling executed the last instruction, we fetch the result of the last operation given by the
        OperationEngine and compare it with qiling result
        """
        last_trace_entry = self.trace_records.get_last_entry()
        if not last_trace_entry:
            return

        last_operation = last_trace_entry.operation
        cinsn_operands = last_operation.cinsn.operands
        last_v_result = last_operation.v_result

        if last_v_result is not None and len(cinsn_operands) > 0:
            op1 = cinsn_operands[0]

            if op1.type == X86_OP_REG:
                reg_name = self.cs.reg_name(op1.reg).upper()
                value = self.engine.read_reg(reg_name)

            elif op1.type == X86_OP_MEM:
                value = self.engine.read_memory_int(last_operation.mem_access)

            if value:
                last_operation.op_result = value
                last_operation.eval_v_result = eval(str(last_v_result), globals())
                print(
                    "idx",
                    self.operation_executed_count.value,
                    "op_result",
                    hex(last_operation.op_result),
                    "eval_v_result",
                    hex(last_operation.eval_v_result),
                )

    def evaluate_current_symbolic_state(self, operation: Operation):
        """
        Evaluate the current symbolic state of the registers and memory
        """
        # register new variables var_xxxxx
        vars_to_register = sorted(
            set(self.symbolic_taint_store.keys()).difference(set(globals().keys()))
        )
        for var_name in vars_to_register:
            if var_name.startswith("var_"):
                globals()[var_name] = eval(
                    str(self.symbolic_taint_store[var_name]), globals()
                )

        # eval last mem access
        if operation.mem_access:
            name = create_name_from_address(operation.mem_access)
            if name in self.symbolic_taint_store:
                globals()[name] = eval(str(self.symbolic_taint_store[name]), globals())
            else:
                globals()[name] = self.engine.read_memory_int(operation.mem_access)

        # update registers values
        for op in operation.cinsn.operands:
            if op.type == X86_OP_REG:
                reg_name = self.cs.reg_name(op.reg)
                if reg_name in self.symbolic_taint_store:
                    globals()[reg_name] = eval(
                        str(self.symbolic_taint_store[reg_name]), globals()
                    )

    def register_execution_state(
        self, current_operation: Operation, last_operation: Operation
    ):
        idx = self.operation_executed_count.value

        for operation in (current_operation, last_operation):
            if operation is None:
                continue

            # Register last instructions changes
            for i in range(min(len(operation.cinsn.operands), 3)):
                operand = operation.cinsn.operands[i]

                if operand.type == X86_OP_REG:
                    # update the parent register
                    register_name = get_parent_register(
                        self.cs.reg_name(operand.reg), self.CONFIG["BINARY_ARCH_SIZE"]
                    )
                    register_value = self.engine.read_reg(register_name.upper())
                    self.registers_state.register_item(
                        register_name, idx, register_value
                    )

                elif operand.type == X86_OP_MEM:
                    address = operation.mem_access
                    if address is None:
                        continue
                    name = create_name_from_address(address)
                    memory_value = self.engine.read_memory_int(address)
                    self.memory_state.register_item(name, idx, memory_value)

        # register pc
        pc_name = "RIP" if self.CONFIG["BINARY_ARCH_SIZE"] == 64 else "EIP"
        self.registers_state.register_item(pc_name, idx, self.engine.get_ea())

    def initialize_execution_state(self):
        for reg_id in self.engine.map_regs():
            try:
                reg_name = self.cs.reg_name(reg_id)
                register_value = self.engine.read_reg(reg_name.upper())
                self.registers_state.register_item(reg_name, 0, register_value)
            except (KeyError, AttributeError):
                pass

    def initialize(self):
        self.initialize_execution_state()
        self.initialize_symbolic_evaluator()

    def clone(self):
        # delete current ql hooks
        self.engine.clear()
        new_runner = self.__class__(self.engine, self.debug_level, self.timeout)
        # Copy the state of VariableStates
        new_runner.state = self.symbolic_taint_store.clone()
        # Copy architecture-specific attributes
        new_runner.cs = self.cs
        new_runner.ks = self.ks
        new_runner.operation_engine = self.operation_engine
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
        new_runner.operation_executed_count = self.operation_executed_count
        # copy data store
        new_runner.registers_state = self.registers_state.clone()
        new_runner.memory_state = self.memory_state.clone()
        return new_runner


class QilingRunner(Runner):
    def __init__(self, engine, debug_level, timeout, symbolic_check, *args):
        super().__init__(engine, debug_level, timeout, symbolic_check, *args)

        self.ql = engine.ql

        # Check if the architecture is 32-bit or 64-bit
        if self.ql.arch.type == QL_ARCH.X8664:
            self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
            self.ks = Ks(KS_ARCH_X86, KS_MODE_64)

        elif self.ql.arch.type == QL_ARCH.X86:
            self.cs = Cs(CS_ARCH_X86, CS_MODE_32)
            self.ks = Ks(KS_ARCH_X86, KS_MODE_32)

        # Find the base and end address of the text section
        self.text_base = self.ql.loader.images[0].base
        self.text_end = self.ql.loader.images[0].end

    def initialize_configuration(self):
        """
        Initialize the global shared among all the modules via superglobal library
        """

        if self.ql.arch.type in (QL_ARCH.X86, QL_ARCH.X8664):
            self.CONFIG["BAD_OPERANDS"] = BAD_OPERANDS_X86_64

        if self.ql.arch.type == QL_ARCH.X8664:
            self.CONFIG["BINARY_MAX_MASK"] = 0xFFFFFFFFFFFFFFFF
            self.CONFIG["BINARY_ARCH_SIZE"] = 64

        elif self.ql.arch.type == QL_ARCH.X86:
            self.CONFIG["BINARY_MAX_MASK"] = 0xFFFFFFFF
            self.CONFIG["BINARY_ARCH_SIZE"] = 32

        # make first update
        setglobal("CONFIG", self.CONFIG)
        # Must be called after CONFIG BINARY_MAX_MASK and BINARY_ARCH_SIZE are set
        self.CONFIG["SYM_REGISTER_FACTORY"] = create_sym_register_factory()
        self.CONFIG["IS_INITIALIZED"] = True
        # make second update
        setglobal("CONFIG", self.CONFIG)

    def initialize(self):
        if self.CONFIG["IS_INITIALIZED"]:
            return
        # Synchronize config with the global config
        self.initialize_configuration()
        self.operation_engine.set_config(self.CONFIG)
        super().initialize()

        # Set up memory read, memory write, and code hooks
        self.ql.hook_mem_read(self.memory_read_hook)
        self.ql.hook_mem_write(self.memory_write_hook)
        self.ql.hook_code(self.code_execution_hook)

    def run_emulation(self):
        # must be call at the start of the emulation and not before
        self.initialize()
        # Start measuring emulation time
        self.start_time = time.time()
        try:
            # Start Qiling engine emulation
            self.ql.run(self.addr_emu_start)
        except (UserStoppedExecution, unicorn.UcError) as e:
            log(
                DebugLevel.ERROR,
                f"Emulation stopped: {e}",
                self.debug_level,
                ANSIColors.ERROR,
            )
        finally:
            # Calculate emulation time and instructions per second
            end_time = time.time()
            self.emulation_time += end_time - self.start_time
            instructions_per_second = (
                self.operation_executed_count.value / self.emulation_time
            )
            # Format the output message
            output = "\n".join(
                [
                    "=" * 80,
                    f"Emulation time: {self.emulation_time:.1f} seconds",
                    f"{self.operation_executed_count.value} instructions executed",
                    f"Operations per second: {instructions_per_second:.1f}",
                    "=" * 80,
                ]
            )
            # Log emulation results
            log(DebugLevel.ERROR, output, self.debug_level, ANSIColors.OKGREEN)

            # print performance report
            global profile
            profile.print_stats()

            # post process
            self.trace_records.post_process()
