#########################################################
# Author: @d0raken - Antoine Blaud
# Date: 2023-09-18
# CodexRebirth is a symbolic execution engine based on Qiling
# It is used to emulate a binary and to extract the symbolic execution trace
#########################################################

from contextlib import suppress
import contextlib
from capstone.x86_const import X86_OP_MEM, X86_OP_REG, X86_OP_IMM
import random
from capstone import *
from typing import Mapping
from capstone import Cs
from unicorn.unicorn_const import UC_MEM_READ, UC_MEM_WRITE
from unicorn import unicorn
from qiling import Qiling
from qiling.const import QL_ARCH
from keystone import *
import re
from superglobals import *


from z3 import (
    BitVec,
    BitVecVal,
    set_option,
)
import z3
import sys
import time
import itertools
import textwrap
import uuid
import traceback


from codexrebirth.exceptions import *

# get current stdout
stdout = sys.stdout
# check if stdout is a tty
isatty = stdout.isatty()


__all__ = ["DebugLevel", "ARCH", "CodexRebirth", "Instruction", "TraceEntry"]




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


class _Color:
    ANSI_COLOR_FORMAT = "\033[38;5;{}m"

    def __init__(self):
        self.color_code = self.ANSI_COLOR_FORMAT.format(random.randint(30, 200))

    def __repr__(self):
        return self.color_code

    def get_colored_text(self, text):
        """
        Returns the input text with the ANSI color code applied.
        """
        if not isatty:
            return text
        return f"{self.color_code}{text}\033[0m"


class ANSIColors:
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    PURPLE = "\033[95m"
    ERROR = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


def log(dlevel, message, debug_level, color):
    """
    Log messages based on the debug level.

    Args:
        dlevel (int): Debug level.
        info (str): Information to log.
    """
    date = time.strftime("%H:%M:%S", time.localtime())
    if dlevel <= debug_level:
        if isatty:
            message = f"\033[2m{date}\033[0m  {color}{message}\033[0m"
        else:
            message = f"{message}"
        print(message)


class ARCH:
    X86 = {
        "binary_mask": 0xFFFFFFFF,
        "binary_size": 32,
    }
    X86_64 = {
        "binary_mask": 0xFFFFFFFFFFFFFFFF,
        "binary_size": 64,
    }


class ArchitectureTranslator(dict):
    def __init__(self):
        super().__init__(
            {
                "X86": ARCH.X86,
                "x64": ARCH.X86_64,
            }
        )


if getglobal("BINARY_ARCH") is None:
    msg = (
        "BINARY_ARCH not defined, please define it in your script before importing CodexRebirth\n"
        + "from superglobals import setglobal\n"
        + "setglobal('BINARY_ARCH', 'X86') # X86, X64,\n"
        + "from codexrebirth.corexrebirth import *"
    )
    log(DebugLevel.ERROR, msg, DebugLevel.ERROR, ANSIColors.ERROR)
    raise SetupError(msg)

if getglobal("BINARY_ARCH") not in ArchitectureTranslator():
    msg = f"Unknown architecture {getglobal('BINARY_ARCH')}, please choose between X86 or X64"
    log(DebugLevel.ERROR, msg, DebugLevel.ERROR, ANSIColors.ERROR)
    raise SetupError(msg)

BINARY_ARCH = ArchitectureTranslator()[getglobal("BINARY_ARCH")]

BINARY_MAX_MASK = BINARY_ARCH["binary_mask"]
BINARY_ARCH_SIZE = BINARY_ARCH["binary_size"]
MAX_RAW_REPR_LENGTH = 88
new_var_counter = itertools.count(1)


###################################################################################################
# Utility functions
# - reformat_expression
# - instructions/addr get
# - check_memory_access
# - log
# - Some math functions for binary operations
###################################################################################################


def extract_special_marker(expression, marker):
    while marker in expression:
        index = expression.find(marker)
        if index >= 0:
            open_parenthesis_count = 0
            for i in range(index + len(marker) - 1, -1, -1):
                if expression[i] == ")":
                    open_parenthesis_count += 1
                elif expression[i] == "(":
                    open_parenthesis_count -= 1
                    if open_parenthesis_count == 0:
                        expression = (
                            expression[:i]
                            + "addrof"
                            + expression[i:index]
                            + ""
                            + expression[index + len(marker) :]
                        )
                        break
    return expression


def remove_all_masks(expression):
    return re.sub(r"&[ ]*0xfffff*", "", expression)


def replace_integers_with_hex(input_string):
    # Define a regular expression pattern to match integers
    integer_pattern = r"\b\d+\b"

    # Use a lambda function to convert matched integers to hexadecimal format
    hex_string = re.sub(
        integer_pattern, lambda match: hex(int(match.group())), input_string
    )

    return hex_string


def reformat_expression(expression):
    # expression = simplify_parentheses(expression)
    expression = expression.strip().replace("\t", " ").replace("\n", " ")
    expression = replace_integers_with_hex(expression)
    expression = expression.replace(" ", "")
    expression = extract_special_marker(expression, "*0x1111")
    special_operators = ["^", "*", "&", "|", "+"]
    for operator in special_operators:
        expression = expression.replace(operator, f" {operator} ")
    return expression


def __map_regs() -> Mapping[int, int]:
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


# capstone to unicorn regs mapping
CS_UC_REGS = __map_regs()


def get_instruction_address(ql):
    if ql.arch.type == QL_ARCH.X8664:
        return ql.arch.regs.rip
    elif ql.arch.type == QL_ARCH.X86:
        return ql.arch.regs.eip

    raise ValueError("Unknown architecture type")


def get_current_instruction(ql):
    pc = get_instruction_address(ql)
    md = ql.arch.disassembler
    buf = ql.mem.read(pc, 0x10)
    return next(md.disasm(buf, pc))


def get_instruction_from_address(ql, addr):
    pc = addr
    md = ql.arch.disassembler
    buf = ql.mem.read(pc, 0x10)
    return next(md.disasm(buf, pc))


def get_stack_pointer(ql):
    if ql.arch.type == QL_ARCH.X8664:
        return ql.arch.regs.rsp
    elif ql.arch.type == QL_ARCH.X86:
        return ql.arch.regs.esp
    raise ValueError("Unknown architecture type")


def check_memory_access(insn):
    # lea instruction is not a memory access
    if insn.mnemonic == "lea":
        return False

    for op in insn.operands:
        if op.type == X86_OP_MEM:
            return True
    return False


def read_while_ptr(ql, addr):
    real_value = addr
    if is_mapped(ql, addr):
        real_value = read_memory_int(ql, addr)
        while is_mapped(ql, real_value):
            real_value = read_memory_int(ql, real_value)
    return real_value


def ask_to_continue(sentence):
    try:
        import easygui
        y_n = easygui.ynbox(f"{sentence}\n")
        if not y_n:
            raise UserStoppedExecution("User stopped the execution")
        
    except EOFError as e:
        print(f"Unexpected error: {e}")
        y_n = input(f"{sentence}\n[y/n]: ")
        if y_n.lower() == "n":
            raise UserStoppedExecution("User stopped the execution")



def create_name_from_addr(name):
    # Process the name, converting integers to 'mem_0xXXXX' format
    if isinstance(name, int):
        return "mem_" + hex(name)
    return name


def Not(x):
    return ~x & BINARY_MAX_MASK


def binary_subtraction(X, Y):
    # Calculate the two's complement of Y
    # Assuming 64-bit integers
    Y_complement = (Not(Y) + 1) & BINARY_MAX_MASK
    # Perform binary subtraction by adding X and the two's complement of Y
    result = (X + Y_complement) & BINARY_MAX_MASK
    return result


# Must only be used with 'eval' function to evaluate the expression
def RotateLeft(x, n):
    return ((x << n) | (x >> (BINARY_ARCH_SIZE - n))) & BINARY_MAX_MASK


# Must only be used with 'eval' function to evaluate the expression
def RotateRight(x, n):
    return ((x >> n) | (x << (BINARY_ARCH_SIZE - n))) & BINARY_MAX_MASK


def read_memory_int(ql, address):
    return int.from_bytes(
        ql.mem.read(address, BINARY_ARCH_SIZE // 8), byteorder="little"
    )


def is_mapped(ql: Qiling, address):
    if not isinstance(address, int):
        return False

    for start, end, _, _, _ in ql.mem.map_info:
        if start <= address <= end:
            return True
    return False


# This class is used to store the name of the symbolic variables
# and also name for functions, and memory addresses
class AddressBook(dict):
    def __init__(self):
        super().__init__()

    def __repr__(self) -> str:
        return super().__repr__()


# Instanciate the AddressBook class, used to store the name of the symbolic variables
AddressBookInst = AddressBook()


# This class is used to store the name of the symbolic variables
# and also name for functions, and memory addresses
class ValueBook(dict):
    def __init__(self):
        super().__init__()

    def __repr__(self) -> str:
        return super().__repr__()


ValueBookInst = ValueBook()


# This class is used to store the mask of the symbolic variables
# from tainted memory addresses
class MaskBook(dict):
    def __init__(self):
        super().__init__()

    def __repr__(self) -> str:
        return super().__repr__()


MaskBookInst = MaskBook()


###################################################################################################
# Instruction set definitions
###################################################################################################


class InstructionSet(list):
    def __init__(self, insn_list):
        super().__init__()
        # set items to the list
        self.extend(insn_list)

    def __contains__(self, insn):
        for item in self:
            if re.match(item, insn):
                return True
        return False


# class used to store Unicorn operand and our own operand
class Instruction:
    def __init__(self, cinsn):
        # Instruction can have up to 3 operands
        self.op1 = None
        self.op2 = None
        self.op3 = None
        self.cinsn = cinsn
        self.v_op1 = None
        self.v_op2 = None
        self.v_op3 = None

    def __repr__(self) -> str:
        res = self.cinsn.mnemonic + " " + self.cinsn.op_str + "\n"
        if self.v_op1:
            res += f"op1 = {self.v_op1}\n"
        elif self.op1:
            res += f"op1 = {self.op1}\n"   
            
        if self.v_op2:
            res += f"op2 = {self.v_op2}\n"
        
        elif self.op2:
            res += f"op2 = {self.op2}\n"
            
        if self.v_op3:
            res += f"op3 = {self.v_op3}\n"
            
        elif self.op3:
            res += f"op3 = {self.op3}\n"
            
        return res

    def clone(self):
        clone = Instruction(self.cinsn)
        clone.op1 = self.op1
        clone.op2 = self.op2
        clone.op3 = self.op3
        clone.v_op1 = self.v_op1.clone() if self.v_op1 else None
        clone.v_op2 = self.v_op2.clone() if self.v_op2 else None
        clone.v_op3 = self.v_op3.clone() if self.v_op3 else None
        return clone


class TraceEntry:
    def __init__(self, Insn: Instruction, is_symbolic: bool) -> None:
        self.Insn = Insn
        self.is_symbolic = is_symbolic

    def __repr__(self) -> str:
        return f"{self.Insn}, {self.is_symbolic}"


class Trace(dict):
    # store all instructions that have been executed
    def __init__(self):
        super().__init__()
        self.counter = 0

    def register(self, insn_addr: int, Insn: Instruction, is_symbolic: bool) -> None:
        if insn_addr not in self:
            self[insn_addr] = {}
        self[insn_addr][self.counter] = TraceEntry(Insn.clone(), is_symbolic)
        self.counter += 1

    def __repr__(self) -> str:
        res = ""
        for addr in self:
            res += f"{hex(addr)}:\n"
            for counter in self[addr]:
                res += f"\t{counter}: {self[addr][counter].Insn, self[addr][counter].is_symbolic}\n"
        return res


# instanciante the CodexDump class, used to register all instructions that have been executed
TraceInst = Trace()


class SymValue:
    def __init__(self) -> None:
        pass


###################################################################################################
# *Value, *Memory, *Register classes
# Used to store real and symbolic operands and values
# We apply operation, on them, proagate values, etc...
###################################################################################################


# _SymValue and _RealValue are used to store symbolic(ast) and real values


# This class is used to store symbolic values
# We have to wrap 'value' inside a object class to avoid
# copy and reference problems, specially when we have to clone it
class _SymValue:
    def __init__(self, value):
        self._value = value

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, new_value):
        self._value = new_value

    def __repr__(self):
        value_str = str(self.value)
        for key, _ in AddressBookInst.items():
            value_str = value_str.replace(key, AddressBookInst[key])
        value_str = reformat_expression(value_str)
        return value_str

    def __raw_repr__(self):
        return str(self.value)

    def clone(self):
        return _SymValue(self.value)

    def __and__(self, other: int):
        if other != BINARY_ARCH_SIZE:
            return _SymValue(self.value & (1 << other) - 1)
        else:
            return self


# This class is used to store real values
# We have to wrap 'value' inside a object class to avoid
# copy and reference problems, specially when we have to clone it
class _RealValue:
    def __init__(self, value):
        self._value = value

    def __repr__(self):
        return str(self.value)

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, new_value):
        self._value = new_value

    @property
    def sym_value(self):
        return self._value


# ==================================================================================================
# _RealValue are wrapped by RealValue
# With this wrapper, we can apply operation between all kind of values
# -> RealValue -> _RealValue
# -> SymValue -> SymRegister, SymMemory -> _SymValue


class RealValue:
    def __init__(self, value):
        self.sym_value = _RealValue(value)

    @property
    def value(self):
        return self.sym_value.value

    @property
    def size(self):
        return BINARY_ARCH_SIZE

    def clone(self):
        return RealValue(self.sym_value.value)

    # For the following methods, we have to clone the 'other' object
    # because we apply the operation on the 'other' object itself,
    # even if the dest operand is not the other object
    # We proceding like this because we want to make operation on
    # SymValue and not RealValue in the end
    # Also, as we working in 32 or 64 bits, we have to mask the result

    def __repr__(self) -> str:
        return self.sym_value.__repr__()

    def __add__(self, other):
        other = other.clone()
        other.sym_value.value += self.sym_value.value
        other.sym_value.value &= BINARY_MAX_MASK
        return other

    def __sub__(self, other):
        other = other.clone()
        other.sym_value.value = binary_subtraction(
            self.sym_value.value, other.sym_value.value
        )
        return other

    def __xor__(self, other):
        other = other.clone()
        other.sym_value.value ^= self.sym_value.value
        return other

    def __and__(self, other):
        other = other.clone()
        other.sym_value.value &= self.sym_value.value
        return other

    def __mul__(self, other):
        other = other.clone()
        other.sym_value.value *= self.sym_value.value
        if not (isinstance(other.sym_value, int) and other.sym_value.value == 0x1111):
            other.sym_value.value &= BINARY_MAX_MASK
        return other

    def __or__(self, other):
        other = other.clone()
        other.sym_value.value |= self.sym_value.value
        return other

    def __div__(self, other):
        other = other.clone()
        other.sym_value.value /= self.sym_value.value
        return other

    def __rshift__(self, other):
        other = other.clone()
        other.sym_value.value >>= self.sym_value.value
        other.sym_value.value &= BINARY_MAX_MASK
        return other

    def __lshift__(self, other):
        other = other.clone()
        other.sym_value.value <<= self.sym_value.value
        other.sym_value.value &= BINARY_MAX_MASK
        return other

    def ror(self, other):
        other = other.clone()
        other.sym_value.value = z3.RotateRight(
            other.sym_value.value, self.sym_value.value
        )
        return other

    def rol(self, other):
        other = other.clone()
        other.sym_value.value = z3.RotateLeft(
            other.sym_value.value, self.sym_value.value
        )
        return other

    def _not(self):
        self.sym_value.value = ~self.sym_value.value & BINARY_MAX_MASK
        return self


class SymMemory(SymValue):
    def __init__(self, name: int, value: int = None):
        super().__init__()
        self.color = _Color()
        self.name = name
        self._value = value
        if isinstance(value, int):
            self.sym_value = _SymValue(BitVecVal(value, BINARY_ARCH_SIZE))
        elif isinstance(name, str):
            self.sym_value = _SymValue(BitVec(name, BINARY_ARCH_SIZE))
        else:
            raise Exception("SymMemory name must be a string")

    @property
    def size(self):
        return BINARY_ARCH_SIZE

    @property
    def value(self):
        # return ast_value of _SymValue
        return self.sym_value.value

    def update(self, target):
        if isinstance(target, (_SymValue)):
            self.sym_value = target.clone()
        elif isinstance(target, SymValue):
            self.sym_value = target.sym_value.clone()

    def clone(self):
        clone = SymMemory(self.name, self._value)
        clone.sym_value = self.sym_value.clone()
        return clone

    def __repr__(self) -> str:
        return f"{self.sym_value.__repr__()}"

    def __add__(self, other):
        self.sym_value.value += other.sym_value.value
        self.sym_value.value &= BINARY_MAX_MASK
        return self

    def __sub__(self, other):
        self.sym_value.value = binary_subtraction(
            self.sym_value.value, other.sym_value.value
        )
        return self

    def __xor__(self, other):
        self.sym_value.value ^= other.sym_value.value
        return self

    def __and__(self, other):
        self.sym_value.value &= other.sym_value.value
        return self

    def __mul__(self, other):
        self.sym_value.value *= other.sym_value.value
        if not (isinstance(other.sym_value, int) and other.sym_value.value == 0x1111):
            self.sym_value.value &= BINARY_MAX_MASK
        return self

    def __or__(self, other):
        self.sym_value.value |= other.sym_value.value
        return self

    def __div__(self, other):
        self.sym_value.value /= other.sym_value.value
        return self

    def __rshift__(self, other):
        self.sym_value.value >>= other.sym_value.value
        self.sym_value.value &= BINARY_MAX_MASK
        return self

    def __lshift__(self, other):
        self.sym_value.value <<= other.sym_value.value
        self.sym_value.value &= BINARY_MAX_MASK
        return self

    def ror(self, other):
        self.sym_value.value = z3.RotateRight(
            self.sym_value.value, other.sym_value.value
        )
        return self

    def rol(self, other):
        self.sym_value.value = z3.RotateLeft(
            self.sym_value.value, other.sym_value.value
        )
        return self

    def _not(self):
        self.sym_value.value = ~self.sym_value.value & BINARY_MAX_MASK
        return self


class SymRegister(SymValue):
    # This class is used to store symbolic data inside registers
    # It is used to propagate values to all registers that are part of the same register
    # self.

    def __init__(self, name, high, low, parent=None):
        super().__init__()
        self.parent = parent
        self.color = _Color() if not parent else parent.color
        self._low = low
        self._high = high
        self._name = name
        if parent:
            assert self.high <= parent.high
            self.sym_value = parent.sym_value.clone()
        else:
            self.sym_value = _SymValue(BitVec(str(name), BINARY_ARCH_SIZE))

        assert high >= low

    @property
    def name(self):
        return self._name

    @property
    def high(self):
        return self._high

    @property
    def low(self):
        return self._low

    @property
    def size(self):
        return self.high - self.low + 1

    @property
    def value(self):
        # return ast_value of _SymValue
        return self.sym_value.value

    @value.setter
    def value(self, new_value):
        self.update(new_value)

    def __getitem__(self, index):
        assert isinstance(index, slice) and index.step is None
        return SymRegister(self, index.start, index.stop)

    def _set(self, target: _SymValue):
        # Update current symbolic value, depending of the target value
        # and the current register size
        # Ex: If target is rax and self is eax, then self = rax & 0xffffffff
        if isinstance(target, (_SymValue)):
            self.sym_value = target.clone()
            # TODO: check target size diferrent from self
        elif isinstance(target, SymValue):
            self.sym_value = target.sym_value.clone()

        else:
            raise Exception("Target type unknown '{}'".format(type(target)))

        # if self.low != 0:
        #         # adjust self.sym_value to with self high and low using z3 extract
        #     self.sym_value.value = Extract(self.high, self.low, self.sym_value.value)

    def __setitem__(self, index, target):
        raise Exception(
            "You cannot set a value with =, use .update() instead\n Not implemented in order \
            to remain that register are dependent of each other"
        )

    def update(self, target):
        # Propagate value to all symbolic registers that are part of this register
        # ex: 'ah': [rax, eax, ax, ah, al]
        if self.name in SymRegisterFactory:
            [reg._set(target) for reg in SymRegisterFactory[self.name]]
        else:
            self._set(target)
        return self

    def reset(self):
        self.sym = _SymValue(BitVec(str(self.name), BINARY_ARCH_SIZE))
        self.color = _Color()
        return self

    def apply_mask(self, other):
        if isinstance(other, RealValue) and self.size != BINARY_ARCH_SIZE:
            other.sym_value.value &= (1 << self.size) - 1

        if isinstance(other, SymValue) and self.size != other.size:
            other.sym_value.value &= (1 << self.size) - 1

        return other

    def clone(self):
        cloned_name = "{}_clone_{}".format(self.name, str(uuid.uuid4()))
        clone = SymRegister(cloned_name, self.high, self.low, self.parent)
        clone._set(self.sym_value)
        return clone

    def __repr__(self) -> str:
        return self.sym_value.__repr__()

    def __add__(self, other):
        other = self.apply_mask(other)
        self.sym_value.value += other.sym_value.value
        self.sym_value.value &= BINARY_MAX_MASK
        return self.update(self.sym_value)

    def __sub__(self, other):
        other = self.apply_mask(other)
        self.sym_value.value = binary_subtraction(
            self.sym_value.value, other.sym_value.value
        )
        return self.update(self.sym_value)

    def __xor__(self, other):
        other = self.apply_mask(other)
        self.sym_value.value ^= other.sym_value.value
        return self.update(self.sym_value)

    def __and__(self, other):
        other = self.apply_mask(other)
        self.sym_value.value &= other.sym_value.value
        return self.update(self.sym_value)

    def __mul__(self, other):
        other = self.apply_mask(other)
        self.sym_value.value *= other.sym_value.value
        self.sym_value.value &= BINARY_MAX_MASK
        return self.update(self.sym_value)

    def __or__(self, other):
        other = self.apply_mask(other)
        self.sym_value.value |= other.sym_value.value
        return self.update(self.sym_value)

    def __div__(self, other):
        other = self.apply_mask(other)
        self.sym_value.value /= other.sym_value.value
        return self.update(self.sym_value)

    def __rshift__(self, other):
        self.sym_value.value >>= other.sym_value.value
        self.sym_value.value &= BINARY_MAX_MASK
        return self.update(self.sym_value)

    def __lshift__(self, other):
        self.sym_value.value <<= other.sym_value.value
        self.sym_value.value &= BINARY_MAX_MASK
        return self.update(self.sym_value)

    def ror(self, other):
        return self.update(
            _SymValue(z3.RotateRight(self.sym_value.value, other.sym_value.value))
        )

    def rol(self, other):
        return self.update(
            _SymValue(z3.RotateLeft(self.sym_value.value, other.sym_value.value))
        )

    def _not(self):
        self.sym_value.value = ~self.sym_value.value & BINARY_MAX_MASK
        return self.update(self.sym_value)


if BINARY_ARCH in (ARCH.X86_64, ARCH.X86):
    SUPPORTED_INSTRUCTIONS = InstructionSet(
        [
            ".?mov.*",
            "lea",
            "add",
            "sub",
            "xor",
            "and",
            "or",
            "imul",
            "shl",
            "shr",
            "sar",
            "cdq",
            "rol",
            "ror",
            "mul",
            "not",
            "cmp",
            "test",
            "push",
            "pop",
            "sete"
        ]
    )

    rax = SymRegister("rax", 63, 0)
    rcx = SymRegister("rcx", 63, 0)
    rdx = SymRegister("rdx", 63, 0)
    rbx = SymRegister("rbx", 63, 0)
    rbp = SymRegister("rbp", 63, 0)
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
    ebp = SymRegister("ebp", 31, 0, rbp)
    esi = SymRegister("esi", 31, 0, rsi)
    edi = SymRegister("edi", 31, 0, rdi)
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

    al = SymRegister("al", 7, 0, ax)
    cl = SymRegister("cl", 7, 0, cx)
    dl = SymRegister("dl", 7, 0, dx)
    bl = SymRegister("bl", 7, 0, bx)
    bpl = SymRegister("bpl", 7, 0, bp)
    sil = SymRegister("sil", 7, 0, si)
    dil = SymRegister("dil", 7, 0, di)
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
    }


class CodexState(dict):
    def __init__(self):
        super().__init__()

    def __contains__(self, key_object: object) -> bool:
        # Check if a key_object (possibly processed) exists in the dictionary
        processed_name = create_name_from_addr(key_object)
        return super().__contains__(processed_name)

    def new_symbolic_register(self, name) -> SymRegister:
        # Create a new symbolic register and propagate the value to its parts (e.g., 'ah' to ['rax', 'eax', 'ax', 'ah', 'al'])
        for reg in SymRegisterFactory[name]:
            self[reg.name] = reg.reset()
        return self[name]

    def __setitem__(self, key, value):
        # Set an item in the dictionary after processing the key
        processed_key = create_name_from_addr(key)
        super().__setitem__(processed_key, value)

    def __getitem__(self, key):
        # Get an item from the dictionary after processing the key
        processed_key = create_name_from_addr(key)
        return super().__getitem__(processed_key)

    def new_symbolic_memory(self, address, value=None):
        # Create a new symbolic memory object
        name = create_name_from_addr(address)
        self[name] = SymMemory(name, value)
        return self[name]

    def delete_symbolic_var(self, name):
        # Delete a symbolic variable, handling register parts and individual variables
        processed_name = create_name_from_addr(name)
        if processed_name in self:
            if (
                isinstance(self[processed_name], SymRegister)
                and processed_name == self[processed_name].name
            ):
                for reg in SymRegisterFactory[processed_name]:
                    try:
                        del self[reg.name]
                    except KeyError:
                        pass
            else:
                del self[processed_name]

    def __repr__(self) -> str:
        # Prepare a representation of the CodexState object for printing
        representation = []

        # Add _SymValue entries (e.g., var_00XXX) to the representation
        sym_value_entries = [
            f"{key} = {value}"
            for key, value in self.items()
            if isinstance(value, _SymValue)
        ]
        representation.extend(sym_value_entries)

        # Add SymRegister entries (e.g., rax, eax, ax, ah, al) to the representation
        sym_register_entries = [
            f"{key} = {value}"
            for key, value in self.items()
            if isinstance(value, SymRegister)
        ]
        representation.extend(sym_register_entries)

        # Add SymMemory entries (e.g., mem_0xXXXX) to the representation
        sym_memory_entries = [
            f"{key} = {value}"
            for key, value in self.items()
            if isinstance(value, SymMemory)
        ]
        representation.extend(sym_memory_entries)

        # Join all entries into a string with newline separators
        return "\n".join(representation)


class CodexInstructionEngineX86_64:
    """
    A class for performing symbolic execution on x86-64 machine code using Qiling.

    Args:
        ql_instance (Qiling): An instance of the Qiling emulator.
        debug_level (int): The level of debugging to use during execution.
        symbolic_check_interval (int, optional): The number of instructions to execute before performing a symbolic check. Defaults to 1000.
        strict_symbolic_check (bool, optional): Whether to perform strict symbolic checks. Defaults to True.
    """

    def __init__(
        self, ql_instance, debug_level, symbolic_check=True, strict_symbolic_check=False
    ):
        # Store the Qiling instance and configure Capstone disassembler and Keystone assembler
        self.ql = ql_instance
        self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
        self.cs.detail = True
        self.ks = Ks(KS_ARCH_X86, KS_MODE_64)
        self.ks.detail = True

        # Initialize variables for tracking the last executed instruction
        self.last_instruction_executed = None
        self.is_last_instruction_symbolic = False

        # Set the debug level and symbolic execution check interval
        self.debug_level = debug_level
        self.symbolic_check = symbolic_check

        # Specify whether to perform strict symbolic checks
        self.strict_symbolic_check = strict_symbolic_check

    def check_symop_div(self, insn, codex_state: CodexState):
        if insn.mnemonic == "div":
            for reg in SymRegisterFactory["rax"]:
                if reg in codex_state:
                    log(
                        DebugLevel.DEBUG,
                        f"Symbolic register found in {reg.name} => {codex_state[reg.name]}",
                        self.debug_level,
                        ANSIColors.PURPLE,
                    )
                    return True
            op1 = insn.operands[0]
            regname = self.cs.reg_name(op1.reg)
            if regname in codex_state:
                log(
                    DebugLevel.DEBUG,
                    f"Symbolic register found in {regname} => {codex_state[regname]}",
                    self.debug_level,
                    ANSIColors.PURPLE,
                )
                return True
            return False

    def process_mem_access(self, op, codex_state: CodexState):
        # Return the symbolic register that is used in the mem_access instruction (ex: lea rbx, [rax + 5]) with
        # rax symbolic
        # if no symbolic register is used, return RealValue
        value = RealValue(0)

        if op.mem.base != 0:
            base = self.ql.arch.regs.read(self.cs.reg_name(op.mem.base))
            # if the register is symbolic, fetch it from the codex_state
            if self.cs.reg_name(op.mem.base) in codex_state:
                value = codex_state[self.cs.reg_name(op.mem.base)].clone()
            else:
                value = RealValue(base)

        if op.mem.index != 0:
            index = self.ql.arch.regs.read(self.cs.reg_name(op.mem.index))
            if self.cs.reg_name(op.mem.index) in codex_state:
                if not value:
                    value = codex_state[self.cs.reg_name(op.mem.index)].clone()
                else:
                    # process in this order to avoid adding a SymValue to a RealValue
                    value = codex_state[self.cs.reg_name(op.mem.index)].clone() + value
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

    def is_symbolic_operation(self, mem_access, insn, codex_state: CodexState):
        # if isnn is div, we need to check if the register or eax are symbolic
        if self.check_symop_div(insn, codex_state):
            return True

        if insn.mnemonic == "mul" and len(insn.operands) == 1 and "rax" in codex_state:
            return True

        if insn.mnemonic == "pop":
            stack_pointer = get_stack_pointer(self.ql)
            if stack_pointer in codex_state:
                return True

        # For operands in instruction, if the operand is a sym register, or a sym memory, return True
        for op in insn.operands:
            # Check if the operand is a register
            if op.type == X86_OP_REG:
                regname = self.cs.reg_name(op.reg)
                # If the register is in the dictionary, set the flag
                if regname in codex_state:
                    log(
                        DebugLevel.DEBUG,
                        f"Symbolic register found in {regname} => {codex_state[regname].sym_value}",
                        self.debug_level,
                        ANSIColors.PURPLE,
                    )
                    return True

            # Check if the operand is a memory access
            if op.type == X86_OP_MEM and mem_access in codex_state:
                log(
                    DebugLevel.DEBUG,
                    f"Symbolic memory found in {hex(mem_access)} => {codex_state[mem_access]}",
                    self.debug_level,
                    ANSIColors.PURPLE,
                )
                return True

            elif op.type == X86_OP_MEM:
                # get register used in the memory access
                sym_access = self.process_mem_access(op, codex_state)
                if isinstance(sym_access, SymValue):
                    # add sym_access to codex_state
                    log(
                        DebugLevel.DEBUG,
                        f"Symbolic indirect access found => {sym_access.sym_value}",
                        self.debug_level,
                        ANSIColors.PURPLE,
                    )
                    return True

        return False

    def parse_insn_operands(
        self, ql, insn, mem_access, codex_state: CodexState
    ) -> Instruction:
        # Parse the operands of the instruction, create symbolic values if needed, and return the Instruction object

        Insn = Instruction(insn)
        if len(Insn.cinsn.operands) == 0:
            return Insn

        # Check if the operand is a symbolic memory access and create a symbolic value
        for op in insn.operands:
            if op.type == X86_OP_MEM:
                sym_access = self.process_mem_access(op, codex_state)
                if isinstance(sym_access, SymValue):
                    log(
                        DebugLevel.DEBUG,
                        f"Adding symbolic memory {hex(mem_access)} => {sym_access.sym_value}",
                        self.debug_level,
                        ANSIColors.PURPLE,
                    )
                    codex_state[mem_access] = sym_access
                    break

        # Process the operands
        for i in range(min(len(Insn.cinsn.operands), 3)):
            operand = Insn.cinsn.operands[i]
            setattr(Insn, f"op{i+1}", operand)

            if operand.type == X86_OP_REG:
                regname = self.cs.reg_name(operand.reg)
                if regname in codex_state:
                    setattr(Insn, f"v_op{i+1}", codex_state[regname])
                else:
                    setattr(
                        Insn,
                        f"v_op{i+1}",
                        RealValue(ql.arch.regs.read(regname.upper())),
                    )

            elif operand.type == X86_OP_IMM:
                setattr(Insn, f"v_op{i+1}", RealValue(operand.imm))

            elif operand.type == X86_OP_MEM:
                if Insn.cinsn.mnemonic in [
                    "cmp",
                    "test",
                ]:
                    if mem_access > is_mapped(self.ql, mem_access):
                        setattr(
                            Insn,
                            f"v_op{i+1}",
                            RealValue(read_memory_int(self.ql, mem_access)),
                        )
                    else:
                        setattr(Insn, f"v_op{i+1}", RealValue(mem_access))

                elif mem_access in codex_state:
                    log(
                        DebugLevel.DEBUG,
                        f"Loading a value from a previous symbolic memory write {codex_state[mem_access]}",
                        self.debug_level,
                        ANSIColors.PURPLE,
                    )
                    setattr(Insn, f"v_op{i+1}", codex_state[mem_access])
                else:
                    log(
                        DebugLevel.DEBUG,
                        f"Instantiating v_op{i+1} RealValue",
                        self.debug_level,
                        ANSIColors.PURPLE,
                    )
                    # only the first operand of the can be instantiated as a symbolic value (mov instruction)
                    if i == 0:
                        setattr(
                            Insn,
                            f"v_op{i+1}",
                            codex_state.new_symbolic_memory(
                                mem_access, read_memory_int(self.ql, mem_access)
                            ),
                        )

                    elif is_mapped(self.ql, mem_access):
                        setattr(
                            Insn,
                            f"v_op{i+1}",
                            RealValue(read_memory_int(self.ql, mem_access)),
                        )
                    else:
                        setattr(Insn, f"v_op{i+1}", RealValue(mem_access))

            assert getattr(Insn, f"v_op{i+1}") is not None

        return Insn

    def make_var_substitutions(self, insn, codex_state: CodexState):
        for varname in list(codex_state.keys()):
            symvar = codex_state[varname]

            if not isinstance(symvar, SymValue):
                continue

            raw_repr = symvar.sym_value.__raw_repr__()
            # check if the raw_repr is already in the codex_state
            if len(raw_repr) > MAX_RAW_REPR_LENGTH:
                for new_varname, new_symvar in codex_state.items():
                    if not isinstance(new_symvar, _SymValue):
                        continue
                    if new_symvar.__raw_repr__() == raw_repr:
                        log(
                            DebugLevel.DEBUG,
                            f"Substituting {varname} with {new_varname}",
                            self.debug_level,
                            ANSIColors.PURPLE,
                        )
                        codex_state[varname].update(
                            _SymValue(BitVec(str(new_varname), BINARY_ARCH_SIZE))
                        )

            # if not, then we didn't updated yet, so we create a new varname and assign it to the symvar
            if len(raw_repr) > MAX_RAW_REPR_LENGTH:
                new_varname = f"var_{next(new_var_counter):05d}"
                codex_state[new_varname] = symvar.sym_value.clone()
                log(
                    DebugLevel.DEBUG,
                    f"Creating new varname {new_varname} for {varname}=>{symvar.sym_value}",
                    self.debug_level,
                    ANSIColors.PURPLE,
                )
                codex_state[varname].update(
                    _SymValue(BitVec(str(new_varname), BINARY_ARCH_SIZE))
                )
                # TraceInst.

    def _mov(self, Insn: Instruction, mem_access: int, codex_state: CodexState):
        # instanciate a new symbolic register if needed
        # if condition is not met, then delete the symbolic register
        if Insn.op1.type == X86_OP_REG:
            regname = self.cs.reg_name(Insn.op1.reg)
            if regname not in codex_state:
                codex_state.new_symbolic_register(regname)

        # if op2 is a concrete value, then for sur the symbolic Register or memory witch stored the sym value
        # in op1 is destroyed
        if not isinstance(Insn.v_op2, SymValue):
            if Insn.op1.type == X86_OP_REG:
                regname = self.cs.reg_name(Insn.op1.reg)
                codex_state.delete_symbolic_var(regname)
            elif Insn.op1.type == X86_OP_MEM:
                codex_state.delete_symbolic_var(mem_access)
            return None

        # if op2 is a symbolic value, then update the symbolic register or memory
        elif isinstance(Insn.v_op2, SymValue):
            if Insn.op1.type == X86_OP_REG:
                regname = self.cs.reg_name(Insn.op1.reg)
                # Use to detected 'addrof' operation, ex: mov rax, [rbx + 0x1000] with rbx symbolic
                if self.check_direct_addrof(Insn.cinsn, mem_access) and isinstance(
                    Insn.v_op2, SymRegister
                ):
                    Insn.v_op2 *= RealValue(0x1111)
                codex_state[regname].update(Insn.v_op2.sym_value & Insn.v_op2.size)
                return codex_state[regname]

            elif Insn.op1.type == X86_OP_MEM:
                codex_state[mem_access].update(Insn.v_op2.sym_value)
                return codex_state[mem_access]

        raise Exception("Operation {Insn.cinsn.mnemonic} not supported")

    def _compute(self, Insn: Instruction, mem_access: int, codex_state: CodexState, op):
        codex_entry = None

        # special operation for mul
        if op == "mul":
            codex_entry = "rax"
            if codex_entry not in codex_state:
                codex_state.new_symbolic_register(codex_entry)
            codex_state[codex_entry].update((codex_state[codex_entry] * Insn.v_op1))

        # create symbolic entry if needed
        if Insn.op1.type == X86_OP_MEM:
            if mem_access not in codex_state:
                codex_state.new_symbolic_memory(
                    mem_access, read_memory_int(self.ql, mem_access)
                )
            codex_entry = mem_access
        else:
            regname = self.cs.reg_name(Insn.op1.reg)
            if regname not in codex_state:
                codex_state.new_symbolic_register(regname)
            codex_entry = regname

        if op == "add":
            codex_state[codex_entry].update((Insn.v_op1 + Insn.v_op2))

        if op == "sub":
            codex_state[codex_entry].update(Insn.v_op1 - Insn.v_op2)

        if op == "xor":
            codex_state[codex_entry].update(Insn.v_op1 ^ Insn.v_op2)

        if op == "imul":
            if Insn.v_op3 is not None:
                codex_state[codex_entry].update((Insn.v_op2 * Insn.v_op3))
            if Insn.v_op2 is not None:
                codex_state[codex_entry].update((Insn.v_op1 * Insn.v_op2))
            else:
                if "rax" in codex_state:
                    codex_state["rax"].update((codex_state["rax"] * Insn.v_op1))

        if op == "and":
            codex_state[codex_entry].update(Insn.v_op1 & Insn.v_op2)

        if op == "or":
            codex_state[codex_entry].update(Insn.v_op1 | Insn.v_op2)

        if op == "shl":
            codex_state[codex_entry].update(Insn.v_op1 << Insn.v_op2)

        if op == "shr":
            codex_state[codex_entry].update(Insn.v_op1 >> Insn.v_op2)

        if op == "ror":
            codex_state[codex_entry].update(Insn.v_op1.ror(Insn.v_op2))

        if op == "rol":
            codex_state[codex_entry].update(Insn.v_op1.rol(Insn.v_op2))

        if op == "not":
            codex_state[codex_entry].update(Insn.v_op1._not())

        # if the value is a memory address, add a marker to transform
        # the result into  'addrof'
        if isinstance(Insn.v_op2, RealValue) and is_mapped(self.ql, Insn.v_op2.value):
            codex_state[codex_entry] *= RealValue(0x1111)
        if isinstance(Insn.v_op1, RealValue) and is_mapped(self.ql, Insn.v_op1.value):
            codex_state[codex_entry] *= RealValue(0x1111)

        return codex_state[codex_entry]

    def _add(self, Insn: Instruction, mem_access: int, codex_state: CodexState):
        return self._compute(Insn, mem_access, codex_state, "add")

    def _imul(self, Insn: Instruction, mem_access: int, codex_state: CodexState):
        return self._compute(Insn, mem_access, codex_state, "imul")

    def _sub(self, Insn: Instruction, mem_access: int, codex_state: CodexState):
        return self._compute(Insn, mem_access, codex_state, "sub")

    def _xor(self, Insn: Instruction, mem_access: int, codex_state: CodexState):
        return self._compute(Insn, mem_access, codex_state, "xor")

    def _and(self, Insn: Instruction, mem_access: int, codex_state: CodexState):
        return self._compute(Insn, mem_access, codex_state, "and")

    def _or(self, Insn: Instruction, mem_access: int, codex_state: CodexState):
        return self._compute(Insn, mem_access, codex_state, "or")

    def _shl(self, Insn: Instruction, mem_access: int, codex_state: CodexState):
        return self._compute(Insn, mem_access, codex_state, "shl")

    def _shr(self, Insn: Instruction, mem_access: int, codex_state: CodexState):
        return self._compute(Insn, mem_access, codex_state, "shr")

    def _ror(self, Insn: Instruction, mem_access: int, codex_state: CodexState):
        return self._compute(Insn, mem_access, codex_state, "ror")

    def _rol(self, Insn: Instruction, mem_access: int, codex_state: CodexState):
        return self._compute(Insn, mem_access, codex_state, "rol")

    def _mul(self, Insn: Instruction, mem_access: int, codex_state: CodexState):
        return self._compute(Insn, mem_access, codex_state, "mul")

    def _not(self, Insn: Instruction, mem_access: int, codex_state: CodexState):
        return self._compute(Insn, mem_access, codex_state, "not")

    def _push(self, Insn: Instruction, mem_access: int, codex_state: CodexState):
        stack_pointer = get_stack_pointer(self.ql)
        codex_state[stack_pointer] = Insn.v_op1.clone()

    def _pop(self, Insn: Instruction, mem_access: int, codex_state: CodexState):
        stack_pointer = get_stack_pointer(self.ql)
        reg = self.cs.reg_name(Insn.op1.reg)
        # Delete the symbolic register
        if reg in codex_state:
            codex_state.delete_symbolic_var(reg)
        # Copy the value from the stack to the register
        if stack_pointer in codex_state:
            codex_state[reg] = codex_state[stack_pointer]
            codex_state.delete_symbolic_var(stack_pointer)
            return codex_state[reg]

    def validate_symbolic_memory(self, codex_state):
        # Check if we should perform the symbolic memory check based on a random interval
        if not self.symbolic_check:
            return

        # Create dictionaries to store intermediate values
        symbolic_reg_and_mem_expr = {}

        # Copy values from ValueBookInst to locals
        for var_name, eval_value in ValueBookInst.items():
            globals()[var_name] = eval_value
            locals()[var_name] = eval_value

        # Sort and filter variable names starting with "var_"
        vars_int = sorted(
            [var_name for var_name in codex_state if var_name.startswith("var_")]
        )

        # Evaluate and store values for the filtered variables
        # Only register new var_ variables, not already defined in the global scope
        for var_name in vars_int:
            if var_name in globals():
                locals()[var_name] = globals()[var_name]
            
            else:
                eval_value = codex_state[var_name]
                eval_value = (
                    eval_value.sym_value
                    if isinstance(eval_value, SymValue)
                    else reformat_expression(str(eval_value))
                )
                if isinstance(eval_value, str) and "addrof" in eval_value:
                    return
                globals()[var_name] = eval(str(eval_value), globals())
                locals()[var_name] = globals()[var_name]
            

        # Evaluate and store values for other variables
        for var_name, eval_value in codex_state.items():
            if not var_name.startswith("var_"):
                eval_value = eval_value.sym_value
                symbolic_reg_and_mem_expr[var_name] = eval(str(eval_value), locals())
                del locals()["__builtins__"]

        # Check symbolic memory values
        for var_name, eval_value in symbolic_reg_and_mem_expr.items():
            real_value = None
            if var_name.startswith("mem_"):
                real_value = read_while_ptr(self.ql, int(var_name[4:], 16))

            elif (BINARY_ARCH == ARCH.X86 and var_name.startswith("e")) or (
                BINARY_ARCH == ARCH.X86_64 and var_name.startswith("r")
            ):
                with contextlib.suppress(KeyError):
                    real_value = read_while_ptr(
                        self.ql, self.ql.arch.regs.read(var_name.upper())
                    )

            if real_value is None:
                continue

            # apply mask setted when the memory was tainted
            if var_name in AddressBookInst:
                real_value &= MaskBookInst[AddressBookInst[var_name]]

            if eval_value != real_value:
                # Delete the symbolic memory
                codex_state.delete_symbolic_var(var_name)
                log(
                    DebugLevel.ERROR,
                    f"Found a wrong symbolic memory value, deleting it: {var_name} => {hex(real_value)}"
                    + f"\nSymbolic Computed Value : {eval_value}",
                    self.debug_level,
                    ANSIColors.ERROR,
                )
                if self.strict_symbolic_check and not var_name.startswith("mem_"):
                    raise Exception(
                        ANSIColors.ERROR
                        + "Found a wrong symbolic memory value. "
                        + "You could Disable 'strict mode' to continue the execution even with"
                        + "some sym mistakes."
                        + ANSIColors.ENDC
                    )

    def check_resulting_operation(self, codex_state: CodexState):
        # Get the address of the last executed instruction
        insn_addr = self.last_instruction_executed
        if insn_addr is None:
            return

        # Get the instruction object for the last executed instruction
        insn = get_instruction_from_address(self.ql, insn_addr)

        # Compute memory access for the last executed instruction if not already computed
        if self.last_mem_access is None:
            self.last_mem_access = self.compute_mem_access(insn)

        # Iterate through the operands of the instruction
        for operand in insn.operands:
            if operand.type == X86_OP_REG:
                # If the operand is a register, retrieve and log its value
                reg_name = self.cs.reg_name(operand.reg)
                reg_value = hex(self.ql.arch.regs.read(reg_name.upper()))
                log(
                    DebugLevel.DEBUG,
                    f"{reg_name} => {reg_value}",
                    self.debug_level,
                    ANSIColors.OKBLUE,
                )
            elif operand.type == X86_OP_MEM and is_mapped(
                self.ql, self.last_mem_access
            ):
                # If the operand is a memory location, retrieve and log its value
                mem_value = hex(read_memory_int(self.ql, self.last_mem_access))
                log(
                    DebugLevel.DEBUG,
                    f"{hex(self.last_mem_access)} => {mem_value}",
                    self.debug_level,
                    ANSIColors.OKBLUE,
                )

        # Check if the last executed instruction was symbolic
        if self.is_last_instruction_symbolic is True:
            return

        # Validate symbolic memory, optionally in strict mode
        self.validate_symbolic_memory(codex_state)

    def evaluate_instruction(self, mem_access, codex_state: CodexState):
        # Get the current instruction
        insn = get_current_instruction(self.ql)
        insn_addr = get_instruction_address(self.ql)

        if insn_addr == self.last_instruction_executed:
            self.is_last_instruction_symbolic = False
            return False

        self.check_resulting_operation(codex_state)

        if self.debug_level == DebugLevel.DEBUG:
            print("{}   {} {}".format(hex(insn_addr), insn.mnemonic, insn.op_str))

        self.last_instruction_executed = insn_addr
        self.last_mem_access = mem_access

        # mem_access can be calculated from insn of directly
        # read base, index, disp and scale from insn operands
        if mem_access is None:
            mem_access = self.compute_mem_access(insn)

        # treat special operations
        if insn.mnemonic.startswith("cdq"):
            codex_state.delete_symbolic_var("rdx")

        # check if the instruction is symbolic (at least one operand is symbolic)
        # operands are symbolic when they are first tainted, then when the current operand
        # depends on a tainted operand
        if not self.is_symbolic_operation(mem_access, insn, codex_state):
            self.is_last_instruction_symbolic = False
            Insn = Instruction(insn)
            # parse_op_values allow to fill Insn with the values of the operands
            return (Insn, self.parse_op_values(insn, mem_access, Insn), False)

        # check if the instruction is supported
        if insn.mnemonic not in SUPPORTED_INSTRUCTIONS:
            log(
                DebugLevel.DEBUG,
                f"Instruction is not supported",
                self.debug_level,
                ANSIColors.ERROR,
            )
            raise Exception(f"Instruction {insn.mnemonic} is not supported")

        if self.debug_level == DebugLevel.INFO:
            print("{}   {} {}".format(hex(insn_addr), insn.mnemonic, insn.op_str))

        self.make_var_substitutions(insn, codex_state)

        # Parse operands do a lot of things, like creating symbolic values, fetching values from memory
        # All the results are stored in the Instruction object (v_op1, v_op2, v_op3)
        Insn = self.parse_insn_operands(self.ql, insn, mem_access, codex_state)
        resulting_operation = None

        if "mov" in insn.mnemonic or insn.mnemonic.startswith("lea"):
            resulting_operation = self._mov(Insn, mem_access, codex_state)

        elif insn.mnemonic.startswith("add"):
            resulting_operation = self._add(Insn, mem_access, codex_state)

        elif insn.mnemonic.startswith("imul"):
            resulting_operation = self._imul(Insn, mem_access, codex_state)

        elif insn.mnemonic.startswith("sub"):
            resulting_operation = self._sub(Insn, mem_access, codex_state)

        elif insn.mnemonic.startswith("xor"):
            resulting_operation = self._xor(Insn, mem_access, codex_state)

        elif insn.mnemonic.startswith("and"):
            resulting_operation = self._and(Insn, mem_access, codex_state)

        elif insn.mnemonic.startswith("or"):
            resulting_operation = self._or(Insn, mem_access, codex_state)

        elif insn.mnemonic.startswith("shl"):
            resulting_operation = self._shl(Insn, mem_access, codex_state)

        elif insn.mnemonic.startswith("shr") or insn.mnemonic.startswith("sar"):
            resulting_operation = self._shr(Insn, mem_access, codex_state)

        elif insn.mnemonic.startswith("ror"):
            resulting_operation = self._ror(Insn, mem_access, codex_state)

        elif insn.mnemonic.startswith("rol"):
            resulting_operation = self._rol(Insn, mem_access, codex_state)

        elif insn.mnemonic.startswith("mul"):
            resulting_operation = self._mul(Insn, mem_access, codex_state)

        elif insn.mnemonic.startswith("not"):
            resulting_operation = self._not(Insn, mem_access, codex_state)

        elif insn.mnemonic.startswith("push"):
            resulting_operation = self._push(Insn, mem_access, codex_state)

        elif insn.mnemonic.startswith("pop"):
            resulting_operation = self._pop(Insn, mem_access, codex_state)

        elif insn.mnemonic.startswith("cmp") or insn.mnemonic.startswith("test"):
            self.show_op_values(insn, mem_access)
            ask_to_continue("Found a cmp or test instruction, do you want to continue?")

        if resulting_operation is not None:
            msg = resulting_operation.color.get_colored_text(
                f"Symbolic instruction {insn.mnemonic} executed, result: {resulting_operation.sym_value}"
            )
            log(DebugLevel.INFO, msg, self.debug_level, ANSIColors.PURPLE)
        else:
            log(
                DebugLevel.DEBUG,
                f"Symbolic operation gives no result",
                self.debug_level,
                ANSIColors.PURPLE,
            )
            self.show_op_values(insn, mem_access)

        self.is_last_instruction_symbolic = True
        # add a new line
        return (Insn, self.parse_op_values(insn, mem_access, Insn), True)

    def compute_mem_access(self, insn):
        """
        Computes the memory access from the instruction, using base, index, disp and scale.

        Args:
            insn (CsInsn): The instruction to compute memory access from.

        Returns:
            int: The computed memory access.
        """
        mem_access = 0
        try:
            for op in insn.operands:
                if op.type == X86_OP_MEM:
                    mem_access += (
                        self.ql.arch.regs.read(self.cs.reg_name(op.mem.base))
                        if op.mem.base != 0
                        else 0
                    )
                    mem_access += (
                        self.ql.arch.regs.read(self.cs.reg_name(op.mem.index))
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

    def parse_op_values(self, insn, mem_access, Insn=None):
        """
        Get the value of the operands.

        Args:
            insn: 
            mem_access: A memory access object.

        Returns:
            op_values: A dictionary containing operand values.
        """
        if Insn is None:
            Insn = Instruction(insn)
        op_values = {}
        # Get the value of the operands
        for i, op in enumerate(insn.operands):
            if op.type == X86_OP_REG:
                regname = self.cs.reg_name(op.reg)
                reg_value = self.ql.arch.regs.read(regname.upper())
                reg_ptr_value = ""
                if is_mapped(self.ql, reg_value):
                    reg_ptr_value = hex(read_memory_int(self.ql, reg_value))
                full_value = hex(reg_value) + " " + reg_ptr_value
                op_values[f"{regname}"] = full_value
                setattr(Insn, f"op{i + 1}", reg_value)
            elif op.type == X86_OP_MEM and is_mapped(self.ql, mem_access):
                mem_value = read_memory_int(self.ql, mem_access)
                op_values[f"{hex(mem_access)}"] = hex(mem_value)
                setattr(Insn, f"op{i + 1}", hex(mem_value))

        return op_values

    def show_op_values(self, insn, mem_access):
        """
        Display the value of the operands.

        Args:
            insn: An instruction object.
            mem_access: A memory access object.

        Returns:
            None
        """
        op_values = self.parse_op_values(insn, mem_access)
        # Print the values of the operands
        for op_name, op_value in op_values.items():
            log(
                DebugLevel.DEBUG,
                f"{op_name} = {op_value}",
                self.debug_level,
                ANSIColors.OKBLUE,
            )

    def check_direct_addrof(self, insn, mem_access):
        # check if the instruction is a mov or lea with a memory access that
        # do a direct computation of the memory address
        if (
            insn.operands[1].mem.scale < 2
            and insn.operands[1].mem.disp == 0
            and insn.operands[1].mem.index == 0
        ):
            return False

        if "lea" in insn.mnemonic and is_mapped(self.ql, mem_access):
            return True

        return False


class CodexSourceForge:
    pass


class  CodexRebirth:
    """
    The CodexRebirth class is responsible for managing the Codex state and providing an interface for interacting with
    the Codex instruction engine.

    :param ql_instance: The Qiling instance to use for emulation.
    :param debug_level: The debug level to use for logging. Defaults to DebugLevel.INFO.
    :param args: Additional arguments to pass to the CodexInstructionEngine.
    :param kwargs: Additional keyword arguments to pass to the CodexInstructionEngine.
    """

    def __init__(self, ql_instance, debug_level=DebugLevel.INFO, *args, **kwargs):
        # Set the debug level and create a CodexState instance
        self.debug_level = debug_level
        self.state = CodexState()

        # Store the Qiling instance
        self.ql = ql_instance

        # Check if the architecture is 32-bit or 64-bit
        if ql_instance.arch.type == QL_ARCH.X8664:
            self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
            self.ks = Ks(KS_ARCH_X86, KS_MODE_64)
            self.instruction_engine = CodexInstructionEngineX86_64(
                ql_instance, debug_level, *args, **kwargs
            )
        elif ql_instance.arch.type == QL_ARCH.X86:
            self.cs = Cs(CS_ARCH_X86, CS_MODE_32)
            self.ks = Ks(KS_ARCH_X86, KS_MODE_32)
            self.instruction_engine = CodexInstructionEngineX86_64(
                ql_instance, debug_level, *args, **kwargs
            )

        # Find the base and end address of the text section
        self.text_base = ql_instance.loader.images[0].base
        self.text_end = ql_instance.loader.images[0].end

        # Create an empty dictionary for callbacks
        self.callbacks = {}

        # Initialize start and end addresses for emulation
        self.addr_emu_start = None
        self.addr_emu_end = None

        # Allow exporting the address book and codex dump
        self.address_book = AddressBookInst

        # Allow exporting the TraceInst
        self.trace_records = TraceInst

        # Initialize the count of executed instructions
        self.insn_executed_count = 0

    def check_instruction_scope(self, ql):
        if ql.arch.type == QL_ARCH.X8664:
            pc = ql.arch.regs.rip
        else:
            pc = ql.arch.regs.eip

        if pc < self.text_base or pc >= self.text_end:
            return False
        return True

    def show_register_stack_dump(self):
        # Display register values
        print("Register Values:")
        for reg_id in CS_UC_REGS.keys():
            reg_name = self.cs.reg_name(reg_id)
            with suppress(Exception):
                reg_value = self.ql.arch.regs.read(reg_name)
                print(f"{reg_name}= 0x{reg_value:016X}")

        # Display stack values from the current stack pointer
        print("Stack Values:")
        pc = get_instruction_address(self.ql)
        for i in range(0, 0x200, 8):
            offset = pc - i
            with suppress(Exception):
                stack_value = read_memory_int(self.ql, offset)
                print(f"{hex(offset)} = 0x{stack_value:016X}")

    def register_callback(self, address: int, fn: callable):
        assert isinstance(address, int)
        assert callable(fn)
        self.callbacks[address] = fn

    def taint_memory(self, address: int, name: str, value: int, mask=BINARY_MAX_MASK):
        assert (
            isinstance(address, int)
            and isinstance(name, str)
            and isinstance(value, int)
            and isinstance(mask, int)
        )
        self.state.new_symbolic_memory(address, name)
        self.set_var_name(address, name)
        self.set_var_value(name, value)
        self.set_mask(name, mask)

    def taint_register(self, reg: str, name: str, value: int, mask=BINARY_MAX_MASK):
        assert (
            isinstance(reg, str)
            and isinstance(name, str)
            and isinstance(value, int)
            and isinstance(mask, int)
        )
        self.state.new_symbolic_register(reg)
        self.set_var_name(reg, name)
        self.set_var_value(name, value)
        self.set_mask(name, mask)

    def memory_write_hook(
        self, ql: Qiling, access: int, address: int, size: int, value: int
    ):
        assert access == UC_MEM_WRITE
        # process instruction only if it is in the text section
        if not self.check_instruction_scope(ql):
            return

        insn, insn_addr = get_current_instruction(ql), get_instruction_address(ql)
        result = self.instruction_engine.evaluate_instruction(address, self.state)
        if isinstance(result, tuple):
            Insn = result[0]
            return TraceInst.register(
                insn_addr, Insn, result[2]
            )

    def memory_read_hook(
        self, ql: Qiling, access: int, address: int, size: int, value: int
    ):
        assert access == UC_MEM_READ
        # process instruction only if it is in the text section
        if not self.check_instruction_scope(ql):
            return

        insn, insn_addr = get_current_instruction(ql), get_instruction_address(ql)
        result = self.instruction_engine.evaluate_instruction(address, self.state)
        if isinstance(result, tuple):
            Insn = result[0]
            return TraceInst.register(
                insn_addr, Insn, result[2]
            )

    def code_execution_hook(self, ql: Qiling, address: int, size):
        try:
            # Get the current instruction and its address
            insn, insn_addr = get_current_instruction(ql), get_instruction_address(ql)

            # Check if there's a registered callback for the current address
            if insn_addr in self.callbacks:
                # Execute the callback with the Qiling instance as an argument
                self.callbacks[insn_addr](self)

            # Check if the instruction is a call instruction
            if insn.mnemonic.startswith("call"):
                # Get the address of the function being called
                if insn.operands[0].type == X86_OP_IMM:
                    fn_addr = insn.operands[0].imm
                    if fn_addr in self.callbacks:
                        # Execute the callback associated with the function address
                        self.callbacks[fn_addr](ql)

            # Check if the instruction is within the text section
            if not self.check_instruction_scope(ql):
                log(
                    DebugLevel.DEBUG,
                    f"Instruction not in text section {hex(insn_addr)}",
                    self.debug_level,
                    ANSIColors.ERROR,
                )
                Insn = Instruction(insn)
                return TraceInst.register(
                    insn_addr,
                    Insn,
                    False,
                )

            # Check if we have reached the user-defined end address for emulation
            if insn_addr == self.addr_emu_end:
                log(
                    DebugLevel.INFO,
                    f"Reached end of emulation",
                    self.debug_level,
                    ANSIColors.OKGREEN,
                )
                return

            # If the instruction involves memory access, delegate to dedicated functions (mem_read, mem_write)
            if check_memory_access(insn):
                return

            # Evaluate the instruction with the current codex state
            result = self.instruction_engine.evaluate_instruction(None, self.state)
            if isinstance(result, tuple):
                Insn = result[0]
                return TraceInst.register(
                    insn_addr, Insn, result[2]
                )
        finally:
            # Increment the instruction executed count
            self.insn_executed_count += 1

    def set_emu_start(self, address: int):
        self.addr_emu_start = address

    def set_emu_end(self, address: int):
        self.addr_emu_end = address

    def set_register(self, register: str, value: int):
        self.ql.arch.regs.write(register, value)

    def get_register(self, register: str):
        return self.ql.arch.regs.read(register)

    def set_memory(self, address: int, value: bytes):
        assert isinstance(value, bytes)
        self.ql.mem.write(address, value)

    def set_var_name(self, addr_or_reg, name: str):
        # real_name can be a register or a memory address
        if isinstance(addr_or_reg, int):
            AddressBookInst["mem_{}".format(hex(addr_or_reg))] = name
        else:
            AddressBookInst[addr_or_reg] = name

    def set_var_value(self, name, value: int):
        ValueBookInst[name] = value

    def set_mask(self, name, mask: int):
        MaskBookInst[name] = mask

    def show_codex(self):
        print(self.state)

    def run_emulation(self):
        # Configure the disassembler for detailed information
        disassembler = self.ql.arch.disassembler
        disassembler.detail = True

        # Set up memory read, memory write, and code hooks
        self.ql.hook_mem_read(self.memory_read_hook)
        self.ql.hook_mem_write(self.memory_write_hook)
        self.ql.hook_code(self.code_execution_hook)

        # Display register and stack dump before emulation starts
        self.show_register_stack_dump()

        # Start measuring emulation time
        start_time = time.time()

        try:
            # Start Qiling engine emulation within the specified address range
            if self.addr_emu_start and self.addr_emu_end:
                self.ql.run(self.addr_emu_start, self.addr_emu_end)
            elif self.addr_emu_start:
                self.ql.run(self.addr_emu_start)
            else:
                self.ql.run()

        except unicorn.UcError as e:
            log(
                DebugLevel.ERROR,
                f"Exception occurred while emulating: {str(e)}",
                self.debug_level,
                ANSIColors.ERROR,
            )

        end_time = time.time()
        emulation_time = end_time - start_time
        instructions_per_second = self.insn_executed_count / emulation_time

        # Create a separator line for output formatting
        separator_line = "=" * 80
        output = textwrap.dedent(
            f"""
            {separator_line}
            Emulation time: {emulation_time:.1f} seconds
            {self.insn_executed_count} instructions executed
            Instructions per second: {instructions_per_second:.1f}
            {separator_line}
            """
        )

        # Log emulation results
        log(DebugLevel.ERROR, output, self.debug_level, ANSIColors.OKGREEN)
        log(
            DebugLevel.INFO,
            f"Emulation finished",
            self.debug_level,
            ANSIColors.OKGREEN,
        )
        log(
            DebugLevel.INFO,
            f"Validating and dumping codex",
            self.debug_level,
            ANSIColors.OKGREEN,
        )

        # Pause for 2 seconds
        time.sleep(2)

        # Validate symbolic memory and codex
        self.instruction_engine.validate_symbolic_memory(self.state)

        return True
