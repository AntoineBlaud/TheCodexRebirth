from superglobals import *
import uuid
import re
from z3 import (
    BitVec,
    BitVecVal,
    Extract,
    RotateLeft,
    RotateRight,
    Not,
    BitVecRef,
    BitVecNumRef,
)
from ..tools import ustring
from ..tools import bitwise_math
from ..tools.color import Color
import line_profiler

BINARY_MAX_MASK = None
BINARY_ARCH_SIZE = None
SYM_REGISTER_FACTORY = None
INSN_EXECUTED_COUNT = None


profile2 = line_profiler.LineProfiler()


def initialize_global(func):
    def wrapper(*args, **kwargs):
        global BINARY_MAX_MASK, BINARY_ARCH_SIZE, SYM_REGISTER_FACTORY, INSN_EXECUTED_COUNT

        # we have to create a wrapper to avoid calling getglobal multiple times, it slow down the execution
        def get_config(varname, func):
            if getglobal("CONFIG") is None:
                return func(*args, **kwargs)
            return getglobal("CONFIG")[varname]

        if not BINARY_MAX_MASK:
            BINARY_MAX_MASK = get_config("BINARY_MAX_MASK", func)
        if not BINARY_ARCH_SIZE:
            BINARY_ARCH_SIZE = get_config("BINARY_ARCH_SIZE", func)
        if not SYM_REGISTER_FACTORY:
            SYM_REGISTER_FACTORY = get_config("SYM_REGISTER_FACTORY", func)
        if not INSN_EXECUTED_COUNT:
            INSN_EXECUTED_COUNT = get_config("INSN_EXECUTED_COUNT", func)
        return func(*args, **kwargs)

    return wrapper


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
        value_str = ustring.reformat_expression(value_str)
        return value_str

    def __raw_repr__(self):
        return str(self.value)

    def clone(self):
        return self.__class__(self.value)


# This class is used to store real values
# We have to wrap 'value' inside a object class to avoid
# copy and reference problems, specially when we have to clone it
class _RealValue:
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
        value_str = ustring.reformat_expression(value_str)
        return value_str

    def __raw_repr__(self):
        return str(self.value)

    def clone(self):
        return self.__class__(self.value)


class RealValue:
    @initialize_global
    def __init__(self, value):
        self.v_wrapper = _RealValue(value)
        self.id = -1

    @property
    def value(self):
        return self.v_wrapper.value

    @value.setter
    def value(self, target):
        assert isinstance(target, (int, _RealValue))
        self.v_wrapper.value = target

    @property
    def size(self):
        return BINARY_ARCH_SIZE

    @property
    def binary_mask(self):
        return (1 << self.size) - 1

    def clone(self):
        clone = RealValue(self.value)
        clone.id = self.id
        return clone

    def update(self, target):
        if isinstance(target, RealValue):
            self.v_wrapper = target.v_wrapper.clone()
        elif isinstance(target, int):
            self.v_wrapper = _RealValue(target.clone())
        else:
            raise Exception("Target type unknown '{}'".format(type(target)))

    # For the following methods, we have to clone the 'other' object
    # because we apply the operation on the 'other' object itself,
    # even if the dest operand is not the other object
    # We proceding like this because we want to make operation on
    # SymValue and not RealValue in the end
    # Also, as we working in 32 or 64 bits, we have to mask the result

    def __repr__(self) -> str:
        return self.v_wrapper.__repr__()

    def __raw_repr__(self) -> str:
        return self.v_wrapper.__repr__()

    def __add__(self, other):
        other = other.clone()
        other.value += self.value
        other.value &= self.binary_mask
        return other

    def __sub__(self, other):
        other = other.clone()
        other.value = bitwise_math.binary_subtraction(self.value, other.value)
        return other

    def __xor__(self, other):
        other = other.clone()
        other.value ^= self.value
        return other

    def __and__(self, other):
        other = other.clone()
        other.value &= self.value
        return other

    def __mul__(self, other):
        other = other.clone()
        other.value *= self.value
        other.value &= self.binary_mask
        return other

    def __or__(self, other):
        other = other.clone()
        other.value |= self.value
        return other

    def __div__(self, other):
        other = other.clone()
        other.value /= self.value
        return other

    def __rshift__(self, other):
        other = other.clone()
        other.value >>= self.value
        other.value &= self.binary_mask
        return other

    def __lshift__(self, other):
        other = other.clone()
        other.value <<= self.value
        other.value &= self.binary_mask
        return other

    def ror(self, other):
        other = other.clone()
        if isinstance(other.value, int):
            other.value = bitwise_math.RotateRight(other.value, self.value)
        else:
            other.value = RotateRight(other.value, self.value)
        return other

    def rol(self, other):
        other = other.clone()
        if isinstance(other.value, int):
            other.value = bitwise_math.RotateLeft(other.value, self.value)
        else:
            other.value = RotateLeft(other.value, self.value)
        return other

    def _not(self):
        self.value = ~self.value & BINARY_MAX_MASK
        return self


class SymValue:
    def __init__(self, value, name=None, id=-1):
        super().__init__()
        self.color = Color()
        self.name = name
        self.v_wrapper = None
        self.id = id
        if isinstance(value, int):
            self.v_wrapper = _SymValue(BitVecVal(value, BINARY_ARCH_SIZE))
        elif isinstance(value, str):
            self.v_wrapper = _SymValue(BitVec(str(value), BINARY_ARCH_SIZE))
        elif isinstance(value, (RealValue, SymValue)):
            self.v_wrapper = value.v_wrapper.clone()

    @property
    def size(self):
        return BINARY_ARCH_SIZE

    @property
    def value(self):
        assert isinstance(self.v_wrapper, (_SymValue, _RealValue))
        return self.v_wrapper.value

    @property
    def binary_mask(self):
        return (1 << self.size) - 1

    @value.setter
    def value(self, target):
        self.v_wrapper.value = target

    def update(self, target):
        if isinstance(target, (SymValue, RealValue)):
            self.v_wrapper = target.v_wrapper.clone()
            self.update_id(target)
        elif isinstance(target, (BitVecRef, BitVecNumRef)):
            self.v_wrapper = _SymValue(target.clone())
        else:
            raise Exception("Target type unknown '{}'".format(type(target)))

    def update_id(self, other):
        if isinstance(other, (SymValue)):
            if self.id == -1:
                self.id = other.id
            elif other.id != -1:
                self.id = min(self.id, other.id)

    def clone(self):
        clone = SymValue(self.name, self.v_wrapper)
        clone.id = self.id
        clone.v_wrapper = self.v_wrapper.clone()
        return clone

    def __repr__(self) -> str:
        return f"{self.v_wrapper.__repr__()}"

    def __add__(self, other):
        self.value += other.value
        self.value &= self.binary_mask
        self.update_id(other)
        return self

    def __sub__(self, other):
        self.value = bitwise_math.binary_subtraction(self.value, other.value)
        self.value &= self.binary_mask
        self.update_id(other)
        return self

    def __xor__(self, other):
        self.value ^= other.value
        self.value &= self.binary_mask
        self.update_id(other)
        return self

    def __and__(self, other):
        self.value &= other.value
        self.value &= self.binary_mask
        self.update_id(other)
        return self

    def __mul__(self, other):
        self.value *= other.value
        self.value &= self.binary_mask
        self.update_id(other)
        return self

    def __or__(self, other):
        self.value |= other.value
        self.update_id(other)
        return self

    def __div__(self, other):
        self.value /= other.value
        self.value &= self.binary_mask
        self.update_id(other)
        return self

    def __rshift__(self, other):
        self.value >>= other.value
        self.value &= self.binary_mask
        self.update_id(other)
        return self

    def __lshift__(self, other):
        self.value <<= other.value
        self.value &= self.binary_mask
        self.update_id(other)
        return self

    def ror(self, other):
        if isinstance(self.value, int) and isinstance(other.value, int):
            self.value = bitwise_math.RotateRight(self.value, other.value)
        else:
            self.value = RotateRight(self.value, other.value)
        self.value &= self.binary_mask
        self.update_id(other)
        return self

    def rol(self, other):
        if isinstance(self.value, int) and isinstance(other.value, int):
            self.value = bitwise_math.RotateLeft(self.value, other.value)
        else:
            self.value = RotateLeft(self.value, other.value)
        self.value &= self.binary_mask
        self.update_id(other)
        return self

    def _not(self):
        self.value = ~self.value & self.binary_mask
        return self


class IndirectSymValue(SymValue):
    def __init__(self, value):
        super().__init__(value)

    def __repr__(self):
        value_str = str(self.value)
        value_str = ustring.reformat_expression(value_str)
        return f"MEMORY[{value_str}]"


class SymMemory(SymValue):
    def __init__(self, address, value):
        super().__init__(hex(value))


class SymRegister(SymValue):
    # This class is used to store symbolic data inside registers
    # It is used to propagate values to all registers that are part of the same register
    # self.

    @initialize_global
    def __init__(self, name, high, low, value=None, parent=None):
        super().__init__(None, name=name)
        self.parent = parent
        self._low = low
        self._high = high

        if parent:
            assert self.high <= parent.high
            self.v_wrapper = parent.v_wrapper.clone()
        else:
            self.v_wrapper = _SymValue(BitVec(str(name), BINARY_ARCH_SIZE))

        assert high >= low

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
    def binary_mask(self):
        return ((1 << self.size) - 1) << self.low

    def _update(self, target):
        # Update current symbolic value, depending of the target value
        # and the current register size
        # Ex: If target is rax and self is eax, then self = rax & 0xffffffff
        if isinstance(target, (SymValue, RealValue)):
            self.v_wrapper = target.v_wrapper.clone()
            self.update_id(target)
        else:
            raise Exception("Target type unknown '{}'".format(type(target)))

        if self.size != BINARY_ARCH_SIZE:
            self.v_wrapper.value &= self.binary_mask

    @initialize_global
    def update(self, target):
        # Propagate value to all symbolic registers that are part of this register
        # ex: 'ah': [rax, eax, ax, ah, al]
        if self.name in SYM_REGISTER_FACTORY:
            [reg._update(target) for reg in SYM_REGISTER_FACTORY[self.name]]

        # special case for cloned registers
        else:
            self._update(target)
        return self

    @initialize_global
    def reset(self):
        self.sym = SymValue(BitVec(str(self.name), BINARY_ARCH_SIZE))
        self.color = Color()
        self.id = -1
        return self

    def clone(self):
        cloned_name = "{}_clone_{}".format(self.name, str(uuid.uuid4()))
        clone = SymRegister(cloned_name, self.high, self.low, self.parent)
        clone.id = self.id
        clone.v_wrapper = self.v_wrapper.clone()
        return clone
