from superglobals import *
import uuid
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
from tenet.util import ustring
from tenet.util import bitwise_math
from tenet.util.color import Color

BINARY_MAX_MASK = None
BINARY_ARCH_SIZE = None
SYM_REGISTER_FACTORY = None
ID_COUNTER = None

from .debug_profiler import profile


def initialize_global(func):
    def wrapper(*args, **kwargs):
        global BINARY_MAX_MASK, BINARY_ARCH_SIZE, SYM_REGISTER_FACTORY, ID_COUNTER

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
        if not ID_COUNTER:
            ID_COUNTER = get_config("ID_COUNTER", func)
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
        # VERY VERY SLOW 
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
        self.id = set([ID_COUNTER.value])

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
        clone.id = set(self.id)
        return clone

    def update(self, target):
        if isinstance(target, RealValue):
            self.v_wrapper = target.v_wrapper.clone()
            self.id = set(target.id)
        elif isinstance(target, int):
            self.v_wrapper = _RealValue(target.clone())
        else:
            return target.clone()

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
    def __init__(self, value, name=None, id=None):
        super().__init__()
        global ID_COUNTER
        self.color = Color()
        self.name = None
        if isinstance(name, str):
            self.name = name.upper()
        self.v_wrapper = None
        if id is None:
            id = [ID_COUNTER.value]
        self._id = set(id)
        if isinstance(value, int):
            self.v_wrapper = _SymValue(BitVecVal(value, BINARY_ARCH_SIZE))
        elif isinstance(value, str):
            self.v_wrapper = _SymValue(BitVec(str(value), BINARY_ARCH_SIZE))
        elif isinstance(value, (RealValue, SymValue)):
            self.v_wrapper = value.v_wrapper.clone()
            self._id = set(value.id)

    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, id):
        if isinstance(id, set):
            self._id = id

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
        global ID_COUNTER
        if isinstance(target, (SymValue)):
            self.v_wrapper = target.v_wrapper.clone()
            # add the current id to the new id, allow to trace all the instruction that use this value
            self._id = set(target._id) | set([ID_COUNTER.value])
        elif isinstance(target, (RealValue)):
            return target.clone()
        elif isinstance(target, (BitVecRef, BitVecNumRef)):
            self.v_wrapper = _SymValue(target.clone())
        else:
            raise Exception("Target type unknown '{}'".format(type(target)))

    def update_id(self, target):
        global ID_COUNTER, COPY_CACHE

        if isinstance(target, (SymValue, RealValue)):
            self.id |= target.id

    def clone(self):
        clone = SymValue(self.name, self.v_wrapper)
        clone.id = set(self._id)
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


class SymMemory(SymValue):
    def __init__(self, address, value):
        super().__init__(hex(value))


class SymRegister(SymValue):
    # This class is used to store symbolic data inside registers
    # It is used to propagate values to all registers that are part of the same register
    # self.

    @initialize_global
    def __init__(self, name, high, low, value=None, parent=None):
        name = name.upper()
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
        res = super().update(target)
        if self.size != BINARY_ARCH_SIZE:
            self.v_wrapper.value &= self.binary_mask
        return res

    @initialize_global
    def update(self, target):
        # Propagate value to all symbolic registers that are part of this register
        # ex: 'ah': [rax, eax, ax, ah, al]
        return self._update(target)

    @initialize_global
    def reset(self):
        self.sym = SymValue(BitVec(str(self.name), BINARY_ARCH_SIZE))
        self.color = Color()
        self._id = set([ID_COUNTER.value])
        return self

    def clone(self):
        cloned_name = "{}_clone_{}".format(self.name, str(uuid.uuid4()))
        clone = SymRegister(cloned_name, self.high, self.low, self.parent)
        clone.id = set(self._id)
        clone.v_wrapper = self.v_wrapper.clone()
        return clone
