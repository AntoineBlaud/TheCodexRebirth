
from superglobals import *
import uuid

from codexrebirth.util.binaryop import (
    binary_subtraction,
    RotateLeft,
    RotateRight,
    Not
)

from codexrebirth.util.ustring import (
    remove_all_masks,
    replace_integers_with_hex,
    reformat_expression
)

from z3 import BitVec, BitVecVal, Extract, RotateLeft, RotateRight, Not
from codexrebirth.util.color import Color


BINARY_MAX_MASK = None
BINARY_ARCH_SIZE = None

def initialize_global(func):
    def wrapper(*args, **kwargs):
        global BINARY_MAX_MASK, BINARY_ARCH_SIZE
        if not BINARY_MAX_MASK:
            BINARY_MAX_MASK = getglobal('CONFIG')['BINARY_MAX_MASK']
        if not BINARY_ARCH_SIZE:
            BINARY_ARCH_SIZE = getglobal('CONFIG')['BINARY_ARCH_SIZE']
        return func(*args, **kwargs)
    return wrapper

class SymValue:
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
        value_str = reformat_expression(value_str)
        return value_str

    def __raw_repr__(self):
        return str(self.value)

    def clone(self):
        return SymValue(self.value)

    @initialize_global
    def __and__(self, other: int):
        if other != BINARY_ARCH_SIZE:
            return SymValue(self.value & (1 << other) - 1)
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
# -> SymValue -> SymRegister, SymMemory -> SymValue


class RealValue:
    @initialize_global
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
        other.sym_value.value = RotateRight(
            other.sym_value.value, self.sym_value.value
        )
        return other

    def rol(self, other):
        other = other.clone()
        other.sym_value.value = RotateLeft(
            other.sym_value.value, self.sym_value.value
        )
        return other

    def _not(self):
        self.sym_value.value = ~self.sym_value.value & BINARY_MAX_MASK
        return self
    
    

class ASymValue:
    def __init__(self) -> None:
        pass


class SymMemory(ASymValue):
    @initialize_global
    def __init__(self, name: int, value: int = None):
        super().__init__()
        self.color = Color()
        self.name = name
        self._value = value
        self.id = -1
        if isinstance(value, int):
            self.sym_value = SymValue(BitVecVal(value, BINARY_ARCH_SIZE))
        elif isinstance(name, str):
            self.sym_value = SymValue(BitVec(name, BINARY_ARCH_SIZE))
        else:
            raise Exception("SymMemory name must be a string")

    @property
    def size(self):
        return BINARY_ARCH_SIZE

    @property
    def value(self):
        # return ast_value of SymValue
        return self.sym_value.value

    def update(self, target, **kwargs):
        if isinstance(target, (SymValue)):
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
        self.sym_value.value = RotateRight(
            self.sym_value.value, other.sym_value.value
        )
        return self

    def rol(self, other):
        self.sym_value.value = RotateLeft(
            self.sym_value.value, other.sym_value.value
        )
        return self

    def _not(self):
        self.sym_value.value = ~self.sym_value.value & BINARY_MAX_MASK
        return self


class SymRegister(ASymValue):
    # This class is used to store symbolic data inside registers
    # It is used to propagate values to all registers that are part of the same register
    # self.

    def __init__(self, name, high, low, parent=None):
        super().__init__()
        self.parent = parent
        self.color = Color() if not parent else parent.color
        self._low = low
        self._high = high
        self._name = name
        self.id = -1
        if parent:
            assert self.high <= parent.high
            self.sym_value = parent.sym_value.clone()
        else:
            self.sym_value = SymValue(BitVec(str(name), high - low + 1))

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
        # return ast_value of SymValue
        return self.sym_value.value

    @value.setter
    def value(self, new_value):
        self.update(new_value)

    def __getitem__(self, index):
        assert isinstance(index, slice) and index.step is None
        return SymRegister(self, index.start, index.stop)

    def _set(self, target: SymValue):
        # Update current symbolic value, depending of the target value
        # and the current register size
        # Ex: If target is rax and self is eax, then self = rax & 0xffffffff
        if isinstance(target, (SymValue)):
            self.sym_value = target.clone()
            # TODO: check target size diferrent from self
        elif isinstance(target, ASymValue):
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

    def update(self, target, **kwargs):
        SymRegisterFactory = kwargs.get("SymRegisterFactory", None)
        # Propagate value to all symbolic registers that are part of this register
        # ex: 'ah': [rax, eax, ax, ah, al]
        if self.name in SymRegisterFactory:
            [reg._set(target) for reg in SymRegisterFactory[self.name]]
        else:
            self._set(target)
        return self

    @initialize_global
    def reset(self):
        self.sym = SymValue(BitVec(str(self.name), BINARY_ARCH_SIZE))
        self.color = Color()
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
        return self

    def __sub__(self, other):
        other = self.apply_mask(other)
        self.sym_value.value = binary_subtraction(
            self.sym_value.value, other.sym_value.value
        )
        return self

    def __xor__(self, other):
        other = self.apply_mask(other)
        self.sym_value.value ^= other.sym_value.value
        return self

    def __and__(self, other):
        other = self.apply_mask(other)
        self.sym_value.value &= other.sym_value.value
        return self

    def __mul__(self, other):
        other = self.apply_mask(other)
        self.sym_value.value *= other.sym_value.value
        self.sym_value.value &= BINARY_MAX_MASK
        return self

    def __or__(self, other):
        other = self.apply_mask(other)
        self.sym_value.value |= other.sym_value.value
        return self

    def __div__(self, other):
        other = self.apply_mask(other)
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
        return SymValue(RotateRight(self.sym_value.value, other.sym_value.value))
      

    def rol(self, other):
        return SymValue(RotateLeft(self.sym_value.value, other.sym_value.value))
        

    def _not(self):
        self.sym_value.value = ~self.sym_value.value & BINARY_MAX_MASK
        return self
    
    