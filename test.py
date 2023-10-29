
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
    @set_global
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
    

for _ in range (1000):
    a = RealValue(1)