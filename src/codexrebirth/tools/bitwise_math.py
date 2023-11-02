from superglobals import *


BINARY_MAX_MASK = None
BINARY_ARCH_SIZE = None


def set_global(func):
    def wrapper(*args, **kwargs):
        global BINARY_MAX_MASK, BINARY_ARCH_SIZE
        # we have to create a wrapper to avoid calling getglobal multiple times, it slow down the execution
        def get_config(varname, func):
            if getglobal('CONFIG') is None:
                return func(*args, **kwargs)
            return getglobal('CONFIG')[varname]
    
        if BINARY_MAX_MASK is None:
            BINARY_MAX_MASK = get_config('BINARY_MAX_MASK', func)
        if BINARY_ARCH_SIZE is None:
            BINARY_ARCH_SIZE = get_config('BINARY_ARCH_SIZE', func)
        return func(*args, **kwargs)
    return wrapper

@set_global
def Not(x):
    return ~x & BINARY_MAX_MASK

@set_global
def binary_subtraction(X, Y):
    # Calculate the two's complement of Y
    # Assuming 64-bit integers
    Y_complement = (Not(Y) + 1) & BINARY_MAX_MASK
    # Perform binary subtraction by adding X and the two's complement of Y
    result = (X + Y_complement) & BINARY_MAX_MASK
    return result


# Must only be used with 'eval' function to evaluate the expression
@set_global
def RotateLeft(x, n):
    return ((x << n) | (x >> (BINARY_ARCH_SIZE - n))) & BINARY_MAX_MASK

# Must only be used with 'eval' function to evaluate the expression
@set_global
def RotateRight(x, n):
    return ((x >> n) | (x << (BINARY_ARCH_SIZE - n))) & BINARY_MAX_MASK
