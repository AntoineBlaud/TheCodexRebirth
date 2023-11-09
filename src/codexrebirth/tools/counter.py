import random
from z3 import BitVec , BitVecRef, BitVecNumRef

class alt_count:
    def __init__(self, start=0, step=1, random=False):
        self.value = start
        self.step = step
        if random:
            self.random()

    def __next__(self):
        self.value = self.value + self.step
        return self.value
    
    def reset(self):
        self.value = 0
        return self.value
    
    def random(self):
        self.value = random.randint(0, 0xFFFFFFFFFFFFFF)
        return self.value




def _z3_ast_size(var):
    assert isinstance(var, (BitVecRef, BitVecNumRef))
    if var.num_args() == 0:
        return 1
    size = 0
    for i in range(var.num_args()):
        size += _z3_ast_size(var.arg(i))
    return size
    


def z3_ast_size(var):
    if not isinstance(var, (BitVecRef, BitVecNumRef)):
        return 1
    size = 0
    for i in range(var.num_args()):
        size += _z3_ast_size(var.arg(i))
    return size
