
from codexrebirth.core.instruction import Instruction

class TraceEntry:
    def __init__(self, Insn: Instruction) -> None:
        self.Insn = Insn
        self.sym_id = -1
        if Insn.v_op_result:
            self.sym_id = Insn.v_op_result.id

    def __repr__(self) -> str:
        return f"{self.Insn}"
    
    def clone(self):
        clone = TraceEntry(self.Insn.clone())
        return clone


class Trace(dict):
    # store all instructions that have been executed
    def __init__(self):
        super().__init__()
        self.idx = 0

    def register(self, insn_addr: int, Insn: Instruction) -> None:
        
        if not isinstance(Insn, Instruction):
            return
        
        if insn_addr not in self:
            self[insn_addr] = {}
        self[insn_addr][self.idx] = TraceEntry(Insn.clone())
        self.idx += 1

    def __repr__(self) -> str:
        raise NotImplementedError()
    
    def clone(self):
        clone = Trace()
        clone.idx = self.idx
        for addr in self:
            clone[addr] = {}
            for idx in self[addr]:
                clone[addr][idx] = self[addr][idx].clone()
        return clone