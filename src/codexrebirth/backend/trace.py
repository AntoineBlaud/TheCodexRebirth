
from codexrebirth.backend.instruction import Instruction

class TraceEntry:
    def __init__(self, Insn: Instruction) -> None:
        self.Insn = Insn
        self.taint_id = -1
        if self.Insn.v_op_result:
            self.taint_id = Insn.v_op_result.id

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
        self.insn_access = []

    def register(self, insn_addr: int, Insn: Instruction) -> None:
        
        if not isinstance(Insn, Instruction):
            return
        
        if insn_addr not in self:
            self[insn_addr] = {}
        self[insn_addr][self.idx] = TraceEntry(Insn.clone())
        self.idx += 1
        self.insn_access.append(insn_addr)
        
    def get_last_entry(self) -> TraceEntry:
        if self.idx == 0:
            return None
        return self[self.insn_access[-1]][self.idx - 1]

    def __repr__(self) -> str:
        raise NotImplementedError()
    
    def clone(self):
        clone = Trace()
        clone.idx = self.idx
        clone.insn_access = self.insn_access.copy()
        for addr in self:
            clone[addr] = {}
            for idx in self[addr]:
                clone[addr][idx] = self[addr][idx].clone()
        return clone