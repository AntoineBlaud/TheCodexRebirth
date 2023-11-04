
from codexrebirth.backend.operation import Operation

class TraceEntry:
    def __init__(self, operation: Operation) -> None:
        self.operation = operation
        self.taint_id = -1
        if self.operation.v_result:
            self.taint_id = operation.v_result.id

    def __repr__(self) -> str:
        return f"{self.operation}"
    
    def clone(self):
        clone = TraceEntry(self.operation.clone())
        return clone


class Trace(dict):
    # store all instructions that have been executed
    def __init__(self):
        super().__init__()
        self.idx = 0
        self.access = []

    def register(self, operation_addr: int, operation: Operation) -> None:
        
        if not isinstance(operation, Operation):
            return
        
        if operation_addr not in self:
            self[operation_addr] = {}
        self[operation_addr][self.idx] = TraceEntry(operation.clone())
        self.idx += 1
        self.access.append(operation_addr)
        
    def get_last_entry(self) -> TraceEntry:
        if self.idx == 0:
            return None
        return self[self.access[-1]][self.idx - 1]

    def __repr__(self) -> str:
        raise NotImplementedError()
    
    def clone(self):
        clone = Trace()
        clone.idx = self.idx
        clone.access = self.access.copy()
        for addr in self:
            clone[addr] = {}
            for idx in self[addr]:
                clone[addr][idx] = self[addr][idx].clone()
        return clone