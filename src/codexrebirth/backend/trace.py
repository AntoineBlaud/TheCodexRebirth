from .operation import Operation


class TraceEntry:
    def __init__(self, operation: Operation) -> None:
        self.operation = operation
        self.taint_ids = set()
        if self.operation.v_result:
            self.taint_ids = operation.v_result.id

    def __repr__(self) -> str:
        return f"{self.operation}"

    def clone(self):
        clone = TraceEntry(self.operation.clone())
        return clone


class Trace(dict):
    # store all instructions that have been executed
    def __init__(self):
        super().__init__()
        self.last_idx = None
        self.last_addr = None

    def register(self, ea: int, operation: Operation, idx) -> None:
        if not isinstance(operation, Operation):
            return
        if ea not in self:
            self[ea] = {}
        self[ea][idx] = TraceEntry(operation)

        self.last_addr = ea
        self.last_idx = idx

    def get_last_entry(self) -> TraceEntry:
        if self.last_addr is None or self.last_idx is None:
            return None
        return self[self.last_addr][self.last_idx]

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
