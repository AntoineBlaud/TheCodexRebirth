from .operation import Operation


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
        self.last_idx = None
        self.last_addr = None

    def register(self, ea: int, operation: Operation, idx) -> None:
        if not isinstance(operation, Operation):
            return
        if ea not in self:
            self[ea] = {}
        self[ea][idx] = TraceEntry(operation.clone())

        self.last_addr = ea
        self.last_idx = idx

    def get_last_entry(self) -> TraceEntry:
        if self.last_addr is None or self.last_idx is None:
            return None
        return self[self.last_addr][self.last_idx]

    def __repr__(self) -> str:
        raise NotImplementedError()

    def post_process(self):
        self.post_process_taint()

    def post_process_taint(self):
        taint_id_count = {}
        # Count taint_id occurrences
        for addr in self:
            for idx in self[addr]:
                taint_id = self[addr][idx].taint_id
                taint_id_count[taint_id] = taint_id_count.get(taint_id, 0) + 1
        # Set tainted value to -1 if it's used only once
        for addr in self:
            for idx in self[addr]:
                taint_id = self[addr][idx].taint_id
                if taint_id_count[taint_id] == 1:
                    self[addr][idx].taint_id = -1

    def clone(self):
        clone = Trace()
        clone.idx = self.idx
        clone.access = self.access.copy()
        for addr in self:
            clone[addr] = {}
            for idx in self[addr]:
                clone[addr][idx] = self[addr][idx].clone()
        return clone
