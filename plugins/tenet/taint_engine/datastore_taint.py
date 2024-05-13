class State:
    """
    A simple class wrapper to store value and its index.
    """

    def __init__(self, idx, value):
        self.idx = idx
        self.value = value

    def __repr__(self):
        return f"({self.idx}, {hex(self.value)})\n"


class _StateChain:
    """
    Store multiple states for a given item, and allows to fetch the state
    # using its idx value in a log2(size) time.
    """

    def __init__(self, item_name):
        self.states = []
        self.item_name = item_name

    def get(self, idx):
        left, right = 0, len(self.states) - 1

        while left <= right:
            mid = (left + right) // 2
            state = self.states[mid]

            if idx == state.idx:
                return state.value
            elif idx < state.idx:
                right = mid - 1
            else:
                left = mid + 1

        right = max(0, right)
        return self.states[right].value

    def add(self, idx, value):
        # check value is not equal to the last value
        if len(self.states) > 0 and self.states[-1].value == value:
            return
        self.states.append(State(idx, value))

    def clone(self):
        new_chain = _StateChain(self.item_name)
        for state in self.states:
            new_chain.add(state.idx, state.value)
        return new_chain

    def __repr__(self):
        return f"{self.states}"


class DataStoreManager:
    """
    Store StateChain for each item, and allows fetching the state
    """

    def __init__(self):
        self.chains = {}

    def _normalize_item_name(self, item_name):
        return item_name.upper()

    def get_state(self, item_name, idx):
        item_name = self._normalize_item_name(item_name)
        chain = self.chains.get(item_name)
        return chain.get(idx) if chain else None

    def add_item(self, item_name):
        item_name = self._normalize_item_name(item_name)
        self.chains[item_name] = _StateChain(item_name)

    def register_item(self, item_name, idx, value):
        if value is None:
            return
        item_name = self._normalize_item_name(item_name)
        chain = self.chains.setdefault(item_name, _StateChain(item_name))
        chain.add(idx, value)

    def clone(self):
        new_manager = DataStoreManager()
        for item_name, chain in self.chains.items():
            new_manager.chains[item_name] = chain.clone()
        return new_manager

    def __repr__(self):
        return str(self.chains)
