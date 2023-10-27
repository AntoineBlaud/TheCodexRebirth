class State:
    def __init__(self, idx, value):
        self.idx = idx
        self.value = value
        
    def __repr__(self):
        return f"({self.idx}, {hex(self.value)})"

class _StateChain:
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
    def __init__(self):
        self.chains = {}

    def get_state(self, idx, item_name):
        if item_name in self.chains:
            return self.chains[item_name].get(idx)
        else:
           raise Exception(f"Item {item_name} not found in state manager")  

    def add_item(self, item_name):
        self.chains[item_name] = _StateChain(item_name)
        
    def register(self, idx, item_name, value):
        if item_name not in  self.chains:
            self.chains[item_name] = _StateChain(item_name)
        self.chains[item_name].add(idx, value)
            
    def clone(self):
        new_manager = DataStoreManager()
        for item_name in self.chains:
            new_manager.chains[item_name] = self.chains[item_name].clone()
        return new_manager
    
    def __repr__(self):
        return str(self.chains)

