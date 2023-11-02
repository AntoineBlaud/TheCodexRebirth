class Book(dict):
    def __init__(self):
        super().__init__()

    def __repr__(self) -> str:
        return super().__repr__()
    
    def clone(self):
        clone = Book()
        for key in self:
            clone[key] = self[key]
        return clone