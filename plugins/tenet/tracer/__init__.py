


class LibraryCall:
    def __init__(self, ea, mod_name, f_name, idx, mod_base) -> None:
        self.ea = ea
        self.mod_name = mod_name
        self.f_name = f_name
        self.idx = idx
        self.mod_base = mod_base

    def __str__(self) -> str:
        return f"idx= {str(self.idx):5s} {self.mod_name} {hex(self.mod_base)}  -> {hex(self.ea)} {self.f_name:20s}"
