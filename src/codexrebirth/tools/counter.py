class alt_count:

    def __init__(self, start=0, step=1):
        self.current = start
        self.step = step

    def __next__(self):
        self.current = self.current + self.step
        return self.current