class alt_count:
    def __init__(self, start=0, step=1):
        self.value = start
        self.step = step

    def __next__(self):
        self.value = self.value + self.step
        return self.value
