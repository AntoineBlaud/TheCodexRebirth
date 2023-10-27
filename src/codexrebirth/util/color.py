import random 
import sys

class Color:
    ANSI_COLOR_FORMAT = "\033[38;5;{}m"

    def __init__(self):
        self.color_code = self.ANSI_COLOR_FORMAT.format(random.randint(30, 200))

    def __repr__(self):
        return self.color_code

    def get_colored_text(self, text):
        """
        Returns the input text with the ANSI color code applied.
        """
        if not sys.stdout.isatty():
            return text
        return f"{self.color_code}{text}\033[0m"


class ANSIColors:
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    PURPLE = "\033[95m"
    ERROR = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
