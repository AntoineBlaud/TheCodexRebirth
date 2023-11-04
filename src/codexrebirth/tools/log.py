import time
import sys


def log(dlevel, message, debug_level, color):
    """
    Log messages based on the debug level.

    Args:
        dlevel (int): Debug level.
        info (str): Information to log.
    """
    date = time.strftime("%H:%M:%S", time.localtime())
    if dlevel <= debug_level:
        if sys.stdout.isatty():
            message = f"\033[2m{date}\033[0m  {color}{message}\033[0m"
        else:
            message = f"{message}"
        print(message)
