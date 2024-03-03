import random
import sys

def rbg_ida_color(r, g, b):
    return 0xFF << 24 | b << 16 | g << 8 | r

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


def generate_visually_distinct_colors(num_colors, min_color_diff=40):
    colors = []
    # set random seed
    random.seed(0)

    def generate_color():
        # Generate random values for the red, green, and blue components
        red = random.randint(0, 150)
        green = random.randint(0, 150)
        blue = random.randint(0, 150)

        return red, green, blue

    def color_distance(color1, color2):
        # Calculate the Euclidean distance between two colors in RGB space
        return sum((c1 - c2) ** 2 for c1, c2 in zip(color1, color2)) ** 0.5

    while len(colors) < num_colors:
        new_color = generate_color()
        is_distinct = True
        for existing_color in colors:
            if color_distance(new_color, existing_color) < min_color_diff:
                is_distinct = False
                break

        if is_distinct:
            colors.append(new_color)

    colors = [rbg_ida_color(r, g, b) for r, g, b in colors]
    return colors
