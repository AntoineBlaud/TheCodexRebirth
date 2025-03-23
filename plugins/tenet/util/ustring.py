import re


def simplify_mask(expression):
    """
    Simplify mask expressions within a given string expression.
    """
    # Regular expression to match a mask expression within parentheses
    mask_pattern = r"(( (\& )?0x[0-9a-f]+)+)"

    # Repeatedly find and simplify mask expressions inside parentheses
    while re.search(mask_pattern, expression):
        match = re.search(mask_pattern, expression)
        mask_expression = match[0]
        if mask_expression[1] == "&":
            mask_expression = mask_expression[2:]
        # Replace the mask expression with its evaluated value
        expression = expression.replace(
            mask_expression, f" EVAL{eval(mask_expression)}", 1)

    # Regular expression to match evaluated mask expressions
    mask_pattern = r"((EVAL[0-9]+)+)"
    while re.search(mask_pattern, expression):
        match = re.search(mask_pattern, expression)
        mask_expression = match[0]
        # Replace the evaluated mask expression with its hexadecimal value
        expression = expression.replace(
            mask_expression, hex(int(mask_expression[4:])), 1)

    return expression


def replace_integers_with_hex(input_string):
    """
    Replace all integers in the input string with their hexadecimal representation.
    """
    # Define a regular expression pattern to match integers
    integer_pattern = r"\b\d+\b"

    # Use a lambda function to convert matched integers to hexadecimal format
    hex_string = re.sub(integer_pattern, lambda match: hex(
        int(match.group())), input_string)
    return hex_string


def reformat_expression(expression):
    """
    Reformat a given expression by simplifying masks, converting integers to hex, and adding spaces around operators.
    """
    # Strip whitespace and replace tabs and newlines with spaces
    expression = expression.strip().replace("\t", " ").replace("\n", " ")
    # Replace integers with their hexadecimal representation
    expression = replace_integers_with_hex(expression)
    # Remove all spaces
    expression = expression.replace(" ", "")
    # Add spaces around special operators
    special_operators = ["^", "*", "&", "|", "+"]
    for operator in special_operators:
        expression = expression.replace(operator, f" {operator} ")
    # Simplify mask expressions
    expression = simplify_mask(expression)
    return expression


def create_name_from_address(name):
    """
    Convert an integer address to a 'mem_0xXXXX' format string.
    """
    if isinstance(name, int):
        return "mem_" + hex(name)
    return name


def get_str_operand_index(operand, index):
    """
    Get the operand index from the operand name.
    """
    return operand.split(",")[index]


def extract_part_of_list(input_list, max_len, idx):
    """
    Extract a sub-list from the input list centered around the given index.
    """
    if idx not in input_list:
        # Find the closest number to idx in the list
        closest_number = min(input_list, key=lambda x: abs(x - idx))
        idx = closest_number

    # Find the index of idx in the list
    idx_index = input_list.index(idx)

    # Calculate the start and end indices for the sub-list
    start = max(0, idx_index - max_len)
    end = min(idx_index + max_len, len(input_list))

    # Extract the desired sub-list
    result = input_list[start:end]

    return result


def extract_part_of_str_list(input_list_str, max_len, idx):
    """
    Extract a sub-list from a comma-separated string of integers centered around the given index.
    """
    try:
        if len(input_list_str) < 20:
            return input_list_str
        input_list = [int(x) for x in input_list_str.split(",")]
        result = extract_part_of_list(input_list, max_len, idx)
        return ", ".join([str(x) for x in result]) + ", ..."
    except Exception as e:
        print(e)
        return input_list_str


def center(s: str, width) -> str:
    """
    Center a string in the console.
    """
    return f"|{' '.join([s.center(width-2)])}|"


def right(s: str, width) -> str:
    """
    Right-align a string in the console.
    """
    return f"| {' '.join([s.ljust(width-4)])} |"


def is_valid_string(s: str) -> bool:
    """
    Check if a string is valid based on the following criteria:
    - Contains at least one vowel
    - Contains at least one consonant
    - Has a minimum length of 6 characters
    """
    vowels = "aeiouyAEIOUY"
    consonants = "bcdfghjklmnpqrstvwxzBCDFGHJKLMNPQRSTVWXZ"
    digits = "0123456789"

    vowel_count = sum(1 for char in s if char in vowels)
    consonant_count = sum(1 for char in s if char in consonants)
    digit_count = sum(1 for char in s if char in digits)

    if vowel_count >= 1 and consonant_count >= 1 and len(s) >= 6:
        return True
    else:
        return False