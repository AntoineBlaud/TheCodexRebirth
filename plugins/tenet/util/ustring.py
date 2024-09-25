import re


def simplify_mask(expression):
    # Regular expression to match a mask expression within parentheses
    mask_pattern = r"(( (\& )?0x[0-9a-f]+)+)"

    # Repeatedly find and simplify mask expressions inside parentheses
    while re.search(mask_pattern, expression):
        match = re.search(mask_pattern, expression)
        # Get the mask expression
        mask_expression = match[0]
        if mask_expression[1] == "&":
            mask_expression = mask_expression[2:]
        expression = expression.replace(mask_expression, f" EVAL{eval(mask_expression)}", 1)

    mask_pattern = r"((EVAL[0-9]+)+)"
    while re.search(mask_pattern, expression):
        match = re.search(mask_pattern, expression)
        # Get the mask expression
        mask_expression = match[0]
        expression = expression.replace(mask_expression, hex(int(mask_expression[4:])), 1)

    return expression


def replace_integers_with_hex(input_string):
    # Define a regular expression pattern to match integers
    integer_pattern = r"\b\d+\b"

    # Use a lambda function to convert matched integers to hexadecimal format
    hex_string = re.sub(integer_pattern, lambda match: hex(int(match.group())), input_string)
    return hex_string


def reformat_expression(expression):
    # expression = simplify_parentheses(expression)
    expression = expression.strip().replace("\t", " ").replace("\n", " ")
    expression = replace_integers_with_hex(expression)
    expression = expression.replace(" ", "")
    special_operators = ["^", "*", "&", "|", "+"]
    for operator in special_operators:
        expression = expression.replace(operator, f" {operator} ")
    expression = simplify_mask(expression)
    return expression


def create_name_from_address(name):
    # Process the name, converting integers to 'mem_0xXXXX' format
    if isinstance(name, int):
        return "mem_" + hex(name)
    return name


def get_str_operand_index(operand, index):
    # Get the operand index from the operand name
    return operand.split(",")[index]


def extract_part_of_list(input_list, max_len, idx):
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
