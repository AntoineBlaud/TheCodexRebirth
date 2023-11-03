
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
        expression =  expression.replace(mask_expression, hex(int(mask_expression[4:])), 1)
        
    return expression


def replace_integers_with_hex(input_string):
    # Define a regular expression pattern to match integers
    integer_pattern = r"\b\d+\b"

    # Use a lambda function to convert matched integers to hexadecimal format
    hex_string = re.sub(
        integer_pattern, lambda match: hex(int(match.group())), input_string
    )
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
