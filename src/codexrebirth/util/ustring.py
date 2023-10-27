
import re

def remove_all_masks(expression):
    return re.sub(r"&[ ]*0xfffff*", "", expression)


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
    return expression

def create_name_from_addr(name):
    # Process the name, converting integers to 'mem_0xXXXX' format
    if isinstance(name, int):
        return "mem_" + hex(name)
    return name
