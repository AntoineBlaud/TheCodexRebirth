from typing import List
from tenet.util.misc import tohex
from tenet.util.ustring import *


# A node represents a basic block in the control flow graph.


class Node:
    def __init__(self, address: int, ptr_size):
        self.address: int = address
        self.ptr_size = ptr_size
        self.successors: List["Node"] = []
        self.predecessors: List["Node"] = []
        self.j_target: int = None
        self.j_next: int = None
        self.is_loop_initiator: bool = False
        self.hit_count: int = 0
        self.instructions: List[str] = []
        self.is_complete: bool = False
        self.exit_target: int = None
        self.width: int = 65
        self.disable_successor: bool = False

    def __repr__(self):
        return f"Node {tohex(self.address, self.ptr_size)}"

    def fstr(self, seen_instructions_count):
        str_box = "\n"
        str_box += "+" + "-" * (self.width - 2) + "+" + "\n"
        str_box += center(f"Node {tohex(self.address, self.ptr_size)}", self.width)
        if self.is_loop_initiator:
            str_box += right(f"Hit count: {self.hit_count}", self.width)
        str_box += right(f"Is loop initiator: {self.is_loop_initiator}", self.width)
        str_box += right(f"Disabled successor: {self.disable_successor}", self.width)
        str_box += right(f"Successors: {', '.join([str(n) for n in self.successors])}", self.width)
        str_box += right(f"Predecessors: {', '.join([str(n) for n in self.predecessors])}", self.width)
        if self.j_next:
            str_box += right(f"Jump next: {tohex(self.j_next, self.ptr_size)}", self.width)
        if self.j_target:
            str_box += right(f"Jump target: {tohex(self.j_target, self.ptr_size)}", self.width)
        if self.exit_target:
            str_box += right(f"Exit target: {tohex(self.exit_target, self.ptr_size)}", self.width)

        str_box += center("", self.width)
        for ea, instr in self.instructions:
            line = instr + f"  # {seen_instructions_count.get(ea, 0)}"
            str_box += right(line, self.width)
        str_box += "+" + "-" * (self.width - 2) + "+" + "\n"
        return str_box


# A control flow graph represents the flow of instructions.
class CFG:
    def __init__(self):
        self.root_node: Node = None
        self.node_mapping: dict[int, "Node"] = {}
