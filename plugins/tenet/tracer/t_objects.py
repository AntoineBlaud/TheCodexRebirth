from typing import List, Optional, Dict
from tenet.util.misc import tohex
from tenet.util.ustring import *


class CFG:
    def __init__(self):
        self.root_node: Optional[Node] = None
        self.node_mapping: Dict[int, Node] = {}


class Hook():

    original_code = None
    shellcode_location : Optional[int] = None
    total_shellcode_size : Optional[int] = None
    shellcode_size : Optional[int] = None
    address_hooked : Optional[int] = None
    node_associated : Optional[int] = None
    watchdog_address : Optional[int] = None
    instruction_size_at_hooked_address : Optional[int] = None

    def __init__(self):
        pass
        
class Node:
    def __init__(self, address: int, ptr_size: int):
        self.address: int = address
        self.ptr_size: int = ptr_size
        
        # Flow-related attributes
        self.successors: List["Node"] = []
        self.predecessors: List["Node"] = []
        self.jump_target: Optional[int] = None
        self.jump_next: Optional[int] = None
        self.exit_target: Optional[int] = None
        self.is_unconditional_jump: bool = False
        self.already_seen_targets: List[int] = []
        self.is_call : bool = False
        
        # Loop and hit tracking
        self.is_loop_initiator: bool = False
        self.hit_count: int = 0
        self.disable_successor: bool = False
        
        # Instruction-related attributes
        self.instructions: List[str] = []
        self.first_operand_reg_name: Optional[str] = None
        self.is_node_instructions_complete: bool = False
        
        # Miscellaneous attributes
        self.width: int = 65

        # hook
        self.hook : Optional[Hook] = None

    def __repr__(self):
        return f"Node {tohex(self.address, self.ptr_size)}"

    def format_node(self, seen_instructions_count: Dict[int, int]) -> str:
        """Returns a formatted string representation of the node's state."""
        box_lines = ["+" + "-" * (self.width - 2) + "+"]
        
        # Node header
        box_lines.append(center(f"Node {tohex(self.address, self.ptr_size)}", self.width))
        
        # Loop information and properties
        if self.is_loop_initiator:
            box_lines.append(right(f"Hit count: {self.hit_count}", self.width))
        box_lines.append(right(f"Is loop initiator: {self.is_loop_initiator}", self.width))
        box_lines.append(right(f"Disabled successor: {self.disable_successor}", self.width))
        
        # Successors and predecessors
        box_lines.append(right(f"Successors: {', '.join(map(str, self.successors))}", self.width))
        box_lines.append(right(f"Predecessors: {', '.join(map(str, self.predecessors))}", self.width))
        
        # Jump and exit information
        if self.jump_next:
            box_lines.append(right(f"Jump next: {tohex(self.jump_next, self.ptr_size)}", self.width))
        if self.jump_target:
            box_lines.append(right(f"Jump target: {tohex(self.jump_target, self.ptr_size)}", self.width))
        if self.exit_target:
            box_lines.append(right(f"Exit target: {tohex(self.exit_target, self.ptr_size)}", self.width))
        if self.first_operand_reg_name:
            box_lines.append(right(f"First operand reg: {self.first_operand_reg_name}", self.width))
        
        # Instructions with hit count
        box_lines.append(center("", self.width))
        for ea, instr in self.instructions:
            line = f"{instr}  # {seen_instructions_count.get(ea, 0)}"
            box_lines.append(right(line, self.width))
        
        # Footer
        box_lines.append("+" + "-" * (self.width - 2) + "+")
        
        return "\n".join(box_lines)


