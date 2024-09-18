from tenet.tracer.structures_tracer import *
from tenet.util.disasm import *
from collections import deque
import logging
import time


def get_jump_target(dctx, arch, ea):
    mnemonic = dctx.print_insn_mnemonic(ea)
    if mnemonic.startswith(arch.COND_JUMP_INSTRUCTION) and not mnemonic.startswith("bic"):
        try:
            j_target_address = dctx.get_operand_value(ea, 0)
            return j_target_address if j_target_address != 0 else None
        except Exception as e:
            pass
    return None

def get_jump_register(dctx, arch, ea):
    pass


class LibraryCall:
    def __init__(self, ea, mod_name, f_name, idx, mod_base) -> None:
        self.ea = ea
        self.mod_name = mod_name
        self.f_name = f_name
        self.idx = idx
        self.mod_base = mod_base

    def __str__(self) -> str:
        return f"idx= {str(self.idx):5s} {self.mod_name} {hex(self.mod_base)}  -> {hex(self.ea)} {self.f_name:20s}"


class SkipLoopLogic:
    def __init__(self, dctx, arch, model, max_bp, flog):
        self.cfg = CFG()
        self.counter = model.counter
        self.flog = flog
        self.model = model
        self.dctx = dctx
        self.arch = arch
        self.node_current = None
        self.node_previous = None
        self.max_bp = max_bp - 2  # to avoid overflow
        self.jump_stack = deque(maxlen=max_bp)
        self.call_stack = list()
        self.next_disable_successor = False
        self.saved_node_before_call_insn = {}
        self.is_last_fn_return = False
        self.must_check_max_call = False
        self.block_changed = False
        self.callback_get_ea = None
        self.library_calls = []
        self.breakpoints_set = {}
        self.check_loop_next = False
        self.count_bad_exit = 0
        self.skipall = False

    def set_callback_get_ea(self, callback: callable):
        """Set the callback for getting the current ea."""
        self.callback_get_ea = callback

    def set_cached_breakpoint(self, ea):
        if ea in self.breakpoints_set:
            return
        self.flog(f"Set breakpoint at {hex(ea)}")
        self.dctx.set_breakpoint(ea)
        self.breakpoints_set[ea] = True
        
    def set_cached_conditional_breakpoint(self, ea, condition, reg):
        if ea in self.breakpoints_set:
            return
        self.flog(f"Set conditional breakpoint at {hex(ea)} {condition}")
        self.dctx.set_conditional_breakpoint(ea, condition, reg)
        self.breakpoints_set[ea] = True
        
    def delete_cache_breakpoint(self, ea):
        if ea in self.breakpoints_set:
            del self.breakpoints_set[ea]
        self.dctx.delete_breakpoint(ea)
        

    def cleanup_bp(self):
        for bp in self.breakpoints_set:
            self.dctx.delete_breakpoint(bp)
        self.breakpoints_set = {}
        self.flog("Cleanup breakpoints")
        
        
    def remove_doobleons(self, stack):
        seens = dict()
        to_remove = []
        for i, call in enumerate(stack):
            if call in seens:
                to_remove.append(i)
            else:
                seens[call] = True
        for i in reversed(to_remove):
            stack.pop(i)
        return stack
        
    def cleanup_call_stack(self, stack):
        # remove doubloons but keep same order
        return self.remove_doobleons(stack)
                
            
    def show_call_stack(self):
        self.flog("Call stack:")
        for call in self.call_stack:
            f_name = self.dctx.get_function_name_at(call)
            self.flog(f"{hex(call)} {f_name}")
    @property
    def ea(self):
        return self.callback_get_ea()

    def check_and_skip_library_function(self, ea: int):
        """
        Check if a library function should be skipped.

        :param ea: The address of the instruction.
        :return: True if the function should be skipped, False otherwise.
        """
        mod_name = self.dctx.get_segm_name(ea)
        f_name = self.dctx.get_function_name_at(ea)
        idx = self.counter.value
        if (
            mod_name != self.model.module_name
            and "dll" in mod_name.lower()
            or "lib" in mod_name.lower()
            or "so" in mod_name.lower()
        ):
            mod_base = self.dctx.get_segm_start(ea)
            lib_call = LibraryCall(ea, mod_name, f_name, idx, mod_base)
            self.library_calls.append(lib_call)
            self.flog(f"Library call: {lib_call}")
            self.cleanup_bp()
            bp_ea = self.call_stack.pop()
            self.set_cached_breakpoint(bp_ea)
            self.dctx.continue_process()
            self.delete_cache_breakpoint(bp_ea)
            self.block_changed = True
            self.is_last_fn_return = True
            return True
        return False

    def cleanup_jump_stack(self, stack):
        """
        Clean up the stack by removing destinations that have been seen before.

        :param stack: The stack of destinations
        :return: The cleaned-up stack
        """
        stack =  self.remove_doobleons(stack)
        to_remove = []
        for dest in set(stack):  # Use a set to avoid duplicates
            if self.model.seen_instructions_count.get(dest, 0) > 0:
                to_remove.append(dest)
        for dest in to_remove:
            stack.remove(dest)
            self.delete_cache_breakpoint(dest)
        # limit to 10
        return list(reversed(stack))[:10]

    def tohex(self, ea: int):
        return tohex(ea, self.arch.POINTER_SIZE)

    def has_predecessor_node(self, node_1, node_2):
        # Check if node_1 has node_2 in its predecessors
        predecessors_exploration = [(node_1, [])]  # Storing path
        done = set([node_1.address])
        while len(predecessors_exploration) > 0:
            p, path = predecessors_exploration.pop()
            # we already set the node as loop, so we skip it
            if p.address == node_2.address:
                return path + [p]
            for pred in p.predecessors:
                if pred.address not in done:
                    done.add(pred.address)
                    predecessors_exploration.append((pred, path + [p]))
        return None

    # TODO: refactor
    def step(self):
        if None in [self.callback_get_ea]:
            raise ValueError("Callbacks not set")
        saved_ea = self.ea
        show_previous_node = False
        self.init_node = False
        must_find_loop = False
        
        # We hit the return address of a function
        if len(self.call_stack) > 0 and self.ea in self.call_stack:
            # remove all address after the return address
            while self.ea in self.call_stack:
                self.call_stack.pop()
            self.block_changed = True
            self.is_last_fn_return = True
            if self.node_previous:
                self.node_previous.is_complete = True

        # We did a call, we have a max number of hits for the function
        # if reached, we need to set a breakpoint to the return address
        # Code handling max hits for function
        if self.must_check_max_call and len(self.call_stack) > 0:
            self.must_check_max_call = False
            if self.model.seen_instructions_count.get(self.ea, 0) > self.model.watchdog_max_hits:
                self.flog(f"Max hits reached for function {self.tohex(self.ea)}")
                # we hit the max number of hits
                self.cleanup_bp()
                b_count = 0
                # Add bp to all call stack
                for call_target in reversed(self.call_stack):
                    self.set_cached_breakpoint(call_target)
                    if b_count > self.max_bp:
                        break
                    b_count += 1
                self.show_call_stack()
                self.dctx.continue_process()
                self.is_last_fn_return = True
                self.block_changed = True
                self.next_disable_successor = False
                return
        
        # Code handling breakpoint cleanup
        if self.max_bp < 10000:
            self.cleanup_bp()

        # Code handling node change
        if self.block_changed:
            self.node_previous = self.node_current
            self.node_current = None

        if self.model.seen_instructions_count.get(self.ea, 0) >= 3 * self.model.max_step_inside_loop:
            self.skipall = True

        if self.model.seen_instructions_count.get(self.ea, 0) < 3 * self.model.max_step_inside_loop:
            self.skipall = False
            
        if self.model.seen_instructions_count.get(self.ea, 0) > self.model.watchdog_max_hits:
            raise Exception("Watchdog max hits limit reached")

        # Code handling return instruction
        if self.is_last_fn_return:
            if self.node_previous:
                self.node_previous.is_complete = True
                self.flog(self.node_previous.fstr(self.model.seen_instructions_count))
            self.node_previous = self.saved_node_before_call_insn.get(self.ea, None)
            address = self.tohex(self.node_previous.address) if self.node_previous else "None"
            self.flog(f"Return detected, previous node is {address}")
            self.is_last_fn_return = False

        # Code handling node change without jump or conditional jump
        if self.node_current:
            if self.cfg.node_mapping.get(self.ea, None) and self.cfg.node_mapping[self.ea] != self.node_current:
                self.flog(f"Node change without jump at {self.tohex(self.ea)}")
                self.node_previous = self.node_current
                self.node_current = self.cfg.node_mapping[self.ea]
                self.node_previous.j_next = self.node_current.address
                self.node_previous.j_target = None
                self.node_previous.is_complete = True
                show_previous_node = True
                self.node_current.hit_count += 1
                # special case, disable predecessors check
                self.block_changed = False

        # Code handling node change with jump or conditional jump for code already visited
        else:
            self.flog(f"Node change at {self.tohex(self.ea)}, no current node")
            self.block_changed = True
            # complete the previous node
            if self.node_previous:
                self.node_previous.is_complete = True
                show_previous_node = True
            # check if the current ea is already in the node map
            if self.ea in self.cfg.node_mapping:
                self.node_current = self.cfg.node_mapping[self.ea]
                self.node_current.hit_count += 1
                self.flog(f"Fetch Node from mapping {self.tohex(self.node_current.address)}, ea={self.tohex(self.ea)}")
                self.flog(self.node_current.fstr(self.model.seen_instructions_count))
            # Ask to create a new node
            else:
                self.init_node = True

        #  Code handling new node creation
        if self.init_node:
            self.flog(f"Creating new node at {self.tohex(self.ea)}")
            self.node_current = Node(self.ea, self.arch.POINTER_SIZE)
            self.node_current.disable_successor = self.next_disable_successor
            # set the root node if not already set
            if not self.cfg.root_node:
                self.cfg.root_node = self.node_current

            self.node_current.hit_count += 1
            self.cfg.node_mapping[self.ea] = self.node_current

        # Code Handling configuring exit target for loop initiator
        if self.node_previous and self.node_current:

            # loop on the same block, special case
            if self.node_previous.j_target == self.node_previous.address:
                self.node_previous.exit_target = self.node_previous.j_next

            elif self.node_current.address == self.node_previous.j_next:
                self.node_previous.exit_target = self.node_previous.j_target

            elif self.node_current.address == self.node_previous.j_target:
                self.node_previous.exit_target = self.node_previous.j_next

            else:
                self.node_previous.exit_target = self.node_current.address
                # self.flog("Previous node:")
                # self.flog(self.node_previous.fstr(self.model.seen_instructions_count))
                # self.flog("Current node:")
                # self.flog(self.node_current.fstr(self.model.seen_instructions_count))
                # raise Exception("Invalid block loop_initiator")

        # Code Handling loop detection part 1
        if (
            (self.node_current
            and self.node_previous
            and (self.node_previous not in self.node_current.predecessors or self.check_loop_next)
            and not self.node_current.disable_successor)
        ):
            self.check_loop_next = False
            if len(self.node_current.predecessors) > 0:

                # check the node has a jump target and a next jump
                node = self.node_previous if self.block_changed else self.node_current
                if node.is_unconditional_jump:
                    must_find_loop = True
                else:
                    self.check_loop_next = True

            if self.node_previous not in self.node_current.predecessors:
                self.node_current.predecessors.append(self.node_previous)
                self.node_previous.successors.append(self.node_current)

        assert self.node_current is not None

        # Code Handling loop detection part 2
        if must_find_loop:
            self.flog("Checking loop")
            # Check if the previous node has the current node in its predecessors
            if self.node_previous and not self.node_previous.is_loop_initiator:
                path = self.has_predecessor_node(self.node_previous, self.node_current)
                if path:
                    if self.block_changed:
                        self.node_previous.is_loop_initiator = True
                    else:
                        self.node_current.is_loop_initiator = True
                    self.flog(f"Current node is {self.tohex(self.node_current.address)}")
                    self.flog(f"Previous node is {self.tohex(self.node_previous.address)}")
                    self.flog("Path to loop:")
                    for i, n in enumerate([self.tohex(n.address) for n in path]):
                        self.flog(f"{' '*i} -> {n}")

        # reset block change
        self.block_changed = False
        self.next_disable_successor = False

        # add the instruction to the current node
        if not self.node_current.is_complete:
            self.node_current.instructions.append(
                (
                    self.ea,
                    f"{self.tohex(self.ea)} {' '*8}{generate_disasm_line(self.dctx, self.arch, self.ea)}",
                )
            )

        if show_previous_node:
            self.flog("Previous Node :")
            self.flog(self.node_previous.fstr(self.model.seen_instructions_count))

        # Code Handling max hits for loop
        if (
            (self.node_current.is_loop_initiator or self.skipall)
            and self.node_current.exit_target
            and self.node_current.hit_count >= self.model.max_step_inside_loop
        ):
            self.flog(f"Loop hits count reach for {self.node_current}")
            
            if not (self.node_current.is_unconditional_jump and self.node_current.op1_reg):
                b_count = 0
                self.set_cached_breakpoint(self.node_current.exit_target)
                # "Security" reason.
                for call_target in reversed(self.call_stack):
                    self.set_cached_breakpoint(call_target)
                    if b_count > self.max_bp:
                        break
                    b_count += 1
                for call_target in reversed(self.jump_stack):
                    if b_count > self.max_bp:
                        break
                    self.set_cached_breakpoint(call_target)
                    b_count += 1
                    
                self.show_call_stack()
                self.dctx.continue_process()
                self.delete_cache_breakpoint(self.ea)
                self.block_changed = True
                
            else:
                self.flog(f"Setting breakpoint to jump ea {self.tohex(self.node_current.jump_ea)} ")
                self.set_cached_breakpoint(self.node_current.jump_ea)
                self.dctx.continue_process()
                self.delete_cache_breakpoint(self.ea)
                self.dctx.step_into()
    

            # check if we hit the loop exit
            if self.node_current.exit_target != self.ea:
                self.node_current = None
                self.flog("Set node current to None because we hit a other branch")

            else:
                # fetch the node using the current ea (after the continue)
                exit_target_node = self.cfg.node_mapping.get(self.ea, None)
                if exit_target_node:
                    self.flog(f"Exit target node hitted {self.tohex(exit_target_node.address)}")
                    # check if exit target is the true exit target, exit target_node must
                    # not be inside predecessors of the current node (before the continue)
                    path = self.has_predecessor_node(self.node_current, exit_target_node)
                    # oups, exit_target is the wrong one,
                    # test the next block
                    if path:
                        self.flog(f"Exit target is not the right one, found a path : {path}")
                        # invert the exit target (because we swith loop initiator we must do it now)                       
                        self.flog(f"Set new node loop initiator to {self.tohex(exit_target_node.address)}")
                        self.node_current.is_loop_initiator = False
                        exit_target_node.is_loop_initiator = True

            return

        j_target_address = get_jump_target(self.dctx, self.arch, self.ea)
        nmemonic = self.dctx.print_insn_mnemonic(self.ea)

        # Code handling jump instructionn
        if j_target_address is not None:
            self.block_changed = True
            j_next_address = self.ea + self.dctx.get_item_size(self.ea)
            
            self.node_current.j_target = j_target_address
            if nmemonic != self.arch.JUMP_INSTRUCTION:
                self.node_current.j_next = j_next_address
            else:
                self.node_current.j_next = j_target_address
                self.node_current.is_unconditional_jump = True
                self.node_current.op1_reg = self.dctx.get_operand_reg_name(self.ea, 0)
                self.node_current.jump_ea = self.ea
                

            if nmemonic != self.arch.JUMP_INSTRUCTION:
                self.jump_stack.append(j_next_address)
                self.jump_stack.append(j_target_address)
                # add to last_jump is not already hit

        # Code handling call instruction
        if nmemonic.startswith(self.arch.CALL_INSTRUCTION):
            self.block_changed = True
            self.next_disable_successor = True
            # add next insn to call stack if not already hit
            insn_addr_after_call = self.ea + self.dctx.get_item_size(self.ea)
            call_target = self.dctx.get_operand_value(self.ea, 0)
            self.call_stack.append(insn_addr_after_call)
            self.saved_node_before_call_insn[insn_addr_after_call] = (
                self.node_current
            )  # used to restore the node after return
            self.flog(
                f"Call detected, current node is {self.tohex(self.node_current.address)}, fname is {self.dctx.get_function_name_at(self.ea)}"
            )
            self.must_check_max_call = True
            self.node_current.is_complete = True

        # Code handling return instruction
        if nmemonic.startswith("ret"):
            self.block_changed = True
            self.is_last_fn_return = True
            self.node_current.is_complete = True

        # clean jump stack
        self.jump_stack = self.cleanup_jump_stack(self.jump_stack)
        self.call_stack = self.cleanup_call_stack(self.call_stack)

        # Code handling library function skippin
        if self.check_and_skip_library_function(self.ea):
            return

        self.flog(f"Making step, current ea is {self.tohex(self.ea)}")
        self.flog(f"idx={self.model.counter.value}")
        self.dctx.step_into()