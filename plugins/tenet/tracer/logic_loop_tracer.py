
from collections import deque
import logging
import time

from tenet.tracer.t_objects import *
from tenet.util.disasm import *
from tenet.tracer.managers import BreakpointManager
from tenet.tracer.librarycall import LibraryCall



class SkipLoopLogic:
    def __init__(self, dctx, arch, model, max_bp, flog):
        # Context and architecture
        self.dctx = dctx
        self.arch = arch
        
        # Model and state tracking
        self.model = model
        self.counter = model.counter
        self.block_changed = False
        self.skip_node_instructions = False
        self.count_bad_exit = 0
        self.skip_all = False

        # Logging
        self.flog = flog
        
        # Node management
        self.node_current = None
        self.node_previous = None
        self.saved_node_before_call_insn = {}
        self.last_function_returns = False
        self.disable_successors_next_node = False
        self.must_call_loop_detection_next_step = False

        # Call and jump stacks
        self.call_stack = list()
        self.jump_stack = list()

        # Breakpoint management
        self.breakpoints_states = {}
        self.must_check_max_call = False
        self.max_bp = max_bp - 2  # To avoid overflow

        # Callback for EA (Effective Address) retrieval
        self.callback_get_ea = None

        # Library function tracking
        self.library_calls = []
        
        # Control flow graph (CFG)
        self.cfg = CFG()

        # Managers
        self.bm = BreakpointManager(self.dctx, self.flog, self.max_bp)

    # Setter for callback
    def set_callback_get_ea(self, callback: callable):
        """Set the callback for getting the current ea."""
        self.callback_get_ea = callback

    @property
    def ea(self):
        return self.callback_get_ea()
    
    def tohex(self, ea: int):
        return tohex(ea, self.arch.POINTER_SIZE)

    # Stack Management
    def remove_duplicates(self, stack):
        """Remove duplicate items from the stack, keeping the original order."""
        seen = set()
        return [x for x in stack if not (x in seen or seen.add(x))]

    def cleanup_stack(self, stack):
        """Remove duplicates and clean up the stack."""
        stack = self.remove_duplicates(stack)
        to_remove = []
        for dest in set(stack):  # Use a set to avoid duplicates
            if self.model.seen_instructions_count.get(dest, 0) > 0:
                to_remove.append(dest)
        for dest in to_remove:
            stack.remove(dest)
            self.bm.delete_cached_breakpoint(dest)
        # limit to 10
        return list(reversed(stack))[:int(self.max_bp/2)]

    def show_call_stack(self):
        """Display the current call stack."""

        self.flog("Current saved callstack:")

        for call in self.call_stack:
            f_name = self.dctx.get_function_name_at(call)
            self.flog(f"{hex(call)} {f_name}")

    def node_in_predecessors(self, node_1, node_2):
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

    # Flow Control Helpers
    def handle_function_return(self):
        """Handle return instruction by updating the call stack and nodes."""

        if self.node_previous:
            self.node_previous.is_node_instructions_complete = True
            self.flog(self.node_previous.format_node(self.model.seen_instructions_count))

        self.node_previous = self.saved_node_before_call_insn.get(self.ea, None)
        self.last_function_returns = False


    def handle_function_return_setup(self):

        while self.ea in self.call_stack:
            self.call_stack.pop()

        self.last_function_returns = True
        self.block_changed = True

        if self.node_previous:
            self.node_previous.is_node_instructions_complete = True


    def handle_max_hits(self):
        """Check and handle function max hits by setting breakpoints on the call stack."""

        self.must_check_max_call = False
        
        if self.model.seen_instructions_count.get(self.ea, 0) <= self.model.max_instruction_hits:
            return False

        self.flog(f"Max hits reached for function {self.tohex(self.ea)}")

        self.bm.reset_breakpoints_states()
        self.bm.set_breakpoints_on_stack(self.call_stack)
        self.show_call_stack()

        self._continue_process()

        self.last_function_returns = True
        self.block_changed = True
        self.disable_successors_next_node = False
        return True


    def get_jump_target_address(self, ea):
        mnemonic = self.dctx.print_insn_mnemonic(ea)
        if mnemonic.startswith(self.arch.COND_JUMP_INSTRUCTION) and \
            not mnemonic.startswith("bic"):
            try:

                jump_target_address = self.dctx.get_operand_value(ea, 0)
                return jump_target_address if jump_target_address != 0 else None
            
            except Exception as e:
                pass
        return None


    def check_and_skip_library_function(self):
        """Check if the current instruction belongs to a library function and handle skipping."""

        mod_name = self.dctx.get_segm_name(self.ea)
        f_name = self.dctx.get_function_name_at(self.ea)
        idx = self.counter.value

        if not mod_name:
            return False

        if any(x in mod_name.lower() for x in ["dll", "lib", "so"]):

            mod_base = self.dctx.get_segm_start(self.ea)
            lib_call = LibraryCall(self.ea, mod_name, f_name, idx, mod_base)

            self.library_calls.append(lib_call)
            self.flog(f"Library call: {lib_call}")

            self.bm.reset_breakpoints_states()
            self.bm.set_cached_breakpoint(self.call_stack.pop())

            self._continue_process()
            self.bm.delete_cached_breakpoint(self.ea)

            self.block_changed = True
            self.last_function_returns = True
            return True
        
        return False

    # Main step logic
    def step(self):

        """Main stepping logic of the program execution."""

        if not self.callback_get_ea:
            raise ValueError("Callback not set")

        self.prepare_for_step()

        # Handle return if we hit the return address of a function
        if len(self.call_stack) > 0 and self.ea in self.call_stack:
            self.handle_function_return_setup()

        # Check for max function hits
        if self.must_check_max_call and len(self.call_stack) > 0:

            if self.handle_max_hits():
                return

        if self.block_changed:
            self.node_previous = self.node_current
            self.node_current = None

        if self.last_function_returns:
            self.handle_function_return()

        # --

        if self.node_current:
            self.handle_undetected_node_change()

        if self.node_current is None:
            self.handle_change_to_unknown_node()

        if self.node_initialization_required:
            self.instanciate_new_node()

        if self.node_current and self.node_previous:

            self.configure_node_exit_targets()
            self.check_loop_detection_required()

        if self.must_find_loop:
            self.handle_loop_detection()

        self.reset_controls()
        self.append_instruction()
        self.handle_show_previous_node()

        if self.handle_loop_max_hits():

            self.process_loop_exit()
            return

        self.process_instruction()


        self.jump_stack = self.cleanup_stack(self.jump_stack)
        self.call_stack = self.remove_duplicates(self.call_stack)

        # Code handling library function skippin
        if self.check_and_skip_library_function():
            return
        
        self._step()

    def _step(self):

        self.flog(f"Making step, current ea is {self.tohex(self.ea)}")
        self.flog(f"idx={self.model.counter.value}")

        self.dctx.step_into()

    def _continue_process(self):

        self.dctx.continue_process()

        self.flog(f"Continue process, current ea is {self.tohex(self.ea)}")
        self.flog(f"idx={self.model.counter.value}")

    def prepare_for_step(self):
        """Prepare state before stepping into a new instruction."""
        self.saved_ea = self.ea
        self.show_previous_node = False
        self.must_find_loop = False
        self.node_initialization_required = False
        self.skip_all = False

        if self.model.seen_instructions_count.get(self.ea, 0) >= 3 * self.model.max_instruction_hits:
            self.skip_all = True

    def handle_function_return_instruction(self):
        """Handle the case where a return instruction was encountered."""
        self.node_current.is_node_instructions_complete = True
        self.last_function_returns = True
        self.block_changed = True

    def handle_undetected_node_change(self):
        """Handle node changes during stepping."""

        if self.cfg.node_mapping.get(self.ea, None) == None:
            return 
        
        if self.cfg.node_mapping.get(self.ea) == self.node_current:
            return
        
        self.flog(f"Node change without jump at {self.tohex(self.ea)}")

        self.node_previous = self.node_current
        self.node_previous.jump_next = self.node_current.address
        self.node_previous.jump_target = None
        self.node_previous.is_node_instructions_complete = True

        self.node_current = self.cfg.node_mapping[self.ea]
        self.node_current.hit_count += 1

        self.show_previous_node = True
        self.block_changed = False

    def handle_change_to_unknown_node(self):
        self.block_changed = True

        if self.node_previous:
            self.node_previous.is_branch_complete = True
            self.show_previous_node = True

        if self.ea not in self.cfg.node_mapping:
            self.node_initialization_required = True
            return 
        
        self.node_current = self.cfg.node_mapping[self.ea]
        self.node_current.hit_count += 1


    def instanciate_new_node(self):

        self.flog(f"Create new node at {self.tohex(self.ea)}")

        self.node_current = Node(self.ea, self.arch.POINTER_SIZE)
        self.node_current.disable_successor = self.disable_successors_next_node

        if not self.cfg.root_node:
            self.cfg.root_node = self.node_current

        self.node_current.hit_count += 1
        self.cfg.node_mapping[self.ea] = self.node_current


    def configure_node_exit_targets(self):

        if self.node_previous.jump_target == self.node_previous.address:
            self.node_previous.exit_target = self.node_previous.jump_next

        elif self.node_current.address == self.node_previous.jump_next:
            self.node_previous.exit_target = self.node_previous.jump_target

        elif self.node_current.address == self.node_previous.jump_target:
            self.node_previous.exit_target = self.node_previous.jump_next

        else:
            self.node_previous.exit_target = self.node_current.address


    def check_loop_detection_required(self):
        if (self.node_previous not in self.node_current.predecessors \
            or self.must_call_loop_detection_next_step) and not self.node_current.disable_successor:
        
            self.must_call_loop_detection_next_step = False

            if len(self.node_current.predecessors) > 0:

                node = self.node_previous if self.block_changed else self.node_current
                if node.is_unconditional_jump:
                    self.must_call_loop_detection_next_step = True

                else:
                    self.must_find_loop = True

                
            if self.node_previous not in self.node_current.predecessors:
                self.node_current.predecessors.append(self.node_previous)
                self.node_previous.successors.append(self.node_current)


    def handle_loop_detection(self):

        if not self.node_previous:
            return
        
        if self.node_previous.is_loop_initiator:
            return 
        
        path = self.node_in_predecessors(self.node_previous, self.node_current)

        if not path:
            return 
        
        if self.block_changed:
            self.node_previous.is_loop_initiator = True

        else: 
            self.node_current.is_loop_initiator = True

        for i, n in enumerate([self.tohex(n.address) for n in path]):
            self.flog(f"{' '*i} -> {n}")


    def reset_controls(self):

        self.block_changed = False
        self.disable_successors_next_node = False

    def append_instruction(self):
        if not self.node_current.is_node_instructions_complete:
            self.node_current.instructions.append(
                (
                    self.ea,
                    f"{self.tohex(self.ea)} {' '*8}{generate_disasm_line(self.dctx, self.arch, self.ea)}",
                )
            )

    def handle_show_previous_node(self):
        if self.show_previous_node:
            self.flog("Previous Node :")
            self.flog(self.node_previous.format_node(self.model.seen_instructions_count))


    def handle_loop_max_hits(self):

        if (self.node_current.is_loop_initiator or self.skip_all) \
        and self.node_current.exit_target \
        and self.node_current.hit_count >= self.model.max_instruction_hits :
            
            self.flog(f"Loop hits count reach for {self.node_current}")

            if self.model.seen_instructions_count.get(self.ea, 0) > self.model.watchdog_max_hits:
                raise Exception(f"Watchdog Max Hits triggered at {self.tohex(self.ea)}")

            return True
        
        return False


    def process_instruction(self):
        """Process and analyze the current instruction."""
        nmemonic = self.dctx.print_insn_mnemonic(self.ea)

        # Handle jump instructions
        if jump_target_address := self.get_jump_target_address(self.ea):
            self.handle_jump_instruction(nmemonic, jump_target_address)

        # Handle call instructions
        elif nmemonic.startswith(self.arch.CALL_INSTRUCTION):
            self.handle_call_instruction()

        # Handle return instructions
        elif nmemonic.startswith("ret"):
            self.handle_function_return_instruction()

    def handle_jump_instruction(self, mnemonic, target):
        """Handle logic for jump instructions."""
        self.block_changed = True

        jump_next_address = self.ea + self.dctx.get_item_size(self.ea)
        self.node_current.jump_target = target
        self.node_current.jump_next = jump_next_address if mnemonic != self.arch.JUMP_INSTRUCTION else target

        if mnemonic == self.arch.JUMP_INSTRUCTION:

            self.node_current.is_unconditional_jump = True
            self.node_current.first_operand_reg_name = self.dctx.get_operand_register_name(self.ea, 0)
            self.node_current.jump_ea = self.ea

        else:

            self.jump_stack.append(jump_next_address)
            self.jump_stack.append(target)

    def handle_call_instruction(self):
        """Handle logic for call instructions."""

        self.block_changed = True
        self.disable_successors_next_node = True
        next_address = self.ea + self.dctx.get_item_size(self.ea)
        self.saved_node_before_call_insn[next_address] = self.node_current

        self.call_stack.append(next_address)
        self.node_current.is_node_instructions_complete = True
        self.must_check_max_call = True


    def process_loop_exit(self):
        

        self.bm.reset_breakpoints_states()
        self.show_previous_node  = True

        if self.node_current.is_unconditional_jump or self.node_current.first_operand_reg_name:
            self.bm.set_cached_breakpoint(self.node_current.jump_ea)
            self._continue_process()
            self.bm.delete_cached_breakpoint(self.ea)
            self.dctx.step_into()

        else:
            
            self.bm.set_cached_breakpoint(self.node_current.exit_target)
            self.bm.set_breakpoints_on_stack(self.call_stack)
            self.bm.set_breakpoints_on_stack(self.jump_stack)

            self.show_call_stack()
            self._continue_process()

            self.bm.delete_cached_breakpoint(self.ea)
            self.block_changed = True
            self.flog("L")

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
                path = self.node_in_predecessors(self.node_current, exit_target_node)
                # oups, exit_target is the wrong one,
                # test the next block
                if path:
                    self.flog(f"Exit target is not the right one, found a path : {path}")
                    # invert the exit target (because we swith loop initiator we must do it now)                       
                    self.flog(f"Set new node loop initiator to {self.tohex(exit_target_node.address)}")
                    self.node_current.is_loop_initiator = False
                    exit_target_node.is_loop_initiator = True

