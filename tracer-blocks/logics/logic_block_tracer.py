from tenet.tracer.managers import BreakpointManager
from tenet.tracer.librarycall import LibraryCall

from tenet.tracer.librarycall import *
from tenet.tracer.t_objects import *
from tenet.util.disasm import *
from capstone.x86 import *
from tenet.util.ustring import *

from tenet.util.misc import *
from sortedcontainers import SortedDict
import idc
import importlib
import ida_bytes
import idaapi
import logics.memory_manager

class LogicBlockTracer:
    def __init__(self, dctx, arch, model, flog, shellcode_manager):

        importlib.reload(logics.memory_manager)

        # Initialization of core components
        self.cfg = CFG()
        self.model = model
        self.counter = model.counter
        self.flog = flog
        self.dctx = dctx
        self.arch = arch

        # Library function tracking
        self.library_calls = []

        # Shellcode tracking 
        self.shellcode_pokes = {}

        # Tracing-related attributes
        self.breakpoints_set = {}
        self.set_breakpoint_on_next = False
        self.blocks_addresses = SortedDict()

        # Breakpoint management
        self.breakpoint_manager = BreakpointManager(self.dctx, self.flog, 100000)

        # Capstone & Keystone 
        self.cs = get_capstone_md(self.arch)
        self.ks = get_keystone_md(self.arch)

        # Memory and shellcode management
        self.memory_manager = logics.memory_manager.MemoryManager(self.cs, self.ks)
        self.shellcode_manager = shellcode_manager


        # callback methods 
        self.callback_get_ea = None


    def set_callback_get_ea(self, callback: callable):
        """Set the callback for getting the current ea."""
        self.callback_get_ea = callback
        

    @property
    def ea(self):
        return self.callback_get_ea()


    def check_and_skip_library_function(self):
        """Check if the current instruction belongs to a library function and handle skipping."""

        mod_name = self.dctx.get_segm_name(self.ea)
        f_name = self.dctx.get_function_name_at(self.ea)
        idx = self.counter.value

        if not mod_name:
            return False

        if any(x in mod_name.lower() for x in ["dll", "lib", "so", "plt"]):

            mod_base = self.dctx.get_segm_start(self.ea)
            lib_call = LibraryCall(self.ea, mod_name, f_name, idx, mod_base)

            self.library_calls.append(lib_call)
            self.flog(f"Library call: {lib_call}")

            self.dctx.continue_process()

            return True
        
        return False

    
    def tohex(self, ea: int):
        return tohex(ea, self.arch.POINTER_SIZE)


    def parse_jump(self, node, ea):
        # Retrieve the mnemonic of the current instruction
        mnemonic = self.dctx.print_insn_mnemonic(ea)

        # Get the register name for the first operand
        node.op1_reg = self.dctx.get_operand_register_name(ea, 0)

        # Determine jump target based on the operand register or value
        if node.op1_reg:
            node.jump_target = self.dctx.get_reg_value(node.op1_reg)
        else:
            node.jump_target = self.dctx.get_operand_value(ea, 0)

        # Handle unconditional jump
        if mnemonic == self.arch.JUMP_INSTRUCTION:
            node.is_unconditional_jump = True
            node.jump_next = node.jump_target
        else:
            # Handle conditional jump
            node.jump_next = ea + self.dctx.get_item_size(ea)

        return node


    def parse_call(self, node, ea):
        # Set the next instruction address after the call
        node.jump_next = ea + self.dctx.get_item_size(ea)

        # Get the register name for the first operand
        node.op1_reg = self.dctx.get_operand_register_name(ea, 0)

        # Determine call target based on the operand register or value
        if node.op1_reg:
            node.jump_target = self.dctx.get_reg_value(node.op1_reg)
        else:
            node.jump_target = self.dctx.get_operand_value(ea, 0)

        # Mark the node as a call and an unconditional jump
        node.is_call = True
        node.is_unconditional_jump = True

        return node
    
    def is_relative_address(self, instr):
        # Initialize Capstone disassembler for x86/x86_64 architecture (32-bit or 64-bit)
        # Check if the instruction is in the relative-address family (jumps, calls, loops)
        if instr.id in [X86_INS_JMP, X86_INS_CALL] or \
            instr.id in range(X86_INS_JAE, X86_INS_JS + 1) or \
            instr.id in [X86_INS_LOOP, X86_INS_LOOPE, X86_INS_LOOPNE]:
            return True
        
        # Check if the instruction is LEA (Load Effective Address)
        if instr.id == X86_INS_LEA:
            # Examine the operands of LEA for RIP-relative addressing
            for op in instr.operands:
                if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                    return True

        # Check if the operand is an immediate value, which is often used for relative addresses
        for op in instr.operands:
            if op.type == X86_OP_IMM:
                return True

        return False



    def init(self):
        # Retrieve necessary addresses and shellcode parameters
        shellcode_location = self.model.shellcode_location
        target_address = self.ea
        memory_size = 0x128000
        zone_address = self.memory_manager.find_free_space_near(target_address, min_size=memory_size)[0]

        # Build shellcode to allocate memory in the target zone
        alloc_shellcode = self.shellcode_manager.build_allocate_memory(zone_address, memory_size)
        
                
        # Assemble and hook shellcode to the target address
        assembled_opcodes = self.memory_manager.assemble_shellcode(alloc_shellcode)
        hook = self.memory_manager.hook_code_with_shellcode(
            target_address,
            assembled_opcodes,
            shellcode_location,
            overwrite_instruction_at_address=False
        )

        # Set breakpoint after hooking shellcode
        alloc_result_address = hook.shellcode_location + hook.shellcode_size + self.shellcode_manager.ALLOC_RESULT_OFFSET
        self.breakpoint_manager.set_cached_breakpoint(alloc_result_address)
        self.dctx.continue_process()

        # Adjust zone address if on a 64-bit architecture
        zone_address = self.dctx.get_reg_value(self.shellcode_manager.ALLOC_RESULT_REG)

        # Initialize shellcode pokes for monitoring memory addresses
        self.shellcode_pokes = {
            poke: None for poke in range(zone_address, zone_address + memory_size, 0x200)
        }

        # Set and manage breakpoints at the hooked address
        hooked_address_end = hook.address_hooked + len(hook.original_code)
        self.breakpoint_manager.set_cached_breakpoint(hooked_address_end)
        self.dctx.continue_process()
        self.dctx.delete_breakpoint(hooked_address_end)
        self.restore_memory_at_shellcode_location(hook)
        self.restore_hook(hook)
   

    def generate_shellcode_hook(self, poke, node):
        if node.hook:
            raise NotImplementedError("Hook already present is not implemented yet")

        # Step 1: Build the shellcode
        shellcode = self.build_shellcode_for_node(node)

        # Step 2: Remove breakpoints for the target address
        self.clear_breakpoints_in_range(node.address, 5)

        try:
            # Step 3: Get instruction blocks and determine space for hook
            new_target_address, target_addr_instructions_size, total_instructions_size = self.calculate_instruction_space(node.address)
        except Exception as e:
            print(e)
            return None
        

        if None in [new_target_address, target_addr_instructions_size]:
            return None
        
        print(hex(node.address), hex(new_target_address))

        # Step 4: Assemble and apply the shellcode hook
        opcodes = self.memory_manager.assemble_shellcode(shellcode)
        hook = self.memory_manager.hook_code_with_shellcode(
            new_target_address,
            opcodes,
            poke,
            overwrite_instruction_at_address=False,
            split=True,
            max_patch_size=total_instructions_size
        )

        # Remove breakpoints for the target address
        self.clear_breakpoints_in_range(new_target_address, 5)

        # Calculate the address to place the NOP instruction
        nop_address = hook.shellcode_location + hook.shellcode_size - 0x10 + (total_instructions_size - target_addr_instructions_size)
        hook.stop_address = nop_address

        # Step 5: Set the hook information and finalize
        hook.node = node
        hook.target_addr_instructions_size = target_addr_instructions_size
        self.breakpoint_manager.set_cached_breakpoint(hook.stop_address)

        return hook

    # Step 1: Build shellcode based on the node's information
    def build_shellcode_for_node(self, node):
        shellcode = self.shellcode_manager.build_macros()
        cmp_op_reg = self.shellcode_manager.get_cmp_reg(node.op1_reg)

        # Add comparisons for past jump targets
        for past_target in node.already_seen_targets:
            shellcode += self.shellcode_manager.build_compare(cmp_op_reg, past_target, node.op1_reg)

        # Add NOP sled for padding
        shellcode += self.shellcode_manager.build_nop_sled()

        self.flog(shellcode)
        return shellcode

    # Step 2: Remove breakpoints in a specified range
    def clear_breakpoints_in_range(self, start_address, length):
        for addr in range(start_address, start_address + length):
            self.breakpoint_manager.delete_cached_breakpoint(addr)

    # Step 3: Determine available instruction space for hooking
    def calculate_instruction_space(self, target_address):
        block_instructions = self.get_block_instructions(target_address)
        block_instructions.reverse()
        print([hex(b) for b in block_instructions])
        
        total_instructions_size = 0
        offset = 0
        target_addr_instruction_size = 0

        while total_instructions_size < 5:
            if offset >= len(block_instructions):
                raise Exception("Not enough space for shellcode hook")

            new_target_address = block_instructions[offset]
            code = idc.get_bytes(new_target_address, 15)

            for instr in self.cs.disasm(code, new_target_address):
                # If relative address encountered after the first instruction, it's impossible to hook
                if self.is_relative_address(instr) and offset > 0:
                    self.flog("IMPOSSIBLE to insert shellcode hook")
                    return None, None, None

                total_instructions_size += instr.size
                break

            if offset == 0:
                target_addr_instruction_size = total_instructions_size

            offset += 1

        return new_target_address, target_addr_instruction_size, total_instructions_size


    def restore_hook(self, hook: Hook):
        self.restore_original_code(hook.address_hooked, hook.original_code)
        
    def restore_memory_at_shellcode_location(self, hook: Hook):
        self.restore_original_code(hook.shellcode_location, hook.original_code_at_shellcode_location)

    def restore_original_code(self, address, original_code):
        ida_bytes.put_bytes(address, original_code)

    def get_free_poke(self):
        poke = self.find_free_poke()
        if poke is None:
            raise Exception("No more poke available")
        return poke

    def find_free_poke(self):
        for poke, value in self.shellcode_pokes.items():
            if not value:
                return poke
        return None

    def create_special_hook(self, node):
        poke = self.get_free_poke()

        # Generate and apply the shellcode hook
        hook = self.generate_shellcode_hook(poke, node)

        if hook:
            
            self.model.seen_instructions_count[self.ea] +=1

            # Update the instruction pointer to the new shellcode location
            self.update_instruction_pointer(hook)

            # Store the hook in the shellcode pokes
            self.shellcode_pokes[poke] = hook

            return True

        return False

    def update_instruction_pointer(self, hook):
        rip = hook.shellcode_location + hook.total_shellcode_size - hook.target_addr_instructions_size
        self.dctx.set_reg_value("RIP", rip)

    def get_hook_associated(self, address):
        poke = self.find_associated_poke(address)
        return (poke, self.shellcode_pokes[poke]) if poke is not None else None

    def find_associated_poke(self, address):
        sorted_pokes = sorted(self.shellcode_pokes.keys())
        for i in range(len(sorted_pokes) - 1):
            if sorted_pokes[i] <= address and address <= sorted_pokes[i + 1]:
                return sorted_pokes[i]
        return None

    def get_block_instructions(self, ea):
        block_start = self.find_current_block(ea)
        return self.get_instructions_in_block(block_start, ea)

    def find_current_block(self, ea):
        current_block = None
        for blocks_address in self.blocks_addresses:
            if blocks_address > ea:
                break
            current_block = blocks_address
        return current_block

    def get_instructions_in_block(self, block_start, ea):
        return sorted([
            addr for addr in self.model.seen_instructions_count
            if block_start <= addr and addr <= ea
        ])

    def step(self):

        self.log_instruction()
        if self.check_instruction_hit_limit():
            return

        hook_info = self.get_hook_associated(self.ea)
        if hook_info:
            poke, hook = hook_info
            if self.handle_hook(poke, hook):
                return

        self.handle_node_creation()

        if self.set_breakpoint_on_next:
            self.finalize_breakpoint_on_next()

        if not self.handle_instruction():
            return 

        self.model.seen_instructions_count.setdefault(self.ea, 0)
        self.model.seen_instructions_count[self.ea] +=1


        # Check for library function and skip if necessary
        if self.check_and_skip_library_function():
            return

        self.dctx.step_into()

    def log_instruction(self):
        self.model.seen_instructions_count.setdefault(self.ea, 0)
        self.flog(f"{self.tohex(self.ea)} {' '*4}{self.dctx.generate_disasm_line(self.ea)} {self.model.seen_instructions_count[self.ea]}")

    def check_instruction_hit_limit(self):
        hit_count = self.model.seen_instructions_count[self.ea]
        if hit_count >= self.model.max_instruction_hits:
            self.breakpoint_manager.delete_cached_breakpoint(self.ea)
            self.dctx.continue_process()
            return True
        return False

    def handle_hook(self, poke, hook):
        if hook.stop_address != self.ea:
            if self.handle_hook_stop_address_mismatch(hook):
                return True

        self.breakpoint_manager.delete_cached_breakpoint(self.ea)
        node_current = hook.node
        self.update_node_targets(node_current)
        self.set_and_remove_breakpoint(original_address=self.ea + 0x10)

        # Restore and regenerate the hook
        return self.restore_and_generate_hook(poke, hook, node_current)
        

    def handle_hook_stop_address_mismatch(self, hook):
        self.flog(f"handle_hook_stop_address_mismatch, stop address is {hex(hook.stop_address)}")

        for i in range(50):
            self.dctx.step_into()
            hook_info = self.get_hook_associated(self.ea)
            self.flog(f"mismatch at :{self.tohex(self.ea)} {' '*4}{self.dctx.generate_disasm_line(self.ea)}")

            if not hook_info:
                return True
            
            if i > 45:
                raise Exception("Hook stop address mismatch")

  

    def update_node_targets(self, node):
        value = self.dctx.get_reg_value(node.op1_reg)
        node.already_seen_targets.append(value)
        self.flog(f"original_address {hex(self.ea + 0x10)}")

    def set_and_remove_breakpoint(self, original_address):
        self.breakpoint_manager.set_cached_breakpoint(original_address)
        self.dctx.continue_process()
        self.breakpoint_manager.delete_cached_breakpoint(original_address)
        self.dctx.step_into()

    def restore_and_generate_hook(self, poke, hook, node):
        self.restore_hook(hook)
        new_hook = self.generate_shellcode_hook(poke, node)
        if new_hook:
            self.shellcode_pokes[poke] = new_hook
            self.patch_return_address(new_hook)
            return True

        return False

    def patch_return_address(self, hook):
        if self.dctx.is_64bit() or True:
            rsp = self.dctx.get_reg_value("RSP")
            return_address = self.dctx.read_memory(rsp, self.arch.POINTER_SIZE)
            patched_return_address = struct.unpack("<Q", return_address)[0] + 0xf
            ida_bytes.put_bytes(rsp, struct.pack("<Q", patched_return_address))
            self.flog(f"Return address f{hex(patched_return_address)}")
        else:
            raise Exception("Only 64-bit architecture supported for patching return address")

    def handle_node_creation(self):
        if not self.cfg.node_mapping.get(self.ea):
            self.cfg.node_mapping[self.ea] = Node(self.ea, self.arch.POINTER_SIZE)

    def finalize_breakpoint_on_next(self):
        self.set_breakpoint_on_next = False
        self.breakpoint_manager.set_cached_breakpoint(self.ea)

    def handle_instruction(self):
        node_current = self.cfg.node_mapping[self.ea]
        nmemonic = self.dctx.print_insn_mnemonic(self.ea)

        if nmemonic.startswith(self.arch.COND_JUMP_INSTRUCTION) and not nmemonic.startswith("bic"):
            self.handle_conditional_jump(node_current)

        elif nmemonic.startswith(self.arch.CALL_INSTRUCTION):
            self.handle_call_instruction(node_current)

        if self.model.seen_instructions_count[self.ea] == 0 and node_current.jump_target:
            return self.update_jump_targets(node_current)

        return True

    def handle_conditional_jump(self, node):
        node = self.parse_jump(node, self.ea)

    def handle_call_instruction(self, node):
        node = self.parse_call(node, self.ea)
        self.flog(f"Call detected, current node is {self.tohex(node.address)}, fname is {self.dctx.get_function_name_at(self.ea)}")

    def update_jump_targets(self, node):
        self.blocks_addresses[node.jump_next] = True
        self.blocks_addresses[node.jump_target] = True

        if not node.op1_reg and not node.is_call:
            self.breakpoint_manager.set_cached_breakpoint(node.jump_next)
            self.breakpoint_manager.set_cached_breakpoint(node.jump_target)

        elif node.is_call and not node.op1_reg:
            self.breakpoint_manager.set_cached_breakpoint(node.jump_next)
            self.set_breakpoint_on_next = True

        else:
            node.already_seen_targets.append(node.jump_target)
            if self.create_special_hook(node):
                self.dctx.step_into()
                return False

        return True







# ne pas hook un call
    


    
