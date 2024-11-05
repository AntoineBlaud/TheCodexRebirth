

import struct

import ida_bytes
import idaapi
import idc

from tenet.tracer.t_objects import *

PAGE_SIZE = 0x10000
MAX_JUMP_RANGE = 0x80000000  # ±2 GB range for 32-bit or rel32 in 64-bit


class MemoryManager():

    def __init__(self, cs, ks) -> None:
        self.cs = cs
        self.ks = ks

    def hook_code_with_shellcode(self, address, shellcode, shellcode_location, overwrite_instruction_at_address=True , split =False, max_patch_size = 5):
        """
        Patch the given effective address to jump to a new executable section with shellcode,
        execute the shellcode, and then jump back to the next instruction after the original instructions.

        Args:
            ea (int) : The effective address to hook (where to insert the initial jump).
            shellcode (bytes): The shellcode to execute.
            overwrite_instruction_at_address (bool): If true, the target address instruction will be erased

        """

        print(f'Shellcode parameters : \nHook address: 0x{address:X} \nShellcode : {shellcode} \nShellcode Location: {shellcode_location:X}')

        # Step 1: Disassemble the instruction at the target effective address
        instr_size = 0
        instructions_to_copy = []

        copy_start_address = address

        if overwrite_instruction_at_address:
            # Fetch a block of code to disassemble
            code = idc.get_bytes(copy_start_address, 15)

            # Since the instruction at that specific address won't be copied, we bypass it and reduce maxpathsize 
            # to accommodate one less instruction size
            instruction_to_overwrite = next(self.cs.disasm(code, address))
            max_patch_size -= instruction_to_overwrite.size

            copy_start_address = address + instruction_to_overwrite.size


        # Fetch a block of code to disassemble
        code = idc.get_bytes(copy_start_address, 15)
        # Disassemble instructions until we have accumulated a total of 'maxpatchsize' bytes in our code buffer
        for instr in self.cs.disasm(code, copy_start_address):
            instructions_to_copy.append(instr)
            instr_size += instr.size
            if instr_size >= max_patch_size:
                break


        shellcode_size = len(shellcode)

        # Step 2: Copy the instructions to be patched
        original_code = b''.join(instr.bytes for instr in instructions_to_copy)
        original_code_at_shellcode_location = idc.get_bytes(shellcode_location, shellcode_size)

        if split:

            original_code_before_jump = b''

            if len(instructions_to_copy) > 1:
                original_code_before_jump = b''.join(instr.bytes for instr in instructions_to_copy[:-1])
                
            original_code_jump = instructions_to_copy[-1].bytes


        instr_size += (copy_start_address - address)

        print(f"Original code that will be moved {original_code}, size: 0x{instr_size:X}")

        jump_back_address = address + instr_size
        

        # Step 3 & 4: Map a new executable section for the shellcode and write the shellcode into the new section

        # Note that IDA Pro does not support dynamic memory allocation like Unicorn Engine.

        if split:
            ida_bytes.put_bytes(shellcode_location, bytes(original_code_before_jump))
            ida_bytes.put_bytes(shellcode_location + len(original_code_before_jump), bytes(shellcode))

            # Step 5: Append the copied original instructions to the end of the shellcode
            ida_bytes.put_bytes(shellcode_location + shellcode_size + len(original_code_before_jump), bytes(original_code_jump))


        else:
            ida_bytes.put_bytes(shellcode_location, shellcode)
            ida_bytes.put_bytes(shellcode_location + shellcode_size, bytes(original_code))

        # Step 6 & 7: Add a jump back to the next instruction after the hook at the end of

        # the shellcode and patch the original address with a jump to the shellcode's new location

        total_shellcode_size = shellcode_size + len(original_code)

        print(f'Total Shellcode Size {total_shellcode_size:X}, jump_back_address: 0x{jump_back_address:X}')

        jump_back_offset = jump_back_address - (shellcode_location + total_shellcode_size + 5)
        print(hex(jump_back_address), hex(shellcode_location), hex(total_shellcode_size))
        
        # x86/x64 unconditional jump opcode is 0xE9 followed by a 32-bit signed relative offset
        jmp_back_instruction = b'\xE9' + struct.pack('<i', jump_back_offset)


        # x86/x64 unconditional jump opcode is 0xE9 followed by a 32-bit signed relative offset

        jmp_instruction = b'\xE9' + struct.pack('<i', jump_back_offset)
        ida_bytes.put_bytes(shellcode_location + total_shellcode_size, jmp_back_instruction)

        jump_offset = shellcode_location - (address + 5)  # 5 bytes is the length of a JMP instruction


        print(f'Jump offset {hex(jump_offset)}')

        jmp_instruction = b'\xE9' + struct.pack('<i', jump_offset)

        print(f'Jump back offset {jump_back_offset}')

        # Step 8: Fill jmp_instruction with nop until we reach the instr_size to avoid missing bytes corrupting program flow
        for _ in range(5, instr_size):
            jmp_instruction += b'\x90'


        # Patch the original address with this jump
        ida_bytes.put_bytes(address, jmp_instruction)

        print(f"Shellcode created at 0x{shellcode_location:x} from 0x{address:x}")

        hook = Hook()

        hook.address_hooked = address
        hook.original_code = original_code
        hook.shellcode_location = shellcode_location
        hook.total_shellcode_size = total_shellcode_size
        hook.shellcode_size = shellcode_size
        hook.original_code_at_shellcode_location = original_code_at_shellcode_location
        
        return hook

    def assemble_shellcode(self, code):

        encoding, count = self.ks.asm(code)
        instructions = b''
        
        for dec in encoding:
            instructions += int(dec).to_bytes(1, 'little')

        print("Opcodes Hex = (\"" + instructions.hex() + "\")")

        return instructions
        

    def align_to_page(self, addr):
        """Align an address to the start of its page (0x1000 byte boundaries)."""
        return addr & ~(PAGE_SIZE - 1)


    def is_address_within_jump_range(self, target_addr, candidate_addr):
        """
        Check if a candidate address is within the jump range of the target address.
        """
        distance = abs(candidate_addr - target_addr)
        return distance <= MAX_JUMP_RANGE

    def find_free_space_near(self, target_addr, min_size=PAGE_SIZE, max_results=10):
        """
        Find free regions of memory that are not covered by any section, within jump range
        from the target address.
        
        Args:
            target_addr: The address of the instruction we are hooking.
            section_name: The name of the section we're operating near.
            min_size: Minimum size of the free space to consider (default: 1 page).
            max_results: Maximum number of results to return (default: 10).
            
        Returns:
            A list of addresses that are free, within jump range, and fit the minimum size.
        """
        # Get all segments (sections) in the binary
        segments = []
        for i in range(idaapi.get_segm_qty()):
            seg = idaapi.getnseg(i)
            segments.append((seg.start_ea, seg.end_ea))

        # Sort segments by their start addresses
        segments.sort(key=lambda s: s[0])

        # Look for gaps between segments
        free_spaces = []
        for i in range(len(segments) - 1):
            seg_end = segments[i][1]
            next_seg_start = segments[i + 1][0]
            
            # Gap between two segments
            gap_start = self.align_to_page(seg_end + PAGE_SIZE) + PAGE_SIZE * 4
            gap_end = self.align_to_page(next_seg_start)
            
            # If the gap is large enough and within the jump range of the target address
            gap_size = gap_end - gap_start



            # if the gap does not satisfise the min_size and the jump range condition
            if gap_size < min_size or not self.is_address_within_jump_range(target_addr, gap_start):
                continue

            for location in range(gap_start, gap_end, min_size):

                if self.is_address_within_jump_range(target_addr, location):
                    free_spaces.append(location)
                    if len(free_spaces) >= max_results:
                        return free_spaces
            
        # Return only the addresses (start of free spaces)
        return free_spaces
