from tenet.util.qt import *
from tenet.util.common import *
from tenet.util.misc import *
from tenet.util.counter import alt_count
from tenet.tracer.node import *
from tenet.ui import *
from tenet.integration.api import disassembler
from tenet.util.disasm import *
import logging
from pathlib import Path
from typing import List
from capstone.x86_const import *
from capstone.arm_const import *
import time
import datetime

logger = logging.getLogger(f"Tenet.{__name__}")


class Watcher:
    def __init__(self, address):
        self.address = address
        self.is_saved = False
        self.path = None


class StepTracerModel:
    def __init__(self):
        self.run_timeout = 0
        self.dump_size = 10
        self.max_step_inside_loop = 1
        self.stop_at_idx = 10000000
        self.counter = alt_count()
        self.root_filename = None
        self.module_name = None
        self.module_base = None
        self.watchdog_max_hits = 5000
        self.watcher = Watcher(0x0)
        self.execution_counter_outside_main_module = alt_count()
        self.tenet_trace = []
        self.reset()

    def reset(self):
        self.seen_instructions_count = {}
        self.cache_string_value = {}


class StepTracerController(object):
    def __init__(self, dctx, arch):
        self.prev_ea = None
        self.arch = arch
        self.dctx = dctx
        self.start = None
        self.skip_logic = None
        self.model = StepTracerModel()
        self.model.root_filename = self.dctx.get_root_filename()

    @property
    def ea(self):
        return self.dctx.get_pc(self.arch)

    @property
    def idx(self):
        return self.model.counter.value

    @property
    def log_dir(self):
        """Return the plugin log directory."""
        root_dir = self.dctx.get_root_filename_dir()
        return Path(root_dir).joinpath("tenet_traces")


    def read_memory_and_append_entry(self, mem_addr, new_trace_entry):

        ptr_size = self.arch.POINTER_SIZE
        cache_string_value = self.model.cache_string_value

        try:
            if not self.dctx.is_mapped(mem_addr):
                return
        except Exception as e:
            return

        mem_value = self.dctx.read_memory(mem_addr, ptr_size)
        cached_mem_value = cache_string_value.get(mem_addr, None)

        # check is the same value and the same register or instruction where the memory was read
        if cached_mem_value == mem_value:
            return True

        cache_string_value[mem_addr] = mem_value
        hex_mem_value = "".join([f"{byte:02x}" for byte in mem_value])
        hex_mem_value = hex_mem_value.ljust(ptr_size * 2, "0")

        # append memory read to trace entry 
        new_trace_entry.append(f"mr={tohex(mem_addr, ptr_size)}:{hex_mem_value}")
        
        # if there is 2 \x00 in a row, we stop the memory dump
        if b"\x00\x00" in mem_value:
            return False
        
        return True
    
    def update_tenet_trace(self):
        """
        Register execution state in tenet format
        """

        ptr_size = self.arch.POINTER_SIZE
        registers = self.arch.REGISTERS_MAIN
        cache_string_value = self.model.cache_string_value
        dump_size = self.model.dump_size

        new_trace_entry = []
        
        # Reset the cache every 2048 instructions
        if self.model.counter.value % 2048 == 0:
            self.model.cache_string_value = {}

        for reg in registers:

            reg_value_cursor = self.dctx.get_reg_value(reg)
            cached_mem_value = cache_string_value.get(reg, None)

            if reg_value_cursor == cached_mem_value:
                continue

            new_trace_entry.append(f"{reg.lower()}={tohex(reg_value_cursor, ptr_size)}")
            cache_string_value[reg] = reg_value_cursor

        # for each register, if the value correspond to a pointer, read the memory associated
        for reg in registers:

            value_address = self.dctx.get_reg_value(reg)
            reg_value_cursor = value_address - value_address % 8
            saved_reg_value = reg_value_cursor

            # Dump until read_memory_and_append_entry considers the data has no more value
            for _ in range(dump_size):
                if not self.read_memory_and_append_entry(reg_value_cursor, new_trace_entry) and reg_value_cursor > saved_reg_value:
                    break
                reg_value_cursor += ptr_size


        # If the operation contains a memory access, save the memory values pointed
        # ex : push offsetString
        asm = disasm(self.dctx, self.arch, self.ea)

        if asm is not None:

            mem_access = compute_mem_access(asm, self.dctx, self.arch)
            mem_access_bak = mem_access
            mem_access = mem_access - mem_access % 8

            for _ in range(dump_size):
                if not self.read_memory_and_append_entry(mem_access, new_trace_entry) and mem_access > mem_access_bak:
                    break
                mem_access += ptr_size

        # Append the trace entry to the tenet trace
        self.model.tenet_trace.append(new_trace_entry)


    def backup_files(self):
        return


    def save_trace(self):
        """
        Save a trace to a file in the log directory.

        :param trace: The trace entries as a list of strings
        :return: The path to the saved trace file
        """
        trace = [",".join(entry) for entry in self.model.tenet_trace]

        if not self.log_dir.exists():
            self.log_dir.mkdir(parents=True)

        root_filename = self.dctx.get_root_filename()

        trace_file = self.log_dir.joinpath(f"ida_trace_{root_filename}_{self.idx}.tenet")
     
        with open(trace_file, "w") as f:
            f.write('\n'.join(trace))

        logger.info(f"Trace saved to {trace_file}")

        return str(trace_file)
    

    def save_library_calls(self, library_calls: List[str]):
        """
        Save the library calls to a file in the log directory.

        :param library_calls: The library calls as a list of strings
        :return: The path to the saved library calls file
        """
        library_calls = [str(call) for call in library_calls]

        if not self.log_dir.exists():
            self.log_dir.mkdir(parents=True)

        root_filename = self.dctx.get_root_filename()
        library_calls_file = self.log_dir.joinpath(f"ida_library_calls_{root_filename}_{self.idx}.txt")

        with open(library_calls_file, "w") as f:
            f.write('\n'.join(library_calls))

        logger.info(f"Library calls saved to {library_calls_file}")

        return str(library_calls)


    def update_seen_instructions_count(self, ea):
        self.model.seen_instructions_count[ea] = self.model.seen_instructions_count.get(ea, 0) + 1


    def skip_special_loop_instruction(self, ea, prev_ea):

        if ea != prev_ea:
            return 
        
        next_insn = ea + get_item_size(self.dctx, self.arch, ea)

        self.dctx.set_breakpoint(next_insn)
        self.dctx.delete_breakpoint(ea)

        logger.info(f"Skipping special loop instruction at {tohex(ea, self.arch.POINTER_SIZE)}")

        self.dctx.continue_process()
        self.dctx.delete_breakpoint(next_insn)

        if ea == self.ea:
            raise RuntimeError("Failed to skip special loop instruction")


    def finalize_step(self, ea, prev_ea):

        self.update_seen_instructions_count(ea)

        self.skip_special_loop_instruction(ea, prev_ea)

        if self.dctx.get_segm_name(ea) == self.model.module_name:
            self.update_tenet_trace()
            next(self.model.counter)
            self.model.execution_counter_outside_main_module.reset()

        else:
            next(self.model.execution_counter_outside_main_module)


        if self.model.execution_counter_outside_main_module.value > 500:
            raise RuntimeError("Execution outside module")
        
        self.update_ui()
