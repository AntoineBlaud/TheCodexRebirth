from tenet.util.qt import *
from tenet.util.common import *
from tenet.util.misc import *
from tenet.util.counter import alt_count
from tenet.tracer.structures_tracer import *
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
        self.watchdog_max_hits = 50
        self.watcher = Watcher(0x0)
        self.counter_exec_outside_module = alt_count()
        self.reset()

    def reset(self):
        self.tenet_trace = []
        self.seen_instructions_count = {}
        self.cache_string_value = {}


class StepTracerController(object):
    def __init__(self, dctx, arch):
        self.prev_ea = None
        self.arch = arch
        self.dctx = dctx
        self.start = time.time()
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

    #  After the instruction is executed, the controller will add the trace entry
    # to tenet trace. We register the memory and register values in the trace entry.

    def add_trace_entry(self):
        PTR_SIZE = self.arch.POINTER_SIZE
        cache_string_value = self.model.cache_string_value
        dump_size = self.model.dump_size
        
        # Reset the cache every 2048 instructions
        if self.model.counter.value % 2048 == 0:
            self.model.cache_string_value = {}

        def read_memory_and_append_entry(mem_addr):
            try:
                if not self.dctx.is_mapped(mem_addr):
                    return
            except Exception as e:
                return

            mem_value = self.dctx.read_memory(mem_addr, PTR_SIZE)
            cached_mem_value = cache_string_value.get(mem_addr, None)
            # check is the same value and the same register or instruction where the memory was read
            if cached_mem_value == mem_value:
                return True

            cache_string_value[mem_addr] = mem_value
            hex_mem_value = "".join([f"{byte:02x}" for byte in mem_value])
            hex_mem_value = hex_mem_value.ljust(PTR_SIZE * 2, "0")
            new_trace_entry.append(f"mr={tohex(mem_addr, PTR_SIZE)}:{hex_mem_value}")
            # if there is 2 \x00 in a row, we stop the memory dump
            if b"\x00\x00" in mem_value:
                return False
            return True

        # fetch the register values
        new_trace_entry = []
        for reg in self.arch.REGISTERS_MAIN:
            reg_value = self.dctx.get_reg_value(reg)
            cached_mem_value = cache_string_value.get(reg, None)
            if reg_value == cached_mem_value:
                continue
            new_trace_entry.append(f"{reg.lower()}={tohex(reg_value, PTR_SIZE)}")
            cache_string_value[reg] = reg_value

        # for each register, if is a pointer, read the memory
        for reg in self.arch.REGISTERS_MAIN:
            v = self.dctx.get_reg_value(reg)
            reg_value = v - v % 8
            saved_reg_value = reg_value
            for _ in range(dump_size):
                if not read_memory_and_append_entry(reg_value) and reg_value > saved_reg_value:
                    break
                reg_value += PTR_SIZE

        # Fetch operation and is the memory is accessed, read the memory
        # ex : push offsetString
        asm = disasm(self.dctx, self.arch, self.ea)
        if asm is not None:
            mem_access = compute_mem_access(asm, self.dctx, self.arch)
            mem_access_bak = mem_access
            mem_access = mem_access - mem_access % 8
            for _ in range(dump_size):
                if not read_memory_and_append_entry(mem_access) and mem_access > mem_access_bak:
                    break
                mem_access += PTR_SIZE

        # Append the trace entry to the tenet trace
        self.model.tenet_trace.append(new_trace_entry)

    def backup_files(self):

        return

    def save_trace(self, backup=False):
        """
        Save a trace to a file in the log directory.

        :param trace: The trace entries as a list of strings
        :return: The path to the saved trace file
        """
        trace = [",".join(entry) for entry in self.model.tenet_trace]
        dir = self.log_dir
        if not dir.exists():
            dir.mkdir(parents=True)
        root_filename = self.dctx.get_root_filename()
        date_timestamp = datetime.datetime.now().strftime("%m-%d-%Y-%H.%M.%S")
        if not backup:
            filename = f"ida_trace_{root_filename}_{date_timestamp}.tenet"
        else:
            filename = f"ida_trace_{root_filename}_backup.tenet"

        trace_file = dir.joinpath(filename)
        with open(trace_file, "w") as f:
            f.write("\n".join(trace))
        logger.info(f"Trace saved to {trace_file}")
        return str(trace_file)

    def save_library_calls(self, library_calls: List[str]):
        """
        Save the library calls to a file in the log directory.

        :param library_calls: The library calls as a list of strings
        :return: The path to the saved library calls file
        """
        library_calls = [str(call) for call in library_calls]
        dir = self.log_dir
        if not dir.exists():
            dir.mkdir(parents=True)
        root_filename = self.dctx.get_root_filename()
        date_timestamp = datetime.datetime.now().strftime("%m-%d-%Y-%H.%M.%S")
        filename = f"ida_library_calls_{root_filename}_{date_timestamp}.txt"
        library_calls_file = dir.joinpath(filename)
        with open(library_calls_file, "w") as f:
            f.write("\n".join(library_calls))
        logger.info(f"Library calls saved to {library_calls_file}")
        return str(library_calls_file)

    def inc_seen_instructions_count(self, ea):
        self.model.seen_instructions_count[ea] = self.model.seen_instructions_count.get(ea, 0) + 1

    def skip_special_loop_instruction(self, ea, prev_ea):
        if ea == prev_ea:
            next_insn = ea + get_item_size(self.dctx, self.arch, ea)
            self.dctx.set_breakpoint(next_insn)
            self.dctx.delete_breakpoint(ea)
            logger.info(f"Skipping special loop instruction at {tohex(ea, self.arch.POINTER_SIZE)}")
            self.dctx.continue_process()
            self.dctx.delete_breakpoint(next_insn)

            if ea == self.ea:
                raise RuntimeError("Failed to skip special loop instruction")

    def finalize_step(self, ea, prev_ea):
        self.inc_seen_instructions_count(ea)
        self.skip_special_loop_instruction(ea, prev_ea)
        mod_name = self.dctx.get_segm_name(ea)
        if mod_name == self.model.module_name:
            self.add_trace_entry()
            next(self.model.counter)
            self.model.counter_exec_outside_module.reset()
        else:
            next(self.model.counter_exec_outside_module)
        if self.model.counter_exec_outside_module.value > 500:
            raise RuntimeError("Execution outside module")
        self.update_ui()
