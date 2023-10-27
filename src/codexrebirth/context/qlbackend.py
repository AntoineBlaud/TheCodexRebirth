import os
import sys
import tempfile
import contextlib
import importlib
import time
import idaapi
import ida_dbg
import idautils
import idc
import ida_kernwin
import ida_bytes
from codexrebirth.backend.core import QilingRunner
import codexrebirth.util.misc as utils
import json
from superglobals import setglobal
from qiling import *

class QilingBackend:
    def __init__(self):
        self.sym_engine = None
        self.config = None
        self.is_initialized = False
        # Create a temporary log file for debugging.
        self.log_file = self.setup_logger() 
        # Redirect standard input to /dev/null (suppress user input).
        sys.stdin = open(os.devnull, 'r')
        

    def initialize(self, config):
        self.is_initialized = False
        utils.print_banner("Initializing CodexRebirth context (can take up to 180 seconds, please be patient)...")
        # Initialize the backend for emulation.
        self.initialize_symbolic_engine(config)
        self.is_initialized = True
        
        
    def run_emulation(self):
        # Check if the debugger is active; otherwise, there's no need to map segments.
        if not ida_dbg.is_debugger_on():
            utils.show_msgbox("Please start the debugger before running the emulation")
        # Map IDA Pro segments to Qiling.
        self.map_segments_to_qiling()
        # Set up the emulation environment.
        self.map_registers()
            # Run the emulation.
        self.sym_engine.run_emulation()
       


    def setup_logger(self):
        return tempfile.NamedTemporaryFile(prefix="cr_trace", suffix=".txt", delete=False, mode="w")



    def get_binary_path(self):
        """
        Get the path to the binary file from IDA Pro.

        Returns:
            str: Path to the binary file.
        """
        return os.path.join(os.getcwd(), idaapi.get_input_file_path())



    def initialize_symbolic_engine(self, config):
        """
        Initialize the backend for emulation:
        
        1. Redirect standard output and standard error to the log file.
        2. Redirect standard input to /dev/null to suppress user input.
        3. Configure Qiling with the provided binary and rootfs paths.
        4. Set up the emulation environment.
        5. Map IDA Pro segments to Qiling.
        """
        
        # Extract configuration parameters.
        binary_path = self.get_binary_path()
        rootfs_path = config["rootfs_path"]
        log_plain = config["log_plain"]
        debug_level = config["debug_level"]

        # Determine the file type from IDA Pro.
        file_type = idaapi.get_file_type_name()

        # Configure the rootfs path based on the binary's architecture and file type.
        if file_type.startswith("Portable executable"):
            rootfs_path = os.path.join(rootfs_path, "x8664_windows" if "AMD64" in file_type else "x86_windows")
        elif file_type.startswith("ELF"):
            rootfs_path = os.path.join(rootfs_path, "x8664_linux" if "64" in file_type else "x86_linux")

        # Redirect standard output and standard error to the log file.
        with contextlib.redirect_stdout(self.log_file), contextlib.redirect_stderr(self.log_file):
            # Redirect standard input to /dev/null to suppress user input.
            sys.stdin = open(os.devnull, 'r')
            
            # Initialize the Qiling emulator.
            ql = Qiling([binary_path], rootfs_path, log_plain=log_plain)
            self.sym_engine = QilingRunner(ql, debug_level)

        # Map IDA Pro segments to Qiling.
        self.map_segments_to_qiling()
        
        # Set up the emulation environment.
        self.map_registers()

    

    def map_segments_to_qiling(self):
        """
        Map IDA Pro segments to Qiling's memory.

        This function aligns the segments to the page size and joins adjacent segments with the same permissions.
        """
        ql = self.sym_engine.ql

        # Clear existing memory mappings in Qiling.
        ql.mem.unmap_all()
        ql.mem.map_info = []

        # Get a list of segments in IDA Pro, including their start address, end address, and name.
        segments = [(idc.get_segm_start(seg), idc.get_segm_end(seg), idc.get_segm_name(seg)) for seg in idautils.Segments()]

        # Sort segments by their start address.
        segments.sort(key=lambda x: x[0])

        to_map = []
        for start, end, name in segments:
            # Align the start address to the previous segment's end, if available.
            start = max(start, to_map[-1][1] if len(to_map) > 0 else 0)
            # Align the start and end addresses to the page size (4 KB).
            start = (start // 0x1000) * 0x1000
            end = ((end + 0xFFF) // 0x1000) * 0x1000
            size = end - start
            if size > 0:
                to_map.append((start, end, size, name))
            

        # Join adjacent segments with the same permissions.
        for i in range(len(to_map) - 1):
            if to_map[i] is None:
                continue
            for j in range(i + 1, len(to_map)):
                # if current segment end address is equal to next segment start address
                # merge the segments
                if to_map[i][1] == to_map[j][0]:
                    to_map[i] = (to_map[i][0], to_map[j][1], to_map[j][1] - to_map[i][0], f"{to_map[i][3]}_{to_map[j][3]}")
                    to_map[j] = None
                    break

        # Remove segments marked for deletion.
        to_map = [seg for seg in to_map if seg is not None]

        print("Registering memory mappings")
        # Map the segments to Qiling's memory.
        for start, end, size, name in to_map:
            ql.mem.map(start, size)
            if abs(size) < 0xFFFFFF:
                data = ida_bytes.get_bytes(start, size)
                ql.mem.write(start, data)
            else:
                print(hex(start), hex(end), hex(size), name)
                print("Segment too large to map")
            
            #  update the start and end address of the text segment
            if ".text" in name:
                self.sym_engine.text_start = start
                self.sym_engine.text_end = end

    def map_registers(self):
        """
        Set up the emulation environment based
        """
        # Get the current execution address as the emulation start.
        emu_start = utils.get_ea()
        self.sym_engine.set_emu_start(emu_start)
 
        # Set register values based on the current state.
        for regname in utils.get_regs_name():
            val = utils.get_reg_value(regname)
            self.sym_engine.set_register(regname, val)
            print(regname, hex(val))



