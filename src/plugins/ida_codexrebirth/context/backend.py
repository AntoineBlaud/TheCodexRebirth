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
from ida_codexrebirth.util.misc import ask_file, msgbox, get_ea, get_regs_name, get_reg_value
from codexrebirth.exceptions import UserStoppedExecution
import  ida_codexrebirth.util.misc as utils
import json
from superglobals import setglobal
from qiling import *

class CodexRebirthBackendContext:
    def __init__(self):
        self.sym_engine = None
        self.config = None
        
        self.is_initialized = False
        
        # Create a temporary log file for debugging.
        self.log_file = self.setup_logger()
        
        # Redirect standard input to /dev/null (suppress user input).
        sys.stdin = open(os.devnull, 'r')
        
        

    def initialize(self):
        
        self.is_initialized = False
        
        utils.print_banner("Initializing CodexRebirth context (can take up to 180 seconds, please be patient)...")
    
        # Show a message box to the user.
        self.show_message_box()

        # Load the config script.
        self.load_config()
    
        # Initialize the backend for emulation.
        self.initialize_symbolic_engine()
        
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


    def show_message_box(self):
        msgbox("Welcome to Codex Rebirth!\n\n" + \
            "1) Please select a config script to start the emulation \n" \
             )

    def load_config(self):
        """
        Load the config script selected by the user.

        Raises:
            Exception: If no config is selected or loading fails.

        Returns:
            str: Path to the loaded config script.
        """
        config = ask_file("Select a config file (.json)", "JSON Files (*.json)")
        if config is None or len(config) < 5:
            raise Exception("No config selected")
        
        config = json.load(open(config, "r"))
        utils.validate_config(config)
        print("Configuration file has been validated")
        self.config = config
        

    def get_binary_path(self):
        """
        Get the path to the binary file from IDA Pro.

        Returns:
            str: Path to the binary file.
        """
        return os.path.join(os.getcwd(), idaapi.get_input_file_path())


    def initialize_symbolic_engine(self):
        """
        This function initializes the backend for emulation. It redirects standard output and standard error to the log file, 
        redirects standard input to /dev/null (suppress user input), maps IDA Pro segments to Qiling, sets up the emulation environment, 
        taints memory and registers, and sets do_not_sym_execute address.
        """
        
        BINARY_PATH_KEY = "binary_path"
        ROOTFS_PATH_KEY = "rootfs_path"
        BINARY_ARCH_KEY = "BinaryArch"
        LOG_PLAIN_KEY = "log_plain"
        SYMBOLIC_CHECK_KEY = "symbolic_check"
        ADDRESSES_KEY = "addresses"
        TAINTED_REGISTERS_KEY = "tainted_registers"
        TAINTED_MEMORY_KEY = "tainted_memory"
        REF_KEY = "ref"
        SIZE_KEY = "size"
        CHUNK_SIZE_KEY = "chunck_size"
        DO_NOT_SYM_EXECUTE_KEY = "do_not_sym_execute"
        config = self.config
                
        # Redirect standard output and standard error to the log file.
        with contextlib.redirect_stdout(self.log_file), contextlib.redirect_stderr(self.log_file):
                # Redirect standard input to /dev/null (suppress user input).
                sys.stdin = open(os.devnull, 'r')
                # Define constants for dictionary keys
                binary_path = config[BINARY_PATH_KEY]
                rootfs_path = config[ROOTFS_PATH_KEY]
                setglobal('BINARY_ARCH', config[BINARY_ARCH_KEY])

                from codexrebirth.core import CodexRebirth, DebugLevel

                ql = Qiling([binary_path], rootfs_path, log_plain=config[LOG_PLAIN_KEY])
                self.sym_engine = CodexRebirth(ql, DebugLevel.INFO, symbolic_check=config[SYMBOLIC_CHECK_KEY])
                
                
        # Map IDA Pro segments to Qiling.
        self.map_segments_to_qiling()
        
        # Set up the emulation environment.
        self.map_registers()
        
        # Taint memory
        for taint_memory in config[TAINTED_MEMORY_KEY]:
            name = taint_memory[REF_KEY]
            size = taint_memory[SIZE_KEY]
            chunk_size = taint_memory[CHUNK_SIZE_KEY]
            ref_addr = config[ADDRESSES_KEY][name]
            segname, offset = ref_addr["segment"], ref_addr["offset"]
            addr = utils.segment_offset_to_address(segname, offset)
            # Read IDA memory to get the value
            expected_value = bytearray(ida_bytes.get_bytes(addr, size))
            # Apply the taint
            print(f"Tainting memory - Name: {name}, Size: {size}, Chunk Size: {chunk_size}, Address: {addr}")
            utils.taint_memory_with_string(self.sym_engine, expected_value, addr, name, chunk_size)

        # Taint registers
        for taint_register in config[TAINTED_REGISTERS_KEY]:
            reg = taint_register["reg"]
            name = taint_register["name"]
            value = get_reg_value(reg)
            # Apply the taint
            print(f"Tainting register - Register: {reg}, Name: {name}, Value: {value}")
            self.sym_engine.taint_register(reg, name, value)
            
            
        # set do_not_sym_execute address
        for do_not_sym_execute in config[DO_NOT_SYM_EXECUTE_KEY]:
            ref_addr = config[ADDRESSES_KEY][do_not_sym_execute]
            segname, offset = ref_addr["segment"], ref_addr["offset"]
            addr = utils.segment_offset_to_address(segname, offset)
            print(f"Address {hex(addr)} added to do_not_sym_execute list")
            self.sym_engine.add_emu_end(addr)
        
        
   

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
        emu_start = get_ea()
        self.sym_engine.set_emu_start(emu_start)
 
        # Set register values based on the current state.
        for regname in get_regs_name():
            val = get_reg_value(regname)
            self.sym_engine.set_register(regname, val)
            print(regname, hex(val))



