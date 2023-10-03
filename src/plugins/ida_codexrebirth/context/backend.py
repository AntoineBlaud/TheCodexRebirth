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
from ida_codexrebirth.util.misc import show_msgbox



class CodexRebirthBackendContext:
    def __init__(self):
        self.sym_engine = None
        self.controller = None
        
        self.is_initialized = False
        
        # Create a temporary log file for debugging.
        self.log_file = self.setup_logger()
        
        # Redirect standard input to /dev/null (suppress user input).
        sys.stdin = open(os.devnull, 'r')
        
        

    def initialize(self):
        
        self.is_initialized = False
        
        print("="*80)
        print("Initializing CodexRebirth context (can take a while, please be patient)...")
        print("="*80)
        # Show a message box to the user.
        self.show_message_box()

        # Load the controller script.
        controller = self.load_controller()

        # Rename the controller script with a timestamp.
        self.rename_controller_script(controller)

        # Get the binary path from IDA Pro.
        binary_path = self.get_binary_path()

        # Initialize the backend for emulation.
        self.sym_engine = self.initialize_symbolic_engine(binary_path)
        
        self.is_initialized = True
        
        
    def run_emulation(self):
        
        
        # Check if the debugger is active; otherwise, there's no need to map segments.
        if not ida_dbg.is_debugger_on():
            show_msgbox("Please start the debugger before running the emulation")

        # Map IDA Pro segments to Qiling.
        self.map_segments_to_qiling()

        # Register callbacks for the backend.
        self.register_callbacks()

        # Set up the emulation environment.
        self.map_registers()
        
        
        # Run the emulation.
        try:
            # Run the emulation.
            self.sym_engine.run_emulation()
        except UserStoppedExecution:
            pass


    def setup_logger(self):
        return tempfile.NamedTemporaryFile(prefix="cr_trace", suffix=".txt", dir=os.path.expanduser("~\\Downloads"), delete=False, mode="w")


    def show_message_box(self):
        msgbox("Welcome to Codex Rebirth!\n\n" + \
            "1) Please select a controller script to start the emulation \n" +  \
            "2) Binary must be located in the same directory as the ida database \n" + \
            "3) I recommand to open the ida output window to see the log ('ALT+0') \n" \
            ,"Codex Rebirth")

    def load_controller(self):
        """
        Load the controller script selected by the user.

        Raises:
            Exception: If no controller is selected or loading fails.

        Returns:
            str: Path to the loaded controller script.
        """
        controller = ask_file("Select a controller file (.py)", "Python Files (*.py)")
        if controller is None or len(controller) < 5:
            raise Exception("No controller selected")
        if os.path.isfile(controller):
            try:
                print("Loading controller script")
                sys.path.append(os.path.dirname(controller))
                self.controller = importlib.import_module(os.path.basename(controller).split(".")[0])
                print("Controller script loaded")
                return controller
            except Exception as e:
                print(e)
                raise Exception("Failed to load controller script")

    def rename_controller_script(self, controller):
        """
        Rename the controller script with a timestamp.

        Args:
            controller (str): Path to the controller script.
        """
        part1 = os.path.basename(controller).split("_")[0] if "_" in os.path.basename(controller) else os.path.basename(controller).split(".")[0]
        os.rename(controller, os.path.join(os.path.dirname(controller),  part1 + "_" + str(int(time.time())) + ".py"))

    def get_binary_path(self):
        """
        Get the path to the binary file from IDA Pro.

        Returns:
            str: Path to the binary file.
        """
        return os.path.join(os.getcwd(), idaapi.get_input_file_path())

    def initialize_symbolic_engine(self, binary_path):
        """
        Initialize the backend for emulation.

        Args:
            binary_path (str): Path to the binary file.

        Returns:
            Backend or None: Initialized backend or None if not available.
        """
        # Redirect standard output and standard error to the log file.
        with contextlib.redirect_stdout(self.log_file), contextlib.redirect_stderr(self.log_file):
                # Redirect standard input to /dev/null (suppress user input).
                sys.stdin = open(os.devnull, 'r')
                if self.controller:
                    return getattr(self.controller, "initialize_codex_rebirth", None)(binary_path)
                return None


    def register_callbacks(self):
        """
        Register callbacks with the initialized backend.

        Note:
            This method assumes that the `self.controller` object is already initialized.

        """
        if self.controller:
            return getattr(self.controller, "configure_and_register_callbacks", None)(self.sym_engine)
        return None


    def map_segments_to_qiling(self):
        """
        Map IDA Pro segments to Qiling's memory.

        This function aligns the segments to the page size and joins adjacent segments with the same permissions.

        Args:
            None

        Returns:
            None
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
            
        print("Detected segments with size > 0")
        for seg in to_map:
            print(hex(seg[0]), hex(seg[1]), hex(seg[2]), seg[3])

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
            print(hex(start), hex(end), hex(size), name)
            ql.mem.map(start, size)
            if abs(size) < 0xFFFFFF:
                data = ida_bytes.get_bytes(start, size)
                ql.mem.write(start, data)
            else:
                print("Segment too large to map")
            
            #  update the start and end address of the text segment
            if ".text" in name:
                self.sym_engine.text_start = start
                self.sym_engine.text_end = end

    def map_registers(self):
        """
        Set up the emulation environment based


        Args:
            None

        Returns:
            None
        """

        # Get the current execution address as the emulation start.
        emu_start = get_ea()[0]
        self.sym_engine.set_emu_start(emu_start)
 
        # Set register values based on the current state.
        for regname in get_regs_name():
            val = get_reg_value(regname)
            self.sym_engine.set_register(regname, val)
            print(regname, hex(val))


