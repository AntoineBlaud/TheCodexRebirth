import os
from capstone.x86_const import *
from capstone.arm_const import *

from tenet.util.qt import *
from tenet.util.common import *
from tenet.util.disasm import *
from tenet.ui import *
from tenet.integration.api import disassembler


class UltimapModel(object):
    """
    The Ultimap Model.
    It holds all the necessary data for the controller to operate correctly.

    Attributes:
        pctx (object): The project context object passed from the main window.
        arch (str): The architecture type of the current process.
        maxHits (int): Maximum number of hits per function before recording starts.
        timeout (float): Timeout value in seconds before stopping the recording.
        fn_filepath (str): Path to the file containing all the imported functions.
        root_filename (str): Name of the main executable module.
        moduleToTrace (str): Name of the module being traced.
    """

    def __init__(self, pctx):
        """
        Initialize the Ultimap Model object with the passed project context.

        Args:
            pctx (object): The project context object passed from the main window.
        """
        self.pctx = pctx
        self.arch = self.pctx.arch
        self.maxHits = 1
        self.timeout = 30
        self.fn_filepath = ""
        self.root_filename = ""
        self.moduleToTrace = ""
        self.reset()

    def reset(self):
        """
        Reset the model to its original state.

        Resets all variables and data structures in the model.
        """
        # Reset all function breakpoints to false
        self.fn_breakpoints = {}
        # Store imported functions with their addresses
        self.imp_functions = {}
        # Map offsets to function names for efficient lookup
        self.offset_functions = {}
        # List of all recorded execution traces
        self.records = []


class UltimapController(object):
    """
    The Ultimap Controller.

    Attributes:
        pctx (object): The project context object passed from the main window.
        dctx (object): Disassembler context object used to interact with the process.
        model (object): The ultimap model holding all necessary data for operation.
        view (object): The ultimap view displaying everything related to this controller.
    """

    def __init__(self, pctx):
        """
        Initialize the Ultimap Controller object with the passed project context.

        Args:
            pctx (object): The project context object passed from the main window.
        """
        self.pctx = pctx
        # Disassembler context used to interact with the process
        self.dctx = disassembler[self.pctx]
        # Initialize ultimap model with project context
        self.model = UltimapModel(self.pctx)
        # Set root filename from the current project context
        self.model.root_filename = self.dctx.get_root_filename()
        # Create an instance of the ultimap view displaying everything related to this controller
        self.view = UltimapView(self, self.model)
        # Get the architecture type from the project context
        self.arch = self.pctx.arch

    @property
    def ea(self):
        """
        Get the current instruction pointer address.

        Returns:
            int: Current instruction pointer address.
        """
        return self.dctx.get_pc(self.arch)

    def log(self, msg):
        """
        Print a message to stdout with a prefix indicating its origin.

        Args:
            msg (str): The message to be printed.
        """
        print(f"[Ultimap] {msg}")

    def show(self):
        """
        Display the ultimap view containing everything related to this controller.
        """
        self.view.show()

    def set_bp_on_imported_functions(self, imp_functions):
        """
        Set breakpoints on all imported functions.

        Args:
            imp_functions (dict): Dictionary of imported functions with their addresses.
        """
        for name, ea in imp_functions.items():
            # If breakpoint is not already set
            if ea not in self.model.fn_breakpoints:
                # Calculate the address with respect to the base address
                ea = ea + self.base

                # Set a message indicating the breakpoint was successfully set
                self.log(f"Set breakpoint on function {name} {hex(ea)}")

                # Delete any existing breakpoints at this location and then create a new one
                self.dctx.delete_breakpoint(ea)
                self.model.fn_breakpoints[ea] = True
                self.dctx.set_breakpoint(ea)
                self.dctx.update_ui()

    def initialize(self):
        """
        Initialize the controller by setting up all necessary data structures.

        Returns:
            bool: Whether initialization was successful or not.
        """
        # Check if any breakpoints are already set in the debugger
        if self.dctx.get_bpt_qty() > 0:
            show_msgbox(
                "Please remove all breakpoints before starting StepTracer", "StepTracer - Error")
            return False

        # Get the base address of the main executable module
        self.base = self.dctx.get_imagebase()

        # Check if the module was found successfully
        if not self.base:

            # Set a message indicating the module was not found
            self.log(f"Module {self.model.moduleToTrace} not found")
            return False

        # Display a message indicating the module was found successfully
        self.log(
            f"Module {self.model.moduleToTrace} found at {hex(self.base)}")

        # Check if the imported functions file exists in the project directory
        if not os.path.exists(self.model.fn_filepath):
            # Set a message indicating the imported functions file was not found
            self.log(
                f"Imported functions file {self.model.fn_filepath} not found")
            return False
        
        print(f"Imported functions file: {self.model.fn_filepath}")

        # Read all imported functions from the specified file
        with open(self.model.fn_filepath, "r") as f:
            data = f.read().splitlines()
            warning_shown = False
            counter = 0
            for line in data:
                print(line)

                # Split each line into offset and function name
                line = line.strip()
                offset_str, name = line.split(" ")[0], ' '.join(line.split(" ")[1:])
                offset = int(offset_str[2:], 16)

                self.model.imp_functions[name] = offset
                self.model.offset_functions[offset] = name

                # Display a warning if too many imported functions are detected (>1000)
                if counter > 1000 and not warning_shown:
                    warning_shown = True
                    show_msgbox(
                        "The number of imported functions is too high. This may cause performance issues", "Warning"
                    )

                counter += 1

        # Set breakpoints on all imported functions found successfully
        self.set_bp_on_imported_functions(self.model.imp_functions)
        return True

    def run(self):
        """
        Run the controller.

        Returns:
            None: The execution of this method.
        """
        # Check if a debugger is currently attached to the process
        if not self.dctx.is_debugger_on():
            msg = "Debugger is not on"
            show_msgbox(msg, "Error")
            raise Exception(msg)

        # Initialize the controller by setting up all necessary data structures
        if not self.initialize():
            return

        self._run()

    def update_view(self, start, timeout):
        """
        Update the ultimap view displaying everything related to this controller.

        Args:
            start (float): Start time of the recording.
            timeout (float): Timeout value in seconds before stopping the recording.
        """
        percent = int((time.time() - start) * 100 / timeout)
        self.dctx.update_ui()
        self.view.update_progress(percent)

    def disable_breakpoints(self, record_index):
        """
        Disable breakpoints on all imported functions found in a given execution trace.

        Args:
            record_index (int): Index of the execution trace containing imported functions.
        """
        # Check if the provided index is valid
        if len(self.model.records) < record_index:
            return

        record = self.model.records[record_index]

        for name, ea in self.model.imp_functions.items():
            # Check if a breakpoint was found at this location
            if ea in record:

                # Delete any existing breakpoints at this location and then create a new one
                self.dctx.delete_breakpoint(ea)
                self.log(f"Disabled breakpoint on {name}")

    def enable_breakpoints(self, record_index):
        """
        Enable breakpoints on all imported functions found in a given execution trace.

        Args:
            record_index (int): Index of the execution trace containing imported functions.
        """
        # Check if the provided index is valid
        if len(self.model.records) < record_index:
            return

        record = self.model.records[record_index]

        for name, ea in self.model.imp_functions.items():
            # Check if a breakpoint was found at this location
            if ea in record:

                # Delete any existing breakpoints at this location and then create a new one
                self.dctx.set_breakpoint(ea)
                self.log(f"Enabled breakpoint on {name}")

    def _run(self):
        """
        Run the controller.

        Returns:
            None: The execution of this method.
        """
        self.log("Start recording")

        # Start timer and record start time
        self.start_time = time.time()
        self.timeout = self.model.timeout

        current_record = {}
        while True:
            try:
                # Continue the process execution until it finishes or debugger is off
                self.dctx.continue_process()

            except Exception as e:
                self.log(f"Error: {e}")
                break

            self.update_view(self.start_time, self.timeout)

            # Check if debugger is on
            if not self.dctx.is_debugger_on():
                self.log("Debugger is off")
                break

            try:
                # Delete any existing breakpoints at this location and then create a new one
                breakpoint = self.dctx.delete_breakpoint(self.ea)
                offset = self.ea - self.base

                function_name = self.model.offset_functions.get(offset, None)

                if function_name:
                    current_record[function_name] = current_record.get(
                        function_name, 0) + 1
                    self.log(
                        f"Recorded {hex(self.ea + self.base)} ({function_name})")

                else:
                    self.log(f"Function {hex(self.ea + self.base)} not found")

            except Exception as e:
                self.log(f"Error deleting breakpoint: {e}")

            if time.time() - self.start_time >= self.timeout:
                break

        self.update_view(self.start_time, self.timeout)
        self.model.records.append(current_record)
