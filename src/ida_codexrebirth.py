import ctypes

import ida_dbg
import ida_bytes
import ida_idaapi
import ida_kernwin
import idautils
import idc
import idaapi


from codexrebirth.ui.palette import PluginPalette
from codexrebirth.ui.trace_view import TraceDock
from codexrebirth.trace.reader import TraceReader
from codexrebirth.context.launcher import Launcher
from codexrebirth.context.var_explorer import VarExplorer
from codexrebirth.context.similar_code import SimilarCode
from codexrebirth.context.msnapshot import SnapshotManager
from codexrebirth.tools import *

import time
from PyQt5.QtWidgets import QMessageBox
import random
import keyboard
import openai
import os 
import json
import threading



class CodexRebirthIDA(ida_idaapi.plugin_t):
    """
    The plugin integration layer IDA Pro.
    """
    
    flags = ida_idaapi.PLUGIN_MULTI | ida_idaapi.PLUGIN_HIDE | ida_idaapi.PLUGIN_PROC 
    comment = "Codex Rebirth"
    help = ""
    wanted_name = "CodexRebirth"
    wanted_hotkey = ""

    def __init__(self):
        self.load_config()
        self.reset()
        self.load_ui()
        # OpenAI API key
        openai.api_key = self.config["openai_key"]
        # Var explorer, used to renamed registers in disassembly view
        self.var_exp = VarExplorer()
        # Snapshot manager, used to take and restore IDA execution snapshots
        self.snap_manager = SnapshotManager()
        # Similar code, used to find similar code in the disassembly view
        self.similar_code = SimilarCode()
        print("CodexRebirth: IDA Plugin Loaded")
        
    def reset(self):
        self.user_defined_end_address = None
        self.reader = None
        self.blocks_execution_count  = None
        self.ctx = Launcher()
        self.colors = generate_visually_distinct_colors(40)
        self.cached_address = None
        
        
    def init(self):
        return ida_idaapi.PLUGIN_OK
    
    def run(self, arg):
        pass
    
    def term(self):
        pass
    
    def load_config(self):
        """
        Load the config script selected by the user.

        Raises:
            Exception: If no config is selected or loading fails.

        Returns:
            str: Path to the loaded config script.
        """
        # load config from IDA plugin directory
        config_path = os.path.join(os.path.dirname(__file__), "codexrebirth_config.json")
        config = json.load(open(config_path, "r"))
        validate_config(config)
        self.config = config
        

    @open_console
    def _run(self):
        """
        Execute symbolic execution and handle various scenarios.

        This function performs symbolic execution, handles restoration of the symbolic engine state,
        and checks for specific instructions during execution.

        """
        
        self.ctx.initialize(self.config)
        
        if self.user_defined_end_address:
            # we set the end address to the symbolic engine after the initialization
            self.ctx.sym_runner.set_emu_end(self.user_defined_end_address)

        print("Running Symbolic Execution ...")
        print("UI refresh will be disabled until the end of the symbolic execution")
        ida_kernwin.refresh_idaview_anyway()

        self.ctx.run_emulation(callback=self.on_emulation_complete)


    
    def load_ui(self):
        """
        Load the plugin and register universal UI actions with the disassembler.
        """

        # Initialize icons for UI elements.
        self._icon_id_file = ida_idaapi.BADADDR
        self._icon_id_next_execution = ida_idaapi.BADADDR
        self._icon_id_prev_execution = ida_idaapi.BADADDR

        # Initialize event hooks.
        self._hooked = False
        self._ui_hooks = UIHooks()
        self._dbg_hooks = DBGHooks()

        # Create a new 'plugin context' representing this IDB.
        self.contexts = {}
        self._update_checked = False

        # Define the plugin's color palette.
        self.palette = PluginPalette()

        # Integrate the plugin's UI into the disassembler.
        self._install_hooks()

        # Mark the core as loaded and perform necessary warm-up tasks.
        self.loaded = True
        self.palette.warmup()
        
        self.trace_dock = TraceDock(self)
    



    def on_emulation_complete(self):
        """
        Load a trace file and create a trace reader.

        This function loads a trace from a specified file path and creates a trace reader for navigation and querying.
        The trace reader provides access to the loaded trace and its records.
        """
        if len(self.ctx.sym_runner.trace_records) < 1:
            print("Trace records are not available.")
            return
        
        self.reader = TraceReader(self.ctx.sym_runner.trace_records)
        print(f"Trace loaded with {self.reader.length} records.")
        # Hook into the trace for further processing.
        self.hook()
        # Attach the trace engine to various plugin UI controllers, granting them
        # access to the underlying trace reader.
        self.trace_dock.attach_reader(self.reader)
        
        self.show_ui()
        self.update_block_hits()
        print(self.ctx.sym_runner.taint_st)
        
        print("Symbolic Execution Finished.")
        

    def show_ui(self):
        """
        Integrate and display the plugin's UI in the IDA Pro disassembler.

        This function integrates the plugin's UI elements and displays them in the IDA Pro disassembler interface.
        """

        mw = get_qmainwindow()
        mw.addToolBar(QtCore.Qt.RightToolBarArea, self.trace_dock)
        self.trace_dock.show()
        print("UI successfully loaded.")

    def hook(self):
        """
        Hook into the IDA Pro user interface.
        """
        if self._hooked:
            return
        self._hooked = True
        self._ui_hooks.hook()

    def unhook(self):
        """
        Unhook from the IDA Pro user interface.
        """
        if not self._hooked:
            return
        self._hooked = False
        self._ui_hooks.unhook()
        

    @open_console
    def _interactive_end_address(self):
        """
        Set the user-defined end address.

        This function is called when the user clicks on the context menu item "Set End Address."
        """
        self.user_defined_end_address = idc.here()
        print(f"End address set to {hex(self.user_defined_end_address)}")
        
        # Set a comment at the end address
        idaapi.set_cmt(self.user_defined_end_address, " ===== End address =====", False)
        
        # Set a breakpoint at the end address
        ida_dbg.add_bpt(self.user_defined_end_address, 1, idc.BPT_SOFT)


    def _interactive_clean(self):
        """
        Clean up breakpoints, comments, and colors.

        This function deletes all breakpoints, comments, and custom colors applied in the disassembly.
        """
        delete_all_bpts()
        delete_all_comments()
        delete_all_colors()

    @open_console
    def _interactive_color_similar_blocks(self):
        """
        Color similar blocks in a function based on similarity.

        This function groups similar basic blocks in a function and colors them based on the specified similarity threshold.
        """
        if len(self.colors) < 1:
            raise Exception("No more colors available (max 70)")
            return
        
        args = (self.config["similarity_factor"], 
                self.colors.pop(), 
                ida_kernwin.ask_str("", 0, "Enter a comment"))
        self.similar_code.run(*args)
 
                
    @open_console
    def _interactive_ida_create_execution_snapshot(self):
        """
        Take an IDA execution snapshot.

        This function takes a snapshot of the current IDA execution state and saves it to a file.
        """
        if not ida_dbg.is_debugger_on():
            print("Please start the debugger first")
            return
        
        print("Taking IDA execution snapshot ...")
        self.snap_manager.take_ida_execution_snapshot()
        
    @open_console
    def _interactive_ida_restore_ida_execution_snapshot(self):
        """
        Restore an IDA execution snapshot.

        This function restores a previously taken IDA execution snapshot.
        """
        if not ida_dbg.is_debugger_on():
            print("Please start the debugger first")
            return
        
        print("Restoring IDA execution snapshot ...")
        self.snap_manager.restore_ida_execution_snapshot()
        
        
    def _interactive_go_next_execution(self):
        if not self.reader:
            return
        
        self.reader.seek_to_next(idc.here())
        self.trace_dock.refresh()
        
        
    def  _interactive_go_prev_execution(self):
        if not self.reader:
            return
        
        self.reader.seek_to_prev(idc.here())
        self.trace_dock.refresh()
        
    def _interactive_synchronize_variables(self):
        """
        Synchronize variables between IDA Pro and Qiling.
        """
        self.var_exp.update()
        
    def _interactive_color_taint_id(self):
        """
        Color the current taint id.
        """
        if not self.reader:
            return
        
        taint_id = self.reader.get_trace(self.reader.idx).taint_id
        if taint_id == -1:
            return
        self.reader.set_taint_id_color(taint_id, self.colors.pop())
        print(f"Coloring taint id {taint_id} with color {self.reader.get_taint_id_color(taint_id)}")
        
 
    def _uninstall(self):
        """
        Cleanup & remove all plugin UI integrations.
        """
        # remove trace dock
        mw = get_qmainwindow()
        mw.removeToolBar(self.trace_dock)
        self.trace_dock.close()
        # clean IDA trace
        delete_all_colors()
        delete_all_comments()
        # Reset the UI
        self.reset()
        return

    #--------------------------------------------------------------------------
    # IDA Actions
    #--------------------------------------------------------------------------

    ACTION_RUN = "codexrebirth:run"
    ACTION_END_ADDRESS = "codexrebirth:end_address"
    ACTION_CLEAN = "codexrebirth:clean"
    ACTION_RESET = "codexrebirth:reset"
    ACTION_SIMILAR_BLOCKS = "codexrebirth:similar_blocks"
    ACTION_IDA_CREATE_EXECUTION_SNAPSHOT = "codexrebirth:ida_create_execution_snapshot"
    ACTION_IDA_RESTORE_EXECUTION_SNAPSHOT = "codexrebirth:ida_restore_ida_execution_snapshot"
    ACTION_GO_NEXT_EXECUTION = "codexrebirth:go_next_execution"
    ACTION_GO_PREV_EXECUTION = "codexrebirth:go_prev_execution"
    ACTION_SYNCHRONIZE_VARIABLES = "codexrebirth:synchronize_variables"
    ACTION_COLOR_TAINT_ID = "codexrebirth:color_taint_id"

    
    
    def _install_action(self, widget, popup, action_name, action_text, action_handler, icon_name=None, shortcut=None):
        """
        Install an action in the IDA context menu.

        Args:
            widget: The widget to attach the action to.
            popup: The popup menu to attach the action to.
            action_name: The name of the action.
            action_text: The text to display for the action.
            action_handler: The function to call when the action is triggered.
            icon_name: The name of the icon to use for the action (optional).

        Returns:
            None
        """
        if icon_name is not None:
            icon_data = self.palette.gen_icon(icon_name)
        else:
            icon_data = -1
        
        action_desc = ida_kernwin.action_desc_t(
            action_name,                # The action name
            action_text,                # The action text
            IDACtxEntry(action_handler), # The action handler
            shortcut,                       # Optional: action shortcut
            action_text,                # Optional: tooltip
            ida_kernwin.load_custom_icon(data=icon_data) if icon_data != -1 else icon_data)  # Optional: the action icon

        ida_kernwin.register_action(action_desc)
        ida_kernwin.attach_action_to_popup(widget, popup, action_name, "Codexrebirth/")

    def _install_run_action(self, widget, popup):
        self._install_action(widget, popup, self.ACTION_RUN, "Run Symbolic Execution", self._run, "thunder.png")

    def _install_end_address_action(self, widget, popup):
        self._install_action(widget, popup, self.ACTION_END_ADDRESS, "Set End Address", self._interactive_end_address, "end.png")


    def _install_clean_action(self, widget, popup):
        self._install_action(widget, popup, self.ACTION_CLEAN, "Clean IDA", self._interactive_clean, "reset.png")

    def _install_reset(self, widget, popup):
        self._install_action(widget, popup, self.ACTION_RESET, "Reset Context", self.reset, "reset.png")

    def _install_find_similar_blocks(self, widget, popup):
        self._install_action(widget, popup, self.ACTION_SIMILAR_BLOCKS, "Find Similar Code Blocks", self._interactive_color_similar_blocks)

    def _install_ida_create_execution_snapshot(self, widget, popup):
        self._install_action(widget, popup, self.ACTION_IDA_CREATE_EXECUTION_SNAPSHOT, "Create Execution Snapshot", self._interactive_ida_create_execution_snapshot)
        
    def _install_ida_restore_ida_execution_snapshot(self, widget, popup):
        self._install_action(widget, popup, self.ACTION_IDA_RESTORE_EXECUTION_SNAPSHOT, "Restore Execution Snapshot", self._interactive_ida_restore_ida_execution_snapshot)
     
    def _install_go_next_execution(self, widget, popup):
        self._install_action(widget, popup, self.ACTION_GO_NEXT_EXECUTION, "Go to next execution", self._interactive_go_next_execution, shortcut="Shift+n")
        
    def _install_go_prev_execution(self, widget, popup):
        self._install_action(widget, popup, self.ACTION_GO_PREV_EXECUTION, "Go to previous execution", self._interactive_go_prev_execution, shortcut="Shift+p")
        
    def _install_synchronize_variables(self, widget, popup):
        self._install_action(widget, popup, self.ACTION_SYNCHRONIZE_VARIABLES, "Synchronize variables", self._interactive_synchronize_variables, shortcut="Shift+s")
        
    def _install_color_taint_id(self, widget, popup):
        self._install_action(widget, popup, self.ACTION_COLOR_TAINT_ID, "Color taint id", self._interactive_color_taint_id)
    
    def _install_hooks(self):
        """
        Initialize & integrate all plugin UI elements.

        This method sets up hooks for various UI and debugging events, allowing the plugin to integrate with IDA Pro.
        """
        
        self._ui_hooks.finish_populating_widget_popup = self._popup_hook
        self._ui_hooks.get_lines_rendering_info = self._render_lines
        self._ui_hooks.hook()
        
        self._dbg_hooks.dbg_process_exit = self._exit
        self._dbg_hooks.dbg_process_detach = self._exit
        self._dbg_hooks.hook()


    def _exit(self, pid, tid, ea, code):
        """
        (Event) IDA is about to exit.
        """
        
        self._uninstall()
        return 0


    def _uninstall_action(self, action, icon_id=ida_idaapi.BADADDR):
        """
        Uninstalls the specified action and frees the custom icon associated with it (if any).

        Args:
            action (ida_kernwin.action_desc_t): The action to uninstall.
            icon_id (int, optional): The ID of the custom icon associated with the action. Defaults to ida_idaapi.BADADDR.

        Returns:
            bool: True if the action was successfully uninstalled, False otherwise.
        """
        result = ida_kernwin.unregister_action(action)
        if not result:
            print(f"Failed to unregister {action}...")
            return False

        if icon_id != ida_idaapi.BADADDR:
            ida_kernwin.free_custom_icon(icon_id)

        print(f"Uninstalled the {action} menu entry")
        return True

    #--------------------------------------------------------------------------
    # UI Event Handlers
    #--------------------------------------------------------------------------

    def _popup_hook(self, widget, popup):
        
        """
        (Event) IDA is about to show a popup for the given TWidget.
        """
        
        if ida_kernwin.get_widget_type(widget) == ida_kernwin.BWN_DISASM:
            self._install_run_action(widget, popup)
            self._install_end_address_action(widget, popup)
            self._install_clean_action(widget, popup)
            self._install_find_similar_blocks(widget, popup)
            self._install_ida_create_execution_snapshot(widget, popup)
            self._install_ida_restore_ida_execution_snapshot(widget, popup)
            self._install_go_next_execution(widget, popup)
            self._install_go_prev_execution(widget, popup)
            self._install_synchronize_variables(widget, popup)
            self._install_color_taint_id(widget, popup)
     
            
        
    def _render_lines(self, lines_out, widget, lines_in):
        """
        (Event) IDA is about to render code viewer lines.
        """
        widget_type = ida_kernwin.get_widget_type(widget)

        if widget_type == ida_kernwin.BWN_DISASM:
            self._highlight_disassembly(lines_out, widget, lines_in)

        return
    

    def _highlight_disassembly(self, lines_out, widget, lines_in):
        """
        Highlights the disassembly in IDA Pro with different colors based on the current instruction and its context.

        Args:
            lines_out: The output lines.
            widget: The widget to highlight.
            lines_in: The input lines.

        Returns:
            None
        """
        
        def calculate_index(reader, i, j):
            if j == 0:
                return reader.idx - i
            return reader.idx + i

        def get_taint_color_and_trace(reader, idx, address, default_taint_color):
            trace = reader.get_trace(idx)
            taint_id = trace.taint_id if trace else -1
            color = reader.get_taint_id_color(taint_id) or default_taint_color
            return color, trace

        if not self.reader:
            return
    
        current_address = idc.here()
        backward_color = to_ida_color(self.palette.trail_backward)
        forward_color = to_ida_color(self.palette.trail_forward)
        default_taint_color = to_ida_color(self.palette.trail_tainted)
        end_address_color = to_ida_color(self.palette.end_address)
        current_color = to_ida_color(self.palette.trail_current)
        modifiers = QtGui.QGuiApplication.keyboardModifiers()
        step_over = bool(modifiers & QtCore.Qt.ShiftModifier)

        trail = {}
            
        forward_ips = self.reader.get_next_ips(0x100, step_over)
        backward_ips = self.reader.get_prev_ips(0x6, step_over)
        current_address = self.reader.rebased_ip

        trails = [
            (forward_ips, forward_color),
            (backward_ips, backward_color)
        ]
        
        for j, (trail_addresses, trail_color) in enumerate(trails):
            for i, address in enumerate(trail_addresses):

                idx = calculate_index(self.reader, i, j)
                if address not in trail:
                    color, trace = get_taint_color_and_trace(self.reader, idx, address, default_taint_color)
                    if not trace:
                        continue
                    # if the instruction taint_id is different from the current taint_id,
                    # and the color is the default taint color, we use the trail color
                    if not trace.taint_id == self.reader.current_taint_id and color == default_taint_color:
                       color = trail_color
                    if trace.taint_id == -1:
                        color = trail_color
                    trail[address] = (color, trace)

      
        for section in lines_in.sections_lines:
            for line in section:
                address = line.at.toea()
                
                if address not in trail:
                    continue
                
                color, Trace = trail[address]
                
                if not Trace:
                    continue

                # treat special cases
                if address == current_address:
                    color = current_color

                # apply color for end address
                if address == self.user_defined_end_address:
                    color = end_address_color

                entry = ida_kernwin.line_rendering_output_entry_t(line, ida_kernwin.LROEF_FULL_LINE, color)
                lines_out.entries.push_back(entry)
                
                if current_address == self.cached_address:
                    continue
                
                cmt = idaapi.get_cmt(address, False)
                separator = "@@ "
                cmt = cmt.split(separator)[0] if cmt else ""
                cmt += separator + Trace.Insn.__ida__repr__()
                idaapi.set_cmt(address, cmt, False)
                
                
        self.cached_address = current_address
                

        
    def update_block_hits(self):
        """
        Update the disassembly view.
        """
        
        if not self.reader:
            return
        
        trail_length = self.reader.length
        current_address = idc.here()
 
        blocks_info = self.similar_code.get_all_basic_block_bounds(current_address)[1:] # remove first block
        self.blocks_execution_count = {start: 0 for start, end in blocks_info}
            
        forward_ips = self.reader.get_next_ips(trail_length)
        backward_ips = self.reader.get_prev_ips(trail_length)

        trails = [
            (backward_ips), 
            (forward_ips)
        ]
        
     
        for j, trail_addresses in enumerate(trails):
            for i, address in enumerate(trail_addresses):
                if address in self.blocks_execution_count:
                    self.blocks_execution_count[address] += 1
                
        for block_start, execution_count in self.blocks_execution_count.items():
            idaapi.set_cmt(block_start, f"Executed {execution_count} times  ", False)


                
#------------------------------------------------------------------------------
# IDA UI Helpers
#------------------------------------------------------------------------------

class IDACtxEntry(ida_kernwin.action_handler_t):
    """
    A minimal context menu entry class to utilize IDA's action handlers.
    """

    def __init__(self, action_function):
        super(IDACtxEntry, self).__init__()
        self.action_function = action_function

    def activate(self,  ctx=None):
        """
        Execute the embedded action_function when this context menu is invoked.

        NOTE: We pass 'None' to the action function to act as the '
        """
        self.action_function()
        return 1

    def update(self, ctx=None):
        """
        Ensure the context menu is always available in IDA.
        """
        return ida_kernwin.AST_ENABLE_ALWAYS

#------------------------------------------------------------------------------
# IDA UI Event Hooks
#------------------------------------------------------------------------------


class UIHooks(ida_kernwin.UI_Hooks):
    def get_lines_rendering_info(self, lines_out, widget, lines_in):
        pass
    def ready_to_run(self):
        pass
    def finish_populating_widget_popup(self, widget, popup):
        pass
    
    
class DBGHooks(ida_dbg.DBG_Hooks):
    def dbg_process_attach(self, pid, tid, ea, name, base, size):
        pass
    
    def dbg_process_start(self, pid, tid, ea, name, base, size):
        pass
    
    def dbg_process_exit(self, pid, tid, ea, code):
        pass
    
    def dbg_process_detach(self, pid, tid, ea):
        pass
    
   

    
    
    
def PLUGIN_ENTRY():
    """
    Required plugin entry point for IDAPython Plugins.
    """
    print("Tenet: Loading IDA Plugin...")
    return CodexRebirthIDA()


