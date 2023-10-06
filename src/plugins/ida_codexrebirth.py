import ctypes

import ida_dbg
import ida_bytes
import ida_idaapi
import ida_kernwin
import idautils
import idc
import idaapi


from ida_codexrebirth.util.qt import *
from ida_codexrebirth.ui.palette import PluginPalette
import ida_codexrebirth.util.misc as utils

from ida_codexrebirth.ui.trace_view import TraceDock
from ida_codexrebirth.trace.reader import TraceReader
from ida_codexrebirth.context.backend import CodexRebirthBackendContext
import time
from PyQt5.QtWidgets import QMessageBox
import random
import keyboard
import openai

openai.api_key = ""


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
        self.decompilation_block_cache = {}
        self.reset()
        self.load_ui()
        print("CodexRebirth: IDA Plugin Loaded")
        
    def reset(self):
        self.user_defined_end_address = None
        self.sym_engine_last_run = None
        self.reader = None
        self.ctx = CodexRebirthBackendContext()
        
        
    def init(self):
        return ida_idaapi.PLUGIN_OK
    
    def run(self, arg):
        pass
    
    def term(self):
        pass

    @utils.open_console
    def _run(self):
        """
        Execute symbolic execution and handle various scenarios.

        This function performs symbolic execution, handles restoration of the symbolic engine state,
        and checks for specific instructions during execution.

        - If the end address is not set, it shows a message box to the user.
        - If the symbolic engine is not initialized, it initializes it.
        - It restores the sym_engine to its state before symbolic execution if available.
        - Sets the end address to the symbolic engine.
        - Prints messages and sleeps to indicate the execution progress.
        - Checks if the current instruction is in the 'do_not_sym_execute' list and commits symbolic execution if found.
        - Resumes symbolic execution after the 'do_not_sym_execute' instruction if necessary.
        - Prints a banner to indicate the completion of symbolic execution.
        """
        
        if not self.user_defined_end_address:
            # show  a message box to the user
            utils.show_msgbox("Please set the end address first")
            return
                        
        if not self.ctx.is_initialized:
            self.ctx.initialize()
            
        # restore the sym_engine to the state before the symbolic execution
        if self.sym_engine_last_run and len(self.sym_engine_last_run.trace_records) > 0: 
            print("Restoring the symbolic engine to the state before the symbolic execution")
            self.ctx.sym_engine = self.sym_engine_last_run.clone()
            
        # we set the end address to the symbolic engine after the initialization
        self.ctx.sym_engine.set_emu_end(self.user_defined_end_address)
        
        print("Running Symbolic Execution")
        print("UI refresh will be disabled until the end of the symbolic execution")
        time.sleep(0.2)
        self.ctx.run_emulation()
        self.load_trace()
        self.show_ui()
        
        if not self.sym_engine_last_run:
            self.sym_engine_last_run = self.ctx.sym_engine.clone()
            
            
        #check if we land on a 'do_not_sym_execute' instruction
        current_ip = self.ctx.sym_engine.get_current_pc()
        print("Symbolic current IP: ", hex(current_ip))

        if current_ip in self.ctx.do_not_sym_execute:
            print("Current IP is in the list of 'do_not_sym_execute' instructions")
            print("Symbolic execution will be committed")
            self._commit()
            # step over the instruction
            for _ in range(2):
                print("Step over the instruction")
                idaapi.step_over()
                ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)
                
      
            utils.print_banner("Symbolic execution will be resumed in few seconds ...")

            self._run()
        
        utils.print_banner("Symbolic Execution Finished")

        

        
    
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

        # Print a message to indicate successful plugin loading.
        print("UI successfully loaded.")



    def load_trace(self):
        """
        Load a trace file and create a trace reader.

        This function loads a trace from a specified file path and creates a trace reader for navigation and querying.
        The trace reader provides access to the loaded trace and its records.
        """
        
        print("Loading trace records...")
        self.reader = TraceReader(self.ctx.sym_engine.trace_records)
        print(f"Trace loaded with {self.reader.length} records.")

        # Hook into the trace for further processing.
        self.hook()

        print(f"Current state variables:\n {self.ctx.sym_engine.state}")

        # Attach the trace engine to various plugin UI controllers, granting them
        # access to the underlying trace reader.
        self.trace_dock.attach_reader(self.reader)
        

    def show_ui(self):
        """
        Integrate and display the plugin's UI in the IDA Pro disassembler.

        This function integrates the plugin's UI elements and displays them in the IDA Pro disassembler interface.
        """

        mw = get_qmainwindow()
        mw.addToolBar(QtCore.Qt.RightToolBarArea, self.trace_dock)
        self.trace_dock.show()

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

    @utils.open_console
    def _commit(self):
        """
        Commit the current state of the symbolic engine.

        When symbolic execution is launched, it clones the sym_engine and runs emulation on the clone.
        To commit the current state of the sym_engine, we set the sym_engine to the clone.
        """
        if self.ctx.sym_engine:
            self.load_trace()
            self.sym_engine_last_run = self.ctx.sym_engine.clone()
            utils.print_banner("Committing the current state of the symbolic engine")
            # IDA continues to run until the end address
            ida_dbg.continue_process()

    @utils.open_console
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

    @utils.open_console
    def _interactive_get_seg_offset(self):
        """
        Get the segment offset for the current address.

        This function is called when the user wants to retrieve the segment offset for the current address.
        """
        address = idc.here()
        seg = str(utils.address_to_segment_offset(address)).replace('\'', '\"')
        print(f"Offset of {hex(address)}: {seg}")

    def _interactive_clean(self):
        """
        Clean up breakpoints, comments, and colors.

        This function deletes all breakpoints, comments, and custom colors applied in the disassembly.
        """
        utils.delete_all_bpts()
        utils.delete_all_comments()
        utils.delete_all_colors()

    @utils.open_console
    def _interactive_color_common_blocks(self):
        """
        Color common blocks in a function based on similarity.

        This function groups similar basic blocks in a function and colors them based on the specified similarity threshold.
        """
        # Specify the Levenshtein similarity threshold (e.g., 0.7 for 70% similarity)
        similarity_threshold = 0.90
        common_block_color = self.palette.common_block_color
        
        # Specify the address (EA) of the function you want to analyze
        function_address = idc.here()  # Change this to the address of your function
        
        # Get the list of basic blocks with disassembly for the specified function
        blocks_info = utils.get_all_basic_blocks(function_address)

        if blocks_info:
            # Group similar blocks based on the threshold
            grouped_blocks =  utils.group_similar_blocks(blocks_info, similarity_threshold)
            for group in grouped_blocks:
                group = [ea for ea, _ in group]
                # Color blocks in the group if they exceed a certain size
                if len(group) > 5:
                    # apply a random color slightly different than the common block color
                    rand1 = random.randint(0, 50)
                    rand2 = random.randint(0, 50)
                    rand3 = random.randint(0, 50)
                    r, g, b, _ = common_block_color.getRgb()
                    color = 0xFF000000 | (r + rand1) << 16 | (g + rand2) << 8 | (b + rand3)
                    utils.color_blocks(group, color)  

    @utils.open_console       
    def _interactive_decompile_block(self):
        """
        Decompile a block of code using the OpenAI model.

        This function allows the user to decompile a block of code by providing the equivalent C code and condensing it.
        """
        utils.check_openai_api_key()

        ea = idc.here()
        start_ea, disassembly = utils.get_basic_blocks(ea)
        
        if start_ea in self.decompilation_block_cache:
            cached_response = self.decompilation_block_cache[start_ea]
            utils.print_banner(cached_response, "-")
            return

        prompt = "Provide the equivalent C code and condense it:\n" + str(disassembly)
        response = utils.query_model_sync(prompt)
        self.decompilation_block_cache[start_ea] = response
        utils.print_banner(response, "-")

                    
        
 
    def _uninstall(self):
        """
        Cleanup & remove all plugin UI integrations.
        """
        # remove trace dock
        mw = get_qmainwindow()
        mw.removeToolBar(self.trace_dock)
        self.trace_dock.close()
        # clean IDA trace
        self._interactive_clean()
        # Reset the UI
        self.reset()
        
        return

    #--------------------------------------------------------------------------
    # IDA Actions
    #--------------------------------------------------------------------------

    ACTION_RUN = "codexrebirth:run"
    ACTION_COMMIT = "codexrebirth:commit"
    ACTION_END_ADDRESS = "codexrebirth:end_address"
    ACTION_GET_SEG_OFFSET = "codexrebirth:get_seg_offset"
    ACTION_CLEAN = "codexrebirth:clean"
    ACTION_RESET = "codexrebirth:reset"
    ACTION_SIMILAR_BLOCKS = "codexrebirth:similar_blocks"
    ACTION_DECOMPILE_BLOCK = "codexrebirth:decompile_block"
    
    
    def _install_action(self, widget, popup, action_name, action_text, action_handler, icon_name=None):
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
            None,                       # Optional: action shortcut
            action_text,                # Optional: tooltip
            ida_kernwin.load_custom_icon(data=icon_data) if icon_data != -1 else icon_data)  # Optional: the action icon

        ida_kernwin.register_action(action_desc)
        ida_kernwin.attach_action_to_popup(widget, popup, action_name, "Codexrebirth/")

    def _install_run_action(self, widget, popup):
        self._install_action(widget, popup, self.ACTION_RUN, "Run Symbolic Execution", self._run, "thunder.png")

    def _install_commit_action(self, widget, popup):
        self._install_action(widget, popup, self.ACTION_COMMIT, "Commit Symbolic Execution", self._commit, "handshake.png")

    def _install_end_address_action(self, widget, popup):
        self._install_action(widget, popup, self.ACTION_END_ADDRESS, "Set End Address", self._interactive_end_address, "end.png")

    def _install_get_seg_offset_action(self, widget, popup):
        self._install_action(widget, popup, self.ACTION_GET_SEG_OFFSET, "Get Offset", self._interactive_get_seg_offset)

    def _install_clean_action(self, widget, popup):
        self._install_action(widget, popup, self.ACTION_CLEAN, "Clean IDA", self._interactive_clean, "reset.png")

    def _install_reset(self, widget, popup):
        self._install_action(widget, popup, self.ACTION_RESET, "Reset Context", self.reset, "reset.png")

    def _install_find_common_blocks(self, widget, popup):
        self._install_action(widget, popup, self.ACTION_SIMILAR_BLOCKS, "Find Common Blocks", self._interactive_color_common_blocks)

    def _install_decompile_blocks(self, widget, popup):
        self._install_action(widget, popup, self.ACTION_DECOMPILE_BLOCK, "Decompile Block Code", self._interactive_decompile_block)

        
        
     
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
        if self.sym_engine_last_run:
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
            self._install_commit_action(widget, popup)
            self._install_end_address_action(widget, popup)
            self._install_get_seg_offset_action(widget, popup)
            self._install_clean_action(widget, popup)
            self._install_find_common_blocks(widget, popup)
            self._install_decompile_blocks(widget, popup)
            
        
    def _render_lines(self, lines_out, widget, lines_in):
        """
        (Event) IDA is about to render code viewer lines.
        """
        widget_type = ida_kernwin.get_widget_type(widget)

        if widget_type == ida_kernwin.BWN_DISASM:
            self._highlight_disassesmbly(lines_out, widget, lines_in)

        return
    

    def _highlight_disassesmbly(self, lines_out, widget, lines_in):
        """
        Highlights the disassembly in IDA Pro with different colors based on the current instruction and its context.

        Args:
            lines_out: The output lines.
            widget: The widget to highlight.
            lines_in: The input lines.

        Returns:
            None
        """
        if random.randint(0, 80) != 1:
            return

        trail_length = 2000
        execution_times_color = self.palette.trail_backward
        forward_color = self.palette.trail_forward
        current_color = self.palette.trail_current
        symbolic_color = self.palette.symbolic
        end_address_color = self.palette.end_address
        

        modifiers = QtGui.QGuiApplication.keyboardModifiers()
        step_over = bool(modifiers & QtCore.Qt.ShiftModifier)

        current_address = idc.here()
        current_color = utils.to_ida_color(current_color)
        trail = {}

        blocks_start = utils.get_all_basic_blocks_start(current_address)
        blocks_execution_count = {k: 0 for k in blocks_start}
        
        ignored = {}
        


        if self.reader :
            forward_ips = self.reader.get_next_ips(trail_length, step_over)
            backward_ips = self.reader.get_prev_ips(trail_length, step_over)
            current_address = self.reader.rebased_ip

            trails = [
                (backward_ips, forward_color), 
                (forward_ips, forward_color)
            ]
            

            for j, (addresses, trail_color) in enumerate(trails):
                for i, address in enumerate(addresses):

                    # find the index of the current address in the trail
                    idx = self.reader.idx - i if j == 0 else self.reader.idx + i
                    color = trail_color

                    # apply special color to symbolic addresses
                    if self.reader.is_symbolic(idx):
                        color =  symbolic_color

                    # convert to bgr
                    ida_color = utils.to_ida_color(color)

                    if address not in trail or color == symbolic_color:
                        trail[address] = (ida_color, self.reader.get_Insn(idx))
                        
                    if address in blocks_execution_count:
                        blocks_execution_count[address] += 1
                        
            # color block by execution count
            total_execution_count = sum(blocks_execution_count.values())
            for block_start, execution_count in blocks_execution_count.items():
                
                idaapi.set_cmt(block_start, f"Executed {execution_count} times", False)
                ignored[block_start] = True
                
                if execution_count < 1 or execution_count > 4:
                    continue
                
                ida_color = utils.to_ida_color(execution_times_color)
                utils.color_blocks([block_start], ida_color, cinside=False)
                


        for section in lines_in.sections_lines:
            for line in section:
                address = line.at.toea()
                
                if address in ignored:
                    continue

                if address in trail:
                    color, Insn = trail[address]
                    cmt = utils.remove_line(str(Insn))
                    idaapi.set_cmt(address, cmt, False)

                elif address == current_address:
                    color = current_color

                  # apply color for end address
                elif address == self.user_defined_end_address :
                    color = utils.to_ida_color(end_address_color)

                else:
                    continue

                idaapi.set_item_color(address, color)
                

                


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


