import ctypes

import ida_dbg
import ida_bytes
import ida_idaapi
import ida_kernwin
import idautils
import idc
import idaapi
from codexrebirth.exceptions import UserStoppedExecution

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
        self.snaphost_file_path = None
        self.reset()
        self.load_ui()
        print("CodexRebirth: IDA Plugin Loaded")
        
    def reset(self):
        self.user_defined_end_address = None
        self.sym_engine_last_run = None
        self.reader = None
        self.blocks_execution_count  = None
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

        """
        

       
        self.ctx.initialize()

        # we set the end address to the symbolic engine after the initialization
        self.ctx.sym_engine.set_emu_end(self.user_defined_end_address)

        print("Running Symbolic Execution")
        print("UI refresh will be disabled until the end of the symbolic execution")
        ida_kernwin.refresh_idaview_anyway()


        start = time.time()
        
        while True:

            try:
                ida_dbg.del_bpt(utils.get_ea())
                self.ctx.run_emulation()
                break

            except UserStoppedExecution:
                
                current_ip = self.ctx.sym_engine.get_current_pc()
                
                print("User stopped the execution, current ea: ", hex(current_ip))
                
                if time.time() - start > 90:
                    print("Symbolic execution took too long. Aborting ...")
                    break
                
                else:
                    if  utils.get_ea() != current_ip:
                        ida_dbg.add_bpt(current_ip, 1, idc.BPT_SOFT)
                        ida_dbg.continue_process()
                        ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)
                        
                    # avance at least of 2 instructions
                    for _ in range(2):
                        ida_dbg.step_over()
                        ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)
                    
                  


        self.load_trace_ui()
        self.update_disassembly_view(trail_length=0xFFFFF)
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



    def load_trace_ui(self):
        """
        Load a trace file and create a trace reader.

        This function loads a trace from a specified file path and creates a trace reader for navigation and querying.
        The trace reader provides access to the loaded trace and its records.
        """
        if len(self.ctx.sym_engine.trace_records) < 1:
            print("Trace records are not available.")
            return
        
        print("Loading trace records...")
        self.reader = TraceReader(self.ctx.sym_engine.trace_records)
        print(f"Trace loaded with {self.reader.length} records.")

        # Hook into the trace for further processing.
        self.hook()

        print(f"Current state variables:\n {self.ctx.sym_engine.state}")

        # Attach the trace engine to various plugin UI controllers, granting them
        # access to the underlying trace reader.
        self.trace_dock.attach_reader(self.reader)
        
        self.show_ui()
        

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
        similarity_threshold = 0.65
        common_block_color = self.palette.common_block_color
        
        # Specify the address (EA) of the function you want to analyze
        function_address = idc.here()  # Change this to the address of your function
        
        blocks_info = []
        
        # Get the list of basic blocks with disassembly for the specified function
        # remove harcoded values in disassembly (e.g., addresses) to improve the similarity
        for ea, disassembly in utils.get_all_basic_blocks(function_address):
            blocks_info.append((ea, disassembly))

        if blocks_info:
            # Group similar blocks based on the threshold
            grouped_blocks =  utils.group_similar_blocks(blocks_info, similarity_threshold)
            grouped_blocks = [group for group in grouped_blocks if len(group) > 5]
         
            for i, group in enumerate(grouped_blocks):
                # Color blocks in the group if they exceed a certain size
                if len(group) > 5:

                    color = utils.to_ida_color(common_block_color)
                    utils.color_common_blocks(group, color)  
                    ida_kernwin.refresh_idaview_anyway()

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

        prompt = "Please provide a deobfuscated C version of this code. Op1 and op2 represent values found in operands :\n" + str(disassembly)
        response = utils.query_model_sync(prompt)
        self.decompilation_block_cache[start_ea] = response
        utils.print_banner(response, "-")
        
        
    @utils.open_console
    def _interactive_hexdump_mem_diff(self):
        
        print("Hexdumping memory difference (Could take a while) ...")
 
        if not self.ctx.sym_engine:
            print("Symbolic engine is not initialized. Ensure that you run symbolic execution first.")
            return
        
        diff_count = 0
        diff_buffer = []
               
        for seg in idautils.Segments():
            seg_start = idc.get_segm_start(seg)
            seg_end = idc.get_segm_end(seg)
            
            if  abs(seg_end - seg_start) > 0xFFFFF:
                continue
            
            print("Hexdumping segment: ", hex(seg_start), " - ", hex(seg_end))
    
            
            for ea in range(seg_start, seg_end):
                ida_value = int(idc.get_wide_byte(ea))
                ctx_value = int(self.ctx.sym_engine.ql.mem.read(ea, 1)[0])

                if ida_value != ctx_value:
                    
                    if diff_count > 32:
                        continue
                
                    if diff_count < 32:  # Limit to 32 bytes
                        diff_buffer.append((ida_value, ctx_value))
                        
                    elif diff_count == 32:
                        print(hex(ea - diff_count), " :\n", utils.repr_hex_and_ascii(diff_buffer), "...", "\n")
                        diff_buffer = []
                        
                    diff_count += 1
                    
                elif diff_count > 0:
                    print(hex(ea - diff_count), " : ", utils.repr_hex_and_ascii(diff_buffer))
                    diff_buffer = []
                    diff_count = 0  
        
    @utils.open_console
    def _interactive_hightligh_address(self):
        """
        Highlight the current address.
        """
        if not self.reader:
            return
        
        self.reader.set_highlighted_address(idc.here())
         

                    
                  
    @utils.open_console
    def _interactive_ida_create_execution_snapshot(self):
        """
        Take an IDA execution snapshot.

        This function takes a snapshot of the current IDA execution state and saves it to a file.
        """
        if not ida_dbg.is_debugger_on():
            print("Please start the debugger first")
            return
        
        print("Taking IDA execution snapshot ...")
        self.snaphost_file_path = utils.take_execution_snapshot()  
        
    @utils.open_console
    def _interactive_ida_restore_execution_snapshot(self):
        """
        Restore an IDA execution snapshot.

        This function restores a previously taken IDA execution snapshot.
        """
        if not ida_dbg.is_debugger_on():
            print("Please start the debugger first")
            return
        
        if not self.snaphost_file_path:
            print("Please take an execution snapshot first")
            return
        
        print("Restoring IDA execution snapshot ...")
        utils.restore_execution_snapshot(self.snaphost_file_path)
        
        
        
    def _interactive_go_next_execution(self):
        if not self.reader:
            return
        
        self.reader.seek_to_next(idc.here())
        self.trace_dock.update()
        
        
    def  _interactive_go_prev_execution(self):
        if not self.reader:
            return
        
        self.reader.seek_to_prev(idc.here())
        self.trace_dock.update()
        
 
    def _uninstall(self):
        """
        Cleanup & remove all plugin UI integrations.
        """
        # remove trace dock
        mw = get_qmainwindow()
        mw.removeToolBar(self.trace_dock)
        self.trace_dock.close()
        # clean IDA trace
        utils.delete_all_colors()
        # Reset the UI
        self.reset()
        
        return

    #--------------------------------------------------------------------------
    # IDA Actions
    #--------------------------------------------------------------------------

    ACTION_RUN = "codexrebirth:run"
    ACTION_END_ADDRESS = "codexrebirth:end_address"
    ACTION_GET_SEG_OFFSET = "codexrebirth:get_seg_offset"
    ACTION_CLEAN = "codexrebirth:clean"
    ACTION_RESET = "codexrebirth:reset"
    ACTION_SIMILAR_BLOCKS = "codexrebirth:similar_blocks"
    ACTION_DECOMPILE_BLOCK = "codexrebirth:decompile_block"
    ACTION_HEXDUMP_MEM_DIFF = "codexrebirth:hexdump_mem_diff"
    ACTION_IDA_CREATE_EXECUTION_SNAPSHOT = "codexrebirth:ida_create_execution_snapshot"
    ACTION_IDA_RESTORE_EXECUTION_SNAPSHOT = "codexrebirth:ida_restore_execution_snapshot"
    ACTION_GO_NEXT_EXECUTION = "codexrebirth:go_next_execution"
    ACTION_GO_PREV_EXECUTION = "codexrebirth:go_prev_execution"
    ACTION_HIGHLIGHT_ADDRESS = "codexrebirth:highlight_address"

    
    
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

    def _install_hexdump_mem_diff(self, widget, popup):
        self._install_action(widget, popup, self.ACTION_HEXDUMP_MEM_DIFF, "MemDiff with Symbolic Execution", self._interactive_hexdump_mem_diff)
        
    def _install_ida_create_execution_snapshot(self, widget, popup):
        self._install_action(widget, popup, self.ACTION_IDA_CREATE_EXECUTION_SNAPSHOT, "Create Execution Snapshot", self._interactive_ida_create_execution_snapshot)
        
    def _install_ida_restore_execution_snapshot(self, widget, popup):
        self._install_action(widget, popup, self.ACTION_IDA_RESTORE_EXECUTION_SNAPSHOT, "Restore Execution Snapshot", self._interactive_ida_restore_execution_snapshot)
     
    def _install_go_next_execution(self, widget, popup):
        self._install_action(widget, popup, self.ACTION_GO_NEXT_EXECUTION, "Go to next execution", self._interactive_go_next_execution, shortcut="Shift+n")
        
    def _install_go_prev_execution(self, widget, popup):
        self._install_action(widget, popup, self.ACTION_GO_PREV_EXECUTION, "Go to previous execution", self._interactive_go_prev_execution, shortcut="Shift+p")
        
    def _install_highlight_address(self, widget, popup):
        self._install_action(widget, popup, self.ACTION_HIGHLIGHT_ADDRESS, "Highlight address", self._interactive_hightligh_address)
        
    
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
            self._install_end_address_action(widget, popup)
            self._install_get_seg_offset_action(widget, popup)
            self._install_clean_action(widget, popup)
            self._install_find_common_blocks(widget, popup)
            self._install_decompile_blocks(widget, popup)
            self._install_hexdump_mem_diff(widget, popup)
            self._install_ida_create_execution_snapshot(widget, popup)
            self._install_ida_restore_execution_snapshot(widget, popup)
            self._install_go_next_execution(widget, popup)
            self._install_go_prev_execution(widget, popup)
            self._install_highlight_address(widget, popup)
     
            
        
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
        
        current_address = idc.here()
        current_color = utils.to_ida_color(self.palette.trail_current)
        for section in lines_in.sections_lines:
            for line in section:
                address = line.at.toea()
                if address == current_address:
                    entry = ida_kernwin.line_rendering_output_entry_t(line, ida_kernwin.LROEF_FULL_LINE, current_color)
                    lines_out.entries.push_back(entry)
                    

        
    def update_disassembly_view(self, trail_length=100):
        """
        Update the disassembly view.
        """
        
        if not self.reader:
            return
        
        current_address = idc.here()
        
        # one in 700 chance to update a bigger trail
        if random.randint(0, 700) == 1:
            trail_length = 0xFFF
        
        
        is_quick_update = trail_length == 100

        # one chance out of 50 to update if is quick update
        if is_quick_update and random.randint(0, (trail_length * 2 )) != 1:
            return
        
        
        forward_color = self.palette.trail_forward
        symbolic_color = self.palette.symbolic
        end_address_color = self.palette.end_address
        current_color = utils.to_ida_color(self.palette.trail_current)
        common_block_color = utils.to_ida_color(self.palette.common_block_color)
        

        modifiers = QtGui.QGuiApplication.keyboardModifiers()
        step_over = bool(modifiers & QtCore.Qt.ShiftModifier)

  
        trail = {}
  
        
        if not is_quick_update:
            blocks_info = utils.get_all_basic_blocks_bounds(current_address)
            self.blocks_execution_count = {start: 0 for start, end in blocks_info}
            
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
                    
                if not is_quick_update:
                    if address in self.blocks_execution_count:
                        self.blocks_execution_count[address] += 1
        
      
        for address in trail:
            
            color, Insn = trail[address]
            
            cmt = utils.remove_line(str(Insn))
            idaapi.set_cmt(address, cmt, False)

            if address == current_address:
                color = current_color

            # apply color for end address
            if address == self.user_defined_end_address :
                color = utils.to_ida_color(end_address_color)

            # We dont overwrite the color if its a common block
            if utils.get_color(address) != common_block_color:
                idaapi.set_item_color(address, color)
                
        if self.blocks_execution_count:       
            # color block by execution count
            for block_start, execution_count in self.blocks_execution_count.items():
                idaapi.set_cmt(block_start, f"Executed {execution_count} times", False)
                
                if execution_count > 0 and utils.get_color(block_start) != common_block_color:
                    utils.color_blocks([block_start], utils.to_ida_color(self.palette.trail_forward), cinside=False)


                
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


