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
from ida_codexrebirth.util.misc import remove_line, show_msgbox, delete_all_comments

from ida_codexrebirth.ui.trace_view import TraceDock
from ida_codexrebirth.trace.reader import TraceReader
from ida_codexrebirth.context.backend import CodexRebirthBackendContext
import time
from PyQt5.QtWidgets import QMessageBox


#------------------------------------------------------------------------------
# IDA UI Integration
#------------------------------------------------------------------------------



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
        self.user_defined_end_address = None
        self.sym_engine_last_run = None
        self.ctx = CodexRebirthBackendContext()
        self.load_ui()
        print("CodexRebirth: IDA Plugin Loaded")
        
    def init(self):
        return ida_idaapi.PLUGIN_OK
    
    def run(self, arg):
        pass
    
    def term(self):
        pass

    def _run(self):
        
        if not self.user_defined_end_address:
            # show  a message box to the user
            show_msgbox("Please set the end address first")
            return
                        
        if not self.ctx.is_initialized:
            self.ctx.initialize()
            
        # restore the sym_engine to the state before the symbolic execution
        if self.sym_engine_last_run and len(self.sym_engine_last_run.trace_records) > 0: 
            print("Restoring the symbolic engine to the state before the symbolic execution")
            self.ctx.sym_engine = self.sym_engine_last_run.clone()
            
        # delete all comments
        print("Deleting all comments ...")
        delete_all_comments()
            
        # we set the end address to the symbolic engine after the initialization
        self.ctx.sym_engine.set_emu_end(self.user_defined_end_address)
        
        print("Running Symbolic Execution")
        print("UI refresh will be disabled until the end of the symbolic execution")
        time.sleep(0.2)
        self.ctx.run_emulation()
        self.load_trace()
        self.show_ui()
        
 
        print("Symbolic Execution Finished")
        
        
        
    def _commit(self):
        """_summary_
        
        When we launch the symbolic execution, we clone the sym_engine and run the emulation on the clone.
        But if we want to commit the current state of the sym_engine, we need to set the sym_engine to the clone.
        
        """
        if self.ctx.sym_engine:
            self.load_trace()
            self.sym_engine_last_run = self.ctx.sym_engine.clone()
            self.user_defined_end_address = None
            print("="*80)
            print("Committing the current state of the symbolic engine")
            print("IMPORTANT: Now run ida until the end address")
            print("="*80)
            # ida continues to run until the end address
            ida_dbg.continue_process()
            
            
    def _reset_ctx(self):
        """_summary_
        
        This function is called when the user clicks on the context menu item "Reset Context"
        """
        self.ctx = CodexRebirthBackendContext()
        self.ctx.initialize()
        print("Context reset")
            
            
    def _interactive_end_address(self):
        """_summary_
        
        This function is called when the user clicks on the context menu item "Set End Address"
        """
        self.user_defined_end_address = idc.here()
        print(f"End address set to {hex(self.user_defined_end_address)}")
        
        # set a comment at the end address
        idaapi.set_cmt(self.user_defined_end_address, " ===== End address =====", False)
        
        # set a breakpoint at the end address
        ida_dbg.add_bpt(self.user_defined_end_address, 1, idc.BPT_SOFT)
        
 
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

        # Create a new 'plugin context' representing this IDB.
        self.contexts = {}
        self._update_checked = False

        # Define the plugin's color palette.
        self.palette = PluginPalette()

        # Integrate the plugin's UI into the disassembler.
        self._install_ui()

        # Mark the core as loaded and perform necessary warm-up tasks.
        self.loaded = True
        self.palette.warmup()
        
        self.trace_dock = TraceDock(self)

        # Print a message to indicate successful plugin loading.
        print("UI successfully loaded.")



    def load_trace(self):
        """
        Load a trace from the specifi_ui_hookshooed filepath.
        
        If a trace is already loaded or in use prior to calling this function,
        it will be replaced by the newly loaded trace.
        """
            

        # Create a trace reader, which loads the trace file from disk and provides
        # useful APIs for navigating the trace and querying information (memory,
        # registers) at chosen execution states.
        print("Loading trace records...")
        self.reader = TraceReader(self.ctx.sym_engine.trace_records)
        print(f"Trace loaded with {self.reader.length} records.")

        # Hook into the trace for further processing.
        self.hook()

        print(f"Current state variables: {self.ctx.sym_engine.state}")

        # Attach the trace engine to various plugin UI controllers, granting them
        # access to the underlying trace reader.
        self.trace_dock.attach_reader(self.reader)
        
        # Set up UI hooks for rendering lines and widget popups.
        self._ui_hooks.get_lines_rendering_info = self._render_lines

        
    def show_ui(self):
        """
        Integrate and arrange the plugin widgets into the disassembler UI.
        """

        mw = get_qmainwindow()
        mw.addToolBar(QtCore.Qt.RightToolBarArea, self.trace_dock)
        self.trace_dock.show()
        
        
    def hook(self):
        if self._hooked:
            return
        self._hooked = True
        self._ui_hooks.hook()

    def unhook(self):
        if not self._hooked:
            return
        self._hooked = False
        self._ui_hooks.unhook()



    #--------------------------------------------------------------------------
    # IDA Actions
    #--------------------------------------------------------------------------

    ACTION_RUN = "codexrebirth:run"
    ACTION_COMMIT = "codexrebirth:commit"
    ACTION_END_ADDRESS = "codexrebirth:end_address"
    ACTION_RESET_CTX = "codexrebirth:reset_ctx"
    
    
    def _install_run_action(self, widget, popup):
        
        icon_data = self.palette.gen_icon("thunder.png")
        action_desc = ida_kernwin.action_desc_t(
            self.ACTION_RUN,                        # The action name
            "Run Symbolic Execution",                     # The action text
            IDACtxEntry(self._run),     # The action handler
            None,                                   # Optional: action shortcut
            "Run Symbolic Execution",                     # Optional: tooltip
            ida_kernwin.load_custom_icon(data=icon_data))     # Optional: the action icon
        
        ida_kernwin.register_action(action_desc)
        ida_kernwin.attach_action_to_popup(widget, popup, self.ACTION_RUN, "Codexrebirth/")
        
        
    def _install_reset_ctx_action(self, widget, popup):
        icon_data = self.palette.gen_icon("reset.png")
        action_desc = ida_kernwin.action_desc_t(
            self.ACTION_RESET_CTX,                        # The action name
            "Reset Context",                     # The action text
            IDACtxEntry(self._reset_ctx),     # The action handler
            None,                                   # Optional: action shortcut
            "Reset Context",                     # Optional: tooltip
            ida_kernwin.load_custom_icon(data=icon_data))    # Optional: the action icon
        ida_kernwin.register_action(action_desc)
        # attach action to a click on a address in the disassembly view
        ida_kernwin.attach_action_to_popup(widget, popup, self.ACTION_RESET_CTX, "Codexrebirth/")
        
        
    
    def _install_commit_action(self, widget, popup):
        icon_data = self.palette.gen_icon("handshake.png")
        action_desc = ida_kernwin.action_desc_t(
            self.ACTION_COMMIT,                        # The action name
            "Commit Symbolic Execution",                     # The action text
            IDACtxEntry(self._commit),     # The action handler
            None,                                   # Optional: action shortcut
            "Commit Symbolic Execution",                     # Optional: tooltip
            ida_kernwin.load_custom_icon(data=icon_data))    # Optional: the action icon
            
        ida_kernwin.register_action(action_desc)
        ida_kernwin.attach_action_to_popup(widget, popup, self.ACTION_COMMIT, "Codexrebirth/")
        
                
    def _install_end_address_action(self, widget, popup):
        icon_data = self.palette.gen_icon("end.png")
        action_desc = ida_kernwin.action_desc_t(
        self.ACTION_END_ADDRESS,                        # The action name
            "Set End Address",                     # The action text
            IDACtxEntry(self._interactive_end_address),     # The action handler
            None,                                   # Optional: action shortcut
            "Set End Address",                     # Optional: tooltip
            ida_kernwin.load_custom_icon(data=icon_data))    # Optional: the action icon
        ida_kernwin.register_action(action_desc)
        # attach action to a click on a address in the disassembly view
        ida_kernwin.attach_action_to_popup(widget, popup, self.ACTION_END_ADDRESS, "Codexrebirth/")
        
    
    def _install_ui(self):
        """
        Initialize & integrate all plugin UI elements.
        """
        self._ui_hooks.finish_populating_widget_popup = self._popup_hook
        self._ui_hooks.hook()


    def _uninstall_ui(self):
        """
        Cleanup & remove all plugin UI integrations.
        """


    def _uninstall_action(self, action, icon_id=ida_idaapi.BADADDR):

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
            self._install_reset_ctx_action(widget, popup)
            
        
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
        """
        trail_length = 50

        forward_color = self.palette.trail_forward
        current_color = self.palette.trail_current
        backward_color = self.palette.trail_backward
        symbolic_color = self.palette.symbolic
        end_address_color = self.palette.end_address

        r, g, b, _ = current_color.getRgb()
        current_color = 0xFF << 24 | b << 16 | g << 8 | r
        
        step_over = False
        modifiers = QtGui.QGuiApplication.keyboardModifiers()
        step_over = bool(modifiers & QtCore.Qt.ShiftModifier)

        forward_ips = self.reader.get_next_ips(trail_length, step_over)
        backward_ips = self.reader.get_prev_ips(trail_length, step_over)

        trail = {}

        trails = [
            (backward_ips, backward_color), 
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
                    
                if self.user_defined_end_address == address:
                    color = end_address_color
                
                percent = 1.0 - ((trail_length - i) / trail_length)
                # convert to bgr
                r, g, b, _ = color.getRgb()
                ida_color = b << 16 | g << 8 | r
                ida_color |= (0xFF - int(0xFF * percent)) << 24
                
                if address not in trail:
                    trail[address] = (ida_color, self.reader.get_Insn(idx))
                
        current_address = self.reader.rebased_ip

        for section in lines_in.sections_lines:
            for line in section:
                address = line.at.toea()
                
                if address in trail:
                    color, Insn = trail[address]
                    cmt = remove_line(str(Insn), 0)
                    idaapi.set_cmt(address, cmt, False)
         
                elif address == current_address:
                    color = current_color
                else:
                    continue

                entry = ida_kernwin.line_rendering_output_entry_t(line, ida_kernwin.LROEF_FULL_LINE, color)
                lines_out.entries.push_back(entry)


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

    
    
    
def PLUGIN_ENTRY():
    """
    Required plugin entry point for IDAPython Plugins.
    """
    print("Tenet: Loading IDA Plugin...")
    return CodexRebirthIDA()


