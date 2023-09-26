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
from ida_codexrebirth.util.misc import remove_line

from ida_codexrebirth.ui.trace_view import TraceDock
from ida_codexrebirth.trace.reader import TraceReader
from ida_codexrebirth.context.backend import CodexRebirthBackendContext


#------------------------------------------------------------------------------
# IDA UI Integration
#------------------------------------------------------------------------------



class CodexRebirthIDA():
    """
    The plugin integration layer IDA Pro.
    """
    
    flags = ida_idaapi.PLUGIN_PROC | ida_idaapi.PLUGIN_MOD | ida_idaapi.PLUGIN_HIDE
    comment = "Codex Rebirth"
    help = ""
    wanted_name = "CodexRebirth"
    wanted_hotkey = ""

    def __init__(self):
     
        self.run_backend()
        self.load_ui()
        self.load_trace()
        self.show_ui()
        
        
    def run_backend(self):
        self.ctx = CodexRebirthBackendContext()
        self.ctx.run()
        
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
        Load a trace from the specified filepath.
        
        If a trace is already loaded or in use prior to calling this function,
        it will be replaced by the newly loaded trace.
        """

        # Create a trace reader, which loads the trace file from disk and provides
        # useful APIs for navigating the trace and querying information (memory,
        # registers) at chosen execution states.
        print("Loading trace records...")
        self.reader = TraceReader(self.ctx.codex_backend.trace_records)
        print(f"Trace loaded with {self.reader.length} records.")

        # Hook into the trace for further processing.
        self.hook()

        print(f"Current state variables: {self.ctx.codex_backend.state}")

        # Attach the trace engine to various plugin UI controllers, granting them
        # access to the underlying trace reader.
        self.trace_dock.attach_reader(self.reader)
        
        # Set up UI hooks for rendering lines and widget popups.
        self._ui_hooks.get_lines_rendering_info = self._render_lines
        self._ui_hooks.finish_populating_widget_popup = self._popup_hook

        
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

    ACTION_NEXT_EXECUTION  = "codexrebirth:next_execution"
    ACTION_PREV_EXECUTION  = "codexrebirth:prev_execution"
    
    
    def _interactive_next_execution(self, db):
        pself = self.get_context(db)
        pself.interactive_next_execution()

    def _interactive_prev_execution(self, db):
        pself = self.get_context(db)
        pself.interactive_prev_execution()
        
    
    def interactive_next_execution(self):
        """
        Handle UI actions for seeking to the next execution of the selected address.
        """
        address = self.reader.dself.get_current_address()
        result = self.reader.seek_to_next(address, BreakpointType.EXEC)

        # TODO: blink screen? make failure more visible...
        if not result:
            print(f"Go to 0x{address:08x} failed, no future executions of address")

    def interactive_prev_execution(self):
        """
        Handle UI actions for seeking to the previous execution of the selected address.
        """
        address = self.reader.dself.get_current_address()
        result = self.reader.seek_to_prev(address, BreakpointType.EXEC)

        # TODO: blink screen? make failure more visible...
        if not result:
            print(f"Go to 0x{address:08x} failed, no previous executions of address")
    
    
    
    def _install_ui(self):
        """
        Initialize & integrate all plugin UI elements.
        """
        self._install_next_execution()
        self._install_prev_execution()

    def _uninstall_ui(self):
        """
        Cleanup & remove all plugin UI integrations.
        """
        self._uninstall_next_execution()
        self._uninstall_prev_execution()


    def _install_next_execution(self):

        icon_data = self.palette.gen_arrow_icon(self.palette.arrow_next, 0)
        self._icon_id_next_execution = ida_kernwin.load_custom_icon(data=icon_data)

        # describe a custom IDA UI action
        action_desc = ida_kernwin.action_desc_t(
            self.ACTION_NEXT_EXECUTION,                        # The action name
            "Go to next execution",                            # The action text
            IDAselfEntry(self._interactive_next_execution),     # The action handler
            None,                                              # Optional: action shortcut
            "Go to the next execution of the current address", # Optional: tooltip
            self._icon_id_next_execution                       # Optional: the action icon
        )

        # register the action with IDA
        result = ida_kernwin.register_action(action_desc)
        assert result, f"Failed to register '{action_desc.name}' action with IDA"
        print(f"Installed the '{action_desc.name}' menu entry")

    def _install_prev_execution(self):

        icon_data = self.palette.gen_arrow_icon(self.palette.arrow_prev, 180.0)
        self._icon_id_prev_execution = ida_kernwin.load_custom_icon(data=icon_data)

        # describe a custom IDA UI action
        action_desc = ida_kernwin.action_desc_t(
            self.ACTION_PREV_EXECUTION,                            # The action name
            "Go to previous execution",                            # The action text
            IDAselfEntry(self._interactive_prev_execution),         # The action handler
            None,                                                  # Optional: action shortcut
            "Go to the previous execution of the current address", # Optional: tooltip
            self._icon_id_prev_execution                           # Optional: the action icon
        )

        # register the action with IDA
        result = ida_kernwin.register_action(action_desc)
        assert result, f"Failed to register '{action_desc.name}' action with IDA"
        print(f"Installed the '{action_desc.name}' menu entry")

   
    def _uninstall_next_execution(self):
        result = self._uninstall_action(self.ACTION_NEXT_EXECUTION, self._icon_id_next_execution)
        self._icon_id_next_execution = ida_idaapi.BADADDR
        return result
        
    def _uninstall_prev_execution(self):
        result = self._uninstall_action(self.ACTION_PREV_EXECUTION, self._icon_id_prev_execution)
        self._icon_id_prev_execution = ida_idaapi.BADADDR
        return result


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

        # TODO: return if plugin/trace is not active
        pass

        # fetch the (IDA) window type (eg, disas, graph, hex ...)
        view_type = ida_kernwin.get_widget_type(widget)

        # only attach these context items to popups in disas views
        if view_type == ida_kernwin.BWN_DISASMS:

            # prep for some shady hacks
            p_qmenu = ctypes.cast(int(popup), ctypes.POINTER(ctypes.c_void_p))[0]
            qmenu = sip.wrapinstance(int(p_qmenu), QtWidgets.QMenu)

            #
            # inject and organize the Tenet plugin actions
            #

            ida_kernwin.attach_action_to_popup(
                widget,
                popup,
                self.ACTION_NEXT_EXECUTION,  # The action ID (see above)
                "Rename",                    # Relative path of where to add the action
                ida_kernwin.SETMENU_APP      # We want to append the action after ^
            )

            #
            # this is part of our bodge to inject a plugin action submenu
            # at a specific location in the QMenu, cuz I don't think it's
            # actually possible with the native IDA API's (for groups...)
            #

            for action in qmenu.actions():
                if action.text() == "Go to next execution":

                    # inject a group for the exta 'go to' actions
                    goto_submenu = QtWidgets.QMenu("Go to...")
                    qmenu.insertMenu(action, goto_submenu)

                    # hold a Qt ref of the submenu so it doesn't GC
                    self.__goto_submenu = goto_submenu
                    break

            ida_kernwin.attach_action_to_popup(
                widget,
                popup,
                self.ACTION_FIRST_EXECUTION,     # The action ID (see above)
                "Go to.../",                     # Relative path of where to add the action
                ida_kernwin.SETMENU_APP          # We want to append the action after ^
            )

            ida_kernwin.attach_action_to_popup(
                widget,
                popup,
                self.ACTION_FINAL_EXECUTION,     # The action ID (see above)
                "Go to.../",                     # Relative path of where to add the action
                ida_kernwin.SETMENU_APP          # We want to append the action after ^
            )

            ida_kernwin.attach_action_to_popup(
                widget,
                popup,
                self.ACTION_PREV_EXECUTION,  # The action ID (see above)
                "Rename",                    # Relative path of where to add the action
                ida_kernwin.SETMENU_APP      # We want to append the action after ^
            )

            #
            # inject a seperator to help insulate our plugin action group
            #

            for action in qmenu.actions():
                if action.text() == "Go to previous execution":
                    qmenu.insertSeparator(action)
                    break

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

class IDAselfEntry(ida_kernwin.action_handler_t):
    """
    A minimal context menu entry class to utilize IDA's action handlers.
    """

    def __init__(self, action_function):
        super(IDAselfEntry, self).__init__()
        self.action_function = action_function

    def activate(self,  ctx=None):
        """
        Execute the embedded action_function when this context menu is invoked.

        NOTE: We pass 'None' to the action function to act as the '
        """
        self.action_function(IDA_GLOBAL_self)
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



PLUGIN_ENTRY()