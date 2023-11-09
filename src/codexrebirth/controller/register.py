from ..ui import *
from ..tools import register_callback, notify_callback
from ..integration.api import DockableWindow

# ------------------------------------------------------------------------------
# registers.py -- Register Controller
# ------------------------------------------------------------------------------
#
#    The purpose of this file is to house the 'headless' components of the
#    registers window and its underlying functionality. This is split into a
#    model and controller component, of a typical 'MVC' design pattern.
#
#    NOTE: for the time being, this file also contains the logic for the
#    'IDX Shell' as it is kind of attached to the register view and not big
#    enough to demand its own seperate structuring ... yet
#


class RegisterController(object):
    """
    The Registers Controller (Logic)
    """

    def __init__(self, pctx):
        self.pctx = pctx
        self.model = RegistersModel(pctx)
        self.reader = None

        # UI components
        self.view = None
        self.dockable = None

        # signals
        self._ignore_signals = False

    def show(self, target=None, position=0):
        """
        Make the window attached to this controller visible.
        """
        self.view = RegisterView(self, self.model)
        new_dockable = DockableWindow("CPU Registers", self.view)
        print("Register controller dockable")

        #
        # if there is a reference to a left over dockable window (e.g, from a
        # previous close of this window type) steal its dock positon so we can
        # hopefully take the same place as the old one
        #
        if self.dockable:
            new_dockable.copy_dock_position(self.dockable)
        elif target or position:
            new_dockable.set_dock_position(target, position)

        # make the dockable/widget visible
        self.dockable = new_dockable
        self.dockable.show()

        print("Register controller show")

    def hide(self):
        """
        Hide the window attached to this controller.
        """

        # if there is no view/dockable, then there's nothing to try and hide
        if not (self.view and self.dockable):
            return

        # hide the dockable, and drop references to the widgets
        self.dockable.hide()
        self.view = None
        self.dockable = None

    def close(self):
        """
        Close the window attached to this controller.
        """
        self.hide()

    def attach_reader(self, reader):
        """
        Attach a trace reader to this controller.
        """
        self.reader = reader
        # attach trace reader signals to this controller / window
        reader.idx_changed(self._idx_changed)
        #
        # directly call our event handler quick with the current idx since
        # it's the first time we're seeing this. this ensures that our widget
        # will accurately reflect the current state of the reader
        #
        self._idx_changed(reader.idx)

    def detach_reader(self):
        """
        Detach the active trace reader from this controller.
        """
        self.reader = None
        self.model.reset()

    # TODO: maybe we can remove all these 'focus' funcs now?
    def focus_register_value(self, reg_name):
        """
        Focus a register value in the register view.
        """
        self.model.focused_reg_value = reg_name

    def focus_register_name(self, reg_name):
        """
        Focus a register name in the register view.
        """
        self._clear_register_value_focus()
        self.model.focused_reg_name = reg_name

    def clear_register_focus(self):
        """
        Clear all focus on register fields.
        """
        self._clear_register_value_focus()
        self.model.focused_reg_name = None

    def follow_in_dump(self, reg_name):
        """
        Follow a given register value in the memory dump.
        """
        address = self.model.registers[reg_name]
        self.pctx.memory.navigate(address)

    def _clear_register_value_focus(self):
        """
        Clear focus from the active register field.
        """
        self.model.focused_reg_value = None

    def set_registers(self, registers, delta=None):
        """
        Set the registers for the view.
        """
        self.model.set_registers(registers, delta)

    def _handle_command(self, expression):
        """
        Handle the evaluation of commands on the timestamp shell.
        """
        if self._handle_seek_percent(expression):
            return True
        if self._handle_seek_last(expression):
            return True
        return False

    def _handle_seek_percent(self, expression):
        """
        Handle a 'percentage-based' trace seek.

            eg: !0, or !100 to skip to the start/end of trace
        """
        try:
            target_percent = float(expression)  # float, so you could even do 42.1%
        except:
            return False

        # seek to the desired percentage in the trace
        self.reader.seek_percent(target_percent)
        return True

    def _handle_seek_last(self, expression):
        """
        Handle a seek to the last mapped address.
        """
        if expression != "last":
            return False

        last_idx = self.reader.trace.length - 1
        last_ip = self.reader.get_ip(last_idx)
        # seek to the last known / good idx that is mapped within the disassembler
        self.reader.seek(last_idx)
        return True

    def _idx_changed(self, idx):
        """
        The trace position has been changed.
        """
        self.model.idx = idx
        self.set_registers(self.reader.registers, self.reader.get_registers())
        
    def evaluate_expression(self, expression):
        """
        Evaluate the expression in the IDX Shell and navigate to it.
        """

        # a target idx was given as an integer
        if isinstance(expression, int):
            target_idx = expression
            self.reader.seek(target_idx)

        # string handling
        elif isinstance(expression, str):

            # blank string was passed from the shell, nothing to do...
            if not expression:
                return

            # a 'command' / alias idx was entered into the shell ('!...' prefix)
            if expression[0] == '!':
                self._handle_command(expression[1:])
                return

            #
            # not a command, how about a comma seperated timestamp?
            # -- e.g '5,218,121'
            #

            idx_str = expression.replace(',', '')
            try:
                target_idx = int(idx_str)
            except:
                return

            self.reader.seek(target_idx)

        else:
            raise ValueError(f"Unknown input expression type '{expression}'?!?")


class RegistersModel(object):
    """
    The Registers Model (Data)
    """

    def __init__(self, pctx):
        self._pctx = pctx
        self.reset()

        # ----------------------------------------------------------------------
        # Callbacks
        # ----------------------------------------------------------------------

        self._registers_changed_callbacks = []

    # ----------------------------------------------------------------------
    # Properties
    # ----------------------------------------------------------------------

    @property
    def arch(self):
        """
        Return the architecture definition.
        """
        return self._pctx.arch

    # ----------------------------------------------------------------------
    # Public
    # ----------------------------------------------------------------------

    def reset(self):
        # the current timestamp in the trace
        self.idx = -1

        # the { reg_name: reg_value } dict of current register values
        self.registers = {}

        #
        # the names of the registers that have changed since the previous
        # chronological timestamp in the trace.
        #
        # for example if you singlestep forward, any registers that changed as
        # a result of 'normal execution' may be highlighted (e.g. red)
        #

        self.delta_trace = []

        #
        # the names of registers that have changed since the last navigation
        # event (eg, skipping between breakpoints, memory accesses).
        #
        # this is used to highlight registers that may not have changed as a
        # result of the previous chronological trace event, but by means of
        # user navigation within tenet.
        #

        self.delta_navigation = []

        self.focused_reg_name = None
        self.focused_reg_value = None

    def set_registers(self, registers, delta=None):
        # compute which registers changed as a result of navigation
        unchanged = dict(set(self.registers.items()) & set(registers.items()))
        self.delta_navigation = set([k for k in registers if k not in unchanged])

        # save the register delta that changed since the previous trace timestamp
        self.delta_trace = delta if delta else []
        self.registers = registers

        # notify the UI / listeners of the model that an update occurred
        self._notify_registers_changed()

    # ----------------------------------------------------------------------
    # Callbacks
    # ----------------------------------------------------------------------

    def registers_changed(self, callback):
        """
        Subscribe a callback for a registers changed event.
        """
        register_callback(self._registers_changed_callbacks, callback)

    def _notify_registers_changed(self):
        """
        Notify listeners of a registers changed event.
        """
        notify_callback(self._registers_changed_callbacks)
