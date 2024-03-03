import struct

from tenet.ui import *
from tenet.hex import HexController
from tenet.types import HexType, AuxType

#------------------------------------------------------------------------------
# stack.py -- Stack Dump Controller
#------------------------------------------------------------------------------
#
#    The purpose of this file is to house the 'headless' components of the
#    stack dump window and its underlying functionality. This is split into
#    a model and controller component, of a typical 'MVC' design pattern. 
#
#    The stack dump window abstracts from a simple hex dump. We use the code
#    below to configure our underlying hex dump to appear more like a typical
#    stack view might instead.
#

class StackController(HexController):
    """
    The Stack Dump Controller (Logic)
    """

    def __init__(self, pctx):
        super(StackController, self).__init__(pctx)
        self._title = "Stack View"

    def attach_reader(self, reader):
        """
        Attach a trace reader, and configure the view to model a stack.
        """
        self.model.num_bytes_per_line = reader.arch.POINTER_SIZE
        self.model.hex_format = HexType.DWORD if reader.arch.POINTER_SIZE == 4 else HexType.QWORD
        self.model.aux_format = AuxType.STACK
        super(StackController, self).attach_reader(reader)
    
    def _idx_changed(self, idx):
        """
        Override the default hex view idx changed event handler.
        """

        # fade out the upper part of the stack that is currently 'unallocated'
        self.set_fade_threshold(self.reader.sp)

        if self.view:

            #
            # if the user has a byte / range selected or the view is purposely
            # omitting navigation events, we will *not* move the stack view on
            # idx changes.
            #
            # this is to preserve the location of their selection on-screen
            # (eg, when hovering a selected byte, and jumping between its
            # memory accesses)
            #

            if self.view._ignore_navigation or self.view.selection_size:
                self.refresh_memory()
                self.view.refresh()
                return

        #
        # if there is no special user interaction going on with the stack
        # view, we will simply ensure that the stack stays 'pinned' to the
        # top of the stack, per the current trace reader state.
        #
        # we conciously chose to show '3' lines of the unallocated frames
        # to provide a bit more awarness to pops/rets as they happen
        #

        self.navigate(self.reader.sp - self.model.num_bytes_per_line * 3)