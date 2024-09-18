import logging
import functools
import os

#
# TODO: should probably cleanup / document this file a bit better.
#
# it's worth noting that most of this is based on the same shim layer
# used by lighthouse
#

import ida_ua
import ida_dbg
import ida_idp
import ida_pro
import ida_auto
import ida_nalt
import ida_name
import ida_xref
import idautils
import ida_bytes
import ida_idaapi
import ida_idd
import ida_diskio
import ida_kernwin
import ida_segment
import idc
import idaapi
from .api import DisassemblerCoreAPI, DisassemblerContextAPI
from ...util.qt import *
from ...util.misc import is_mainthread

logger = logging.getLogger("Tenet.API.IDA")


class calling_convention:
    fastcall = 112
    nothing = 16
    usercall = 240
    cdecl = 48
    noreturn = 64


# ------------------------------------------------------------------------------
# Utils
# ------------------------------------------------------------------------------


def execute_sync(function, sync_type):
    """
    Synchronize with the disassembler for safe database access.

    Modified from https://github.com/vrtadmin/FIRST-plugin-ida
    """

    @functools.wraps(function)
    def wrapper(*args, **kwargs):
        output = [None]

        #
        # this inline function definition is technically what will execute
        # in the context of the main thread. we use this thunk to capture
        # any output the function may want to return to the user.
        #

        def thunk():
            output[0] = function(*args, **kwargs)
            return 1

        if is_mainthread():
            thunk()
        else:
            ida_kernwin.execute_sync(thunk, sync_type)

        # return the output of the synchronized execution
        return output[0]

    return wrapper


# ------------------------------------------------------------------------------
# Disassembler Core API (universal)
# ------------------------------------------------------------------------------


class IDACoreAPI(DisassemblerCoreAPI):
    NAME = "IDA"

    def __init__(self):
        super(IDACoreAPI, self).__init__()
        self._dockable_factory = {}
        self._init_version()

    def _init_version(self):

        # retrieve IDA's version #
        disassembler_version = ida_kernwin.get_kernel_version()
        major, minor = map(int, disassembler_version.split("."))

        # save the version number components for later use
        self._version_major = major
        self._version_minor = minor
        self._version_patch = 0

    # --------------------------------------------------------------------------
    # Properties
    # --------------------------------------------------------------------------

    @property
    def headless(self):
        return ida_kernwin.cvar.batch

    # --------------------------------------------------------------------------
    # Synchronization Decorators
    # --------------------------------------------------------------------------

    @staticmethod
    def execute_read(function):
        return execute_sync(function, ida_kernwin.MFF_READ)

    @staticmethod
    def execute_write(function):
        return execute_sync(function, ida_kernwin.MFF_WRITE)

    @staticmethod
    def execute_ui(function):
        return execute_sync(function, ida_kernwin.MFF_FAST)

    # --------------------------------------------------------------------------
    # API Shims
    # --------------------------------------------------------------------------

    def get_disassembler_user_directory(self):
        return ida_diskio.get_user_idadir()

    def refresh_views(self):
        ida_kernwin.refresh_idaview_anyway()

    def get_disassembly_background_color(self):
        """
        Get the background color of the IDA disassembly view.
        """

        # create a donor IDA 'code viewer'
        viewer = ida_kernwin.simplecustviewer_t()
        viewer.Create("Colors")

        # get the viewer's qt widget
        viewer_twidget = viewer.GetWidget()
        viewer_widget = ida_kernwin.PluginForm.TWidgetToPyQtWidget(viewer_twidget)

        # fetch the background color property
        # viewer.Show() # TODO: re-enable!
        color = viewer_widget.property("line_bg_default")

        # destroy the view as we no longer need it
        # viewer.Close()

        # return the color
        return color

    def is_msg_inited(self):
        return ida_kernwin.is_msg_inited()

    @execute_ui.__func__
    def warning(self, text):
        super(IDACoreAPI, self).warning(text)

    @execute_ui.__func__
    def message(self, message):
        print(message)

    # --------------------------------------------------------------------------
    # UI API Shims
    # --------------------------------------------------------------------------

    def create_dockable(self, window_title, widget):

        # create a dockable widget, and save a reference to it for later use
        twidget = ida_kernwin.create_empty_widget(window_title)

        # cast the IDA 'twidget' as a Qt widget for use
        dockable = ida_kernwin.PluginForm.TWidgetToPyQtWidget(twidget)
        layout = dockable.layout()
        layout.addWidget(widget)

        # return the dockable QtWidget / container
        return dockable

    def get_root_filename(self):
        return ida_nalt.get_root_filename()

    def get_root_filename_dir(self):
        return os.path.dirname(self.get_root_filename())


# ------------------------------------------------------------------------------
# Disassembler Context API (database-specific)
# ------------------------------------------------------------------------------


class IDAContextAPI(DisassemblerContextAPI):

    def __init__(self, dctx):
        super(IDAContextAPI, self).__init__(dctx)

    @property
    def busy(self):
        return not (ida_auto.auto_is_ok())

    # --------------------------------------------------------------------------
    # API Shims
    # --------------------------------------------------------------------------

    @IDACoreAPI.execute_read
    def get_current_address(self):
        return ida_kernwin.get_screen_ea()

    def get_processor_type(self):
        ## get the target arch, PLFM_386, PLFM_ARM, etc # TODO
        # arch = idaapi.ph_get_id()
        pass

    def is_64bit(self):
        inf = ida_idaapi.get_inf_structure()
        # target_filetype = inf.filetype
        return inf.is_64bit()

    def is_call_insn(self, address):
        insn = ida_ua.insn_t()
        if ida_ua.decode_insn(insn, address) and ida_idp.is_call_insn(insn):
            return True
        return False
    
    def set_conditional_breakpoint(self, ea, condition, reg):
        """
        Set a conditional breakpoint at a given address with a specific condition.

        :param ea: The address where the breakpoint should be set.
        :param condition: A string that represents the condition for the breakpoint.
        :return: None
        """
        # Set a breakpoint at the given address
        idc.add_bpt(ea)
        
        # Attach the condition to the breakpoint
        idc.set_bpt_cond(ea, condition)
    
    def get_operand_reg_name(self, ea, op_off):
        """
        Get the register name of an operand if it is a register, otherwise return None.
        
        :param ea: The address of the instruction.
        :param op_off: The operand offset (0 for first operand, 1 for second operand, etc.).
        :return: Register name if the operand is a register, None otherwise.
        """
        # Decode the instruction at the provided address
        insn = idautils.DecodeInstruction(ea)
        
        PTR_SIZE = 8 if self.is_64bit() else 4
        
        # Check if instruction exists
        if not insn:
            print(f"No valid instruction found at {hex(ea)}")
            return None
        
        # Get the operand at the provided offset
        operand = insn.ops[op_off]
        
        # Check if the operand is a register
        if operand.type == idaapi.o_reg:
            # Get the register name using get_reg_name
            reg_name = idaapi.get_reg_name(operand.reg, PTR_SIZE)
            return reg_name
        else:
            return None
    

    def get_instruction_addresses(self):
        """
        Return all instruction addresses from the executable.
        """
        instruction_addresses = []

        for seg_address in idautils.Segments():

            # fetch code segments
            seg = ida_segment.getseg(seg_address)
            # IDA bug
            # if seg.sclass != ida_segment.SEG_CODE:
            #    continue

            current_address = seg_address
            end_address = seg.end_ea

            # save the address of each instruction in the segment
            while current_address < end_address:
                current_address = ida_bytes.next_head(current_address, end_address)
                if ida_bytes.is_code(ida_bytes.get_flags(current_address)):
                    instruction_addresses.append(current_address)

        #    print(f"Seg {seg.start_ea:08X} --> {seg.end_ea:08X} CODE")
        # print(f" -- {len(instruction_addresses):,} instructions found")

        return instruction_addresses

    def is_mapped(self, address):
        try:
            return ida_bytes.is_mapped(address)
        except:
            return False

    def get_next_insn(self, address):

        xb = ida_xref.xrefblk_t()
        ok = xb.first_from(address, ida_xref.XREF_ALL)

        while ok and xb.iscode:
            if xb.type == ida_xref.fl_F:
                return xb.to
            ok = xb.next_from()

        return -1

    def get_prev_insn(self, address):

        xb = ida_xref.xrefblk_t()
        ok = xb.first_to(address, ida_xref.XREF_ALL)

        while ok and xb.iscode:
            if xb.type == ida_xref.fl_F:
                return xb.frm
            ok = xb.next_to()

        return -1

    def get_database_directory(self):
        return idautils.GetIdbDir()

    def get_function_addresses(self):
        return list(idautils.Functions())

    def get_function_name_at(self, address):
        # test 1
        fn = idaapi.get_func(address)
        if fn:
            return idaapi.get_func_name(fn.start_ea)
        # test 2
        name  = ida_name.get_name(address)
        if name:
            return name
        return "unknown"

    def get_function_raw_name_at(self, function_address):
        return ida_name.get_name(function_address)

    def get_imagebase(self):
        return ida_nalt.get_imagebase()

    def get_root_filename(self):
        return ida_nalt.get_root_filename()

    def get_root_filename_dir(self):
        return os.path.dirname(self.get_root_filename())

    def navigate(self, address):

        # TODO fetch active view? or most recent one? i'm lazy for now...
        widget = ida_kernwin.find_widget("IDA View-A")

        #
        # this call can both navigate to an arbitrary address, and keep
        # the cursor position 'static' within the window at an (x,y)
        # text position
        #
        # TODO: I think it's kind of tricky to figure out the 'center' line of
        # the disassembly window navigation, so for now we'll just make a
        # navigation call always center around line 20...
        #

        CENTER_AROUND_LINE_INDEX = 20

        if widget:
            return ida_kernwin.ea_viewer_history_push_and_jump(widget, address, 0, CENTER_AROUND_LINE_INDEX, 0)

        # ehh, whatever.. just let IDA navigate to yolo
        else:
            return ida_kernwin.jumpto(address)

    def navigate_to_function(self, function_address, address):
        return self.navigate(address)

    def set_function_name_at(self, function_address, new_name):
        ida_name.set_name(function_address, new_name, ida_name.SN_NOWARN)

    def set_breakpoint(self, address):
        ida_dbg.add_bpt(address)
        ida_dbg.enable_bpt(address, True)

    def delete_breakpoint(self, address):
        ida_dbg.del_bpt(address)

    def get_sections(self):
        sections = []
        for seg_address in idautils.Segments():
            seg = ida_segment.getseg(seg_address)
            section_name = ida_segment.get_segm_name(seg)
            sections.append({"name": section_name, "range": f"{seg.start_ea:08X}-{seg.end_ea:08X}"})
        return sections

    # TODO: move outside of this class
    def get_functions_in_section(self, section_name):
        functions = []
        for f_addr in idautils.Functions():
            f_name = ida_name.get_short_name(f_addr)
            seg = ida_segment.getseg(f_addr)
            function_section_name = ida_segment.get_segm_name(seg)
            if function_section_name == section_name and ":" not in f_name:
                functions.append((f_name, f_addr))
        return functions

    # TODO: move outside of this class
    def compute_function_coverage(self, func, section=".text", f_cache_coverages={}, depth=0):
        """Compute the coverage of a function in the binary."""
        # get all sub calls
        if depth > 15:
            return set()
        if func is None:
            return set()
        f_sub_calls = set()
        
        for ea in idautils.FuncItems(func.start_ea):
            mnem = self.print_insn_mnemonic(ea)
            if mnem == "call" or mnem == "bl":
                addr = idc.get_operand_value(ea, 0)
                # get function name
                name = idc.get_func_name(addr)
                # check addr is in code section
                if idc.get_segm_name(addr) == section:
                    f_sub_calls.add((name, addr))

        for sub_call_name, sub_call_addr in f_sub_calls.copy():

            # if already explored get the result
            if sub_call_addr in f_cache_coverages:
                # merge coverage
                f_sub_calls |= f_cache_coverages[sub_call_addr]
                continue
            # show percentage
            # else explore the function
            elif sub_call_name != idc.get_func_name(func.start_ea):
                sub_func = idaapi.get_func(sub_call_addr)
                f_sub_sub_calls = self.compute_function_coverage(sub_func, section, f_cache_coverages, depth + 1)
                # merge coverage
                f_sub_calls |= f_sub_sub_calls

        f_cache_coverages[func.start_ea] = f_sub_calls
        return f_sub_calls

    def to_ida_color(self, color):
        r, g, b, _ = color.getRgb()
        return 0xFF << 24 | b << 16 | g << 8 | r

    def here(self):
        return idc.here()

    def get_segm_name(self, ea):
        for seg in idautils.Segments():
            seg_start = idc.get_segm_start(seg)
            seg_end = idc.get_segm_end(seg)
            seg_name = idaapi.get_segm_name(idaapi.getseg(seg))
            if seg_start <= ea <= seg_end:
                return seg_name

    def get_module_base(self):
        root_filename = idc.get_root_filename()
        for seg_address in idautils.Segments():
            # get seg permissions
            seg = ida_segment.getseg(seg_address)
            seg_name = ida_segment.get_segm_name(seg)
            if root_filename in seg_name:
                return seg_address
        return None

    def get_module_end(self, ea):
        for seg in idautils.Segments():
            seg_start = idc.get_segm_start(seg)
            seg_end = idc.get_segm_end(seg)
            if seg_start <= ea <= seg_end:
                return seg_end
        return None

    def set_color(self, address, color):
        idc.set_color(address, idc.CIC_ITEM, color)

    def set_cmt(self, address, comment):
        idc.set_cmt(address, comment, 0)

    def get_fn_blocks(self, ea):
        func = idaapi.get_func(ea)
        if not func:
            return []
        flow_chart = idaapi.FlowChart(func)
        return [(block.start_ea, block.end_ea) for block in flow_chart]

    def get_reg_value(self, reg):
        try:
            return idc.get_reg_value(reg)
        except:
            return 0

    def read_memory(self, address, size):
        return ida_bytes.get_bytes(address, size)

    def get_root_filename(self):
        return idc.get_root_filename()

    def is_mapped(self, address):
        try:
            return ida_bytes.is_mapped(address)
        except:
            return False

    def rebase_0(self):
        offset = idaapi.get_imagebase()
        idaapi.rebase_program(-offset, idaapi.MSF_NOFIX)
        # wait for rebase
        while idaapi.get_imagebase() != 0:
            time.sleep(0.1)

    def get_imagebase(self):
        return idaapi.get_imagebase()

    def rebase_plus(self, offset):
        idaapi.rebase_program(offset, idaapi.MSF_NOFIX)
        # wait for rebase
        while idaapi.get_imagebase() != offset:
            time.sleep(0.1)

    def rebase_to(self, target_base):
        current_base = idaapi.get_imagebase()
        offset = target_base - current_base
        self.rebase_plus(offset)

    def take_memory_snapshot(self):
        idaapi.take_memory_snapshot(0)

    def get_segm(self, seg_ea):
        for seg in idautils.Segments():
            seg_start = idc.get_segm_start(seg)
            seg_end = idc.get_segm_end(seg)
            if seg_start <= seg_ea <= seg_end:
                return seg
        raise Exception("Segment not found")

    def get_segm_name(self, seg):
        return idaapi.get_segm_name(idaapi.getseg(seg))

    def reset_code_segment(self, seg_ea, hard=True):
        seg = self.get_segm(seg_ea)
        seg_start = idc.get_segm_start(seg)
        seg_end = idc.get_segm_end(seg)
        seg_name = idaapi.get_segm_name(idaapi.getseg(seg))
        for addr in range(seg_start, seg_end):
            # undefined data DELIT_EXPAND del_items
            idc.del_items(addr, idc.DELIT_EXPAND)
        # print(f"Reset segment {seg_name} {hex(seg_start)}, {hex(seg_end)}")
        # do not convert directly
        if not hard:
            return
        curr_addr = seg_start
        while curr_addr < seg_end:
            idc.create_insn(curr_addr)
            curr_addr += idaapi.get_item_size(curr_addr)

    def get_segm(self, ea):
        for seg in idautils.Segments():
            seg_start = idc.get_segm_start(seg)
            seg_end = idc.get_segm_end(seg)
            if seg_start <= ea <= seg_end:
                return seg

    def get_segm_start(self, seg):
        return idc.get_segm_start(seg)

    def get_segm_end(self, seg):
        return idc.get_segm_end(seg)

    def create_insn(self, ea):
        idc.create_insn(ea)

    def print_insn_mnemonic(self, ea):
        return idc.print_insn_mnem(ea).lower()

    def get_operand_value(self, ea, op):
        return idc.get_operand_value(ea, op)

    def continue_process(self, timeout=15):
        idaapi.continue_process()
        idaapi.wait_for_next_event(idaapi.WFNE_SUSP, timeout)
        if self.is_process_running():
            print("Process still running after", timeout, "seconds")
            raise Exception(f"Process still running after {timeout} seconds")

    def  is_process_running(self):
        # check idaapi.WFNE_SUSP is false
        if idaapi.get_process_state() == idaapi.DSTATE_RUN:
            return True
        return False

    def get_bpt_qty(self):
        return ida_dbg.get_bpt_qty()

    def get_func_name(self, ea):
        return idc.get_func_name(ea)

    def list_functions(self):
        return idautils.Functions()

    def user_cancelled(self):
        return idaapi.user_cancelled()

    def get_item_size(self, ea):
        return idaapi.get_item_size(ea)

    def step_into(self):
        idaapi.step_into()
        idaapi.wait_for_next_event(idc.WFNE_SUSP, -1)

    def step_until_ret(self):
        idaapi.step_until_ret()
        idaapi.wait_for_next_event(idc.WFNE_SUSP, -1)

    def generate_disasm_line(self, ea):
        return idc.generate_disasm_line(ea, idc.GENDSM_FORCE_CODE)

    def get_root_filename(self):
        return idc.get_root_filename()

    def is_debugger_on(self):
        return ida_dbg.is_debugger_on()

    def update_ui(self):
        idaapi.refresh_idaview_anyway()

    def enable_breakpoint(self, ea, enable):
        ida_dbg.enable_bpt(ea, enable)

    def disable_breakpoint(self, ea):
        ida_dbg.enable_bpt(ea, False)

    def get_pc(self, arch):
        return self.get_reg_value(arch.IP)
    
    def suspend_other_threads(self):
        # Get the total number of threads
        thread_qty = ida_dbg.get_thread_qty()

        # Get the ID of the current thread
        current_thread_id = ida_dbg.get_current_thread()

        # Iterate through each thread
        for i in range(thread_qty):
            tid = ida_dbg.getn_thread(i)
            # Skip the current thread
            if tid == current_thread_id:
                continue

            # Suspend the thread
            ida_dbg.select_thread(tid)
            ida_dbg.suspend_thread(tid)

        # Restore the current thread selection
        ida_dbg.select_thread(current_thread_id)
        
    def resume_threads(self):
            # Get the total number of threads
        thread_qty = ida_dbg.get_thread_qty()

        # Get the ID of the current thread
        current_thread_id = ida_dbg.get_current_thread()

        # Iterate through each thread
        for i in range(thread_qty):
            tid = ida_dbg.getn_thread(i)

            # Suspend the thread
            ida_dbg.select_thread(tid)
            ida_dbg.resume_thread(tid)

        # Restore the current thread selection
        ida_dbg.select_thread(current_thread_id)
        
    def get_current_thread(self):
        return ida_dbg.get_current_thread()


# ------------------------------------------------------------------------------
# HexRays Util
# ------------------------------------------------------------------------------


def hexrays_available():
    """
    Return True if an IDA decompiler is loaded and available for use.
    """
    try:
        import ida_hexrays

        return ida_hexrays.init_hexrays_plugin()
    except ImportError:
        return False


def map_line2citem(decompilation_text):
    """
    Map decompilation line numbers to citems.

    This function allows us to build a relationship between citems in the
    ctree and specific lines in the hexrays decompilation text.

    Output:

        +- line2citem:
        |    a map keyed with line numbers, holding sets of citem indexes
        |
        |      eg: { int(line_number): sets(citem_indexes), ... }
        '

    """
    line2citem = {}

    #
    # it turns out that citem indexes are actually stored inline with the
    # decompilation text output, hidden behind COLOR_ADDR tokens.
    #
    # here we pass each line of raw decompilation text to our crappy lexer,
    # extracting any COLOR_ADDR tokens as citem indexes
    #

    for line_number in range(decompilation_text.size()):
        line_text = decompilation_text[line_number].line
        line2citem[line_number] = lex_citem_indexes(line_text)

    return line2citem


def map_line2node(cfunc, metadata, line2citem):
    """
    Map decompilation line numbers to node (basic blocks) addresses.

    This function allows us to build a relationship between graph nodes
    (basic blocks) and specific lines in the hexrays decompilation text.

    Output:

        +- line2node:
        |    a map keyed with line numbers, holding sets of node addresses
        |
        |      eg: { int(line_number): set(nodes), ... }
        '

    """
    line2node = {}
    treeitems = cfunc.treeitems
    function_address = cfunc.entry_ea

    #
    # prior to this function, a line2citem map was built to tell us which
    # citems reside on any given line of text in the decompilation output.
    #
    # now, we walk through this line2citem map one 'line_number' at a time in
    # an effort to resolve the set of graph nodes associated with its citems.
    #

    for line_number, citem_indexes in line2citem.items():
        nodes = set()

        #
        # we are at the level of a single line (line_number). we now consume
        # its set of citems (citem_indexes) and attempt to identify explicit
        # graph nodes they claim to be sourced from (by their reported EA)
        #

        for index in citem_indexes:

            # get the code address of the given citem
            try:
                item = treeitems[index]
                address = item.ea

            # apparently this is a thing on IDA 6.95
            except IndexError as e:
                continue

            # find the graph node (eg, basic block) that generated this citem
            node = metadata.get_node(address)

            # address not mapped to a node... weird. continue to the next citem
            if not node:
                # logger.warning("Failed to map node to basic block")
                continue

            #
            # we made it this far, so we must have found a node that contains
            # this citem. save the computed node_id to the list of known
            # nodes we have associated with this line of text
            #

            nodes.add(node.address)

        #
        # finally, save the completed list of node ids as identified for this
        # line of decompilation text to the line2node map that we are building
        #

        line2node[line_number] = nodes

    # all done, return the computed map
    return line2node


def lex_citem_indexes(line):
    """
    Lex all ctree item indexes from a given line of text.

    The HexRays decompiler output contains invisible text tokens that can
    be used to attribute spans of text to the ctree items that produced them.

    This function will simply scrape and return a list of all the these
    tokens (COLOR_ADDR) which contain item indexes into the ctree.

    """
    i = 0
    indexes = []
    line_length = len(line)

    # lex COLOR_ADDR tokens from the line of text
    while i < line_length:

        # does this character mark the start of a new COLOR_* token?
        if line[i] == idaapi.COLOR_ON:

            # yes, so move past the COLOR_ON byte
            i += 1

            # is this sequence for a COLOR_ADDR?
            if ord(line[i]) == idaapi.COLOR_ADDR:

                # yes, so move past the COLOR_ADDR byte
                i += 1

                #
                # A COLOR_ADDR token is followed by either 8, or 16 characters
                # (a hex encoded number) that represents an address/pointer.
                # in this context, it is actually the index number of a citem
                #

                citem_index = int(line[i : i + idaapi.COLOR_ADDR_SIZE], 16)
                i += idaapi.COLOR_ADDR_SIZE

                # save the extracted citem index
                indexes.append(citem_index)

                # skip to the next iteration as i has moved
                continue

        # nothing we care about happened, keep lexing forward
        i += 1

    # return all the citem indexes extracted from this line of text
    return indexes


class DockableWindow(ida_kernwin.PluginForm):

    def __init__(self, title, widget):
        super(DockableWindow, self).__init__()
        self.title = title
        self.widget = widget

        self.visible = False
        self._dock_position = None
        self._dock_target = None

        if ida_pro.IDA_SDK_VERSION < 760:
            self.__dock_filter = IDADockSizeHack()

    def OnCreate(self, form):
        # print("Creating", self.title)
        self.parent = self.FormToPyQtWidget(form)

        layout = QtWidgets.QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.widget)
        self.parent.setLayout(layout)

        if ida_pro.IDA_SDK_VERSION < 760:
            self.__dock_size_hack()

    def OnClose(self, foo):
        self.visible = False
        # print("Closing", self.title)

    def __dock_size_hack(self):
        if self.widget.minimumWidth() == 0:
            return
        self.widget.min_width = self.widget.minimumWidth()
        self.widget.max_width = self.widget.maximumWidth()
        self.widget.setMinimumWidth(self.widget.min_width // 2)
        self.widget.setMaximumWidth(self.widget.min_width // 2)
        self.widget.installEventFilter(self.__dock_filter)

    def show(self):
        dock_position = self._dock_position

        if ida_pro.IDA_SDK_VERSION < 760:
            WOPN_SZHINT = 0x200

            # create the dockable widget, without actually showing it
            self.Show(self.title, options=ida_kernwin.PluginForm.WOPN_CREATE_ONLY | ida_kernwin.WOPN_NOT_CLOSED_BY_ESC)

            # use some kludge to display our widget, and enforce the use of its sizehint
            ida_widget = self.GetWidget()
            ida_kernwin.display_widget(ida_widget, WOPN_SZHINT)
            self.visible = True

        # no hax required for IDA 7.6 and newer
        else:
            self.Show(self.title, options=ida_kernwin.WOPN_NOT_CLOSED_BY_ESC)
            self.visible = True
            dock_position |= ida_kernwin.DP_SZHINT

        # move the window to a given location if specified
        if dock_position is not None:
            ida_kernwin.set_dock_pos(self.title, self._dock_target, dock_position)

    def hide(self):
        self.Close(1)

    def set_dock_position(self, dest_ctrl=None, position=0):
        self._dock_target = dest_ctrl
        self._dock_position = position

        if not self.visible:
            return

        ida_kernwin.set_dock_pos(self.title, dest_ctrl, position)

    def copy_dock_position(self, other):
        self._dock_target = other._dock_target
        self._dock_position = other._dock_position


class IDADockSizeHack(QtCore.QObject):
    def eventFilter(self, obj, event):
        if event.type() == QtCore.QEvent.WindowActivate:
            obj.setMinimumWidth(obj.min_width)
            obj.setMaximumWidth(obj.max_width)
            obj.removeEventFilter(self)
        return False
