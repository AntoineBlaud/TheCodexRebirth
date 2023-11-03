import os
import errno
import struct
import weakref
import threading
import idaapi
import idautils
import ida_kernwin
import ida_segment
import idc
from functools import wraps
import jsonschema
import openai
import functools
import ida_graph
import re 
import pickle
import tempfile
import ida_bytes
from capstone.x86_const import X86_OP_MEM, X86_OP_REG, X86_OP_IMM

from collections import Counter
#------------------------------------------------------------------------------
# Plugin Util
#------------------------------------------------------------------------------

PLUGIN_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

def is_plugin_dev():
    """
    Return True if the plugin is in developer mode.
    """
    return bool(os.getenv("TENET_DEV"))

def plugin_resource(resource_name):
    """
    Return the full path for a given plugin resource file.
    """
    return os.path.join(
        PLUGIN_PATH,
        "ui",
        "resources",
        resource_name
    )

#------------------------------------------------------------------------------
# Thread Util
#------------------------------------------------------------------------------

def is_mainthread():
    """
    Return a bool that indicates if this is the main application thread.
    """
    return isinstance(threading.current_thread(), threading._MainThread)

def assert_mainthread(f):
    """
    A sanity decorator to ensure that a function is always called from the main thread.
    """
    def wrapper(*args, **kwargs):
        assert is_mainthread()
        return f(*args, **kwargs)
    return wrapper

def assert_async(f):
    """
    A sanity decorator to ensure that a function is never called from the main thread.
    """
    def wrapper(*args, **kwargs):
        assert not is_mainthread()
        return f(*args, **kwargs)
    return wrapper

#-----------------------------------------------------------------------------
# Python Utils
#-----------------------------------------------------------------------------

def chunks(lst, n):
    """
    Yield successive n-sized chunks from lst.
    """
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

def hexdump(data):
    """
    Return an ascii hexdump of the given data.
    """
    return '\n'.join([' '.join([f"{x:02X}" for x in chunk]) for chunk in chunks(data, 16)])
        
def makedirs(path, exists_ok=True):
    """
    Create directories along a fully qualified path.
    """
    try:
        os.makedirs(path)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise e
        if not exists_ok:
            raise e
            
def swap_rgb(i):
    """
    Swap a 32bit RRGGBB (integer) to BBGGRR.
    """
    return struct.unpack("<I", struct.pack(">I", i))[0] >> 8

#------------------------------------------------------------------------------
# Python Callback / Signals
#------------------------------------------------------------------------------

def register_callback(callback_list, callback):
    """
    Register a callable function to the given callback_list.

    Adapted from http://stackoverflow.com/a/21941670
    """

    # create a weakref callback to an object method
    try:
        callback_ref = weakref.ref(callback.__func__), weakref.ref(callback.__self__)

    # create a wweakref callback to a stand alone function
    except AttributeError:
        callback_ref = weakref.ref(callback), None

    # 'register' the callback
    callback_list.append(callback_ref)

def notify_callback(callback_list, *args):
    """
    Notify the given list of registered callbacks of an event.

    The given list (callback_list) is a list of weakref'd callables
    registered through the register_callback() function. To notify the
    callbacks of an event, this function will simply loop through the list
    and call them.

    This routine self-heals by removing dead callbacks for deleted objects as
    it encounters them.

    Adapted from http://stackoverflow.com/a/21941670
    """
    cleanup = []

    #
    # loop through all the registered callbacks in the given callback_list,
    # notifying active callbacks, and removing dead ones.
    #

    for callback_ref in callback_list:
        callback, obj_ref = callback_ref[0](), callback_ref[1]

        #
        # if the callback is an instance method, deference the instance
        # (an object) first to check that it is still alive
        #

        if obj_ref:
            obj = obj_ref()

            # if the object instance is gone, mark this callback for cleanup
            if obj is None:
                cleanup.append(callback_ref)
                continue

            # call the object instance callback
            try:
                callback(obj, *args)

            # assume a Qt cleanup/deletion occurred
            except RuntimeError as e:
                cleanup.append(callback_ref)
                continue

        # if the callback is a static method...
        else:

            # if the static method is deleted, mark this callback for cleanup
            if callback is None:
                cleanup.append(callback_ref)
                continue

            # call the static callback
            callback(*args)

    # remove the deleted callbacks
    for callback_ref in cleanup:
        callback_list.remove(callback_ref)
        
        
def ask_file(title, filter):
    """
    Ask the user to select a file.
    """
    from PyQt5.QtWidgets import QFileDialog
    return QFileDialog.getOpenFileName(None, title, "", filter)[0].replace("\\", "\\\\")



def msgbox(text, title="Codex Rebirth"):
    """
    Show a message box.
    """
    from PyQt5.QtWidgets import QMessageBox
    msg = QMessageBox()
    msg.setIcon(QMessageBox.Information)
    msg.setText(text)
    msg.setWindowTitle(title)
    msg.exec_()
    
    
def get_ea() :
    rv = idaapi.regval_t()
    if idaapi.get_inf_structure().is_64bit():
        idaapi.get_reg_val('RIP', rv)
    else:
        idaapi.get_reg_val('EIP', rv)
    return rv.ival

def get_reg_value(reg_name) -> int:
    rv = idaapi.regval_t()
    idaapi.get_reg_val(reg_name, rv)
    return rv.ival


def get_regs_name() -> list:
    if idaapi.get_inf_structure().is_64bit():
        return ['RAX', 'RBX', 'RCX', 'RDX', 'RSP', 'RBP', 'RSI', 'RDI', 'R8', 'R9',
        'R10', 'R11', 'R12', 'R13', 'R14', 'R15', 'RIP']
    else:
        return [ 'EAX', 'EBX', 'ECX', 'EDX', 'ESP', 'EBP', 'ESI', 'EDI', 'EIP']
        
def remove_line(string):
    # remove the first line 
    string = string[string.find('\n')+1:]
    return string.replace("\n", " ; ")

def show_msgbox(text, title="Codex Rebirth"):
    """
    Show a message box.
    """
    from PyQt5.QtWidgets import QMessageBox
    msg = QMessageBox()
    msg.setIcon(QMessageBox.Information)
    msg.setText(text)
    msg.setWindowTitle(title)
    msg.exec_()
    
def delete_all_comments():
    for ea in idautils.Functions():
        for head in idautils.Heads(ea, idc.get_func_attr(ea, idc.FUNCATTR_END)):
            cmt = idc.get_cmt(head, 0)
            cmt = cmt.split("@@ ")[0]
            idc.set_cmt(head, cmt, 0)
            
def to_ida_color(color):
    r, g, b, _ = color.getRgb()
    return 0xFF << 24 | b << 16 | g << 8 | r

def get_rbga_color(color):
    r = color & 0xFF
    g = (color >> 8) & 0xFF
    b = (color >> 16) & 0xFF
    return r, g, b


def rbg_ida_color(r, g, b):
    return 0xFF << 24 | b << 16 | g << 8 | r




def address_to_segment_offset(address):
    # Get the segment name for the given address
    segment_name = idc.get_segm_name(address)

    # Get the start address of the segment
    segment_start = idc.get_segm_start(address)

    # Calculate the offset within the segment
    offset = address - segment_start

    return {
        "segment": segment_name,
        "offset": offset
     }
    
def segment_offset_to_address(segment, offset):
    """
    Convert a segment and offset to an address.
    """
    segment_start = ida_segment.get_segm_by_name(segment).start_ea
    return segment_start + offset
    
    
def delete_all_bpts():
    for ea in idautils.Functions():
        for head in idautils.Heads(ea, idc.get_func_attr(ea, idc.FUNCATTR_END)):
            idc.del_bpt(head)
            
def delete_all_colors():
    for ea in idautils.Functions():
        for head in idautils.Heads(ea, idc.get_func_attr(ea, idc.FUNCATTR_END)):
            idc.set_color(head, idc.CIC_ITEM, 0x242424)
            
        func = idaapi.get_func(ea)
        flow_chart = idaapi.FlowChart(func)
        for block in flow_chart:
            p = idaapi.node_info_t()
            p.bg_color = 0x242424
            gid = get_current_gid()
            idaapi.set_node_info(gid, block.id, p, idaapi.NIF_BG_COLOR)
            

        

def open_console(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        flags = (
                idaapi.PluginForm.WOPN_TAB
                | idaapi.PluginForm.WOPN_MENU
                | idaapi.PluginForm.WOPN_RESTORE
                | idaapi.PluginForm.WOPN_PERSIST
        )
        widget_output = ida_kernwin.find_widget("Output")
        ida_kernwin.display_widget(widget_output,flags)
        func(*args, **kwargs)
    return wrapper


def repr_hex_and_ascii(byte_pairs):
    hex_str_ida = " ".join(f"{ida:02X}" for ida, ctx in byte_pairs)
    ascii_str_ida = "".join(chr(ida) if 32 <= ida <= 126 else '.' for ida, ctx in byte_pairs)
    hex_str_ctx = " ".join(f"{ctx:02X}" for ida, ctx in byte_pairs)
    ascii_str_ctx = "".join(chr(ctx) if 32 <= ctx <= 126 else '.' for ida, ctx in byte_pairs)
    return f"{hex_str_ida}  {ascii_str_ida}\n{hex_str_ctx}  {ascii_str_ctx}"


def get_current_gid():
    tcontrol = idaapi.get_current_viewer()
    view = ida_graph.get_viewer_graph(tcontrol)
    return view.gid


def query_model(query):
    """
    Function which sends a query to davinci-003 and calls a callback when the response is available.
    Blocks until the response is received
    :param query: The request to send to davinci-003
    :param cb: Tu function to which the response will be passed to.
    """
    try:
        
        response = openai.ChatCompletion.create( 
        model = 'gpt-3.5-turbo',
        messages = [ # Change the prompt parameter to the messages parameter
            {'role': 'user', 'content': query}
        ],
        temperature = 0,
        timeout=2,  
        )
        return response['choices'][0]['message']['content']
    except openai.InvalidRequestError as e:
            print("Unfortunately, this function is too big to be analyzed with the model's current API limits.")

    except openai.OpenAIError as e:
        print(f"davinci-003 could not complete the request: {str(e)}")
    except Exception as e:
        print(f"General exception encountered while running the query: {str(e)}")

# -----------------------------------------------------------------------------


def query_model_sync(query):
    print("Request sent...")
    return query_model(query)



def print_banner(message, char="="):
    banner = char * 80
    print(banner)
    print(message)
    print(banner)

def check_openai_api_key():
    if openai.api_key is None:
        show_msgbox("Please set the OpenAI API key on the top of thecodexrebirth.py file")
        return
   
    
def get_op_values(ea):
    disassembly = idc.GetDisasm(ea)
    pattern = re.compile(r"0x[0-9a-fA-F]+")
    return set(pattern.findall(disassembly))
    
def get_vars(ea):
    disassembly = idc.GetDisasm(ea)
    pattern = re.compile(r"var_[0-9a-zA-Z_]+")
    return pattern.findall(disassembly)


def get_segment_name_bounds(name):
    segments = [(idc.get_segm_start(seg), idc.get_segm_end(seg), idc.get_segm_name(seg)) for seg in idautils.Segments()]
    for start, end, seg_name in segments:
        if seg_name == name:
            return start, end
    
    
def get_color(ea):
    return idc.get_color(ea, idc.CIC_ITEM)


def check_memory_access(insn):
        # lea instruction is not a memory access
    if insn.mnemonic == "lea":
        return False

    for op in insn.operands:
        if op.type == X86_OP_MEM:
            return True
    return False


def get_parent_register(register_name, arch_size):
    if arch_size == 64:
        return {
            "rax": "rax",
            "eax": "rax",
            "ax": "rax",
            "ah": "rax",
            "al": "rax",
            "rbx": "rbx",
            "ebx": "rbx",
            "bx": "rbx",
            "bh": "rbx",
            "bl": "rbx",
            "rcx": "rcx",
            "ecx": "rcx",
            "cx": "rcx",
            "ch": "rcx",
            "cl": "rcx",
            "rdx": "rdx",
            "edx": "rdx",
            "dx": "rdx",
            "dh": "rdx",
            "dl": "rdx",
            "rsi": "rsi",
            "esi": "rsi",
            "si": "rsi",
            "sil": "rsi",
            "rdi": "rdi",
            "edi": "rdi",
            "di": "rdi",
            "dil": "rdi",
            "rbp": "rbp",
            "ebp": "rbp",
            "bp": "rbp",
            "bpl": "rbp",
            "rsp": "rsp",
            "esp": "rsp",
            "sp": "rsp",
            "spl": "rsp",
            "r8": "r8",
            "r8d": "r8",
            "r8w": "r8",
            "r8b": "r8",
            "r9": "r9",
            "r9d": "r9",
            "r9w": "r9",
            "r9b": "r9",
            "r10": "r10",
            "r10d": "r10",
            "r10w": "r10",
            "r10b": "r10",
            "r11": "r11",
            "r11d": "r11",
            "r11w": "r11",
            "r11b": "r11",
            "r12": "r12",
            "r12d": "r12",
            "r12w": "r12",
            "r12b": "r12",
            "r13": "r13",
            "r13d": "r13",
            "r13w": "r13",
            "r13b": "r13",
            "r14": "r14",
            "r14d": "r14",
            "r14w": "r14",
            "r14b": "r14",
            "r15": "r15",
            "r15d": "r15",
            "r15w": "r15",
            "r15b": "r15",
        }[register_name]
    elif arch_size == 32:
        return {
            "eax": "eax",
            "ax": "eax",
            "ah": "eax",
            "al": "eax",
            "ebx": "ebx",
            "bx": "ebx",
            "bh": "ebx",
            "bl": "ebx",
            "ecx": "ecx",
            "cx": "ecx",
            "ch": "ecx",
            "cl": "ecx",
            "edx": "edx",
            "dx": "edx",
            "dh": "edx",
            "dl": "edx",
            "esi": "esi",
            "si": "esi",
            "edi": "edi",
            "di": "edi",
            "ebp": "ebp",
            "bp": "ebp",
            "esp": "esp",
            "sp": "esp",
            "r8d": "r8",
            "r8w": "r8",
            "r8b": "r8",
            "r9d": "r9",
            "r9w": "r9",
            "r9b": "r9",
            "r10d": "r10",
            "r10w": "r10",
            "r10b": "r10",
            "r11d": "r11",
            "r11w": "r11",
            "r11b": "r11",
            "r12d": "r12",
            "r12w": "r12",
            "r12b": "r12",
            "r13d": "r13",
            "r13w": "r13",
            "r13b": "r13",
            "r14d": "r14",
            "r14w": "r14",
            "r14b": "r14",
            "r15d": "r15",
            "r15w": "r15",
            "r15b": "r15",
        }[register_name]
    else:
        raise ValueError("Unknown architecture type")


        