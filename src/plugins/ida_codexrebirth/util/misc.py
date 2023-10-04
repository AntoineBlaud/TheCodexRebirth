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
    functionname = idaapi.get_func_name(rv.ival)
    return rv.ival, functionname

def get_reg_value(reg_name) -> int:
    rv = idaapi.regval_t()
    idaapi.get_reg_val(reg_name, rv)
    return rv.ival


def get_regs_name() -> list:
    if idaapi.get_inf_structure().is_64bit():
        return ['RAX', 'RBX', 'RCX', 'RDX', 'RSP', 'RBP', 'RSI', 'RDI', 'R8', 'R9',
        'R10', 'R11', 'R12', 'R13', 'R14', 'R15', 'RIP']
    else:
        return [ 'EAX', 'EBX', 'ECX', 'EDX', 'ESP', 'EBP', 'ESI', 'EDI', 'R8D', 'R9D',
        'R10D', 'R11D', 'R12D', 'R13D', 'R14D', 'R15D', 'EIP']
        
def remove_line(string, n):
    lines = string.split('\n')
    if len(lines) < n:
        return string
    lines.pop(n)
    return '\n'.join(lines)

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
            idc.set_cmt(head, "", 0)
            
def to_ida_color(color):
    r, g, b, _ = color.getRgb()
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
            

def taint_memory_with_string(codex, value, addr, name_pattern, chunk_size=1):
    """
    Taint memory with a string in chunks of a specified size.

    Args:
        codex: The Codex instance.
        value: The input string to taint.
        addr: The starting memory address to write the string.
        name_pattern: A name pattern for tainting.
        chunk_size: The size of each chunk (default is 1 byte).
    """
    for i in range(0, len(value), chunk_size):
        chunk = value[i:i + chunk_size]
        name = f"{name_pattern}_{i}"
        _taint_memory_with_string_chunk(codex, addr, chunk, name)
        addr += chunk_size

def _taint_memory_with_string_chunk(codex, addr, chunk, name):
    """
    Taint memory with a string.

    Args:
        codex: The Codex instance.
        offset: The memory offset to write the string.
        value: The input string to taint.
        name_pattern: A name pattern for tainting.
    """
    mask = 0xff << ((len(chunk) -1) * 8)
    
    if isinstance(chunk, str):
        value_bytes = chunk.encode()
    elif isinstance(chunk, bytearray):
        value_bytes = bytes(chunk)
    else:
        value_bytes = chunk
        
    assert isinstance(value_bytes, bytes)
        
    codex.ql.mem.write(addr, value_bytes)
    value = int.from_bytes(value_bytes, byteorder='little')
    codex.taint_memory(addr, name, value, mask)


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



def validate_config(config):
    schema = {
        "type": "object",
        "properties": {
            "BinaryArch": {"type": "string"},
            "rootfs_path": {"type": "string"},
            "binary_path": {"type": "string"},
            "log_plain": {"type": "boolean"},
            "symbolic_check": {"type": "boolean"},
            "strict_symbolic_check": {"type": "boolean"},
            "addresses": {
                "type": "object",
                "additionalProperties": {
                    "type": "object",
                    "properties": {
                        "segment": {"type": "string"},
                        "offset": {"type": "integer"},
                    },
                    "required": ["segment", "offset"],
                },
            },
            "tainted_memory": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "ref": {"type": "string"},
                        "size": {"type": "integer"},
                        "chunck_size": {"type": "integer"},
                    },
                    "required": ["ref", "size", "chunck_size"]
                }
            },
            "tainted_registers": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "reg": {"type": "string"},
                        "name": {"type": "string"},
                    },
                    "required": ["reg", "name"]
                }
            },
            "do_not_sym_execute": {
                "type": "array", 
                "items": {"type": "string"}}
        },
        "required": [
            "BinaryArch",
            "rootfs_path",
            "binary_path",
            "log_plain",
            "symbolic_check",
            "strict_symbolic_check",
            "addresses",
            "tainted_memory",
            "tainted_registers",
            "do_not_sym_execute"
        ]
    }

   
    jsonschema.validate(config, schema)
       