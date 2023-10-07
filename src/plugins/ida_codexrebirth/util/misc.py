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
            
def delete_all_colors():
    for ea in idautils.Functions():
        for head in idautils.Heads(ea, idc.get_func_attr(ea, idc.FUNCATTR_END)):
            idc.set_color(head, idc.CIC_ITEM, 0x242424)
            

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
       
       
import idaapi
import idautils
import idc


def token_similarity(s1, s2):
    # Convert the strings to sets of characters (or tokens)
    set1 = set(s1)
    set2 = set(s2)

    # Calculate Jaccard similarity
    intersection_size = len(set1.intersection(set2))
    union_size = len(set1.union(set2))
    
    # Avoid division by zero
    if union_size == 0:
        return 0.0

    similarity = intersection_size / union_size
    return similarity


def get_all_basic_blocks(ea):
    func = idaapi.get_func(ea)
    
    if not func:
        print("Function not found at 0x{:X}".format(ea))
        return []

    flow_chart = idaapi.FlowChart(func)

    blocks_info = []
    
    for block in flow_chart:
        block_start = block.start_ea
        block_end = block.end_ea
        block_disassembly = ""
        for address in idautils.Heads(block_start, block_end):
            instruction = idc.GetDisasm(address)
            # remove comments
            if ';' in instruction:
                instruction = instruction.split(';')[0]
            block_disassembly += "{}\n".format(instruction)
        
        blocks_info.append((block_start, block_disassembly))
    
    return blocks_info


def get_all_basic_blocks_start(ea):
    func = idaapi.get_func(ea)
    if not func:
        print("Function not found at 0x{:X}".format(ea))
        return []
    
    flow_chart = idaapi.FlowChart(func)
    return [block.start_ea for block in flow_chart]


def get_basic_blocks(ea):
    func = idaapi.get_func(ea)
    if not func:
        print("Function not found at 0x{:X}".format(ea))

    flow_chart = idaapi.FlowChart(func)
    for block in flow_chart:
        block_start = block.start_ea
        block_end = block.end_ea
        if ea >= block_start and ea <= block_end:
            instructions = []
            for address in idautils.Heads(block_start, block_end):
                instruction = idc.GetDisasm(address)
                # remove comments
                if ';' in instruction:
                    instruction = instruction.split(';')[0]
                instructions.append(instruction)    
            return block_start, "\n".join(instructions)
        
    return None, None
        

    

def group_similar_blocks(blocks_info, similarity_threshold):
    grouped_blocks = []
    total_blocks = len(blocks_info)
    
    while blocks_info:
        current_block_start, current_block_disassembly = blocks_info.pop(0)
        similar_blocks = [(current_block_start, current_block_disassembly)]

        for block_start, block_disassembly in blocks_info:
            similarity = token_similarity(current_block_disassembly, block_disassembly)
            if similarity >= similarity_threshold:
                similar_blocks.append((block_start, block_disassembly))

        for block in similar_blocks:
            blocks_info = [(b_start, b_disassembly) for b_start, b_disassembly in blocks_info if b_start not in [b[0] for b in similar_blocks]]

        grouped_blocks.append(similar_blocks)
        progress_percentage = ((total_blocks - len(blocks_info)) / total_blocks) * 100
        print("Progress: {:.2f}%".format(progress_percentage))

    return grouped_blocks


def remove_hardcoded_values(block_disassembly):
    pattern = re.compile(r"[0-9a-fA-F]+h")
    return pattern.sub("", block_disassembly)


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

def color_blocks(blocks, color, cinside=True):
    if not isinstance(blocks, list):
        blocks = [blocks]
    for block_start in blocks:
        func = idaapi.get_func(block_start)
        flow_chart = idaapi.FlowChart(func)
        for block in flow_chart:
            if block.start_ea == block_start:
                p = idaapi.node_info_t()
                p.bg_color = color
                gid = get_current_gid()
                if cinside:
                    for head in idautils.Heads(block.start_ea, block.end_ea):
                        idaapi.set_item_color(head, color)
                idaapi.set_node_info(gid, block.id, p, idaapi.NIF_BG_COLOR)

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
        show_msgbox("Please set the OpenAI API key on the top of the ida_codexrebirth.py file")
        return
    
    
    
def take_execution_snapshot():
    # Get the current state of segments and registers
    segments = {}
    for seg in idautils.Segments():
        seg_start = idc.get_segm_start(seg)
        seg_end = idc.get_segm_end(seg)
        segments[seg] = (seg_start, seg_end, idc.get_bytes(seg_start, seg_end - seg_start))
    
    registers = {}
    for reg in idautils.GetRegisterList():
        try:
            registers[reg] = idc.get_reg_value(reg)
        except:
            pass
    # Create a temporary directory to store the snapshot
    temp_dir = tempfile.mkdtemp()
    snapshot_file = os.path.join(temp_dir, 'snapshot.pkl')
    
    # Serialize and save the data to a file
    with open(snapshot_file, 'wb') as f:
        snapshot_data = (segments, registers)
        pickle.dump(snapshot_data, f)
    
    print(f"Execution snapshot saved to {snapshot_file}")
    return os.path.join(temp_dir, 'snapshot.pkl')

def restore_execution_snapshot(snapshot_file):
    
    if not os.path.exists(snapshot_file):
        print("Snapshot file not found")
        return
    
    # Deserialize the snapshot data
    with open(snapshot_file, 'rb') as f:
        segments, registers = pickle.load(f)
    
    # Restore segments
    for seg, (seg_start, _, seg_data) in segments.items():
        ida_bytes.patch_bytes(seg_start, seg_data)
    
    # Restore registers
    for reg, value in registers.items():
        idc.set_reg_value(value, reg)
    
    print("Execution snapshot restored")
