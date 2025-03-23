from tenet.ui import QT_AVAILABLE
from tenet.ui.menus import ExportFuncsMenuView
from tenet.integration.api import disassembler, IDAContextAPI
import logging

logger = logging.getLogger(f"Tenet.{__name__}")


def compute_function_coverage(dctx, func, section=".text", f_cache_coverages={}, depth=0):
    """
    Compute the coverage of a function in the binary.

    Args:
        dctx (IDAContextAPI): disassembler context
        func (idaapi_func_t): function to explore
        section (str): code section name
        f_cache_coverages (dict): cached coverages for already explored functions
        depth (int): recursion depth

    Returns:
        set: covered subcalls of the function
    """
    # get all sub calls
    if depth > 15:
        return set()
    if func is None:
        return set()

    f_sub_calls = set()  # set to store covered subcalls
    
    for ea in dctx.get_func_items(func.start_ea):
        mnem = dctx.print_insn_mnemonic(ea)
        
        if mnem == "call" or mnem == "bl":
            addr = dctx.get_operand_value(ea, 0)
            # get function name
            name = dctx.get_func_name(addr)
            # check addr is in code section
            if dctx.get_segm_name(addr) == section:
                f_sub_calls.add((name, addr))  # add subcall to the set

    for sub_call_name, sub_call_addr in f_sub_calls.copy():
        # if already explored get the result
        if sub_call_addr in f_cache_coverages:
            # merge coverage
            f_sub_calls |= f_cache_coverages[sub_call_addr]
            continue
        
        # else explore the function
        elif sub_call_name != dctx.get_func_name(func.start_ea):
            sub_func = dctx.get_func(sub_call_addr)
            f_sub_sub_calls = compute_function_coverage(dctx, sub_func, section, f_cache_coverages, depth + 1)
            # merge coverage
            f_sub_calls |= f_sub_sub_calls

    f_cache_coverages[func.start_ea] = f_sub_calls
    return f_sub_calls


def read_sections_data(dctx):
    """
    Read the sections data.

    Args:
        dctx (IDAContextAPI): disassembler context

    Returns:
        list: sections data with functions metadata
    """
    offset = dctx.get_imagebase()
    sections = dctx.get_sections()

    for section in sections:

        logger.info(f"Processing section {section['name']}")
        section_name = section["name"]
        functions = dctx.get_functions_defined_in_section(section_name)
        
        f_cache_coverages = {}  # cache coverages for already explored functions
        length = len(functions)
        counter = 0
        
        section_functions = []  # list to store exported functions metadata
        functions_metadata = []

        for f_name, f_addr in functions:
            # get all sub calls recursively
            func = dctx.get_func(f_addr)

            logger.info(f"Processing {f_name} in {section_name} ({counter}/{length})")

            f_cover = compute_function_coverage(dctx, func, section_name, f_cache_coverages)
            f_size = func.end_ea - func.start_ea
            print(hex(f_addr), hex(offset))
            
            functions_metadata.append((f_name, f_addr - offset, len(f_cover), f_size))
            counter += 1

        functions_metadata = sorted(functions_metadata, key=lambda f: f[2], reverse=True)

        # keep only functions with coverage > 2 or size > 40
        for f_name, f_addr, f_cover, f_size in functions_metadata:
            if f_size > 40:
                section_functions.append((f_name, f_addr, f_cover, f_size))
        
        # add functions to section data
        section["functions"] = section_functions
            
    return sections

class ExportFunctionsMenuController:
    def __init__(self, pctx):
        """
        Initialize the controller.

        Args:
            pctx (idaapi_process_t): ida process context
        """
        self.pctx = pctx  # store the process context

        self.dctx = disassembler[self.pctx]
        #self.dctx.rebase_0()

        self.model = ExportFunctionsMenuModel(pctx)
        self.view = ExportFuncsMenuView(self, self.model)
        
    def show(self):
        """
        Show the view.
        """
        self.view.show()  # show the view
    
    def hide(self):
        """
        Hide the view.
        """
        self.view.hide()  # hide the view


class ExportFunctionsMenuModel:
    def __init__(self, pctx):
        """
        Initialize the model.

        Args:
            pctx (idaapi_process_t): ida process context
        """
        self.pctx = pctx  # store the process context
        self.dctx = disassembler[self.pctx]

        if self.dctx.is_debugger_on():
            raise Exception("Debugger must be off")

        logger.info("ExportFunctionsMenuModel initialized")
        
        self.sections_data = read_sections_data(self.dctx)
    
   
    
    def register_callback(self, callback):
        """
        Register a callback.

        Args:
            callback (function): callback function
        
        Returns:
            None
        """
        self.register_callbacks.append(callback)  # append callback to the list

