from tenet.ui import QT_AVAILABLE
from tenet.ui.menus import ExportFuncsMenuView
from tenet.integration.api import disassembler
import idaapi
import logging
import idc
import idautils

logger = logging.getLogger(f"Tenet.{__name__}")



    # TODO: move outside of this class
def compute_function_coverage(dctx, func, section=".text", f_cache_coverages={}, depth=0):
    """Compute the coverage of a function in the binary."""
    # get all sub calls
    if depth > 15:
        return set()
    if func is None:
        return set()
    f_sub_calls = set()
    
    for ea in idautils.FuncItems(func.start_ea):
        mnem = dctx.print_insn_mnemonic(ea)
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
            f_sub_sub_calls = compute_function_coverage(dctx, sub_func, section, f_cache_coverages, depth + 1)
            # merge coverage
            f_sub_calls |= f_sub_sub_calls

    f_cache_coverages[func.start_ea] = f_sub_calls
    return f_sub_calls


class ExportFunctionsMenuController:
    def __init__(self, pctx):
        self._pctx = pctx
        self.model = ExportFunctionsMenuModel(pctx)
        self.view = ExportFuncsMenuView(self.model)
        self.view.show()

    def show(self):
        self.view.show()
        raise "Showing the view"

    def hide(self):
        self.view.hide()


class ExportFunctionsMenuModel:
    def __init__(self, pctx):
        self.pctx = pctx
        self.dctx = disassembler[self.pctx]

        if self.dctx.is_debugger_on():
            raise Exception("Debugger must be off")

        logger.info("ExportFunctionsMenuModel initialized")
        self.sections_data = self.read_sections_data()
        self.register_callbacks = []

    def read_sections_data(self):
        offset = idaapi.get_imagebase()
        sections = self.dctx.get_sections() 
        for section in sections:
            logger.info(f"Processing section {section['name']}")
            section_name = section["name"]
            functions = self.dctx.get_functions_defined_in_section(section_name)
            f_cache_coverages = {}
            length = len(functions)
            counter = 0
            functions_to_export = []
            functions_metadata = []
            for f_name, f_addr in functions:
                # get all sub calls recursively
                func = idaapi.get_func(f_addr)
                logger.info(f"Processing {f_name} in {section_name} ({counter}/{length})")
                f_cover = compute_function_coverage(self.dctx, func, section_name, f_cache_coverages)
                f_size = func.end_ea - func.start_ea
                functions_metadata.append((f_name, f_addr, len(f_cover), f_size))
                counter += 1
            functions_metadata = sorted(functions_metadata, key=lambda f: f[2], reverse=True)
            # keep only functions with coverage > 2 or size > 40
            for f_name, f_addr, f_cover, f_size in functions_metadata:
                if f_size > 40:
                    functions_to_export.append((f_name, f_addr - offset, f_cover, f_size))
            # add functions to section data
            section["functions"] = functions_to_export
        return sections

    def register_callback(self, callback):
        self.register_callbacks.append(callback)
