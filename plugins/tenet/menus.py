from tenet.ui import QT_AVAILABLE
from tenet.ui.menus import ExportFuncsMenuView
from tenet.integration.api import disassembler
import idaapi
import idc
    
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
        offset = self.dctx.get_imagebase()
        self.dctx.rebase_0()
        self.sections_data = self.read_sections_data()
        self.dctx.rebase_plus(offset)
        self.register_callbacks = []
        
    def read_sections_data(self):
        sections = self.dctx.get_sections()
        functions_metadata = []
        for section in sections:
            section_name = section['name']
            functions = self.dctx.get_functions_in_section(section_name)
            f_cache_coverages = {}
            for f_name, f_addr in functions:
                # get all sub calls recursively
                func = idaapi.get_func(f_addr)
                f_cover = self.dctx.compute_function_coverage(func, section_name, f_cache_coverages)
                f_size = func.end_ea - func.start_ea
                functions_metadata.append((f_name, f_addr, len(f_cover), f_size))
            functions_metadata = sorted(functions_metadata, key=lambda f: f[2], reverse=True)
            functions = []
            # keep only functions with coverage > 2 or size > 40
            for f_name, f_addr, f_cover, f_size in functions_metadata:
                if f_size > 40:
                    functions.append((f_name, f_addr, f_cover, f_size))
            # add functions to section data
            section['functions'] = functions
        return sections
        

    def register_callback(self, callback):
        self.register_callbacks.append(callback)