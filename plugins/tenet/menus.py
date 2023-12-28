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
        
    
    def show(self):
        #  # if there is no Qt (eg, our UI framework...) then there is no UI
        if not QT_AVAILABLE:
            return
        self.view.show()
        # keep open until the user closes it
        self.view.exec_()
        
    def hide(self):
        self.view.hide()
        
        
        
        
class ExportFunctionsMenuModel:
    def __init__(self, pctx):
        self.pctx = pctx
        self.dctx = disassembler[self.pctx]
        self.sections_data = self.read_sections_data()
        self.register_callbacks = []
        
    def read_sections_data(self):
        sections = self.dctx.get_sections()
        for section in sections:
            section_name = section['name']
            functions = self.dctx.get_functions_in_section(section_name)
            section['functions'] = functions
        return sections
        

    def register_callback(self, callback):
        self.register_callbacks.append(callback)