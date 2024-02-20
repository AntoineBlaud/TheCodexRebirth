from tenet.util.qt import *
from tenet.util.common import *
from tenet.ui import *
from tenet.integration.api import disassembler
from tenet.util.misc import get_temp_dir
import random
import os
from capstone.x86_const import *
from capstone.arm_const import *



class UltimapModel(object):
    """
    The Ultimap Model
    """

    def __init__(self, pctx):
        self.pctx = pctx
        self.arch = self.pctx.arch
        self.firstRunTimeout= 300
        self.timeout = 5
        self.importedFunctionsFilePath = ""
        self.reset()
        
    def reset(self):
        """
        Reset the model.
        """
        self.functionBreakpoints = {}
        self.importedFunctions = {}
        self.reverseImportedFunctions = {}
        self.records = []
    
    
    
class UltimapController(object):
    """
    The Ultimap Controller
    """

    def __init__(self, pctx):
        self.pctx = pctx
        self.dctx = disassembler[self.pctx]
        self.model = UltimapModel(self.pctx)
        self.view = UltimapView(self, self.model)
        self.arch = self.pctx.arch
        self.cs = self.dctx.get_capstone_md(self.arch)
        self.ks = self.dctx.get_keystone_md(self.arch)
        
        
    @property
    def ea(self):
        return self.dctx.get_pc(self.arch)
    
    def log(self, msg):
        print(f"[Ultimap] {msg}")
        
    def show(self):
        self.view.show()
        
    def set_bp_on_imported_functions(self, importedFunctions):
        for name, ea in importedFunctions.items():
            if ea not in self.model.functionBreakpoints:
                self.log(f"Set breakpoint on function {name} {hex(ea)}")
                self.dctx.set_breakpoint(ea)
                self.model.functionBreakpoints[ea] = True
    
    def delete_breakpoint(self, ea):
        if ea in self.model.functionBreakpoints:
            del self.model.functionBreakpoints[ea]
        self.log(f"Delete breakpoint at {hex(ea)}")
        self.dctx.delete_breakpoint(ea)
    
    def run(self):
        """
        Run the Ultimap Controller.
        """
        
        if not self.dctx.is_debugger_on():
            msg = "Debugger is not on"
            show_msgbox(msg, "Error")
            raise Exception(msg)
        
        base = self.dctx.get_module_text_base(self.model.moduleToTrace)
        if not base:
            self.log(f"Module {self.model.moduleToTrace} not found")
            return
        self.log(f"Module {self.model.moduleToTrace} found at {hex(base)}")
        
        if not os.path.exists(self.model.importedFunctionsFilePath):
            self.log(f"Imported functions file {self.model.importedFunctionsFilePath} not found")
            return
        
        # read imported functions
        with open(self.model.importedFunctionsFilePath, "r") as f:
            data = f.read().splitlines()
            for line in data:
                line = line.strip()
                offset, name = line.split(" ")
                offset = int(offset[2:], 16)
                self.model.importedFunctions[name] = base + offset
                self.model.reverseImportedFunctions[base + offset] = name
        self.set_bp_on_imported_functions(self.model.importedFunctions)
        
        
        self.model.records.append({})
        
        if len(self.model.records) == 0:
            self._first_run()
            
            
    def _first_run(self):
        """
        Run the Ultimap Controller.
        """
        self.log(f"Starting Ultimap")
        start = time.time()
        timeout = self.model.firstRunTimeout
        while time.time() - start < timeout:
            self.dctx.continue_process()
            f_name = self.model.reverseImportedFunctions.get(self.ea, None)
            if not f_name:
                raise Exception(f"Function name not found for {hex(self.ea)}")
            self.model.records[-1][f_name] = 1
            self.log(f"Recorded {f_name}")
            self.delete_breakpoint(self.ea)
            
            percent = int((time.time() - start) * 100 / timeout)
            # update ui
            self.dctx.update_ui()
            self.view.update_progress(percent)
            
            
            
        