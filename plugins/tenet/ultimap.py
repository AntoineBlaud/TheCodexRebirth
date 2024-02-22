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
        self.maxHits = 1
        self.timeout = 30
        self.importedFunctionsFilePath = ""
        self.moduleToTrace = ""
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
        try:
            return self.dctx.get_pc(self.arch)
        except:
            return 0
    
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
                self.dctx.update_ui()

        
    def initialize(self):
        if self.dctx.get_bpt_qty() > 0:
            show_msgbox("Please remove all breakpoints before starting StepTracer", "StepTracer - Error")
            return False
        
        base = self.dctx.get_module_text_base(self.model.moduleToTrace)
        if not base:
            self.log(f"Module {self.model.moduleToTrace} not found")
            return False
        self.log(f"Module {self.model.moduleToTrace} found at {hex(base)}")
        
        if not os.path.exists(self.model.importedFunctionsFilePath):
            self.log(f"Imported functions file {self.model.importedFunctionsFilePath} not found")
            return False
        
        # read imported functions
        with open(self.model.importedFunctionsFilePath, "r") as f:
            data = f.read().splitlines()
            counter = 0
            for line in data:
                line = line.strip()
                offset, name = line.split(" ")
                offset = int(offset[2:], 16)
                self.model.importedFunctions[name] = base + offset
                self.model.reverseImportedFunctions[base + offset] = name
                counter += 1
                if counter > 1000:
                    self.log(f"Too many imported functions, limit to 1000")
                    break
        self.set_bp_on_imported_functions(self.model.importedFunctions)
        return True
    
    def run(self):
        """
        Run the Ultimap Controller.
        """
        
        if not self.dctx.is_debugger_on():
            msg = "Debugger is not on"
            show_msgbox(msg, "Error")
            raise Exception(msg)
        
        if len(self.model.records)  == 0:
            if not self.initialize():
                return 
    
        self._run()
            
            
    def update_view(self, start, timeout):
        percent = int((time.time() - start) * 100 / timeout)
        # update ui
        self.dctx.update_ui()
        self.view.update_progress(percent)
        
        
    def disable_breakpoints(self, record_index):
        if len(self.model.records) < record_index:
            return
        record = self.model.records[record_index]   
        for name, ea in self.model.importedFunctions.items():
            if ea in record:
                self.dctx.delete_breakpoint(ea)
                self.log(f"Disabled breakpoint on {name}")
                
    def enable_breakpoints(self, record_index):
        if len(self.model.records) < record_index:
            return
        record = self.model.records[record_index]   
        for name, ea in self.model.importedFunctions.items():
            if ea in record:
                self.dctx.set_breakpoint(ea)
                self.log(f"Enabled breakpoint on {name}")
                  
    def _run(self):
        """
        Run the Ultimap Controller.
        """
        self.log(f"Start recording")
        start = time.time()
        timeout = self.model.timeout
        current_record = {}
        while time.time() - start < timeout:
            self.dctx.continue_process(1)     
            self.update_view(start, timeout)
            
            # check if process is running or stopped
            if self.dctx.is_process_running():
                continue
            
            f_name = self.model.reverseImportedFunctions.get(self.ea, None)
            if not f_name:
                continue
            if f_name in current_record:
                current_record[f_name] += 1
            else:
                current_record[f_name] = 1
                
            if current_record[f_name] > self.model.maxHits:
                self.dctx.delete_breakpoint(self.ea)
                self.log(f"Reached max hits of {self.model.maxHits} for {f_name}")
                continue
            self.log(f"Recorded {f_name}")
            
        self.update_view(start, timeout)
        self.model.records.append(current_record)

            
            
            
            
            
        