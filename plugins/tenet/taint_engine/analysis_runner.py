import os
import sys
import tempfile
import logging
import traceback
from tenet.util.common import *
from tenet.taint_engine import TextEngine
from tenet.taint_engine.core import *

logger = logging.getLogger("Tenet.Taint_Engines.AnalysisRunner")


class TaintAnalysisRunner:
    def __init__(self, arch, dctx, reader):
        global logger
        self.sym_runner = None
        # Create a temporary log file for debugging.
        self.log_file = self.setup_logger()
        # Redirect standard input to /dev/null (suppress user input).
        sys.stdin = open(os.devnull, "r")
        self.dctx = dctx
        self.arch = arch
        self.reader = reader
        
        self.cs = self.dctx.get_capstone_md(self.arch)
        self.ks = self.dctx.get_keystone_md(self.arch)
        self._engine = TextEngine(self.arch, self.dctx, self.cs, self.ks, self.reader)
        self._runner = Runner(self._engine, self.arch, self.cs, self.ks)
        try:
            self._runner.process_analysis()
        except Exception as e:
            print(traceback.format_exc())
            
        

    def setup_logger(self):
        return tempfile.NamedTemporaryFile(prefix="cr_trace", suffix=".txt", delete=False, mode="w")
    

        