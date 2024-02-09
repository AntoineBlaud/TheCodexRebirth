import os
import sys
import tempfile
import logging
import idaapi
from tenet.util.common import *
from tenet.taint_engines import TextEngine
from tenet.taint_engines.core import *

logger = logging.getLogger("tenet")


class TaintAnalysisRunner:
    def __init__(self, arch, dctx, reader):
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
        self._runner.process_analysis()
        

    def setup_logger(self):
        return tempfile.NamedTemporaryFile(prefix="cr_trace", suffix=".txt", delete=False, mode="w")
    

    def get_binary_path(self):
        """
        Get the path to the binary file from IDA Pro.

        Returns:
            str: Path to the binary file.
        """
        return os.path.join(os.getcwd(), idaapi.get_input_file_path())
        
            
        
        

