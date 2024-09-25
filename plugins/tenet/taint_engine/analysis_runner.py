import os
import sys
import tempfile
import logging
import traceback
from tenet.util.common import *
from tenet.util.disasm import *
from tenet.taint_engine.engines import TextEngine
from tenet.taint_engine.core_taint import *

logger = logging.getLogger("Tenet.Taint_Engines.AnalysisRunner")


class TaintAnalysisRunner:
    def __init__(self, arch, dctx, reader):
        global logger
        self.sym_runner = None
        # Create a temporary log file for debugging.
        self.log_file = self.create_empty_file()
        # Redirect standard input to /dev/null (suppress user input).
        sys.stdin = open(os.devnull, "r")
        self.dctx = dctx
        self.arch = arch
        self.reader = reader

        self.cs = get_capstone_md(self.arch)
        self.ks = get_keystone_md(self.arch)
        self._engine = TextEngine(self.arch, self.dctx, self.cs, self.ks, self.reader)
        self._runner = Runner(self._engine)
        try:

            logger.info("Processing Taint Analysis ...")

            taint_trace_records = self._runner.process_analysis()
            self.reader.construct_taint_trace(taint_trace_records)
            
        except Exception as e:
            print(traceback.format_exc())

    def create_empty_file(self):
        return tempfile.NamedTemporaryFile(prefix="cr_trace", suffix=".txt", delete=False, mode="w")
