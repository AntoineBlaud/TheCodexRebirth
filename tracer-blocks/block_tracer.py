from tenet.util.qt import *
from tenet.util.common import *
from tenet.util.misc import *
from tenet.util.counter import alt_count
from tenet.tracer.t_objects import *
from tenet.ui import *
from tenet.integration.api import disassembler
from tenet.context import IDA_GLOBAL_CTX
from tenet.util.misc import get_temp_dir
from tenet.util.disasm import *
from capstone.x86_const import *
from capstone.arm_const import *
from tenet.tracer.core_tracer import *
from tenet.util.misc import tohex
from tenet.util.log import get_log_path
from tenet.integration.api import ida_api
from tenet.integration.api import *
from tenet.trace.arch import *

import time
import importlib


import logics.logic_block_tracer 
import shellcode_managers


logger = logging.getLogger(f"Tenet.{__name__}")




class IDABlockTracerController(TracerController):
    def __init__(self, dctx, arch,  shellcode_class):
        super().__init__(dctx, arch)
        self.dctx = dctx
        self.cs = get_capstone_md(self.arch)
        self.ks = get_keystone_md(self.arch)
        self.shellcode_manager = shellcode_manager
        self.shellcode_location = None

    def show(self):
        self.view.show()

    def stop(self):
        self.trace_file = self.save_trace()
        self.save_library_calls(self.skip_logic.library_calls)
        self.log_segments_metadata()

        # flush log
        self.log_handle.flush()

    def update_ui(self):
        # update ui
        self.dctx.update_ui()
        
    def log_segments_metadata(self):
        sections = dctx.get_sections()
        for section in sections:
            self.print_log(section)
        
    def print_log(self, msg):
        #self.log_handle.write(f"{msg}\n")
        print(msg)

    def initialize(self):
        
        if self.model.module_name:
            return True
        # fetch the current log file
        self.model.reset()

        self.log_handle = open(get_log_path(), "a")
        self.backup_files()

        self.model.module_name = self.dctx.get_segm_name(self.ea)
        base = self.dctx.get_module_base()

        if not base:
            logger.error(f"Module base not found. Filename must be equal to module base name. Check filename has not space")
            return False
        
        self.model.tenet_trace.append([f"base={tohex(base, self.arch.POINTER_SIZE)}"])

        if self.dctx.is_process_running():
            msg = "Please continue process until we reach a breakpoint before starting StepTracer"
            show_msgbox(msg, "StepTracer - Error")
            raise Exception(msg)
        

        self.skip_logic = logics.logic_block_tracer.LogicBlockTracer(
            self.dctx, self.arch, self.model, self.print_log, self.shellcode_manager
        )  
        self.skip_logic.set_callback_get_ea(lambda: self.dctx.get_pc(self.arch))
        self.skip_logic.init()

        return True

    def main_loop(self):

        self.start = time.time()

        while True:

            self.prev_ea = self.ea

            if self.dctx.user_cancelled():
                logger.info("User cancelled")
                return

            if time.time() - self.start > self.model.run_timeout:
                logger.info("Timeout")
                return
            
            if self.idx > self.model.stop_at_idx:
                logger.info("idx limit reached")
                return

            if (self.idx + 1) % 1000 == 0:
                self.save_trace()
                self.save_library_calls(self.skip_logic.library_calls)

     
            try:
                self.skip_logic.step()
                ea = self.ea  # make a copy (needed)
                self.finalize_step(ea, self.prev_ea)

            except Exception as e:

                logger.error(f"Error getting PC: {e}")
                import traceback
                traceback.print_exc()

                return
            

    def invoke(self):

        if not self.initialize():

            print("Failed to initialize. Read logs for more details")
            return

        logger.info(f"Module to trace: {self.model.module_name}")
        logger.info(f"Timeout: {self.model.run_timeout} seconds")
        logger.info(f"Dump size: {self.model.dump_size}")
        logger.info(f"Max step inside loop: {self.model.max_instruction_hits}")
        logger.info(f"Root filename: {self.dctx.get_root_filename()}")
        logger.info(f"Current thread: {self.dctx.get_current_thread()}")
        
        self.dctx.suspend_other_threads()

        try:
            self.main_loop()

        except Exception as e:
            import traceback
            traceback.print_exc()
            logger.error(f"Error: {e}")

        finally:
            self.stop()

        self.dctx.resume_threads()


if __name__ == "__main__":
    importlib.reload(logics.logic_block_tracer)
    importlib.reload(logics.memory_manager)
    importlib.reload(shellcode_managers)
        
    shellcode_manager = shellcode_managers.Windows_64_SM
    dctx = IDAContextAPI(IDACoreAPI())
    arch = ArchAMD64()

    jump_tracer = IDABlockTracerController(dctx, arch, shellcode_manager)

    jump_tracer.model.run_timeout = 6000
    jump_tracer.model.root_filename = dctx.get_root_filename()
    jump_tracer.model.shellcode_location = 0x000000014A730E6E
    jump_tracer.model.shellcode_location = 0x000000014A731000
   
    jump_tracer.invoke()