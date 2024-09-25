from tenet.util.qt import *
from tenet.util.common import *
from tenet.util.misc import *
from tenet.util.counter import alt_count
from tenet.tracer.node import *
from tenet.ui import *
from tenet.integration.api import disassembler
from tenet.util.misc import get_temp_dir
from tenet.util.disasm import *
from tenet.tracer.logic_loop_tracer import SkipLoopLogic
from capstone.x86_const import *
from capstone.arm_const import *
from tenet.tracer.core_tracer import *
from tenet.util.misc import tohex
from tenet.util.log import get_log_path

logger = logging.getLogger(f"Tenet.{__name__}")



class IDAStepTracerController(StepTracerController):
    def __init__(self, pctx):
        super().__init__(disassembler[pctx], pctx.arch)
        self.pctx = pctx
        self.dctx = disassembler[self.pctx]
        self.view = StepTracerView(self, self.model)
        self.view.show()
        self.cs = get_capstone_md(self.arch)
        self.ks = get_keystone_md(self.arch)

    def show(self):
        self.view.show()

    def stop(self):
        self.trace_file = self.save_trace()

        self.model.watcher = Watcher(self.prev_ea)
        self.model.watcher.is_saved = True
        self.model.watcher.path = self.trace_file

        self.view._refresh()
        self.save_library_calls(self.skip_logic.library_calls)

        # flush log
        self.log_handle.flush()

    def update_ui(self):
        # update ui
        self.dctx.update_ui()
        self.view.update_progress(self.start, self.idx)

    def print_log(self, msg):
        self.log_handle.write(f"{msg}\n")

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

        self.skip_logic = SkipLoopLogic(
            self.dctx, self.arch, self.model, 200, self.print_log
        )  
        self.skip_logic.set_callback_get_ea(lambda: self.dctx.get_pc(self.arch))

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
        logger.info(f"Max step inside loop: {self.model.max_step_inside_loop}")
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
