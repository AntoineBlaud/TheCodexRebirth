from tenet.util.qt import *
from tenet.util import *
from tenet.ui import *

from tenet.tracer.tracer_components import *
from tenet.tracer.core_tracer import *
from tenet.integration.api import *
from tenet.trace_analysis.arch import *

from capstone.x86_const import *
from capstone.arm_const import *

import time
import importlib
import logging

from tenet.tracer.logics.tracer_logic_block import LogicBlockTracer
import tenet.tracer.managers.shellcode_managers as shellcode_managers
from tenet.tracer.logics.tracer_logic_step import SkipLoopLogic

logger = logging.getLogger(f"Tenet.{__name__}")


class IDAUnifiedTracerController(TracerController):
    def __init__(self, pctx):
        super().__init__(disassembler[pctx], pctx.arch)
        self.pctx = pctx
        self.dctx = disassembler[self.pctx]
        self.cs = get_capstone_md_from_arch(self.arch)
        self.ks = get_keystone_md_from_arch(self.arch)
        
        # Modèle pour stocker le type de traceur
        if not hasattr(self.model, 'tracer_type'):
            self.model.tracer_type = "step_tracer"  # Valeur par défaut
            
    
        self.model.shellcode_location = hex(self.dctx.get_pc(self.arch) + 0x30)[2:]
        # Composants spécifiques au StepTracer
        self.pctx = pctx
        self.view = StepTracerView(self, self.model)

    def show(self):
        if hasattr(self, 'view'):
            self.view.show()

    def stop(self):
        self.trace_file = self.save_trace()

        self.model.watcher = Watcher(self.prev_ea)
        self.model.watcher.is_saved = True
        self.model.watcher.path = self.trace_file
        self.view._refresh()
            
        self.save_library_calls(self.skip_logic.library_calls)
        self.log_segments_metadata()

        # flush log
        self.log_handle.flush()
        self.view.raise_()

    def update_ui(self):
        # update ui
        self.dctx.update_ui()
        self.view._refresh()

    def create_shellcode_class(self):
        if self.dctx.get_target_filetype() == "PE":
            return shellcode_managers.Windows_64_SM
        elif self.dctx.get_target_filetype() == "ELF":
            return shellcode_managers.Linux_64_SM
        else:
            raise Exception("Unknown file type")
        
    def log_segments_metadata(self):
        sections = self.dctx.get_sections()
        if self.model.tracer_type == "block_tracer":
            for section in sections:
                self.print_log(section)
        
    def print_log(self, msg):
        self.log_handle.write(f"{msg}\n")

    def initialize(self):
        if self.model.module_name:
            return True
    
        # fetch the current log file
        self.model.reset()

        # Composants spécifiques au BlockTracer
        self.shellcode_manager = self.create_shellcode_class()

        self.log_handle = open(get_log_path(), "a")
        self.backup_files()

        self.model.module_name = self.dctx.get_segm_name(self.ea)
        base = self.dctx.get_imagebase()

        if not base:
            logger.error(f"Module base not found. Filename must be equal to module base name. Check filename has not space")
            return False
        
        self.model.tenet_trace.append([f"base={tohex(base, self.arch.POINTER_SIZE)}"])

        if self.dctx.is_process_running():
            msg = "Please continue process until we reach a breakpoint before starting Tracer"
            show_msgbox(msg, "Tracer - Error")
            raise Exception(msg)
        
        if self.model.tracer_type == "block_tracer":
            self.skip_logic = LogicBlockTracer(
                self.dctx, self.arch, self.model, self.print_log, self.shellcode_manager
            )
        else:  # step tracer
            self.skip_logic = SkipLoopLogic(
                self.dctx, self.arch, self.model, 200, self.print_log
            )
            
        self.skip_logic.set_callback_get_ea(lambda: self.dctx.get_pc(self.arch))
        
        if self.model.tracer_type == "block_tracer":
            self.skip_logic.init()

        return True

    def main_loop(self):
        self.model.start_time = time.time()

        while True:
            self.prev_ea = self.ea
            self.model.idx = self.idx

            if self.dctx.user_cancelled():
                logger.info("User cancelled")
                return

            if time.time() - self.model.start_time > self.model.run_timeout:
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
                
                if self.model.tracer_type == "step_tracer":
                    self.update_seen_instructions_count(ea)

            except Exception as e:
                logger.error(f"Error getting PC: {e}")
                import traceback
                traceback.print_exc()
                
                if self.model.tracer_type == "step_tracer":
                    print(f"Error getting PC: {e}")

                return

    def invoke(self):
        if not self.initialize():
            print("Failed to initialize. Read logs for more details")
            return

        logger.info(f"Tracer type: {self.model.tracer_type}")
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
            
            if self.model.tracer_type == "step_tracer":
                print(f"Error: {e}")

        finally:
            self.stop()

        self.dctx.resume_threads()


# Exemple d'utilisation pour un BlockTracer
if __name__ == "__main__" and False:  # Désactivé par défaut
    importlib.reload(logics.logic_block_tracer)
    importlib.reload(logics.memory_manager)
    importlib.reload(shellcode_managers)
        
    shellcode_manager = shellcode_managers.Windows_64_SM
    dctx = IDAContextAPI(IDACoreAPI())
    arch = ArchAMD64()

    tracer = IDAUnifiedTracerController(dctx, arch, shellcode_manager)
    tracer.model.tracer_type = "block_tracer"  # Configurer comme BlockTracer
    tracer.model.run_timeout = 6000
    tracer.model.root_filename = dctx.get_root_filename()
    tracer.model.shellcode_location = 0x000000014A731000
   
    tracer.invoke()

# Exemple d'utilisation pour un StepTracer
if __name__ == "__main__" and False:  # Désactivé par défaut
    from tenet.integration.api import disassembler
    
    pctx = ProcessContext()  # À remplacer par le contexte approprié
    dctx = disassembler[pctx]
    arch = pctx.arch
    
    tracer = IDAUnifiedTracerController(dctx, arch, pctx=pctx)
    tracer.model.tracer_type = "step_tracer"  # Configurer comme StepTracer
    tracer.model.run_timeout = 300
    
    tracer.invoke()
