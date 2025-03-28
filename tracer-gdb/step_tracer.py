import sys
import os
import logging
from capstone.x86_const import *
from capstone.arm_const import *
import time

#
# TODO: SCRIPT NEEDS TO BE FIXED - CURRENT IMPORT AND API CHANGED
#



# Configure logging to stdout
logging.basicConfig(
    format='%(asctime)s %(levelname)5s: %(message)s',
    datefmt='%m-%d-%Y %H:%M:%S',
    level=logging.INFO,
)
logger = logging

try:
    import pwndbg
except ImportError:
    logger.info("Please run this script inside gdb with pwndbg installed")
    sys.exit(1)

# Fetch environment variable PLUGIN_PATH
PLUGIN_PATH = "/mnt/hgfs/vmware_sharefolder/plugins/"
if not os.path.exists(PLUGIN_PATH):
    raise Exception("PLUGIN_PATH not set or invalid")

# Constants
MAX_BREAKPOINTS = 28
MAX_STEP_INSIDE_LOOP = 2
RUN_TIMEOUT = 20
DUMP_SIZE = 10

# Ensure PLUGIN_PATH is in sys.path
if sys.path[0] != PLUGIN_PATH:
    sys.path.insert(0, PLUGIN_PATH)

try:
    from tenet.util.qt import *
    from tenet.util import *
    from tenet.ui import *

    from tenet.tracer.tracer_components import *
    from tenet.tracer.core_tracer import *
    from tenet.integration.api import *
    from tenet.trace_analysis.arch import *
    from tenet.tracer.logics.tracer_logic_step import SkipLoopLogic

except ImportError as e:
    raise Exception(f"Error importing Tenet: {e}")

class GDBStepTracerController(TracerController):
    def __init__(self, dctx, arch):
        super().__init__(dctx, arch)
        self.dctx = dctx
        self.cs = get_capstone_md_from_arch(self.arch)

    @property
    def ea(self):
        return self.dctx.get_reg_value(self.dctx.reg_pc)

    def stop(self):
        self.trace_file = self.save_trace()
        self.model.watcher = Watcher(self.prev_ea)
        self.model.watcher.is_saved = True
        self.model.watcher.path = self.trace_file
        library_calls = self.skip_logic.library_calls
        self.save_library_calls(library_calls)

    def update_ui(self):
        return None

    def initialize(self):
        execute_command("shell clear")
        execute_command("delete")
        execute_command("set scheduler-locking on")
        self.backup_files()
        self.model.module_name = self.dctx.get_segm_name(self.ea)
        if "<" not in self.model.module_name:
            base = self.dctx.get_main_module_start_by_name(self.model.module_name)
        else:
            base = self.dctx.get_main_module_start(self.ea)
        if not base:
            logger.error(f"Module {self.model.module_name} not found")
            return False
        self.model.tenet_trace.append([f"base={tohex(base, self.arch.POINTER_SIZE)}"])

        if self.dctx.is_process_running():
            raise Exception("Process is running, must be paused")

        self.model.run_timeout = RUN_TIMEOUT
        self.model.dump_size = DUMP_SIZE
        self.model.max_step_inside_loop = MAX_STEP_INSIDE_LOOP

        self.skip_logic = SkipLoopLogic(self.dctx, self.arch, self.model, MAX_BREAKPOINTS, print)
        self.skip_logic.set_callback_get_ea(lambda: self.dctx.get_reg_value(self.dctx.reg_pc))
        return True

    def run(self):
        self.start = time.time()
        while True:
            self.prev_ea = self.ea

            if time.time() - self.start > self.model.run_timeout:
                logger.info("Timeout")
                return

            if (self.idx + 1) % 1000 == 0:
                self.save_trace()
                self.save_library_calls(self.skip_logic.library_calls)

            self.skip_logic.step()
            try:
                ea = self.ea  # make a copy
                self.finalize_step(ea, self.prev_ea)
            except Exception as e:
                logger.error(f"Error getting PC: {e}")
                import traceback
                traceback.print_exc()
                return

    def invoke(self, arg, from_tty):
        if not self.initialize():
            return
        logger.info(f"Module to trace: {self.model.module_name}")
        logger.info(f"Timeout: {self.model.run_timeout} seconds")
        logger.info(f"Dump size: {self.model.dump_size}")
        logger.info(f"Max step inside loop: {self.model.max_step_inside_loop}")
        logger.info(f"Root filename: {self.dctx.get_root_filename()}")
        logger.info("Set Locking Scheduler on (disable multi-threading)")
        logger.info("You can edit the script to change the run timeout, dump size, and max step inside loop")
        time.sleep(2)
        try:
            self.run()
        except Exception as e:
            import traceback
            traceback.print_exc()
        finally:
            self.stop()

# Mapping of architectures to Tenet arch classes
pwnlib_archs_mapping = {
    "x86-64": ArchAMD64(),
    "x86": ArchX86(),
    "arm": ArchARM(),
    "aarch64": ArchARM64()
}

try:
    dctx = GDBContextAPI()
    arch = pwnlib_archs_mapping[pwndbg.gdblib.arch.current]
    GDBStepTracerController(dctx, arch).invoke("", False)
except Exception as e:
    import traceback
    traceback.print_exc()
    print("[ERROR] Please attach gdb to a process before loading the script")
