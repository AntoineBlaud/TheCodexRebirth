from tenet.ui import QT_AVAILABLE
from tenet.ui.menus import ExportFuncsMenuView
from tenet.integration.api import disassembler
import idaapi
import logging

logger = logging.getLogger(f"Tenet.{__name__}")

class ExportFunctionsMenuController:
    def __init__(self, pctx):
        self._pctx = pctx
        self.model = ExportFunctionsMenuModel(pctx)
        self.view = ExportFuncsMenuView(self.model)
        self.view.show()

    def show(self):
        self.view.show()
        raise "Showing the view"

    def hide(self):
        self.view.hide()


class ExportFunctionsMenuModel:
    def __init__(self, pctx):
        self.pctx = pctx
        self.dctx = disassembler[self.pctx]

        if self.dctx.is_debugger_on():
            raise Exception("Debugger must be off")

        logger.info("ExportFunctionsMenuModel initialized")
        self.sections_data = self.read_sections_data()
        self.register_callbacks = []

    def read_sections_data(self):
        offset = idaapi.get_imagebase()
        sections = self.dctx.get_sections() 
        for section in sections:
            logger.info(f"Processing section {section['name']}")
            section_name = section["name"]
            functions = self.dctx.get_functions_in_section(section_name)
            f_cache_coverages = {}
            length = len(functions)
            counter = 0
            functions_to_export = []
            functions_metadata = []
            for f_name, f_addr in functions:
                # get all sub calls recursively
                func = idaapi.get_func(f_addr)
                logger.info(f"Processing {f_name} in {section_name} ({counter}/{length})")
                f_cover = self.dctx.compute_function_coverage(func, section_name, f_cache_coverages)
                f_size = func.end_ea - func.start_ea
                functions_metadata.append((f_name, f_addr, len(f_cover), f_size))
                counter += 1
            functions_metadata = sorted(functions_metadata, key=lambda f: f[2], reverse=True)
            # keep only functions with coverage > 2 or size > 40
            for f_name, f_addr, f_cover, f_size in functions_metadata:
                if f_size > 40:
                    functions_to_export.append((f_name, f_addr - offset, f_cover, f_size))
            # add functions to section data
            section["functions"] = functions_to_export
        return sections

    def register_callback(self, callback):
        self.register_callbacks.append(callback)
