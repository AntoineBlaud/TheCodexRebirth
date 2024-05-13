# --------------------------------------------------------------------------
# Disassembler API Selector
# --------------------------------------------------------------------------
#
#    this file will select and load the shimmed disassembler API for the
#    appropriate (current) disassembler platform.
#
#    see api.py for more details regarding this API shim layer
#
import logging

disassembler = None
logger = logging.getLogger(f"Tenet.{__name__}")

# --------------------------------------------------------------------------
# IDA API Shim
# --------------------------------------------------------------------------

if disassembler == None:
    try:
        from .ida_api import IDACoreAPI, IDAContextAPI, DockableWindow

        disassembler = IDACoreAPI()
        DisassemblerContextAPI = IDAContextAPI
    except ImportError:
        pass


##--------------------------------------------------------------------------
## Binary Ninja API Shim
##--------------------------------------------------------------------------
#
# if disassembler == None:
#    try:
#        from .binja_api import BinjaCoreAPI, BinjaContextAPI
#        disassembler = BinjaCoreAPI()
#        DisassemblerContextAPI = BinjaContextAPI
#    except ImportError:
#        pass

# --------------------------------------------------------------------------
# Unknown Disassembler
# --------------------------------------------------------------------------

if disassembler == None:
    logger.info("Unknown or unsupported disassembler!")
