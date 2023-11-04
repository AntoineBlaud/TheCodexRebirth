from ..tools.qt import QT_AVAILABLE

# import Qt based plugin UI if available
if QT_AVAILABLE:
    from .palette import PluginPalette

from .reg_view import RegisterView
from .trace_view import TraceView
from .hex_view import HexView
