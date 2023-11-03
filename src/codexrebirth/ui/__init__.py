from codexrebirth.tools.qt import QT_AVAILABLE

# import Qt based plugin UI if available
if QT_AVAILABLE:
    from codexrebirth.ui.palette import PluginPalette
    
from codexrebirth.ui.reg_view import RegisterView
from codexrebirth.ui.trace_view import TraceView
