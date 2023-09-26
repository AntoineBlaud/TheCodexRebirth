from ida_codexrebirth.util.qt import QT_AVAILABLE

# import Qt based plugin UI if available
if QT_AVAILABLE:
    from ida_codexrebirth.ui.palette import PluginPalette
