from codexrebirth.tools.qt import QT_AVAILABLE

# import Qt based plugin UI if available
if QT_AVAILABLE:
    from codexrebirth.ui.palette import PluginPalette
