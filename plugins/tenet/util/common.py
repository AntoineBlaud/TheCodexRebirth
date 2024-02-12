

def show_msgbox(text, title="Codex Rebirth"):
    """
    Show a message box.
    """
    from PyQt5.QtWidgets import QMessageBox

    msg = QMessageBox()
    msg.setIcon(QMessageBox.Information)
    msg.setText(text)
    msg.setWindowTitle(title)
    msg.exec_()
    
def create_name_from_address(name):
    # Process the name, converting integers to 'MEM_0xXXXX' format
    if isinstance(name, int):
        return "MEM_" + hex(name)
    return name