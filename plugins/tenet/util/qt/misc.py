
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

def show_msgbox_with_checkbox(text, title="Codex Rebirth", default_checked=False):
    """
    Show a message box with a checkbox. Returns True if the checkbox is checked, False otherwise.
    """
    from PyQt5.QtCore import Qt
    from PyQt5.QtWidgets import QMessageBox, QCheckBox
    msg = QMessageBox()
    msg.setIcon(QMessageBox.Information)
    msg.setText(text)
    msg.setWindowTitle(title)

    cb = QCheckBox("Agree/yes")
    cb.setObjectName("agree_checkbox")
    # cb.setState(Qt.Checked if default_checked else Qt.Unchecked)
    msg.layout().addWidget(cb)

    ret = msg.exec_()    
    return cb.isChecked()

    
