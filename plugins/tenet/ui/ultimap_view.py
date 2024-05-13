from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import QDir
from PyQt5.QtCore import Qt
from PyQt5 import QtWidgets
from PyQt5.QtCore import QSize
import os
import tempfile
import json


class UltimapView(QMainWindow):
    def __init__(self, controller, model, parent=None):
        super(UltimapView, self).__init__(parent)
        self.controller = controller
        self.model = model
        self.recording_buttons = []
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Ultimap")
        self.setFixedSize(900, 600)
        self.setWindowFlags(Qt.WindowStaysOnTopHint | Qt.WindowCloseButtonHint)
        self.move(QApplication.desktop().screenGeometry().width() - 930, 20)

        self.create_layouts()
        self.create_configuration_options()
        self.create_files_options()
        self.create_record_buttons()
        self.create_buttons()
        self.create_progress_bar()

    def create_layouts(self):
        splitter = QSplitter(Qt.Horizontal)
        left_widget = QWidget()
        self.left_layout = QVBoxLayout(left_widget)
        right_widget = QWidget()
        self.right_layout = QVBoxLayout(right_widget)
        splitter.addWidget(left_widget)
        splitter.addWidget(right_widget)
        self.setCentralWidget(splitter)

    def create_configuration_options(self):
        self.group_box = QGroupBox("Configuration Options")
        self.group_box_layout = QVBoxLayout(self.group_box)
        self.left_layout.addWidget(self.group_box)
        options = [
            ("Run Timeout (sec)", str(self.model.timeout)),
            ("Module to Trace", self.controller.dctx.get_root_filename() or ""),
        ]
        for label_text, input_text in options:
            self.create_options_input(label_text, input_text)

    def create_options_input(self, label_text, input_text):
        label = QLabel(label_text)
        label.setAlignment(Qt.AlignCenter)
        label.setFont(QFont("Arial", 10))
        label.setMaximumHeight(40)
        label.setStyleSheet(
            "background-color: #edebeb;"
            "color: black;"  # Set text color to white
            "padding: 10px;"  # Add padding around the label
            "border-radius: 5px;"  # Add rounded corners
        )
        input_field = QLineEdit(input_text)
        input_field.setAlignment(Qt.AlignCenter)
        input_field.setFont(QFont("Arial", 10))
        input_field.setMaximumHeight(40)
        input_field.setStyleSheet(
            "background-color: #edebeb;"
            "color: red;"  # Set text color to white
            "padding: 2px;"  # Add padding around the label
            "border-radius: 5px;"  # Add rounded corners
        )
        self.group_box_layout.addWidget(label)
        self.group_box_layout.addWidget(input_field)

    def create_files_options(self):
        # Group Box for file options
        file_group_box = QGroupBox("File Options")
        file_group_layout = QVBoxLayout()

        # File path label
        self.file_path_label = QLabel("Exported Functions File Path:")
        file_group_layout.addWidget(self.file_path_label)

        # File path text box
        self.file_path_text_box = QLineEdit()
        file_group_layout.addWidget(self.file_path_text_box)

        # File path selection button
        self.file_path_button = QPushButton("Select File")
        self.file_path_button.clicked.connect(self.select_file)
        file_group_layout.addWidget(self.file_path_button)

        # Save button
        self.save_button = QPushButton("Save Ultimap")
        self.save_button.clicked.connect(self.save)
        file_group_layout.addWidget(self.save_button)

        # Load button
        self.load_button = QPushButton("Load Ultimap")
        self.load_button.clicked.connect(self.load)
        file_group_layout.addWidget(self.load_button)

        # Set group layout and add to main layout
        file_group_box.setLayout(file_group_layout)
        self.left_layout.addWidget(file_group_box)

    def create_record_buttons(self):
        # create grid layout
        self.grid_layout = QtWidgets.QGridLayout()
        for i in range(6):
            self.grid_layout.setColumnMinimumWidth(i, 80)
        for i in range(70):
            button = QPushButton(f"Record {i}")
            button.setFixedSize(80, 40)
            button.clicked.connect(lambda _, i=i: self.open_record(i))
            button.setContextMenuPolicy(Qt.CustomContextMenu)
            button.customContextMenuRequested.connect(self.button_record_context_menu)
            self.recording_buttons.append(button)
            self.grid_layout.addWidget(button)
        self.right_layout.addLayout(self.grid_layout)

    def button_record_context_menu(self, pos):
        button = self.sender()
        menu = QMenu()
        action = QAction("Rename", self)
        action.triggered.connect(lambda _, button=button: self.rename_record(button))
        menu.addAction(action)
        menu.exec_(button.mapToGlobal(pos))

    def rename_record(self, button):
        text, ok = QLineEdit.getText(self, "Rename Record", "Enter new name:")
        if ok:
            button.setText(text)

    def create_buttons(self):
        button_layout = QHBoxLayout()
        self.start_button = self.create_button("Run", self.start)
        self.reset_button = self.create_button("Reset", self.reset)
        self.info_button = self.create_button("Info", self.show_info)
        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.reset_button)
        button_layout.addWidget(self.info_button)
        self.left_layout.addLayout(button_layout)

    def create_button(self, text, on_click):
        button = QPushButton(text)
        button.setFont(QFont("Arial", 10))
        button.clicked.connect(on_click)
        return button

    def create_progress_bar(self):
        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximum(100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat(" %p%")
        self.progress_bar.setAlignment(Qt.AlignBottom)
        self.progress_bar.setStyleSheet(
            "QProgressBar { color: black; border: 1px solid black; border-radius: 3px; height: 10px; }"
        )
        self.left_layout.addWidget(self.progress_bar)

    def _get_root_filename(self):
        try:
            return self.controller.dctx.get_root_filename() or ""
        except Exception as e:
            print(f"Error retrieving root filename: {e}")
            return ""

    def show_info(self):
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Information)
        msg.setText("Step Tracer")
        msg.setInformativeText(
            "Step Tracer is a dynamic analysis tool that allows you to trace the execution "
            "of a program and monitor the changes in memory and registers. It also allows "
            "you to set breakpoints on specific memory addresses and functions."
        )
        msg.setWindowTitle("Step Tracer")
        msg.setStandardButtons(QMessageBox.Ok)
        msg.exec_()

    def _button_record_context_menu(self, pos):
        button = self.sender()
        menu = self._create_context_menu()
        menu.exec_(button.mapToGlobal(pos))

    def _create_context_menu(self):
        menu = QMenu(self)
        action = menu.addAction("Rename")
        action.triggered.connect(lambda checked, button=self.sender(): self.rename_record(button))
        action = menu.addAction("Disable Breakpoints")
        action.triggered.connect(lambda checked, button=self.sender(): self.disable_breakpoint(button))
        action = menu.addAction("Enable Breakpoints")
        action.triggered.connect(lambda checked, button=self.sender(): self.enable_breakpoint(button))
        return menu

    def rename_record(self, button):
        text, ok = QInputDialog.getText(self, "Rename Record", "Enter new name:")
        if ok:
            button.setText(text)

    def disable_breakpoint(self, button):
        record_index = self.recording_buttons.index(button)
        self.controller.disable_breakpoints(record_index)
        self.log(f"Disabled breakpoints for record {record_index}")

    def enable_breakpoint(self, button):
        record_index = self.recording_buttons.index(button)
        self.controller.enable_breakpoints(record_index)
        self.log(f"Enabled breakpoints for record {record_index}")

    def log(self, msg):
        print(f"[Ultimap] {msg}")

    def reset(self):
        self.model.reset()
        self.progress_bar.setValue(0)
        for i, button in enumerate(self.recording_buttons):
            button.setText(f"Record {i}")
        self.log("Successfully reset")
        self._refresh()

    def open_record(self, i):
        if i >= len(self.model.records):
            return
        records = self.model.records[i]
        self._create_record_window(records, i)

    def _create_record_window(self, records, i):
        self.record_window = QMainWindow()
        self.record_window.setWindowTitle(f"Record {i}")
        self.record_window.setFixedSize(400, 500)
        self.record_text = QTextEdit()
        self.record_text.setReadOnly(True)
        self._populate_record_text(records)
        self.record_window.setCentralWidget(self.record_text)
        self.record_window.show()

    def _populate_record_text(self, records):
        for k, v in records.items():
            self.record_text.append(f"{k}")

    def save(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Save file", QDir.currentPath())
        if file_path:
            data_to_save = self._get_input()
            data_to_save["records"] = self.model.records
            with open(file_path, "w") as file:
                json.dump(data_to_save, file)

    def load(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Open file", QDir.currentPath())
        if file_path:
            with open(file_path, "r") as file:
                data = json.load(file)
            self._load_data(data)
            self._refresh()

    def _load_data(self, data):
        self.model.reset()
        self.model.timeout = data["timeout"]
        self.model.moduleToTrace = data["moduleToTrace"]
        self.model.importedFunctionsFilePath = data["importedFunctionsFilePath"]
        self._set_input(self.model.timeout, self.model.moduleToTrace, self.model.importedFunctionsFilePath)
        self.model.records = data["records"]
        if not self.controller.initialize():
            self.log("Error initializing controller")
            self.model.reset()

    def select_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Open file", QDir.currentPath())
        if file_path:
            self.file_path_text_box.setText(file_path)

    def start(self):
        self._refresh()
        input_data = self._get_input()
        for key in input_data:
            if key == "timeout":
                value = int(input_data[key])
                if value < 15:
                    self.log(f"{key} must be at least 15 seconds")
                    return
            setattr(self.model, key, input_data[key])
        self.controller.run()

    def update_progress(self, value):
        self.progress_bar.setValue(value)

    def _get_input(self):
        input_data = {}
        input_data["timeout"] = int(self.group_box_layout.itemAt(1).widget().text())
        input_data["moduleToTrace"] = self.group_box_layout.itemAt(3).widget().text()
        input_data["importedFunctionsFilePath"] = self.file_path_text_box.text()
        return input_data

    def _set_input(self, timeout=None, moduleToTrace=None, importedFunctionsFilePath=None):
        if timeout is not None:
            self.group_box_layout.itemAt(1).widget().setText(str(timeout))
        if moduleToTrace:
            self.group_box_layout.itemAt(3).widget().setText(moduleToTrace)
        if importedFunctionsFilePath:
            self.file_path_text_box.setText(importedFunctionsFilePath)

    def _refresh(self):
        pass  # Placeholder for any refreshing operations


# class UltimapModel(object):
#     """
#     The Ultimap Model
#     """

#     def __init__(self, pctx):
#         self.pctx = pctx
#         try:
#             self.arch = self.pctx.arch
#         except:
#             pass
#         self.timeout = 5
#         self.importedFunctionsFilePath = ""
#         self.reset()

#     def reset(self):
#         """
#         Reset the model.
#         """
#         self.functionBreakpoints = {}
#         self.importedFunctions = {}
#         self.reverseImportedFunctions = {}
#         self.moduleToTrace = ""
#         self.records = []


# # # creat the main window
# app = QApplication([])
# # create the controller
# controller = None
# # create the model
# model = UltimapModel(None)
# # create the view
# view = UltimapView(controller, model)
# view._refresh()
# # show the view
# view.show()
# # start the application
# app.exec_()
