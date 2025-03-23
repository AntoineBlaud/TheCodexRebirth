from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import QDir, Qt, QSize
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
        self.setWindowFlags(Qt.WindowMinimizeButtonHint | Qt.WindowMaximizeButtonHint | Qt.WindowCloseButtonHint | Qt.Window)
        self.move(QApplication.desktop().screenGeometry().width() - 930, 20)

        self.create_layouts()
        self.create_configuration_options()
        self.create_files_options()
        self.create_record_buttons()
        self.create_buttons()
        self.create_progress_bar()

    def create_layouts(self):
        splitter = QSplitter(Qt.Horizontal)
        left_widget, right_widget = QWidget(), QWidget()
        self.left_layout, self.right_layout = QVBoxLayout(left_widget), QVBoxLayout(right_widget)
        splitter.addWidget(left_widget)
        splitter.addWidget(right_widget)
        self.setCentralWidget(splitter)

    def create_configuration_options(self):
        self.group_box = QGroupBox("Configuration Options")
        self.group_box_layout = QVBoxLayout(self.group_box)
        self.left_layout.addWidget(self.group_box)
        options = [("Run Timeout (sec)", str(self.model.timeout)), ("Module to Trace", self.model.root_filename or "")]
        for label_text, input_text in options:
            self.create_options_input(label_text, input_text)

    def create_options_input(self, label_text, input_text):
        label = QLabel(label_text)
        label.setFont(QFont("Arial", 12))
        input_field = QLineEdit(input_text)
        input_field.setAlignment(Qt.AlignCenter)
        input_field.setFont(QFont("Arial", 12))
        self.group_box_layout.addWidget(label)
        self.group_box_layout.addWidget(input_field)

    def create_files_options(self):
        file_group_box = QGroupBox("File Options")
        file_group_layout = QVBoxLayout()

        self.file_path_text_box = QLineEdit()
        self.file_path_button = QPushButton("Select File")
        self.file_path_button.clicked.connect(self.select_file)

        self.save_button = QPushButton("Save Ultimap")
        self.save_button.clicked.connect(self.save)

        self.load_button = QPushButton("Load Ultimap")
        self.load_button.clicked.connect(self.load)

        for widget in [
            QLabel("Exported Functions File Path:"), self.file_path_text_box,
            self.file_path_button, self.save_button, self.load_button
        ]:
            file_group_layout.addWidget(widget)

        file_group_box.setLayout(file_group_layout)
        self.left_layout.addWidget(file_group_box)

    def create_record_buttons(self):
        self.grid_layout = QGridLayout()
        num_buttons = 20  # Reduced number for performance
        for i in range(num_buttons):
            button = QPushButton(f"Record {i}")
            button.clicked.connect(lambda _, idx=i: self.open_record(idx))
            button.setContextMenuPolicy(Qt.CustomContextMenu)
            button.customContextMenuRequested.connect(self.button_record_context_menu)
            self.recording_buttons.append(button)
            self.grid_layout.addWidget(button, i // 5, i % 5)  # 5 columns
        self.right_layout.addLayout(self.grid_layout)

    def button_record_context_menu(self, pos):
        button = self.sender()
        menu = QMenu()
        rename_action = QAction("Rename", self)
        rename_action.triggered.connect(lambda _, btn=button: self.rename_record(btn))
        menu.addAction(rename_action)
        menu.exec_(button.mapToGlobal(pos))

    def rename_record(self, button):
        text, ok = QInputDialog.getText(self, "Rename Record", "Enter new name:")
        if ok:
            button.setText(text)

    def create_buttons(self):
        button_layout = QHBoxLayout()
        for label, func in [("Run", self.start), ("Reset", self.reset), ("Info", self.show_info)]:
            button_layout.addWidget(self.create_button(label, func))
        self.left_layout.addLayout(button_layout)

    def create_button(self, text, on_click):
        button = QPushButton(text)
        button.setFont(QFont("Arial", 12))
        button.clicked.connect(on_click)
        self._style_button(button)
        return button

    def create_progress_bar(self):
        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximum(100)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat(" %p%")
        self.left_layout.addWidget(self.progress_bar)

    def show_info(self):
        QMessageBox.information(
            self, "Step Tracer",
            "Step Tracer allows you to trace program execution and monitor memory/register changes."
        )

    def select_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Open file", QDir.currentPath())
        if file_path:
            self.file_path_text_box.setText(file_path)

    def start(self):
        self._refresh()
        input_data = self._get_input()
        timeout = int(input_data.get("timeout", 0))
        if timeout < 15:
            self.log("Timeout must be at least 15 seconds")
            return
        for key, value in input_data.items():
            setattr(self.model, key, value)
        self.controller.run()

    def reset(self):
        self.model.reset()
        self.progress_bar.setValue(0)
        for i, button in enumerate(self.recording_buttons):
            button.setText(f"Record {i}")
        self.log("Reset completed")
        self._refresh()

    def open_record(self, index):
        if index >= len(self.model.records):
            return
        record_window = QMainWindow()
        record_window.setWindowTitle(f"Record {index}")
        record_window.setFixedSize(400, 500)
        record_text = QTextEdit()
        record_text.setReadOnly(True)
        for k, v in self.model.records[index].items():
            record_text.append(f"{k}: {v}")
        record_window.setCentralWidget(record_text)
        record_window.show()

    def save(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Save file", QDir.currentPath())
        if file_path:
            data = self._get_input()
            data["records"] = self.model.records
            with open(file_path, "w") as f:
                json.dump(data, f)

    def load(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Open file", QDir.currentPath())
        if file_path:
            with open(file_path, "r") as f:
                data = json.load(f)
            self._load_data(data)
            self._refresh()

    def _load_data(self, data):
        self.model.reset()
        self.model.timeout = data.get("timeout", 5)
        self.model.moduleToTrace = data.get("moduleToTrace", "")
        self.model.fn_filepath = data.get("fn_filepath", "")
        self._set_input(self.model.timeout, self.model.moduleToTrace, self.model.fn_filepath)
        self.model.records = data.get("records", [])
        if not self.controller.initialize():
            self.log("Controller initialization failed")
            self.model.reset()

    def update_progress(self, value):
        self.progress_bar.setValue(value)

    def _get_input(self):
        return {
            "timeout": int(self.group_box_layout.itemAt(1).widget().text()),
            "moduleToTrace": self.group_box_layout.itemAt(3).widget().text(),
            "fn_filepath": self.file_path_text_box.text()
        }
    def _style_button(self, button):
        button.setFixedHeight(35)
        button.setStyleSheet("""
            QPushButton { background-color: #4287f5; color: white; border-radius: 8px; }
            QPushButton:hover { background-color: #306bd1; }
        """)
    def _set_input(self, timeout, module, file_path):
        self.group_box_layout.itemAt(1).widget().setText(str(timeout))
        self.group_box_layout.itemAt(3).widget().setText(module)
        self.file_path_text_box.setText(file_path)

    def _refresh(self):
        pass  # Placeholder for UI refresh

    def log(self, msg):
        print(f"[Ultimap] {msg}")
