from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import Qt, QSize
import os
import tempfile
import time


class WatcherWidget(QWidget):
    def __init__(self, parent=None, index=0):
        super().__init__(parent)
        self.index = index
        self.parentw = parent
        self._init_ui()

    def _init_ui(self):
        self.setFixedHeight(200)
        self.setStyleSheet("background-color: #f5f5f5; border: 1px solid #ccc; border-radius: 8px; padding: 5px;")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 0, 10, 0)
        layout.setSpacing(10)

        # Index Label
        index_label = QLabel(str(self.index), self)
        index_label.setFixedSize(30, 30)
        index_label.setAlignment(Qt.AlignCenter)
        index_label.setFont(QFont("Arial", 10, QFont.Bold))

        # add a horizontal layout for buttons
        button_layout = QHBoxLayout()
        # Saved path display
        self.saved_value_label = QLabel("Not Saved", self)
        self.saved_value_label.setFixedHeight(30)
        self.saved_value_label.setFixedHeight(30)
        self.saved_value_label.setAlignment(Qt.AlignCenter)
        self.saved_value_label.setFont(QFont("Arial", 10))
        self.saved_value_label.setStyleSheet("background-color: #db1a4b; color: white; border-radius: 5px; padding: 2px;")


        # Load button
        load_btn = QPushButton("Load", self)
        load_btn.setFixedHeight(30)
        load_btn.setStyleSheet("""
            QPushButton { background-color: #4287f5; color: white; border-radius: 5px; }
            QPushButton:hover { background-color: #306bd1; }
        """)
        load_btn.clicked.connect(self._load)

        button_layout.addWidget(index_label, 1)
        button_layout.addWidget(load_btn, 1)
        button_layout.addWidget(self.saved_value_label, 3)

        layout.addLayout(button_layout)

    def _load(self):
        path = self.saved_value_label.text()
        if os.path.isfile(path):
            self.parentw.pctx.load_trace(path)
            self.parentw.pctx.show_ui()

    def set_saved(self, path):
        path = path.replace(tempfile.gettempdir(), "")
        self.saved_value_label.setText(path)
        self.saved_value_label.setStyleSheet("background-color: #4CAF50; color: white; border-radius: 5px; padding: 2px;")


class StepTracerView(QMainWindow):
    def __init__(self, controller, model, parent=None):
        super().__init__(parent)
        self.controller = controller
        self.model = model
        self.pctx = getattr(controller, 'pctx', None)

        self.setWindowTitle("Step Tracer")
        self.setGeometry(100, 100, 700, 450)
        self.setWindowFlags(Qt.Window | Qt.WindowMinimizeButtonHint | Qt.WindowCloseButtonHint)
        self.selected_tracer = "Step Tracer"
        self._init_ui()

    def _init_ui(self):
        self.splitter = QSplitter(Qt.Horizontal)
        self.setCentralWidget(self.splitter)

        # Left Panel
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_panel.setMaximumWidth(int(self.width() * 0.4))
        left_layout.setSpacing(10)
        left_layout.setContentsMargins(15, 15, 15, 15)

        config_title = QLabel("Configuration Options", self)
        config_title.setFixedHeight(40)
        config_title.setFont(QFont("Arial", 12, QFont.Bold))
        config_title.setAlignment(Qt.AlignCenter)
        config_title.setStyleSheet("background-color: #444; color: white; padding: 8px; border-radius: 5px;")
        left_layout.addWidget(config_title)

        self.tracer_combo = QComboBox()
        self.tracer_combo.addItems(["Step Tracer", "Block Tracer"])
        
        if self.selected_tracer:
            self.tracer_combo.setCurrentIndex(self.tracer_combo.findText(self.selected_tracer))
        
        self.tracer_combo.currentIndexChanged.connect(self._on_tracer_changed)
        left_layout.addWidget(self.tracer_combo)

        self.config_fields_layout = QVBoxLayout()
        left_layout.addLayout(self.config_fields_layout)

        self._setup_config_fields(self.selected_tracer)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setStyleSheet("""
            QProgressBar { border: 0px solid #ccc; border-radius: 20px; background-color: #f5f5f5; height: 5px; }
            QProgressBar::chunk { background-color: #4287f5; }
        """)
        self.progress_bar.setAlignment(Qt.AlignBottom)
        self.progress_bar.setFixedHeight(5)
        self.progress_bar.setTextVisible(False)
        self.progress_bar_info = QLabel("0%")
        self.progress_bar_info.setFixedHeight(25)
        self.progress_bar_info.setAlignment(Qt.AlignLeft)
        self.progress_bar_info.setStyleSheet("color: #595959; font-size: 12px;")
        left_layout.addWidget(self.progress_bar_info)
        left_layout.addWidget(self.progress_bar)

        # Buttons
        start_button = QPushButton("Start")
        start_button.clicked.connect(self._start)
        self._style_button(start_button)
        left_layout.addWidget(start_button)

        self.splitter.addWidget(left_panel)

        # Right Panel
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        right_layout.setSpacing(15)
        right_layout.setContentsMargins(15, 15, 15, 15)

        watchers_label = QLabel("Trace Results")
        watchers_label.setFixedHeight(40)
        watchers_label.setFont(QFont("Arial", 12, QFont.Bold))
        watchers_label.setAlignment(Qt.AlignCenter)
        watchers_label.setStyleSheet("background-color: #444; color: white; padding: 8px; border-radius: 5px;")
        right_layout.addWidget(watchers_label)

        self.extendable_list_view = QWidget()
        self.extendable_list_view_layout = QVBoxLayout(self.extendable_list_view)
        self.extendable_list_view_layout.setAlignment(Qt.AlignTop)
        right_layout.addWidget(self.extendable_list_view)

        # Add watcher widget
        self.extendable_list_view_layout.addWidget(WatcherWidget(self, 0))

        self.splitter.addWidget(right_panel)

    def _create_input_field(self, label_text, default_value):
        layout = QHBoxLayout()
        label = QLabel(label_text + ":")
        label.setFont(QFont("Arial", 12))
        label.setFixedWidth(160)
        line_edit = QLineEdit(default_value)
        line_edit.setFont(QFont("Arial", 12))
        layout.addWidget(label)
        layout.addWidget(line_edit)
        return layout

    def _style_button(self, button):
        button.setFixedHeight(35)
        button.setStyleSheet("""
            QPushButton { background-color: #4287f5; color: white; border-radius: 8px; }
            QPushButton:hover { background-color: #306bd1; }
        """)

    def _setup_config_fields(self, tracer_name):
        # Remove any existing config input widgets from layout

        print(f"Setting up config fields for {tracer_name}")

        config_fields = {
                "Step Tracer" : [
                ("Run Timeout", self.model.run_timeout),
                ("Dump Size", self.model.dump_size),
                ("Max Step Inside Loop", self.model.max_instruction_hits),
                ("Module to Trace", self.model.root_filename),
                ("Stop at Idx", self.model.stop_at_idx),
                ("Watchdog Max Hits", self.model.watchdog_max_hits),
            ],
                "Block Tracer" : [
                ("Run Timeout", self.model.run_timeout),
                ("Dump Size", self.model.dump_size),
                ("Module to Trace", self.model.root_filename),
                ("Stop at Idx", self.model.stop_at_idx),
                ("Init Shellcode Location", self.model.shellcode_location)
            ]
        }

        self.config_inputs = {}

        self.model.tracer_type = tracer_name.lower().replace(" ", "_")

        for label, value in config_fields[tracer_name]:
            input_line = self._create_input_field(label, str(value))
            self.config_inputs[label] = input_line.itemAt(1).widget()
            self.config_fields_layout.addLayout(input_line)

    def _on_tracer_changed(self, index):
        self.selected_tracer = self.tracer_combo.currentText()
        self.splitter.deleteLater()
        self._init_ui()

    def _start(self):
        self.model.run_timeout = int(self.config_inputs["Run Timeout"].text())
        self.model.dump_size = int(self.config_inputs["Dump Size"].text())
        self.model.root_filename = self.config_inputs["Module to Trace"].text()
        self.model.stop_at_idx = int(self.config_inputs["Stop at Idx"].text())
        
        if self.selected_tracer == "Block Tracer":
            self.model.shellcode_location = int(self.config_inputs["Init Shellcode Location"].text(), 16)

        if self.selected_tracer == "Step Tracer":
            self.model.max_instruction_hits = int(self.config_inputs["Max Step Inside Loop"].text())
            self.model.watchdog_max_hits = int(self.config_inputs["Watchdog Max Hits"].text())
        
        self.controller.invoke()

    def update_progress(self, start_time, idx):
        elapsed = time.time() - start_time
        percent = min(int((elapsed / self.model.run_timeout) * 100), 100)
        step_per_second = idx / elapsed if elapsed else 0
        self.progress_bar_info.setText(f"{percent}%  - idx={idx} - {step_per_second:.2f} steps/s ")
        self.progress_bar.setValue(percent)


    def _refresh_watcher(self):

        if not self.model.watcher.is_saved:
            return

        watcher_widget = self.extendable_list_view.layout().itemAt(0).widget()
        watcher_widget.set_saved(self.model.watcher.path)



    def _refresh(self):
        self.update_progress(self.model.start_time, self.model.idx)
        self._refresh_watcher()
