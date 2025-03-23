from PyQt5.QtWidgets import (
    QMainWindow, QTreeView, QVBoxLayout, QWidget, QLabel, QLineEdit,
    QPushButton, QHBoxLayout, QFileDialog
)
from PyQt5.QtGui import QStandardItemModel, QStandardItem, QBrush, QColor
from PyQt5.QtCore import Qt, QSize, QDir
import logging

from tenet.util.common import *

logger = logging.getLogger(f"Tenet.{__name__}")


class MyTreeView(QTreeView):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.clicked.connect(self.on_clicked)

    def on_clicked(self, index):
        # Handle tree view item click
        pass


class ExportFuncsMenuView(QMainWindow):
    def __init__(self, controller, model, parent=None):
        super().__init__(parent)
        self.controller = controller
        self.model = model

        self._setup_window()
        self._setup_layout()
        self._setup_filters()
        self._setup_export_button()
        self._setup_tree_model()

    def _setup_window(self):
        self.setWindowTitle("Export Functions")
        self.setGeometry(100, 100, 800, 600)
        self.setWindowFlags(
            Qt.WindowMinimizeButtonHint |
            Qt.WindowMaximizeButtonHint |
            Qt.WindowCloseButtonHint |
            Qt.WindowStaysOnTopHint
        )

    def _setup_layout(self):
        self.tree_view = MyTreeView(self)
        self.central_widget = QWidget(self)
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout(self.central_widget)
        self.layout.addWidget(self.tree_view)

        # File path controls
        self.file_path_label = QLabel("File Path: ", self)
        self.file_path_text_box = QLineEdit(self)
        self.file_path_button = QPushButton("Select File", self)
        self.file_path_button.clicked.connect(self.select_file)

        self.layout.addWidget(self.file_path_label)
        self.layout.addWidget(self.file_path_text_box)
        self.layout.addWidget(self.file_path_button)

    def _setup_filters(self):
        # Filter controls layout
        h_layout = QHBoxLayout()
        self.layout.addLayout(h_layout)

        # Coverage filter
        self.coverage_label = QLabel("Coverage", self)
        self.coverage_greater_button = QPushButton(">", self)
        self.coverage_greater_button.setFixedWidth(20)
        self.coverage_text_box = QLineEdit("80", self)

        h_layout.addWidget(self.coverage_label)
        h_layout.addWidget(self.coverage_greater_button)
        h_layout.addWidget(self.coverage_text_box)

        # Size filter
        self.size_label = QLabel("Size", self)
        self.size_greater_button = QPushButton(">", self)
        self.size_greater_button.setFixedWidth(20)
        self.size_text_box = QLineEdit("40", self)

        h_layout.addWidget(self.size_label)
        h_layout.addWidget(self.size_greater_button)
        h_layout.addWidget(self.size_text_box)

    def _setup_export_button(self):
        self.export_button = QPushButton("Export", self)
        self.export_button.clicked.connect(self.export_data)
        self.layout.addWidget(self.export_button)

    def _setup_tree_model(self):
        self.tree_model = self._create_tree_model()
        self.tree_view.setModel(self.tree_model)

    def select_file(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Select File", QDir.currentPath())
        if file_path:
            self.file_path_text_box.setText(file_path)

    def _create_tree_model(self):
        model = QStandardItemModel()
        model.setHorizontalHeaderLabels(["Sections:"])
        root_node = model.invisibleRootItem()
        model.itemChanged.connect(self.on_item_changed)

        for section in self.model.sections_data:
            section_name, section_range, functions = section["name"], section["range"], section["functions"]
            logger.info(f"Section {section_name} has {len(functions)} functions")

            # Section item
            section_item = QStandardItem(f"{section_name}     {section_range}")
            section_item.setCheckable(True)
            section_item.setBackground(QBrush(QColor(2, 110, 0)))  # Light green

            # Function items
            for f_name, f_addr, f_cover, f_size in functions:
                function_text = f"{hex(f_addr)} {f_name} :   coverage({f_cover})     size({f_size})"
                function_item = QStandardItem(function_text)
                function_item.setCheckable(True)
                function_item.setBackground(QBrush(QColor(0, 2, 110)))  # Light blue
                section_item.appendRow(function_item)

            root_node.appendRow(section_item)

        return model

    def on_item_changed(self, item):
        # Synchronize section and function check states
        if not item.parent():  # Section level
            state = item.checkState()
            for row in range(item.rowCount()):
                item.child(row).setCheckState(state)

    def get_selected_functions(self):
        selected = []
        size_filter = int(self.size_text_box.text())
        coverage_filter = int(self.coverage_text_box.text())
        root_item = self.tree_model.invisibleRootItem()

        for i in range(root_item.rowCount()):
            section_item = root_item.child(i)
            if section_item.checkState() == Qt.Checked:
                for j in range(section_item.rowCount()):
                    function_item = section_item.child(j)
                    if function_item.checkState() == Qt.Checked:
                        try:
                            text = function_item.text()
                            addr_name = text.split(" :")[0]
                            coverage = int(text.split("coverage(")[1].split(")")[0])
                            size = int(text.split("size(")[1].split(")")[0])

                            if coverage > coverage_filter and size > size_filter:
                                selected.append(addr_name)
                        except (IndexError, ValueError):
                            continue  # Safely skip malformed items
        return selected

    def export_data(self):
        file_path = self.file_path_text_box.text().strip()
        if not file_path:
            logger.error("No file path selected.")
            return

        selected_functions = self.get_selected_functions()
        if not selected_functions:
            logger.warning("No functions selected for export.")
            return

        try:
            with open(file_path, "w") as file:
                for func in selected_functions:
                    file.write(func + "\n")
            logger.info(f"Exported {len(selected_functions)} functions to {file_path}")
        except IOError as e:
            logger.error(f"Failed to write file: {e}")
        finally:
            self.close()
