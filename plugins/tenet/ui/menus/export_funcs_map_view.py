from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import QDir
from PyQt5.QtCore import Qt
from tenet.util.common import *

class MyTreeView(QTreeView):
    def __init__(self, parent=None):
        super(MyTreeView, self).__init__(parent=parent)
        self.clicked.connect(self.on_clicked)
        

    def on_clicked(self, index):
        pass
    

class ExportFuncsMenuView(QMainWindow):
    def __init__(self, model, parent=None):
        super(ExportFuncsMenuView, self).__init__(parent)

        self.setWindowTitle("Export Functions Map")
        self.setGeometry(100, 100, 800, 600)
        self.model = model
        self.tree_view = MyTreeView(self)

        #self.file_path_label =QFile

        layout = QVBoxLayout()
        layout.addWidget(self.tree_view)

        central_widget = QWidget()
        central_widget.setLayout(layout)
        self.setCentralWidget(central_widget)
        self.tree_model = self.create_tree_model()
        self.tree_view.setModel(self.tree_model)
        # add the file path label
        self.file_path_label = QLabel(self)
        self.file_path_label.setText("File Path: ")
        layout.addWidget(self.file_path_label)
        # add the file path text box
        self.file_path_text_box = QLineEdit(self)
        layout.addWidget(self.file_path_text_box)
        # add the file path button
        self.file_path_button = QPushButton("Select File", self)
        self.file_path_button.clicked.connect(self.select_file)
        layout.addWidget(self.file_path_button)
        
        # add horizontal layout
        h_layout = QHBoxLayout()
        layout.addLayout(h_layout)
        
        # add filter label for coverage > 
        self.coverage_label = QLabel(self)
        self.coverage_label.setText("Coverage")
        h_layout.addWidget(self.coverage_label)
        
        # add a button with text ">"
        self.coverage_greater_than_button = QPushButton(">", self)
        self.coverage_greater_than_button.setFixedWidth(20)
        h_layout.addWidget(self.coverage_greater_than_button)
        
        # add a text box for coverage
        self.coverage_text_box = QLineEdit(self)
        self.coverage_text_box.setText("80")
        h_layout.addWidget(self.coverage_text_box)
        
        
        # add filter label for size >
        
        self.size_label = QLabel(self)
        self.size_label.setText("Size")
        h_layout.addWidget(self.size_label)
        
        # add a button with text ">"
        self.size_greater_than_button = QPushButton(">", self)
        self.size_greater_than_button.setFixedWidth(20)
        h_layout.addWidget(self.size_greater_than_button)
        
        # add a text box for size
        self.size_text_box = QLineEdit(self)
        self.size_text_box.setText("40")
        h_layout.addWidget(self.size_text_box)
        

        # add the export button
        self.export_button = QPushButton("Export", self)
        self.export_button.clicked.connect(self.export_data)
        layout.addWidget(self.export_button)
        
        # set windows always on top
        self.setWindowFlags(Qt.WindowStaysOnTopHint | Qt.WindowCloseButtonHint)
        
    def select_file(self):
        # open a file dialog
        file_path = QFileDialog.getSaveFileName(self, 'Open file',
                                            QDir.currentPath())
        # set the file path text box
        self.file_path_text_box.setText(file_path[0])
        # set the file path label
        
    


        
        
    def on_item_changed(self, item):
        # check if the item is a section or a function
        if item.parent() is None:
            # item is a section
            if item.checkState() == Qt.Checked:
                # check all the functions in the section
                for row in range(item.rowCount()):
                    item.child(row).setCheckState(Qt.Checked)
            else:
                # uncheck all the functions in the section
                for row in range(item.rowCount()):
                    item.child(row).setCheckState(Qt.Unchecked)
        
    
    def create_tree_model(self):
        model = QStandardItemModel()
        root_node = model.invisibleRootItem()
        model.setHorizontalHeaderLabels(['Sections: '])
        model.itemChanged.connect(self.on_item_changed)
        
        sections_data = self.model.sections_data
        
        for section in sections_data:
            section_name = section["name"]
            functions = section["functions"]
            range = section["range"]
            section_node = QStandardItem(section_name + " "*5 + range)
            # add range to section node
            range_node = QStandardItem(range)
            section_node.setCheckable(True)
            section_node.setCheckState(False)
            # set light green background for sections
            section_node.setBackground(QBrush(QColor(230, 255, 230)))
            root_node.appendRow(section_node)
        

            for function in functions:
                # add a combobox for each function
                f_name, f_addr , f_cover, f_size = function
                function_node = QStandardItem(f"{hex(f_addr)} {f_name} :   coverage({f_cover})     size({f_size})")

                function_node.setCheckable(True)
                function_node.setCheckState(False)
                # set light blue background for functions
                function_node.setBackground(QBrush(QColor(230, 255, 255)))
                section_node.appendRow(function_node)
        return model

    def export_data(self):
        file_path = self.file_path_text_box.text()
        selected_functions = self.get_selected_functions()
        # export the data
        print("Exporting data to: ", file_path)
        with open(file_path, "w") as f:
            for i, function in enumerate(selected_functions):
                f.write(function + "\n")
                if i > 900:
                    show_msgbox("Too many functions, limit to 900", "Export Functions - Error")
        # close the window
        self.close()
        
        
    def get_selected_functions(self):
        selected_items = []
        size_filter = int(self.size_text_box.text())
        coverage_filter = int(self.coverage_text_box.text())
        
        root_item = self.tree_model.invisibleRootItem()
        for i in range(root_item.rowCount()):
            section_item = root_item.child(i)
            if section_item.checkState() == Qt.Checked:
                for j in range(section_item.rowCount()):
                    function_item = section_item.child(j)
                    function_item_text = function_item.text()
                    data_to_export = function_item_text.split(" :")[0]
                    coverage = int(function_item_text.split("coverage(")[1].split(")")[0])
                    size = int(function_item_text.split("size(")[1].split(")")[0])
                    if function_item.checkState() == Qt.Checked and coverage > coverage_filter and size > size_filter:
                        selected_items.append(data_to_export)
        return selected_items


