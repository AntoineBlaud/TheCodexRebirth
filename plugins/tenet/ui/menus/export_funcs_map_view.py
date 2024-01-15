from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import QDir
from PyQt5.QtCore import Qt

class MyTreeView(QTreeView):
    def __init__(self, parent=None):
        super(MyTreeView, self).__init__(parent=parent)
        self.clicked.connect(self.on_clicked)
        

    def on_clicked(self, index):
        pass
    

class ExportFuncsMenuView(QMainWindow):
    def __init__(self, model):
        super(ExportFuncsMenuView, self).__init__()

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
        # add the export button
        self.export_button = QPushButton("Export", self)
        self.export_button.clicked.connect(self.export_data)
        layout.addWidget(self.export_button)
        
    def select_file(self):
        # open a file dialog
        file_path = QFileDialog.getOpenFileName(self, 'Open file',
                                            QDir.currentPath())
        # set the file path text box
        self.file_path_text_box.setText(file_path[0])
        # set the file path label
        
    
    def exec_(self):
        raise NotImplementedError("exec_ not implemented")

        
        
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
                func_name, func_address = function
                function_node = QStandardItem(hex(func_address) + " "*5 + func_name)
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
            for function in selected_functions:
                f.write(function + "\n")
        # close the window
        self.close()
        
        


    def get_selected_functions(self):
        selected_items = []
        root_item = self.tree_model.invisibleRootItem()
        for i in range(root_item.rowCount()):
            section_item = root_item.child(i)
            if section_item.checkState() == Qt.Checked:
                for j in range(section_item.rowCount()):
                    function_item = section_item.child(j)
                    if function_item.checkState() == Qt.Checked:
                        selected_items.append(function_item.text())
        return selected_items


