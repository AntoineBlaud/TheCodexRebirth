from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5.QtCore import QDir
from PyQt5.QtCore import Qt
from PyQt5 import QtWidgets
from PyQt5.QtCore import QSize
import os 
import tempfile


WIDTH = 900
HEIGHT = 600


class UltimapView(QMainWindow):
    
    def __init__(self, controller, model, parent=None):
        super(UltimapView, self).__init__(parent)
        self.controller = controller
        try:
            self.pctx = controller.pctx
        except:
            self.pctx = None
        self.model = model
        self.recording_buttons = []
        self._init_ui()
        # set windows always on top
        self.setWindowFlags(Qt.WindowStaysOnTopHint | Qt.WindowCloseButtonHint)
        # set position to the center
        # get screen size
        height = QApplication.desktop().screenGeometry().height()
        width = QApplication.desktop().screenGeometry().width()
        self.move(width - WIDTH - 30, 20)
        
        
    def create_options_input(self, label_text, input_text):
        label = QtWidgets.QLabel(self)
        label.setText(label_text)
        label.setAlignment(Qt.AlignCenter)
        label.setFont(QFont('Arial', 10))
        label.setStyleSheet(
            "background-color: #edebeb;"
            "color: black;"               # Set text color to white
            "padding: 10px;"              # Add padding around the label
            "border-radius: 5px;"         # Add rounded corners
        )
        inputa = QtWidgets.QLineEdit(self)
        inputa.setText(input_text)
        inputa.setAlignment(Qt.AlignCenter)
        inputa.setFont(QFont('Arial', 10))
        inputa.setStyleSheet(
            "background-color: #edebeb;"
            "color: red;"               # Set text color to white
            "padding: 2px;"              # Add padding around the label
            "border-radius: 5px;"         # Add rounded corners
        )
        self.group_box_layout.addWidget(label)
        self.group_box_layout.addWidget(inputa)
        

    def _init_ui(self):

        # child widgets
        self.setWindowTitle("Step Tracer")
        
        #create splitter layout
        splitter = QtWidgets.QSplitter(self)
        # set the orientation of the splitter
        splitter.setOrientation(Qt.Horizontal)
        # create left layout and widget
        left_widget = QtWidgets.QWidget()
        self.left_layout = QtWidgets.QVBoxLayout()
        left_widget.setLayout(self.left_layout)
        # create right layout
        right_widget = QtWidgets.QWidget()
        self.right_layout = QtWidgets.QVBoxLayout()
        right_widget.setLayout(self.right_layout)
        # add the splitter to the main window
        self.setCentralWidget(splitter)
        # add the left layout to the splitter
        splitter.addWidget(left_widget)
        # add the right layout to the splitter
        splitter.addWidget(right_widget)
        
        # add windows max size
        self.setFixedHeight(HEIGHT)
        self.setFixedWidth(WIDTH)
        
        self.label2 = QtWidgets.QLabel(self)
        self.label2.setText("Configuration Options")
        self.label2.setAlignment(Qt.AlignCenter)
        self.label2.setFont(QFont('Arial', 11))

        # Add styles to improve appearance
        self.label2.setStyleSheet(
            "background-color: #bfbfbf;"  # Set background color to green
            "color: white;"               # Set text color to white
            "padding: 10px;"              # Add padding around the label
            "border-radius: 5px;"         # Add rounded corners
        )
        self.left_layout.setAlignment(Qt.AlignTop)
        self.left_layout.addWidget(self.label2)
        self.right_layout.setAlignment(Qt.AlignTop)
        left_widget.setMaximumWidth(WIDTH * 0.4)
        
        # create grid layout
        self.grid_layout = QtWidgets.QGridLayout()
        # set the grid layout
        self.right_layout.addLayout(self.grid_layout)
        for i in range(6):
            self.grid_layout.setColumnMinimumWidth(i, 80)
        
        for i in range(70):
            # create a button
            button = QtWidgets.QPushButton(f"Record {i}", self)
            # set the button size
            button.setFixedSize(80, 40)
            # set on click event
            button.clicked.connect(lambda checked, i=i: self.open_record(i))
            # add the button to the grid layout
            self.grid_layout.addWidget(button)
            self.recording_buttons.append(button)
            

        

    
        # create the group box for the run timeout, dump size and max step inside loop
        self.group_box = QtWidgets.QGroupBox("")
        # create the group box layout
        self.group_box_layout = QtWidgets.QVBoxLayout()
        # set the group box layout
        self.group_box.setLayout(self.group_box_layout)
        # add the group box to the left layout
        self.left_layout.addWidget(self.group_box)
        # set max height for the group box
        self.group_box.setMaximumHeight(450)
        self.group_box.setMinimumWidth(270)
        # group option attached to the top absolute position
        self.group_box_layout.setAlignment(Qt.AlignTop)
        
        self.create_options_input("First Run Timeout (sec)",  str(self.model.firstRunTimeout))
        self.create_options_input("Run Timeout (sec)",  str(self.model.timeout))
        self.create_options_input("Module to Trace", "ex: 'kernel32.dll' or 'explorer.exe'")
        # add the file path label
        self.file_path_label = QLabel(self)
        self.file_path_label.setText("Exported functions File Path: ")
        self.group_box_layout.addWidget(self.file_path_label)
        # add the file path text box
        self.file_path_text_box = QLineEdit(self)
        self.group_box_layout.addWidget(self.file_path_text_box)
        # add the file path button
        self.file_path_button = QPushButton("Select File", self)
        self.file_path_button.clicked.connect(self.select_file)
        self.group_box_layout.addWidget(self.file_path_button)
        
        bLayout = QHBoxLayout()
        buttonsWidgets = QWidget()
        buttonsWidgets.setLayout(bLayout)
        bLayout.setAlignment(Qt.AlignCenter)
        # add the start button
        self.start_button = QtWidgets.QPushButton("Start", self)
        self.start_button.setFont(QFont('Arial', 10))
        self.start_button.setAutoFillBackground(True)
        self.start_button.setStyleSheet("""
        QPushButton {
            background-color: #edebeb;
            color: black;
            border: 1px solid black;
            border-radius: 5px;
        }
        QPushButton:hover {
            background-color: #8d9bf0; 
        }
        """
        )
        self.start_button.clicked.connect(self._start)
        
        
        # add a progress bar
        self.progress_bar = QtWidgets.QProgressBar(self)
        self.progress_bar.setMaximum(100)
        self.progress_bar.setMinimum(0)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat(" %p%")
        # set progress bar at the bottom
        self.progress_bar.setAlignment(Qt.AlignBottom)
        self.progress_bar.setStyleSheet(
            "color: black;"
            "border: 1px solid black;"
            "border-radius: 3px;"
            "height: 10px;"
        )
        
        # add the progress bar to the right layout
        self.left_layout.addWidget(self.progress_bar)
        
        self.left_layout.addWidget(self.start_button)
            
        # add a info button
        self.info_button = QtWidgets.QPushButton("Info", self)
        self.info_button.setFont(QFont('Arial', 10))
        self.info_button.setAutoFillBackground(True)
        self.info_button.setFixedWidth(50)
        self.info_button.setStyleSheet(
            "QPushButton {"
            "   background-color: #4287f5;"
            "   border-style: outset;"
            "   border-width: 2px;"
            "   border-radius: 10px;"
            "   border-color: beige;"
            "   font: bold 14px;"
            "   color: white;"
            "}"
            "QPushButton:hover {"
            "   background-color: #45a049;"
            "}"
            "QPushButton:pressed {"
            "   background-color: #3c8c40;"
            "}"
        )
        self.info_button.clicked.connect(self.show_info)
        self.left_layout.addWidget(self.info_button)
        
        
    def show_info(self):
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Information)
        msg.setText("Step Tracer")
        msg.setInformativeText("Step Tracer is a dynamic analysis tool that allows you to trace the execution of a program and monitor the changes in memory and registers. It also allows you to set breakpoints on specific memory addresses and functions.")
        msg.setWindowTitle("Step Tracer")
        msg.setStandardButtons(QMessageBox.Ok)
        msg.exec_()
        
        
    def open_record(self, i):
        # create a new text windows with functions names and number of hits
        self.record_window = QtWidgets.QMainWindow()
        self.record_window.setWindowTitle(f"Record {i}")
        self.record_window.setFixedHeight(400)
        self.record_window.setFixedWidth(400)
        self.record_window.move(100, 100)
        self.record_window.show()
        # create a text edit
        self.record_text = QtWidgets.QTextEdit(self.record_window)
        self.record_text.setReadOnly(True)
        self.record_text.setLineWrapMode(QtWidgets.QTextEdit.NoWrap)
        self.record_text.setWordWrapMode(QtWidgets.QTextOption.NoWrap)
        self.record_text.setLineWrapColumnOrWidth(0)
        self.record_text.setLineWrapMode(QtWidgets.QTextEdit.FixedPixelWidth)
        self.record_text.setFixedWidth(400)
        self.record_text.setFixedHeight(400)
        self.record_text.setFont(QFont('Arial', 10))
        self.record_text.setStyleSheet(
            "background-color: #edebeb;"
            "color: black;"
            "padding: 10px;"
            "border-radius: 5px;"
        )
        self.record_window.setCentralWidget(self.record_text)
        # add the text to the text edit
        records = self.model.records[i]
        for k, v in records.items():
            self.record_text.append(f"{k} : {v}\n")
            
        
 
    def select_file(self):
        # open a file dialog
        file_path = QFileDialog.getOpenFileName(self, 'Open file',
                                            QDir.currentPath())
        # set the file path text box
        self.file_path_text_box.setText(file_path[0])
        # set the file path label
    
    
             
    def _start(self):
        self._refresh()
        # fetch options
        self.model.firstRunTimeout = int(self.group_box_layout.itemAt(1).widget().text())
        self.model.timeout = int(self.group_box_layout.itemAt(3).widget().text())
        self.model.moduleToTrace = self.group_box_layout.itemAt(5).widget().text()
        self.model.importedFunctionsFilePath = self.file_path_text_box.text()
        self.controller.run()
        
        
    def update_progress(self, value):
        self.progress_bar.setValue(value)
   
   
    
    def _refresh(self):
        pass
   


# class UltimapModel(object):
#     """
#     The Ultimap Model
#     """

#     def __init__(self, pctx):
#         self.pctx = pctx
#         try:
#             self.arch = self.pctx.arch
#         except:
#             self.arch = None
#         self.firstRunTimeout= 5 * 60
#         self.timeout = 5
#         self.importedFunctionsFilePath = ""
#         self.moduleToTrace = ""
#         self.reset()
        
#     def reset(self):
#         """
#         Reset the model.
#         """
#         pass

    
        
        
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
